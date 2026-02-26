/**
 * C++ Flux Starter - Backend Server
 *
 * Simple WebSocket proxy to Deepgram's Flux API using Crow (HTTP/WS)
 * and Boost.Beast (outbound WS client).
 * Forwards all messages (JSON and binary) bidirectionally between client
 * and Deepgram.
 *
 * Routes:
 *   GET  /api/session              - Issue JWT session token
 *   GET  /api/metadata             - Project metadata from deepgram.toml
 *   GET  /health                   - Health check
 *   WS   /api/flux                 - WebSocket proxy to Deepgram Flux (auth required)
 */

#include <crow.h>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>

#include <jwt-cpp/jwt.h>
#include <toml.hpp>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace beast     = boost::beast;
namespace http      = beast::http;
namespace websocket = beast::websocket;
namespace net       = boost::asio;
namespace ssl       = net::ssl;
using     tcp       = net::ip::tcp;

// ============================================================================
// CONFIGURATION
// ============================================================================

struct Config {
    std::string deepgram_api_key;
    std::string deepgram_stt_url;
    uint16_t    port;
    std::string host;
    std::string session_secret;
};

/// Generate a random hex string of the given byte length.
static std::string random_hex(std::size_t bytes) {
    static const char hex_chars[] = "0123456789abcdef";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(0, 15);
    std::string out;
    out.reserve(bytes * 2);
    for (std::size_t i = 0; i < bytes * 2; ++i)
        out.push_back(hex_chars[dist(gen)]);
    return out;
}

/// Read an environment variable, returning fallback if unset/empty.
static std::string env_or(const char* name, const std::string& fallback) {
    const char* val = std::getenv(name);
    if (val && val[0] != '\0') return val;
    return fallback;
}

/// Load a minimal .env file (KEY=VALUE per line, no quoting).
static void load_dotenv(const std::string& path = ".env") {
    std::ifstream in(path);
    if (!in.is_open()) return;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);
        while (!key.empty() && key.back() == ' ') key.pop_back();
        while (!val.empty() && val.front() == ' ') val.erase(val.begin());
        ::setenv(key.c_str(), val.c_str(), 0);   // don't overwrite existing
    }
}

static Config load_config() {
    load_dotenv();

    Config cfg;
    cfg.deepgram_api_key = env_or("DEEPGRAM_API_KEY", "");
    if (cfg.deepgram_api_key.empty()) {
        std::cerr << "ERROR: DEEPGRAM_API_KEY environment variable is required\n"
                  << "Please copy sample.env to .env and add your API key\n";
        std::exit(1);
    }

    cfg.deepgram_stt_url = "wss://api.deepgram.com/v2/listen";

    auto port_str = env_or("PORT", "8081");
    cfg.port = static_cast<uint16_t>(std::stoi(port_str));

    cfg.host = env_or("HOST", "0.0.0.0");

    cfg.session_secret = env_or("SESSION_SECRET", random_hex(32));
    return cfg;
}

// ============================================================================
// SESSION AUTH - JWT tokens for production security
// ============================================================================

static const auto JWT_EXPIRY = std::chrono::seconds(3600);

/// Create a signed HS256 JWT.
static std::string generate_token(const std::string& secret) {
    auto now = std::chrono::system_clock::now();
    return jwt::create()
        .set_issued_at(now)
        .set_expires_at(now + JWT_EXPIRY)
        .sign(jwt::algorithm::hs256{secret});
}

/// Verify a JWT; returns true if valid.
static bool validate_token(const std::string& token, const std::string& secret) {
    try {
        auto verifier = jwt::verify()
            .allow_algorithm(jwt::algorithm::hs256{secret});
        auto decoded = jwt::decode(token);
        verifier.verify(decoded);
        return true;
    } catch (...) {
        return false;
    }
}

/// Extract and validate a JWT from WebSocket sub-protocols.
/// Returns the full "access_token.<jwt>" string if valid, or empty.
static std::string validate_ws_token(const std::string& protocols,
                                     const std::string& secret) {
    std::istringstream ss(protocols);
    std::string proto;
    while (std::getline(ss, proto, ',')) {
        while (!proto.empty() && proto.front() == ' ') proto.erase(proto.begin());
        while (!proto.empty() && proto.back() == ' ') proto.pop_back();

        const std::string prefix = "access_token.";
        if (proto.size() > prefix.size() &&
            proto.substr(0, prefix.size()) == prefix) {
            auto jwt_str = proto.substr(prefix.size());
            if (validate_token(jwt_str, secret))
                return proto;
        }
    }
    return "";
}

// ============================================================================
// URL / QUERY STRING HELPERS
// ============================================================================

/// Percent-encode a string for use in a URL query value.
static std::string url_encode(const std::string& s) {
    std::ostringstream encoded;
    encoded.fill('0');
    encoded << std::hex;
    for (unsigned char c : s) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            encoded << c;
        } else {
            encoded << '%' << std::setw(2) << int(c);
        }
    }
    return encoded.str();
}

/// Parse a raw query string into a multi-value map.
/// Supports repeated keys like keyterm=a&keyterm=b.
static std::unordered_map<std::string, std::vector<std::string>>
parse_query_string(const std::string& qs) {
    std::unordered_map<std::string, std::vector<std::string>> params;
    std::istringstream stream(qs);
    std::string pair;
    while (std::getline(stream, pair, '&')) {
        auto eq = pair.find('=');
        if (eq == std::string::npos) continue;
        params[pair.substr(0, eq)].push_back(pair.substr(eq + 1));
    }
    return params;
}

/// Get first value of a query parameter, or default.
static std::string qget(
    const std::unordered_map<std::string, std::vector<std::string>>& p,
    const std::string& key, const std::string& def = "") {
    auto it = p.find(key);
    if (it != p.end() && !it->second.empty()) return it->second.front();
    return def;
}

/// Get all values for a multi-value query parameter.
static std::vector<std::string> qget_all(
    const std::unordered_map<std::string, std::vector<std::string>>& p,
    const std::string& key) {
    auto it = p.find(key);
    if (it != p.end()) return it->second;
    return {};
}

// ============================================================================
// PER-CONNECTION PARAMS (stashed at accept time for use in onopen)
// ============================================================================

/// Holds the parsed Deepgram target path for one WebSocket connection.
struct ConnParams {
    std::string deepgram_target;  // e.g. /v2/listen?model=...&keyterm=...
};

// ============================================================================
// DEEPGRAM WEBSOCKET CLIENT (Boost.Beast, outbound TLS)
// ============================================================================

/**
 * DeepgramSession manages a single outbound WebSocket connection to Deepgram
 * and bidirectional message forwarding with the Crow client WebSocket.
 *
 * Lifetime: one per client /api/flux WebSocket connection.
 */
class DeepgramSession : public std::enable_shared_from_this<DeepgramSession> {
public:
    DeepgramSession(net::io_context& ioc,
                    ssl::context& ssl_ctx,
                    crow::websocket::connection& client_conn,
                    const std::string& deepgram_host,
                    const std::string& deepgram_port,
                    const std::string& deepgram_target,
                    const std::string& api_key)
        : resolver_(net::make_strand(ioc))
        , ws_(net::make_strand(ioc), ssl_ctx)
        , client_conn_(client_conn)
        , host_(deepgram_host)
        , port_(deepgram_port)
        , target_(deepgram_target)
        , api_key_(api_key)
    {}

    /// Initiate the async connection to Deepgram.
    void start() {
        resolver_.async_resolve(
            host_, port_,
            beast::bind_front_handler(&DeepgramSession::on_resolve,
                                      shared_from_this()));
    }

    /// Send binary audio data to Deepgram (client -> Deepgram).
    void send_binary(const std::string& data) {
        auto buf = std::make_shared<std::string>(data);
        net::post(ws_.get_executor(),
            [self = shared_from_this(), buf]() {
                self->write_queue_.push_back({*buf, true});
                if (self->write_queue_.size() == 1)
                    self->do_write();
            });
    }

    /// Send text (JSON) data to Deepgram (client -> Deepgram).
    void send_text(const std::string& data) {
        auto buf = std::make_shared<std::string>(data);
        net::post(ws_.get_executor(),
            [self = shared_from_this(), buf]() {
                self->write_queue_.push_back({*buf, false});
                if (self->write_queue_.size() == 1)
                    self->do_write();
            });
    }

    /// Close the Deepgram connection gracefully.
    void close() {
        if (closed_.exchange(true)) return;
        ws_.async_close(websocket::close_code::normal,
            [self = shared_from_this()](beast::error_code) {});
    }

    bool is_open() const {
        return ws_.is_open() && !closed_.load();
    }

private:
    struct QueueEntry { std::string data; bool binary; };

    tcp::resolver resolver_;
    websocket::stream<beast::ssl_stream<beast::tcp_stream>> ws_;
    crow::websocket::connection& client_conn_;
    std::string host_;
    std::string port_;
    std::string target_;
    std::string api_key_;
    beast::flat_buffer read_buf_;
    std::vector<QueueEntry> write_queue_;
    std::atomic<bool> closed_{false};

    // --- async chain: resolve -> connect -> TLS -> WS handshake -> read loop

    void on_resolve(beast::error_code ec, tcp::resolver::results_type results) {
        if (ec) { fail(ec, "resolve"); return; }
        beast::get_lowest_layer(ws_).expires_after(std::chrono::seconds(30));
        beast::get_lowest_layer(ws_).async_connect(
            results,
            beast::bind_front_handler(&DeepgramSession::on_connect,
                                      shared_from_this()));
    }

    void on_connect(beast::error_code ec, tcp::resolver::results_type::endpoint_type) {
        if (ec) { fail(ec, "connect"); return; }
        beast::get_lowest_layer(ws_).expires_after(std::chrono::seconds(30));

        // Set SNI hostname for TLS
        if (!SSL_set_tlsext_host_name(ws_.next_layer().native_handle(),
                                       host_.c_str())) {
            fail(beast::error_code(static_cast<int>(::ERR_get_error()),
                                   net::error::get_ssl_category()), "ssl_sni");
            return;
        }

        ws_.next_layer().async_handshake(
            ssl::stream_base::client,
            beast::bind_front_handler(&DeepgramSession::on_ssl_handshake,
                                      shared_from_this()));
    }

    void on_ssl_handshake(beast::error_code ec) {
        if (ec) { fail(ec, "ssl_handshake"); return; }
        beast::get_lowest_layer(ws_).expires_never();

        ws_.set_option(websocket::stream_base::timeout::suggested(
            beast::role_type::client));

        // Inject Authorization header into the WS upgrade request
        ws_.set_option(websocket::stream_base::decorator(
            [this](websocket::request_type& req) {
                req.set(http::field::authorization, "Token " + api_key_);
            }));

        ws_.async_handshake(host_, target_,
            beast::bind_front_handler(&DeepgramSession::on_handshake,
                                      shared_from_this()));
    }

    void on_handshake(beast::error_code ec) {
        if (ec) { fail(ec, "handshake"); return; }
        CROW_LOG_INFO << "Connected to Deepgram Flux API";
        do_read();
    }

    // --- reading from Deepgram ---

    void do_read() {
        ws_.async_read(read_buf_,
            beast::bind_front_handler(&DeepgramSession::on_read,
                                      shared_from_this()));
    }

    void on_read(beast::error_code ec, std::size_t bytes_transferred) {
        if (ec) {
            if (ec == websocket::error::closed) {
                CROW_LOG_INFO << "Deepgram connection closed normally";
            } else {
                CROW_LOG_ERROR << "Deepgram read error: " << ec.message();
            }
            try { client_conn_.close("Deepgram disconnected"); } catch (...) {}
            return;
        }

        auto data = beast::buffers_to_string(read_buf_.data());
        read_buf_.consume(bytes_transferred);

        bool is_binary = ws_.got_binary();
        try {
            if (is_binary) {
                client_conn_.send_binary(data);
            } else {
                client_conn_.send_text(data);
            }
        } catch (...) {
            CROW_LOG_ERROR << "Error forwarding Deepgram message to client";
            close();
            return;
        }

        do_read();
    }

    // --- writing to Deepgram ---

    void do_write() {
        if (write_queue_.empty() || closed_.load()) return;
        auto& entry = write_queue_.front();
        ws_.binary(entry.binary);
        ws_.async_write(
            net::buffer(entry.data),
            beast::bind_front_handler(&DeepgramSession::on_write,
                                      shared_from_this()));
    }

    void on_write(beast::error_code ec, std::size_t) {
        if (ec) { fail(ec, "write"); return; }
        write_queue_.erase(write_queue_.begin());
        if (!write_queue_.empty())
            do_write();
    }

    void fail(beast::error_code ec, const char* what) {
        CROW_LOG_ERROR << "Deepgram " << what << ": " << ec.message();
        try { client_conn_.close("Deepgram connection failed"); } catch (...) {}
    }
};

// ============================================================================
// ACTIVE CONNECTIONS TRACKING
// ============================================================================

static std::mutex g_connections_mutex;
static std::set<crow::websocket::connection*> g_active_connections;

// ============================================================================
// MAIN
// ============================================================================

int main() {
    auto cfg = load_config();

    // Boost.Asio io_context for outbound Deepgram connections
    net::io_context ioc;
    ssl::context ssl_ctx{ssl::context::tlsv12_client};
    ssl_ctx.set_default_verify_paths();
    ssl_ctx.set_verify_mode(ssl::verify_peer);

    // Map from client connection pointer to its DeepgramSession
    std::mutex sessions_mu;
    std::unordered_map<crow::websocket::connection*,
                       std::shared_ptr<DeepgramSession>> sessions;

    // Run io_context on background threads so Beast async operations proceed
    std::vector<std::thread> io_threads;
    auto work_guard = net::make_work_guard(ioc);
    const int io_thread_count = 2;
    for (int i = 0; i < io_thread_count; ++i) {
        io_threads.emplace_back([&ioc]() { ioc.run(); });
    }

    crow::SimpleApp app;

    // ------------------------------------------------------------------
    // GET /api/session - Issue JWT
    // ------------------------------------------------------------------
    CROW_ROUTE(app, "/api/session").methods(crow::HTTPMethod::GET)(
        [&cfg](const crow::request&) {
            auto token = generate_token(cfg.session_secret);
            crow::json::wvalue resp;
            resp["token"] = token;
            auto r = crow::response(200, resp.dump());
            r.set_header("Content-Type", "application/json");
            r.set_header("Access-Control-Allow-Origin", "*");
            return r;
        });

    // ------------------------------------------------------------------
    // GET /api/metadata - Project metadata from deepgram.toml
    // ------------------------------------------------------------------
    CROW_ROUTE(app, "/api/metadata").methods(crow::HTTPMethod::GET)(
        [](const crow::request&) {
            try {
                auto data = toml::parse("deepgram.toml");
                auto& meta = toml::find(data, "meta");

                crow::json::wvalue resp;
                for (auto& [key, val] : meta.as_table()) {
                    if (val.is_string()) {
                        resp[key] = val.as_string();
                    } else if (val.is_integer()) {
                        resp[key] = val.as_integer();
                    } else if (val.is_boolean()) {
                        resp[key] = val.as_boolean();
                    } else if (val.is_array()) {
                        std::vector<crow::json::wvalue> arr;
                        for (auto& elem : val.as_array()) {
                            if (elem.is_string())
                                arr.emplace_back(elem.as_string());
                            else
                                arr.emplace_back(toml::format(elem));
                        }
                        resp[key] = std::move(arr);
                    } else {
                        resp[key] = toml::format(val);
                    }
                }
                auto r = crow::response(200, resp.dump());
                r.set_header("Content-Type", "application/json");
                r.set_header("Access-Control-Allow-Origin", "*");
                return r;
            } catch (const std::exception& e) {
                CROW_LOG_ERROR << "Error reading deepgram.toml: " << e.what();
                crow::json::wvalue err;
                err["error"] = "INTERNAL_SERVER_ERROR";
                err["message"] = "Failed to read metadata from deepgram.toml";
                auto r = crow::response(500, err.dump());
                r.set_header("Content-Type", "application/json");
                r.set_header("Access-Control-Allow-Origin", "*");
                return r;
            }
        });

    // ------------------------------------------------------------------
    // GET /health - Health check
    // ------------------------------------------------------------------
    CROW_ROUTE(app, "/health").methods(crow::HTTPMethod::GET, crow::HTTPMethod::OPTIONS)(
        [](const crow::request& req) {
            auto r = crow::response(200);
            r.set_header("Access-Control-Allow-Origin", "*");
            r.set_header("Access-Control-Allow-Methods", "GET, OPTIONS");
            r.set_header("Access-Control-Allow-Headers", "Content-Type");

            if (req.method == crow::HTTPMethod::OPTIONS) {
                r.code = 204;
                return r;
            }

            r.set_header("Content-Type", "application/json");
            r.body = R"({"status":"ok"})";
            return r;
        });

    // ------------------------------------------------------------------
    // OPTIONS preflight for CORS
    // ------------------------------------------------------------------
    CROW_ROUTE(app, "/api/<path>").methods(crow::HTTPMethod::OPTIONS)(
        [](const crow::request&, const std::string&) {
            auto r = crow::response(204);
            r.set_header("Access-Control-Allow-Origin", "*");
            r.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
            r.set_header("Access-Control-Allow-Headers", "Content-Type");
            return r;
        });

    // ------------------------------------------------------------------
    // WS /api/flux - WebSocket proxy to Deepgram Flux
    // ------------------------------------------------------------------
    CROW_WEBSOCKET_ROUTE(app, "/api/flux")
        .onaccept([&cfg](const crow::request& req, void** userdata) -> bool {
            // -- 1. Validate JWT from sub-protocol header --
            auto proto_hdr = req.get_header_value("Sec-WebSocket-Protocol");
            auto valid = validate_ws_token(proto_hdr, cfg.session_secret);
            if (valid.empty()) {
                CROW_LOG_WARNING << "WebSocket auth failed: invalid or missing token";
                return false;
            }

            // -- 2. Parse query parameters from the upgrade URL --
            // Extract raw query string from the request URL
            std::string raw_url = req.raw_url;
            std::string qs;
            auto qpos = raw_url.find('?');
            if (qpos != std::string::npos) {
                qs = raw_url.substr(qpos + 1);
            }
            auto params = parse_query_string(qs);

            // Build Deepgram target path with query params
            // Model is fixed for Flux
            std::string model       = "flux-general-en";
            std::string encoding    = qget(params, "encoding", "linear16");
            std::string sample_rate = qget(params, "sample_rate", "16000");
            std::string eot_threshold       = qget(params, "eot_threshold");
            std::string eager_eot_threshold = qget(params, "eager_eot_threshold");
            std::string eot_timeout_ms      = qget(params, "eot_timeout_ms");
            auto keyterms = qget_all(params, "keyterm");

            std::ostringstream target;
            target << "/v2/listen?"
                   << "model=" << url_encode(model)
                   << "&encoding=" << url_encode(encoding)
                   << "&sample_rate=" << url_encode(sample_rate);
            if (!eot_threshold.empty())
                target << "&eot_threshold=" << url_encode(eot_threshold);
            if (!eager_eot_threshold.empty())
                target << "&eager_eot_threshold=" << url_encode(eager_eot_threshold);
            if (!eot_timeout_ms.empty())
                target << "&eot_timeout_ms=" << url_encode(eot_timeout_ms);
            // Multi-value keyterm support: keyterm=word1&keyterm=word2
            for (const auto& term : keyterms) {
                target << "&keyterm=" << url_encode(term);
            }

            // Stash for use in onopen via userdata pointer
            auto* cp = new ConnParams{target.str()};
            *userdata = cp;

            return true;
        })
        .onopen([&](crow::websocket::connection& conn) {
            CROW_LOG_INFO << "Client connected to /api/flux";

            {
                std::lock_guard<std::mutex> lk(g_connections_mutex);
                g_active_connections.insert(&conn);
            }

            // Retrieve the target path stashed during onaccept
            auto* cp = static_cast<ConnParams*>(conn.userdata());
            std::string deepgram_target = "/v2/listen?model=flux-general-en&encoding=linear16&sample_rate=16000";
            if (cp) {
                deepgram_target = cp->deepgram_target;
                delete cp;
                conn.userdata(nullptr);
            }

            CROW_LOG_INFO << "Deepgram URL: wss://api.deepgram.com" << deepgram_target;

            auto session = std::make_shared<DeepgramSession>(
                ioc, ssl_ctx, conn,
                "api.deepgram.com", "443",
                deepgram_target,
                cfg.deepgram_api_key);
            {
                std::lock_guard<std::mutex> lk(sessions_mu);
                sessions[&conn] = session;
            }
            session->start();
        })
        .onmessage([&](crow::websocket::connection& conn,
                        const std::string& data, bool is_binary) {
            std::shared_ptr<DeepgramSession> session;
            {
                std::lock_guard<std::mutex> lk(sessions_mu);
                auto it = sessions.find(&conn);
                if (it != sessions.end()) session = it->second;
            }
            if (!session) return;

            if (is_binary) {
                session->send_binary(data);
            } else {
                session->send_text(data);
            }
        })
        .onclose([&](crow::websocket::connection& conn,
                      const std::string& reason) {
            CROW_LOG_INFO << "Client disconnected: " << reason;

            std::shared_ptr<DeepgramSession> session;
            {
                std::lock_guard<std::mutex> lk(sessions_mu);
                auto it = sessions.find(&conn);
                if (it != sessions.end()) {
                    session = it->second;
                    sessions.erase(it);
                }
            }
            if (session) session->close();

            {
                std::lock_guard<std::mutex> lk(g_connections_mutex);
                g_active_connections.erase(&conn);
            }
        })
        .onerror([&](crow::websocket::connection& conn,
                      const std::string& error_message) {
            CROW_LOG_ERROR << "Client WebSocket error: " << error_message;

            std::shared_ptr<DeepgramSession> session;
            {
                std::lock_guard<std::mutex> lk(sessions_mu);
                auto it = sessions.find(&conn);
                if (it != sessions.end()) {
                    session = it->second;
                    sessions.erase(it);
                }
            }
            if (session) session->close();

            {
                std::lock_guard<std::mutex> lk(g_connections_mutex);
                g_active_connections.erase(&conn);
            }
        });

    // Print startup banner
    std::cout << "\n" << std::string(70, '=') << "\n"
              << "Backend API Server running at http://localhost:" << cfg.port << "\n\n"
              << "GET  /api/session\n"
              << "WS   /api/flux (auth required)\n"
              << "GET  /api/metadata\n"
              << "GET  /health\n"
              << std::string(70, '=') << "\n\n";

    app.port(cfg.port)
       .bindaddr(cfg.host)
       .multithreaded()
       .run();

    // Shutdown: stop io_context threads
    work_guard.reset();
    ioc.stop();
    for (auto& t : io_threads) {
        if (t.joinable()) t.join();
    }

    return 0;
}

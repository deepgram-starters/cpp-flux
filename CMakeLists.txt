cmake_minimum_required(VERSION 3.20)
project(cpp-flux LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find packages installed by vcpkg
find_package(Crow CONFIG REQUIRED)
find_package(Boost REQUIRED COMPONENTS system)
find_package(OpenSSL REQUIRED)
find_package(jwt-cpp CONFIG REQUIRED)
find_package(toml11 CONFIG REQUIRED)

add_executable(cpp-flux src/main.cpp)

target_link_libraries(cpp-flux PRIVATE
    Crow::Crow
    Boost::system
    OpenSSL::SSL
    OpenSSL::Crypto
    jwt-cpp::jwt-cpp
    toml11::toml11
)

cmake_minimum_required(VERSION 3.16)
project(cve_finder LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# add github library for working with JSON data
include(FetchContent)
FetchContent_Declare(
    json
    URL https://github.com/nlohmann/json/releases/download/v3.11.2/json.tar.xz
)
FetchContent_MakeAvailable(json)

# find libcurl download package
find_package(CURL REQUIRED)

#find zlib for decompression
find_package(ZLIB REQUIRED)

#build main program
add_executable(cve_finder src/main.cpp)

# link project with JSON library and libcurl tool and zlib
target_link_libraries(cve_finder PRIVATE
    nlohmann_json::nlohmann_json
    CURL::libcurl
    ZLIB::ZLIB
)


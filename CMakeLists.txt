cmake_minimum_required(VERSION 3.25)
project(cve_finder LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_POLICY_VERSION_MINIMUM 3.5)

# ------------------------------------------
# JSON Library (nlohmann/json)
# ------------------------------------------
include(FetchContent)



set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


# Include nlohmann/json (header-only)
include(FetchContent)

FetchContent_Declare(
    json
    URL https://github.com/nlohmann/json/releases/download/v3.11.2/json.tar.xz
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)

FetchContent_MakeAvailable(json)


# CMake needs to know where these files are
find_package(ZLIB REQUIRED)
find_package(CURL REQUIRED)


# Build your main program
add_executable(cve_finder
    src/main.cpp
    src/Trie.cpp
    src/RedBlackTree.cpp
    src/data_processor.cpp
    src/file_checker.cpp
    )


target_include_directories(cve_finder PRIVATE
    ${CURL_INCLUDE_DIR}
)

target_link_libraries(cve_finder PRIVATE
    nlohmann_json::nlohmann_json
    ${CURL_LIBRARY}
    ZLIB::ZLIB
)
set(CMAKE_POLICY_DEFAULT_CMP0135 NEW)

FetchContent_Declare(
    json
    URL https://github.com/nlohmann/json/releases/download/v3.11.2/json.tar.xz
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)

# Force minimum policy for old CMakeLists inside json
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)
FetchContent_MakeAvailable(json)
unset(CMAKE_POLICY_VERSION_MINIMUM)

# ------------------------------------------
# CURL and ZLIB
# ------------------------------------------
find_package(CURL REQUIRED)
find_package(ZLIB REQUIRED)


target_link_libraries(cve_finder PRIVATE
    nlohmann_json::nlohmann_json
    CURL::libcurl
    ZLIB::ZLIB
)
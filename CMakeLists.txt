cmake_minimum_required(VERSION 3.16)

project(ore_repro_cpp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)

add_library(ore_cpp
    src/crypto.cpp
    src/prp.cpp
    src/small_ore.cpp
    src/large_ore.cpp
    src/range_query.cpp
)

target_include_directories(ore_cpp PUBLIC include)
target_link_libraries(ore_cpp PUBLIC OpenSSL::Crypto)

add_executable(ore_simple_flow examples/simple_flow.cpp)
target_link_libraries(ore_simple_flow PRIVATE ore_cpp)

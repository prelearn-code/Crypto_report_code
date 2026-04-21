cmake_minimum_required(VERSION 3.16)
project(ore_repro_cpp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(ore_core
    src/common.cpp
    src/small_ore.cpp
    src/large_ore.cpp
    src/range_query.cpp
)

target_include_directories(ore_core PUBLIC include)

add_executable(ore_demo examples/demo.cpp)
target_link_libraries(ore_demo PRIVATE ore_core)

add_executable(ore_tests tests/test_main.cpp)
target_link_libraries(ore_tests PRIVATE ore_core)

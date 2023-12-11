cmake_minimum_required(VERSION 3.27.9)

# 这个命令不是强制性的，但最好都加上。
# 它会引入两个变量 demo_BINARY_DIR 和 demo_SOURCE_DIR，同时，cmake 自动定义了两个等价的变量 PROJECT_BINARY_DIR 和 PROJECT_SOURCE_DIR。
project(demo)

set(TARGET "testhook")

file(GLOB SRC test.cpp)

add_library(${TARGET} SHARED ${SRC})

target_link_libraries(${TARGET} log)

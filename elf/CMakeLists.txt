# CMake最低版本号要求
cmake_minimum_required(VERSION 3.6)

# 项目信息
project (elf)

# 设置目标文件的名字
set(TARGET_NAME elf)

# 生成可执行文件
add_executable(${TARGET_NAME} elf.c) 
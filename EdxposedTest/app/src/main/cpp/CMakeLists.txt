cmake_minimum_required(VERSION 3.22.1)

add_definitions(-std=c++11)

ENABLE_LANGUAGE(ASM)

# 这个命令不是强制性的，但最好都加上。
# 它会引入两个变量 demo_BINARY_DIR 和 demo_SOURCE_DIR，同时，cmake 自动定义了两个等价的变量 PROJECT_BINARY_DIR 和 PROJECT_SOURCE_DIR。
project(sohook)

if(${CMAKE_ANDROID_ARCH_ABI} STREQUAL "arm64-v8a")
    set(OS_DEPENDENDED_SRC
            archs/arm/arm64/assembler/assembler_arm64.cpp
            archs/arm/arm64/inst/inst_arm64.cpp
            archs/arm/arm64/register/register_arm64.cpp
            archs/arm/arm64/register/register_list_arm64.cpp
            archs/arm/arm64/decoder/decoder_arm64.cpp
            archs/arm/arm64/relocate/code_relocate_arm64.cpp
            archs/arm/arm64/hook/hook_arm64.cpp)

elseif (${CMAKE_ANDROID_ARCH_ABI} STREQUAL "armeabi-v7a")
    set(OS_DEPENDENDED_SRC
            archs/arm/arm32/inst/inst_arm32.cpp
            archs/arm/arm32/inst/inst_t32.cpp
            archs/arm/arm32/inst/inst_t16.cpp
            archs/arm/arm32/register/register_arm32.cpp
            archs/arm/arm32/register/register_list_arm32.cpp
            archs/arm/arm32/assembler/assembler_arm32.cpp
            archs/arm/arm32/decoder/decoder_arm32.cpp
            archs/arm/arm32/hook/hook_arm32.cpp
            archs/arm/arm32/hook/breakpoint_shellcode.S
            archs/arm/arm32/relocate/code_relocate_arm32.cpp)
endif()

include_directories(
        asm
        decoder
        elf
        utils
        includes
        buffer
        archs/arm
        archs/arm/arm64/inst
        archs/arm/arm64/register
        archs/arm/arm64/decoder
        archs/arm/arm64/assembler
        archs/arm/arm64/relocate
        archs/arm/arm64/hook
        archs/arm/arm32/inst
        archs/arm/arm32/register
        archs/arm/arm32/assembler
        archs/arm/arm32/decoder
        archs/arm/arm32/hook
        archs/arm/arm32/relocate
        src/main/cpp/antihook
)

add_library(
        sohook
        SHARED
        sandhook_native.cpp
        decoder/decoder.cpp
        relocate/code_relocate.cpp
        elf/elf.cpp
        assembler/assembler.cpp
        buffer/code_buffer.cpp
        utils/platform.cpp
        hook/hook.cpp
        ${OS_DEPENDENDED_SRC}
        test_hook.cpp)

target_link_libraries(sohook log)

# 参数设置 https://developer.android.com/ndk/guides/android_mk?hl=zh-cn

LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

# 默认情况下，构建系统会以 thumb 模式生成 ARM 目标二进制文件，其中每条指令都是 16 位宽，并与 thumb/ 目录中的 STL 库链接。将此变量定义为 arm 会强制构建系统以 32 位 arm 模式生成模块的对象文件。
#LOCAL_ARM_MODE := thumb

LOCAL_MODULE := arm64

LOCAL_SRC_FILES := arm64.c

include $(BUILD_EXECUTABLE)

#include #(BUILD_SHARED_LIBRARY)
# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
# Makefile for Android libbpf example
#
# Usage:
#   export ANDROID_NDK=/path/to/android-ndk-r27b
#   make

# 目标架构
ARCH ?= arm64

# SDK 路径（解压后的 SDK 目录）
SDK_DIR ?= ./sdk/$(ARCH)

# Android NDK 配置
ANDROID_NDK ?= $(HOME)/android-ndk-r27b
NDK_VERSION ?= r27b
NDK_API ?= 30

# 根据架构设置目标三元组
ifeq ($(ARCH),arm64)
    ANDROID_TRIPLE := aarch64-linux-android
    BPF_TARGET := arm64
else ifeq ($(ARCH),x86_64)
    ANDROID_TRIPLE := x86_64-linux-android
    BPF_TARGET := x86
else
    $(error Unsupported architecture: $(ARCH). Supported: arm64, x86_64)
endif

# 工具链路径
ANDROID_TOOLCHAIN := $(ANDROID_NDK)/toolchains/llvm/prebuilt/linux-x86_64

# 编译器
CC := $(ANDROID_TOOLCHAIN)/bin/$(ANDROID_TRIPLE)$(NDK_API)-clang
CXX := $(ANDROID_TOOLCHAIN)/bin/$(ANDROID_TRIPLE)$(NDK_API)-clang++
AR := $(ANDROID_TOOLCHAIN)/bin/llvm-ar
STRIP := $(ANDROID_TOOLCHAIN)/bin/llvm-strip

# 用于编译 BPF 程序的 clang（使用 NDK 的 clang 或系统 clang）
BPF_CLANG := clang
BPFTOOL ?= bpftool

# 包含路径
INCLUDES := -I$(SDK_DIR)/include -I.

# 静态库
LIBS := $(SDK_DIR)/lib/libbpf.a \
        $(SDK_DIR)/lib/libelf.a \
        $(SDK_DIR)/lib/libz.a

# 编译选项
CFLAGS := -O2 -Wall -fPIC $(INCLUDES)
CFLAGS += -D__user= -D__force= -D__poll_t=unsigned

# 链接选项
LDFLAGS := -static
LDLIBS := -lm

# 目标
PROG := execsnoop
BPF_OBJ := execsnoop.bpf.o
SKEL := execsnoop.skel.h

# 默认目标
all: $(PROG)

# 生成 BPF 目标文件
# 注意：BPF 程序需要使用特定的目标架构编译
$(BPF_OBJ): execsnoop.bpf.c execsnoop.h vmlinux.h
	@echo ">>> Compiling BPF program..."
	$(BPF_CLANG) -g -O2 -target bpf \
		-D__TARGET_ARCH_$(BPF_TARGET) \
		-I$(SDK_DIR)/include \
		-I. \
		-c $< -o $@

# 生成 skeleton 头文件
$(SKEL): $(BPF_OBJ)
	@echo ">>> Generating skeleton header..."
	$(BPFTOOL) gen skeleton $< > $@

# 编译用户空间程序
$(PROG): execsnoop.c $(SKEL) execsnoop.h
	@echo ">>> Compiling userspace program for Android $(ARCH)..."
	$(CC) $(CFLAGS) -o $@ $< $(LIBS) $(LDFLAGS) $(LDLIBS)
	@echo ">>> Stripping binary..."
	$(STRIP) $@
	@echo ">>> Done! Binary: $@"
	@ls -la $@

# 清理
clean:
	rm -f $(PROG) $(BPF_OBJ) $(SKEL)

# 推送到设备
push: $(PROG)
	adb push $(PROG) /data/local/tmp/
	adb shell chmod +x /data/local/tmp/$(PROG)
	@echo ">>> Pushed to /data/local/tmp/$(PROG)"

# 运行（需要 root）
run: push
	adb shell su -c /data/local/tmp/$(PROG)

# 查看 trace_pipe 输出
trace:
	adb shell su -c "cat /sys/kernel/debug/tracing/trace_pipe"

# 检查设备 eBPF 支持情况
check:
	@echo ">>> Checking kernel BPF config..."
	adb shell su -c "zcat /proc/config.gz 2>/dev/null | grep -E 'CONFIG_BPF|CONFIG_TRACING' || cat /proc/config.gz 2>/dev/null | zcat | grep -E 'CONFIG_BPF|CONFIG_TRACING'"
	@echo ""
	@echo ">>> Checking kernel version..."
	adb shell uname -r
	@echo ""
	@echo ">>> Checking BTF support..."
	adb shell ls -la /sys/kernel/btf/vmlinux 2>/dev/null || echo "BTF not available"

# 帮助
help:
	@echo "libbpf Android Example Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make              - Build the program"
	@echo "  make ARCH=x86_64  - Build for x86_64"
	@echo "  make clean        - Clean build files"
	@echo "  make push         - Push binary to device"
	@echo "  make run          - Push and run on device"
	@echo "  make trace        - View trace_pipe output"
	@echo "  make check        - Check device eBPF support"
	@echo ""
	@echo "Environment variables:"
	@echo "  ANDROID_NDK       - Path to Android NDK (default: ~/android-ndk-r27b)"
	@echo "  ARCH              - Target architecture: arm64 or x86_64 (default: arm64)"
	@echo "  SDK_DIR           - Path to libbpf SDK (default: ./sdk/\$(ARCH))"
	@echo ""
	@echo "Prerequisites:"
	@echo "  1. Download and extract libbpf-android-sdk-\$(ARCH).tar.gz to ./sdk/"
	@echo "  2. Generate vmlinux.h from target device's kernel"
	@echo "  3. Install bpftool and clang on build machine"

.PHONY: all clean push run trace check help

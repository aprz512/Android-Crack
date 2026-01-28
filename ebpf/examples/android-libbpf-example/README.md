# libbpf Android SDK 使用示例

本示例展示如何使用 libbpf Android SDK 在 Android 设备上编写和运行 eBPF 程序。

## 前提条件

1. **Android 设备要求**：
   - 内核版本 >= 4.19（推荐 5.4+）
   - 需要 root 权限
   - 内核需要启用 eBPF 相关 CONFIG（大部分现代 Android 设备已启用）

2. **开发环境**：
   - Linux 系统（用于编译）
   - Android NDK r27b
   - clang/llvm（用于编译 eBPF 程序）
   - bpftool（用于生成 skeleton 头文件）

## 目录结构

```
android-libbpf-example/
├── README.md                   # 本文件
├── execsnoop.bpf.c            # eBPF 内核程序
├── execsnoop.c                # 用户空间程序
├── execsnoop.h                # 共享头文件
├── vmlinux.h                  # 内核 BTF 头文件（需要从目标设备提取）
├── Makefile                   # 构建脚本
└── sdk/                       # 解压 SDK 到这里
    └── arm64/
        ├── include/
        └── lib/
```

## 快速开始

### 1. 解压 SDK

```bash
# 下载 SDK
wget https://github.com/user/repo/releases/download/v1.0.0/libbpf-android-sdk-arm64.tar.gz

# 解压到 sdk 目录
mkdir -p sdk
tar xzf libbpf-android-sdk-arm64.tar.gz -C sdk/
```

### 2. 获取目标设备的 vmlinux.h

从 Android 设备提取 BTF 信息生成 vmlinux.h：

```bash
# 方法1: 如果设备有 /sys/kernel/btf/vmlinux
adb pull /sys/kernel/btf/vmlinux
bpftool btf dump file vmlinux format c > vmlinux.h

# 方法2: 从内核 Image 提取（需要内核编译时启用 CONFIG_DEBUG_INFO_BTF）
# 使用 pahole 或 bpftool 从 vmlinux 文件生成
```

### 3. 编译

```bash
# 设置 NDK 路径
export ANDROID_NDK=/path/to/android-ndk-r27b

# 编译
make
```

### 4. 运行

```bash
# 推送到设备
adb push execsnoop /data/local/tmp/
adb shell chmod +x /data/local/tmp/execsnoop

# 运行（需要 root）
adb shell
su
cd /data/local/tmp
./execsnoop
```

## 示例程序说明

### execsnoop - 进程执行监控

这个示例程序会监控系统中所有的 `execve` 系统调用，实时打印出新启动的进程信息。

**功能**：
- 捕获进程执行事件
- 显示 PID、UID、进程名、命令行参数
- 使用 ring buffer 传递事件到用户空间

## 常见问题

### Q: 设备不支持 eBPF？
检查内核配置：
```bash
adb shell zcat /proc/config.gz | grep BPF
```
需要以下配置：
- CONFIG_BPF=y
- CONFIG_BPF_SYSCALL=y
- CONFIG_BPF_JIT=y

### Q: 权限不足？
eBPF 需要 CAP_BPF 权限（或 root）：
```bash
adb shell su -c ./execsnoop
```

### Q: 找不到 tracepoint？
检查可用的 tracepoint：
```bash
adb shell ls /sys/kernel/debug/tracing/events/syscalls/
```

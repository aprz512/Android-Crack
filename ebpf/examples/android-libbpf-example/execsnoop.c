// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* execsnoop.c - 用户空间程序
 *
 * 加载 eBPF 程序并从 ring buffer 读取事件
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "execsnoop.h"
#include "execsnoop.skel.h"

/* 全局变量用于退出控制 */
static volatile sig_atomic_t exiting = 0;

/* 信号处理函数 */
static void sig_handler(int sig)
{
    exiting = 1;
}

/* libbpf 日志回调函数 */
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    /* 只打印警告和错误 */
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, format, args);
}

/* 设置 RLIMIT，允许锁定内存用于 BPF map */
static int bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit! (需要 root 权限)\n");
        return -1;
    }
    return 0;
}

/* Ring buffer 回调函数 - 处理接收到的事件 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct event *e = data;
    struct tm *tm;
    char ts[32];
    time_t t;

    /* 格式化时间戳 */
    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    /* 打印事件信息 */
    if (e->retval >= 0) {
        printf("%-8s %-7d %-7d %-7d %-16s %s\n",
               ts, e->pid, e->ppid, e->uid, e->comm, e->filename);
    } else {
        /* execve 失败的情况 */
        printf("%-8s %-7d %-7d %-7d %-16s %s (FAILED: %d)\n",
               ts, e->pid, e->ppid, e->uid, e->comm, e->filename, e->retval);
    }

    return 0;
}

/* 打印表头 */
static void print_header(void)
{
    printf("%-8s %-7s %-7s %-7s %-16s %s\n",
           "TIME", "PID", "PPID", "UID", "COMM", "FILENAME");
}

int main(int argc, char **argv)
{
    struct execsnoop_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    /* 设置 libbpf 日志回调 */
    libbpf_set_print(libbpf_print_fn);

    /* 设置信号处理 */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* 提升 memlock 限制 */
    if (bump_memlock_rlimit()) {
        return 1;
    }

    /* 打开 BPF 骨架 */
    skel = execsnoop_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* 加载并验证 BPF 程序 */
    err = execsnoop_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton: %d\n", err);
        goto cleanup;
    }

    /* 附加 BPF 程序到 tracepoint */
    err = execsnoop_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    /* 创建 ring buffer */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    /* 打印表头 */
    printf("Tracing execve syscalls... Hit Ctrl-C to end.\n\n");
    print_header();

    /* 主循环：轮询 ring buffer */
    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        /* Ctrl-C 会导致 -EINTR */
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    execsnoop_bpf__destroy(skel);
    printf("\nExiting...\n");
    return err < 0 ? 1 : 0;
}

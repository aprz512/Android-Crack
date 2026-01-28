// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* execsnoop.bpf.c - eBPF 内核程序
 *
 * 监控所有 execve 系统调用
 * 使用 raw_tracepoint/sys_enter - 适用于只有 raw_syscalls 的 Android 内核
 */

#define BPF_NO_GLOBAL_DATA

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "execsnoop.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Ring Buffer */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* 临时存储 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct event);
} execs SEC(".maps");

static const struct event empty_event = {};

/* ARM64 execve 系统调用号 */
#define __NR_execve 221

/*
 * raw_tracepoint/sys_enter
 */
SEC("raw_tracepoint/sys_enter")
int raw_tp_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    long syscall_id = ctx->args[1];
    struct event *event;
    u32 pid;
    u64 id;
    
    /* 只处理 execve */
    if (syscall_id != __NR_execve)
        return 0;

    id = bpf_get_current_pid_tgid();
    pid = (u32)(id >> 32);

    if (bpf_map_update_elem(&execs, &pid, &empty_event, BPF_NOEXIST))
        return 0;

    event = bpf_map_lookup_elem(&execs, &pid);
    if (!event)
        return 0;

    event->pid = pid;
    event->uid = (u32)bpf_get_current_uid_gid();
    event->ppid = 0;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    /* 从 pt_regs 获取 execve 第一个参数（文件名指针） */
    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
    u64 filename_ptr = 0;
    
    bpf_probe_read_kernel(&filename_ptr, sizeof(filename_ptr), &regs->regs[0]);

    if (filename_ptr) {
        bpf_probe_read_user_str(&event->filename, sizeof(event->filename), 
                                (const char *)filename_ptr);
    }

    return 0;
}

/*
 * raw_tracepoint/sys_exit
 */
SEC("raw_tracepoint/sys_exit")
int raw_tp_sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
    struct event *event;
    struct event *e;
    u32 pid;
    u64 id;
    long ret = ctx->args[1];
    
    /* 用于 bpf_printk 的临时变量（在 submit 之前保存） */
    int saved_pid;
    int saved_ret;

    id = bpf_get_current_pid_tgid();
    pid = (u32)(id >> 32);

    event = bpf_map_lookup_elem(&execs, &pid);
    if (!event)
        return 0;

    event->retval = ret;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_map_delete_elem(&execs, &pid);
        return 0;
    }

    /* 复制事件数据 */
    e->pid = event->pid;
    e->ppid = event->ppid;
    e->uid = event->uid;
    e->retval = event->retval;
    
    /* 使用 bpf_probe_read_kernel 复制数组，避免展开循环 */
    bpf_probe_read_kernel(&e->comm, sizeof(e->comm), &event->comm);
    bpf_probe_read_kernel(&e->filename, sizeof(e->filename), &event->filename);

    /* 保存需要打印的值（必须在 submit 之前） */
    saved_pid = e->pid;
    saved_ret = e->retval;

    /* 提交事件 - 之后 e 就无效了 */
    bpf_ringbuf_submit(e, 0);

    /* 清理 map */
    bpf_map_delete_elem(&execs, &pid);

    /* 使用保存的值打印 */
    bpf_printk("execve: pid=%d ret=%d\n", saved_pid, saved_ret);

    return 0;
}
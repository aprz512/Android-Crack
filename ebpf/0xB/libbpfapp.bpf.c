/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#define BPF_NO_GLOBAL_DATA
#include <vmlinux.h>
// #include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef unsigned int u32;
typedef int pid_t;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Create an array with 1 entry instead of a global variable
 * which does not work with older kernels */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, pid_t);
} my_pid_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, pid_t);
	__type(value, struct event);
} execs SEC(".maps");


struct event {
	pid_t pid;
	pid_t ppid;
	uid_t uid;
	char comm[16];
	char args[128];
};

static const struct event empty_event = {};

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter* ctx)
{
	u32 index = 0;
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	pid_t *my_pid = bpf_map_lookup_elem(&my_pid_map, &index);

	uid_t uid = (u32)bpf_get_current_uid_gid();
	int i;

	u64 id = bpf_get_current_pid_tgid();
	pid = (pid_t)id;
	pid_t tgid = id >> 32;
	if (bpf_map_update_elem(&execs, &pid, &empty_event, BPF_NOEXIST))
		return 0;

	struct event *event = bpf_map_lookup_elem(&execs, &pid);
	if (!event)
		return 0;

	event->pid = tgid;
	event->uid = uid;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	struct task_struct *task;
	const char **args = (const char **)(ctx->args[1]);
	const char *argp;

	pid_t pid2 = 0;
	task = (struct task_struct*)bpf_get_current_task();
	bpf_probe_read(&pid2, sizeof(pid2), &(task->tgid));
	
	unsigned int ret = bpf_probe_read_user_str(&event->args, 127, (const char*)ctx->args[0]);

	bpf_printk("BPF triggered from PID %d.\n", pid);

	bpf_printk("BPF bpf_ktime_get_ns(): %ld.\n", bpf_ktime_get_ns());
	bpf_printk("BPF bpf_ktime_get_boot_ns(): %ld.\n", bpf_ktime_get_boot_ns());
	// bpf_printk("BPF bpf_ktime_get_coarse_ns(): %ld.\n", bpf_ktime_get_coarse_ns());
	bpf_printk("BPF bpf_get_current_uid_gid(): 0x%lx.\n", bpf_get_current_uid_gid());
	bpf_printk("BPF bpf_get_current_pid_tgid(): 0x%lx.\n", bpf_get_current_pid_tgid());
	bpf_printk("BPF bpf_probe_read_user_str(): comm:%s, args:%s\n", event->comm, event->args);
	bpf_printk("BPF bpf_get_current_task pid: 0x%lx.\n", pid2);
	bpf_printk("BPF bpf_get_prandom_u32: 0x%lx.\n", bpf_get_prandom_u32());
	bpf_printk("BPF bpf_get_smp_processor_id: 0x%lx.\n", bpf_get_smp_processor_id()); // 获取当前的处理器ID
	bpf_printk("BPF bpf_task_pt_regs: 0x%lx.\n", bpf_task_pt_regs(bpf_get_current_task_btf()));
	// long out = 0;bpf_strtoul("ebpf", 4, 16, &out);
	// bpf_printk("BPF bpf_strtoul: 0x%lx.\n", out);

	bpf_map_delete_elem(&execs, &pid);

	return 0;
}

// clang hello_world.c -o hello_world -lbcc

// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2023-2024 fei_cong(https://github.com/feicong/ebpf-course) */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <linux/version.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bcc/libbpf.h>
// https://github.com/torvalds/linux/blob/master/samples/bpf/bpf_insn.h

#define LOG_BUF_SIZE 65536

char bpf_log_buf[LOG_BUF_SIZE];

static inline __u64 ptr_to_u64(const void *ptr) {
  return (__u64)(unsigned long)ptr;
}

/**
 * Taken from the man page for bpf(2), though two critical lines
 * of code that are missing from that man page are:
 * (1) The bpf_attr must be zeroed-out before it is used.
 *     Failing to do so will likely result in an EINVAL when
 *     doing the BPF_PROG_LOAD.
 *
 *     memset(&attr, 0, sizeof(attr))
 *
 * (2) kern_version must be defined if the program type is
 *     BPF_PROG_TYPE_KPROBE. Note that LINUX_VERSION_CODE is defined
 *     in <linux/version.h>.
 *
 *     attr.kern_version = LINUX_VERSION_CODE;
 */
int my_bpf_prog_load(enum bpf_prog_type type, const struct bpf_insn *insns,
                  int insn_cnt, const char *license) {
  union bpf_attr attr;
  memset(&attr, 0, sizeof(attr));

  attr.prog_type = type;
  attr.insns = ptr_to_u64(insns);
  attr.insn_cnt = insn_cnt;
  attr.license = ptr_to_u64(license);

  attr.log_buf = ptr_to_u64(bpf_log_buf);
  attr.log_size = LOG_BUF_SIZE;
  attr.log_level = 1;

  // As noted in bpf(2), kern_version is checked when prog_type=kprobe.
  attr.kern_version = LINUX_VERSION_CODE;

  // If this returns a non-zero number, printing the contents of
  // bpf_log_buf may help. libbpf.c has a bpf_print_hints() function that
  // can help with this.
  return syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
}

int wait_for_sig_int() {
  sigset_t set;
  sigemptyset(&set);
  int rc = sigaddset(&set, SIGINT);
  if (rc < 0) {
    perror("Error calling sigaddset()");
    return 1;
  }

  rc = sigprocmask(SIG_BLOCK, &set, NULL);
  if (rc < 0) {
    perror("Error calling sigprocmask()");
    return 1;
  }

  int sig;
  rc = sigwait(&set, &sig);
  if (rc < 0) {
    perror("Error calling sigwait()");
    return 1;
  } else if (sig == SIGINT) {
    fprintf(stderr, "SIGINT received!\n");
    return 0;
  } else {
    fprintf(stderr, "Unexpected signal received: %d\n", sig);
    return 0;
  }
}

/**
 * Port of bpf_attach_tracing_event() from libbpf.c.
 */
int attach_tracing_event(int prog_fd, const char *event_path, int *pfd) {
  int efd;
  ssize_t bytes;
  char buf[PATH_MAX];
  struct perf_event_attr attr = {};
  // Caller did not provided a valid Perf Event FD. Create one with the debugfs
  // event path provided.
  snprintf(buf, sizeof(buf), "%s/id", event_path);
  efd = open(buf, O_RDONLY, 0);
  if (efd < 0) {
    fprintf(stderr, "open(%s): %s\n", buf, strerror(errno));
    return -1;
  }

  bytes = read(efd, buf, sizeof(buf));
  if (bytes <= 0 || bytes >= sizeof(buf)) {
    fprintf(stderr, "read(%s): %s\n", buf, strerror(errno));
    close(efd);
    return -1;
  }
  close(efd);
  buf[bytes] = '\0';
  attr.config = strtol(buf, NULL, 0);
  attr.type = PERF_TYPE_TRACEPOINT;
  attr.sample_period = 1;
  attr.wakeup_events = 1;
  *pfd = syscall(__NR_perf_event_open, &attr, -1 /* pid */, 0 /* cpu */,
                 -1 /* group_fd */, PERF_FLAG_FD_CLOEXEC);
  if (*pfd < 0) {
    fprintf(stderr, "perf_event_open(%s/id): %s\n", event_path,
            strerror(errno));
    return -1;
  }

  if (ioctl(*pfd, PERF_EVENT_IOC_SET_BPF, prog_fd) < 0) {
    perror("ioctl(PERF_EVENT_IOC_SET_BPF)");
    return -1;
  }
  if (ioctl(*pfd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
    perror("ioctl(PERF_EVENT_IOC_ENABLE)");
    return -1;
  }

  return 0;
}

/**
 * Simplified version of bpf_attach_kprobe() from libbpf.c.
 */
int attach_kprobe(int prog_fd, const char *ev_name, const char *fn_name) {
  static char *event_type = "kprobe";

  // Note that bpf_try_perf_event_open_with_probe() fails on my system
  // because I don't have either of
  // /sys/bus/event_source/devices/kprobe/type or
  // /sys/bus/event_source/devices/kprobe/format/retprobe, so this is
  // a port of the fallback code path within bpf_attach_kprobe().
  int kfd =
      open("/sys/kernel/debug/tracing/kprobe_events", O_WRONLY | O_APPEND, 0);
  if (kfd < 0) {
    perror("Error opening /sys/kernel/debug/tracing/kprobe_events");
    return -1;
  }

  char buf[256];
  char event_alias[128];

  // I believe that parameterizing the event alias by PID was done because of:
  // https://github.com/iovisor/bcc/issues/872.
  snprintf(event_alias, sizeof(event_alias), "%s_bcc_%d", ev_name, getpid());

  // These are defined in libbpf.h, not bpf.h.
  int BPF_PROBE_ENTRY = 0;
  int BPF_PROBE_RETURN = 1;

  // I'm assuming the function offset is 0. I'm not sure where to get the
  // function offset because I do not build my program the way libbpf does.
  int attach_type = BPF_PROBE_ENTRY;
  snprintf(buf, sizeof(buf), "%c:%ss/%s %s",
           attach_type == BPF_PROBE_ENTRY ? 'p' : 'r', event_type, event_alias,
           fn_name);

  // We appear to be writing some wacky like:
  // "p:kprobes/p_do_sys_open_bcc_<pid> do_sys_open" to the special kernel file.
  if (write(kfd, buf, strlen(buf)) < 0) {
    if (errno == ENOENT) {
      // write(2) doesn't mention ENOENT, so perhaps this is something special
      // with respect to this kernel file descriptor?
      fprintf(stderr, "cannot attach kprobe, probe entry may not exist\n");
    } else {
      fprintf(stderr, "cannot attach kprobe, %s\n", strerror(errno));
    }
    close(kfd);
    return -1;
  }
  close(kfd);

  // Set buf to:
  // "/sys/kernel/debug/tracing/events/kprobes/p_do_sys_open_bcc_<pid>".
  snprintf(buf, sizeof(buf), "/sys/kernel/debug/tracing/events/%ss/%s",
           event_type, event_alias);

  int pfd = -1;
  // This should read the event ID from the path in buf, create the
  // Perf Event event using that ID, and updated value of pfd.
  if (attach_tracing_event(prog_fd, buf, &pfd) < 0) {
    return -1;
  }

  return pfd;
}

int main(int argc, char **argv) {
  // This array was generated from bpf_trace_printk.py.
  struct bpf_insn prog[] = {
    BPF_MOV64_IMM(BPF_REG_1, 0xa21),	/* '!\n' */
		BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_1, -4),
		BPF_MOV64_IMM(BPF_REG_1, 0x646c726f),	/* 'orld' */
		BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, -8),
		BPF_MOV64_IMM(BPF_REG_1, 0x57202c6f),	/* 'o, W' */
		BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, -12),
		BPF_MOV64_IMM(BPF_REG_1, 0x6c6c6548),	/* 'Hell' */
		BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, -16),
		BPF_MOV64_IMM(BPF_REG_1, 0),
		BPF_STX_MEM(BPF_B, BPF_REG_10, BPF_REG_1, -2),
		BPF_MOV64_REG(BPF_REG_1, BPF_REG_10),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -16),
		BPF_MOV64_IMM(BPF_REG_2, 15),
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_trace_printk),
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
  };

  int insn_cnt = sizeof(prog) / sizeof(struct bpf_insn);
  printf("insn_cnt:%d\n", insn_cnt);
  unsigned char *p = (unsigned char *)prog;
  for (size_t i = 0; i < sizeof(prog); i++)
  {
    printf("0x%02x ", p[i]);
  }
  printf("\n");

  int prog_fd = my_bpf_prog_load(BPF_PROG_TYPE_KPROBE, prog, insn_cnt, "GPL");
  if (prog_fd == -1) {
    perror("Error calling bpf_prog_load()");
    return 1;
  }

  int perf_event_fd = attach_kprobe(prog_fd, "hello_world", "do_unlinkat");
  if (perf_event_fd < 0) {
    perror("Error calling attach_kprobe()");
    close(prog_fd);
    return 1;
  }

  system("cat /sys/kernel/debug/tracing/trace_pipe");
  int exit_code = wait_for_sig_int();
  close(perf_event_fd);
  close(prog_fd);
  return exit_code;
}

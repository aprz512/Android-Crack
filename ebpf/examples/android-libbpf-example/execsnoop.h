/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/* execsnoop.h - 共享数据结构定义 */

#ifndef __EXECSNOOP_H
#define __EXECSNOOP_H

#define TASK_COMM_LEN 16
#define MAX_ARGS_LEN 256
#define MAX_FILENAME_LEN 256

/* 进程执行事件结构 */
struct event {
    int pid;           /* 进程 ID */
    int ppid;          /* 父进程 ID */
    int uid;           /* 用户 ID */
    int retval;        /* execve 返回值 */
    char comm[TASK_COMM_LEN];           /* 进程名 */
    char filename[MAX_FILENAME_LEN];    /* 可执行文件路径 */
};

#endif /* __EXECSNOOP_H */

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "lsm_prevent.skel.h" // 编译时自动生成的骨架头文件

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

int main(int argc, char **argv)
{
    struct lsm_prevent_bpf *skel;
    int err;

    // 1. 设置信号处理，按 Ctrl+C 退出
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // 2. 打开 BPF 骨架
    skel = lsm_prevent_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // 3. 加载到内核
    err = lsm_prevent_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    // 4. 挂载 (Attach) 到 LSM 钩子
    // 注意：LSM 的挂载非常简单，不需要像 perf_event 那样找 id
    err = lsm_prevent_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("Successfully started! Try running: rm secret_file\n");
    printf("Check trace pipe: sudo cat /sys/kernel/debug/tracing/trace_pipe\n");
    printf("Press Ctrl+C to stop.\n");

    // 5. 保持运行
    while (!exiting) {
        sleep(1);
    }

cleanup:
    // 6. 清理资源
    lsm_prevent_bpf__destroy(skel);
    return -err;
}
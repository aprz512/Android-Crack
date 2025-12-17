#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// 在 Linux 中，EPERM 的值固定为 1
#define EPERM 1

char LICENSE[] SEC("license") = "GPL";

// 定义我们要保护的文件名
const char target_name[] = "secret_file";

// 这是一个辅助函数，用于比较字符串
static __always_inline int my_strcmp(const char *s1, const char *s2, int n) {
    for (int i = 0; i < n; i++) {
        if (s1[i] != s2[i])
            return -1;
        if (s1[i] == '\0')
            break;
    }
    return 0;
}

/**
 * 钩子：inode_unlink
 * 触发时机：当即将删除一个文件链接（即 rm 操作）时
 * 参数：
 *   dir: 父目录的 inode
 *   dentry: 要删除的文件的 dentry（包含文件名）
 */
SEC("lsm/inode_unlink")
int BPF_PROG(restrict_unlink, struct inode *dir, struct dentry *dentry)
{
    // 1. 读取文件名
    // qstr 是内核存储字符串的结构，name 是字符指针，len 是长度
    const unsigned char *filename = dentry->d_name.name;
    int len = dentry->d_name.len;

    // 2. 简单的长度过滤
    if (len != sizeof(target_name) - 1) {
        return 0; // 长度不对，肯定不是目标文件，放行
    }

    // 3. 读取文件名内容并比较
    // 注意：BPF 中读取内核内存需要用 bpf_probe_read_kernel 
    char name_buf[20]; 
    
    // filename指向的是一段字符串内存，BPF 校验器为了安全，不允许你直接在那个原始指针上进行 for 循环操作。
    // 安全地将文件名从内核内存读到栈上
    long ret = bpf_probe_read_kernel_str(name_buf, sizeof(name_buf), filename);
    if (ret < 0) {
        return 0; // 读取失败，为了安全起见放行，或者你可以选择拦截
    }

    // 4. 比较是否是 "secret_file"
    if (my_strcmp(name_buf, target_name, sizeof(target_name)) == 0) {
        // 匹配成功！打印日志
        bpf_printk("LSM: Blocked removal of %s\n", name_buf);
        
        // 返回 -EPERM (-1)，告诉内核：操作不被允许
        return -EPERM; 
    }

    // 5. 默认放行
    return 0;
}
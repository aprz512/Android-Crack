#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>
#include <dlfcn.h>

static uint64_t hook_return_addr;
static uint64_t x0, x1;

void __attribute__((naked)) hook_func()
{

    // 获取参数
    asm("ldr x0, [sp, #-0x58]");
    asm("str x0,%0":"=m"(x0));
    asm("str x1,%0":"=m"(x1));

    // 执行被覆盖的指令
    // .text:00000000000783D4 FF 43 01 D1                   SUB             SP, SP, #0x50           ; Alternative name is 'fopen'
    // .text:00000000000783D8 F7 0B 00 F9                   STR             X23, [SP,#0x10]
    // .text:00000000000783DC F6 57 02 A9                   STP             X22, X21, [SP,#0x20]
    // .text:00000000000783E0 F4 4F 03 A9                   STP             X20, X19, [SP,#0x30]
    // .text:00000000000783E4 FD 7B 04 A9                   STP             X29, X30, [SP,#0x40]
    // .text:00000000000783E8 FD 03 01 91                   ADD             X29, SP, #0x40
    // .text:00000000000783EC 56 D0 3B D5                   MRS             X22, #3, c13, c0, #2
    // .text:00000000000783F0 C9 16 40 F9                   LDR             X9, [X22,#0x28]
    asm("SUB             SP, SP, #0x50");
    asm("STR             X23, [SP,#0x10]");
    asm("STP             X22, X21, [SP,#0x20]");
    asm("STP             X20, X19, [SP,#0x30]");
    asm("STP             X29, X30, [SP,#0x40]");
    asm("ADD             X29, SP, #0x40");

    // 跳转到返回地址，这个语句生成的汇编，用到了 x8 寄存器
    asm("ldr x0, %0" ::"m"(hook_return_addr));
    // 还原 x8 寄存器的值
    asm("ldr x8, [sp, #-0x8]");
    asm("br x0");
}

int main()
{
    void *handle = dlopen("libc.so", RTLD_NOW);
    void *hook_addr = dlsym(handle, "fopen");
    if (hook_addr != NULL)
    {
        hook_return_addr = hook_addr + 20;
    }
    else
    {
        return -1;
    }

    printf("hook_addr = %p\n", hook_addr);

    // 这里改变了 0x1000 这个范围的数据的属性
    mprotect((void *)((uint64_t)hook_addr & 0xfffffffffffff000), 0x1000, PROT_WRITE | PROT_EXEC | PROT_READ);

    // getchar();


    // 指令是4字节的，使用 uint32，地址使用 unit64

    // STP X8, X0, [SP, #-0x60]  -> E8 03 3A A9
    (*(uint32_t *)(hook_addr + 0)) = 0xA93A03E8;

    // LDR X0, 8 -> 40 00 00 58
    (*(uint32_t *)(hook_addr + 4)) = 0x58000040;

    // BR X0  -> 00 00 1f d6
    (*(uint32_t *)(hook_addr + 8)) = 0xd61f0000;

    // ADDR  -> 00 00 1f d6，这里要用64位
    (*(uint64_t *)(hook_addr + 12)) = hook_func;

    // 被覆盖的指令操作了sp，所以需要还原 
    // LDR X0, [SP, #-0x10]  -> E0 03 5F F8
    (*(uint32_t *)(hook_addr + 20)) = 0xF85F03E0;


    printf("hook_func = %p\n", hook_func);

    getchar();

    FILE *fp = fopen("/data/local/tmp/android_server64", "rb");
    uint64_t data;
    fread(&data, 4, 1, fp);
    fclose(fp);
    printf("data = %p\n", data);
    printf("x0 = %s\n", x0);
    printf("x1 = %s\n", x1);

    return 0;
}
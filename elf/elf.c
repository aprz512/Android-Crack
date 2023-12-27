#include <stdio.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>

#define PAGE_SIZE (4096)
#define PAGE_MASK (PAGE_SIZE - 1)
#define BASE (0x80000000)

int main()
{

    // FILE *fp = fopen("/data/local/tmp/four.bin", "rb");
    // void *addr = mmap((void *)0x80000000, 0x2000, PROT_EXEC | PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_FIXED, fileno(fp), 0);

    // fclose(fp);

    // printf("%p\n", addr);

    // printf("%08x\n", *(__uint8_t *)0x80000002);
    // // printf("%08x\n", *(__uint8_t *)0x80001000);

    // getchar();

    size_t elf64_header = sizeof(Elf64_Ehdr);

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)malloc(elf64_header);

    FILE *fp = fopen("/data/local/tmp/ls", "rb");

    // read Elf64_Ehdr bytes
    fread(ehdr, elf64_header, 1, fp);

    printf("e_phoff: %08x\n", ehdr->e_phoff);

    size_t elf64_phdr = sizeof(Elf64_Phdr);
    int phdr_num = ehdr->e_phnum;
    printf("phdr_num: %d\n", phdr_num);

    Elf64_Phdr *phdr = (Elf64_Phdr *)malloc(elf64_phdr * phdr_num);

    fseek(fp, ehdr->e_phoff, SEEK_SET);

    fread(phdr, elf64_phdr * phdr_num, 1, fp);

    uint64_t len;
    uint64_t tmp;
    uint64_t pbase;
    uint64_t extra_len;
    uint64_t extra_base;
    uint64_t strtab_addr;

    for (size_t i = 0; i < phdr_num; i++)
    {

        // printf("p_type: %d\n", phdr->p_type);
        if (phdr->p_type == PT_LOAD)
        {
            // 这里计算的是 pbase 的值
            tmp = BASE + phdr->p_vaddr & (~PAGE_MASK);
            // 看图可知，这里的文件大小加上 （ base + p_vaddr - pbase），也就是 mask off 的值
            len = phdr->p_filesz + (phdr->p_vaddr & PAGE_MASK);
            pbase = mmap(
                tmp,
                len,
                PROT_EXEC | PROT_WRITE | PROT_READ,
                MAP_PRIVATE | MAP_FIXED,
                fileno(fp),
                phdr->p_offset & (~PAGE_MASK));

            // zero fill， 如果文件范围比实际大小要小，那么会映射额外的脏数据进来，需要清零
            if ((len & PAGE_MASK))
            {
                memset((void *)(pbase + len), 0, PAGE_SIZE - (len & PAGE_MASK));
            }

            printf("mapped addr: %08x, %08x\n", pbase, len);

            tmp = (unsigned char *)(((unsigned)pbase + len + PAGE_SIZE - 1) & (~PAGE_MASK));
            if (tmp < (BASE + phdr->p_vaddr + phdr->p_memsz))
            {
                extra_len = BASE + phdr->p_vaddr + phdr->p_memsz - tmp;
                extra_base = mmap((void *)tmp, extra_len,
                                  PROT_EXEC | PROT_WRITE | PROT_READ,
                                  MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS,
                                  -1, 0);
                printf("mapped addr: %08x, %08x\n", extra_base, extra_len);
            }
        }
        else if (phdr->p_type == PT_DYNAMIC)
        {
            Elf64_Dyn *p_dyn = phdr->p_vaddr + BASE;
            while (1)
            {
                if (p_dyn->d_tag == DT_STRTAB)
                {
                    // 处理字符串
                    strtab_addr = BASE + p_dyn->d_un.d_ptr;
                    printf("strtab addr: %08x\n", strtab_addr);
                }
                else if (p_dyn->d_tag == DT_NEEDED)
                {
                    // 处理依赖的so
                    printf("needed so: %s\n", strtab_addr + p_dyn->d_un.d_ptr);
                }

                else if (p_dyn->d_tag == DT_NULL)
                {
                    // 后面无需处理
                    break;
                }

                p_dyn++;
            }
        }

        phdr++;
    }

    free(ehdr);
    free(phdr);
    fclose(fp);
    printf("mapped ok!!!\n");

    return 0;
}
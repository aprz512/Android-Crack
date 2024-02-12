#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

uint64_t x;

int main()
{
    getchar();
    x = 0x123456789a;
    printf("x = %lx\n", x);

    return 0;
}
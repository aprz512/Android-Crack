#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

static int func(int a, int b, int c, int d, int e, int f, int g, int h, int i)
{
    printf("%s\n", "add all");
    int x = a + b;
    return a + b + c + d + e + f + g + h + i;
}

int main()
{
    getchar();
    int result = func(1, 2, 3, 4, 5, 6, 7, 8, 9);
    printf("result = %d\n", result);
    return 0;
}
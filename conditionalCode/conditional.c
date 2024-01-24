#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>

int main()
{
    time_t t;
    srand((unsigned) time(&t));

    int a = rand();
    int b = rand();

    printf("a = %d, b = %d\n", a, b);

    if (a > b)
    {
        printf("a win!!!\n");
    }
    else if (a < b)
    {
        printf("b win!!!\n");
    }
    else
    {
        printf("both win!!!\n");
    }

    getchar();

    uint64_t num = 0x123456789abc;
    printf("num = %llx\n", num); 

    return 0;
}
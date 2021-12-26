#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int count = 0;
// int main()
// {
//     for (unsigned int i = 3; i < 0x80000000; i++)
//     {
//         for (unsigned int j = 10000001; j < 0x80000000; j++)
//         {
//             if (( i > 1000000 || j > 1000000) && i * j < (unsigned int)1000000) {
//                 for (unsigned k = i - 1; k > 0 ; --k) {
//                     if (k * j +1000000 > 0x80000000) {
//                         printf("i: 0x%x, j: 0x%x k:0x%x, i*j: 0x%x\n", i, j, k, i*j);
//                         count++;
//                         if (count == 10) {
//                             return 0;
//                         }
//                     }
//                 }
                
//             }
//         }
        
//     }
//     puts("Done!");
//     return 1;
// }

int main()
{
    char buf[0x10];
    memset(buf, 0x61, 0x10);
    fgets(buf, 7, stdin);
    printf("%lx\n", *(size_t*)buf);
    return 0;
}
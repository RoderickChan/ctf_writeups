#include <stdio.h>

int main()
{
    double a = 0.1;
    char *s = (char *)&a;
    for (int i = 0; i < 8; i++) {
        printf("%d\n", (unsigned char)s[i]);
    }
    return 0;
}
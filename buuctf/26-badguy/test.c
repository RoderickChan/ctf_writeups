#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<unistd.h>

int main()
{
	setbuf(stdout, NULL);
	uint64_t *p1 = (uint64_t*)malloc(0x100);
	uint64_t *p2 = (uint64_t*)malloc(0x10);
	
	p2[-1] = 0x20;
	free(p1);
	puts("done!");
	return 0;
}

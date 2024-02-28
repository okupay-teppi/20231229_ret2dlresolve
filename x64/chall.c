/* bof.cd */
#include <stdio.h>
#include <stdlib.h>

void vuln()
{
    char buf[100];
    gets(buf);
    puts(buf);
    puts("[*] Done");
}

void main(void)
{
    vuln();
    exit(0);
}
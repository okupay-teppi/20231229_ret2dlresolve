/* bof.cd */
#include <unistd.h>

void vuln()
{
    char buf[100];
    int size;
    read(0, &size, 4);
    read(0, buf, size);
    write(1, buf, size);
}

int main(void)
{
    vuln();
    return 0;
}
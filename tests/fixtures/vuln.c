#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void win() { system("/bin/sh"); }

int vuln() {
    char buf[64];
    printf("Enter input: ");
    gets(buf);
    char *p = malloc(32);
    strcpy(p, buf);
    free(p);
    return 0;
}

int main() {
    vuln();
    return 0;
}

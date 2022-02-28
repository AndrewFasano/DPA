#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main() {
    int *a = (int*)malloc(5*sizeof(int));
    printf("Int data: %d\n", a[5]);

    char buf[10];
    strcpy(buf, "Hello!\n");
    write(1, buf, 10); // Write message to stdout

    return 0;
}

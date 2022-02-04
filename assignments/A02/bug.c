#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main() {

    printf("Who are you: ");
    char name[10];
    fgets(name, 10, stdin);

    printf("Hello %s\n", name);

    char* data1 = (char*)malloc(1024);
    data1[0] = 'h';
    data1[1] = 'i';
    data1[2] = '0';

    free(data1);
    //int* data2 = (int*)malloc(1024);
    //data2[0] = 0x44434241

    //printf("data is %s\n", data1);

    //data1[0] = 'a';
    //data1[1] = 'b';
    //data1[2] = 'c';
    //printf("data is %s\n", data1);

    return 0;
}

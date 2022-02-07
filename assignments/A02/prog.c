#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main() {

    printf("Who are you: ");
    //char name[10];
    //fgets(name, 10, stdin);
    //printf("Hello %s\n", name);

    char* data1 = (char*)malloc(123);

    printf("Writing to data starting at %p\n", &(data1[0]));
    for (int i=0; i < 123; i++) {
        //printf("%c", (char)data1[i]);
        data1[i] = 'h';
    }
    printf("Data[5] at %p is %c\n", &data1[5], data1[5]);
    free(data1);

    //int* data2 = (int*)malloc(1024);
    //data2[0] = 0x44434241;
    //free(data2);

    //data1[0] = 0x44;
    //data1[1] = 0x44;

    printf("Data[5] at %p is %c\n", &data1[5], data1[5]);

    return 0;
}

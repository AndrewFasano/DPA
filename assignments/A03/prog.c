#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main() {
    char* data1 = (char*)malloc(123);
    printf("Writing to data starting at %p\n", &(data1[0]));
    for (int i=0; i < 123; i++) {
        data1[i] = 'h';
    }
    printf("Data[5] at %p is %c\n", &data1[5], data1[5]);
    free(data1);
    printf("Data[5] at %p is %c\n", &data1[5], data1[5]);
    return 0;
}

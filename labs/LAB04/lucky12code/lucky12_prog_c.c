#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("USAGE: %s: [some number]\n", argv[0]);
        return 1;
    }

    int count = atoi(argv[1]);
    if (count > 12) {
        count = 12;
    }

    char message[] = "hello world!";
    int len = strlen(message);
    if (count > len) {
        count = len;
    }

    size_t i;
    for (i=0; i < count; i++) {
        printf("%d=%c", i, message[i]);
    }
 
    printf("\nPrinted %ld characters of message\n", i);

    return 0;
}

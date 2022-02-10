#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("USAGE: %s: [some number]\n", argv[0]);
        return 1;
    }

    int count = atoi(argv[1]);

    for (int i = 0; i < count; i++) 
        printf("%d\n", i);

    return 0;
}

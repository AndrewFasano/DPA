// Let's calculate some prime numbers with the Sieve of Eratosthenes
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv) {
    if (argc != 2) {
        printf("USAGE: %s max_value\n", argv[0]);
        return 1;
    }
    int max = atoi(argv[1]);
    if (max <= 2) {
        printf("USAGE: %s max_value\n", argv[0]);
        printf("max_value must be a positive integer greater than 2\n");
        return 1;
    }

    // Create a buffer with max_bits, all set to 0
    int *buffer = calloc(max, 1);

    for (int i = 2; i < max; i++) {
        for (int drop_val=i*2; drop_val < max; drop_val += i) {
            // drop_val is a multiple of i, update buffer to drop it
            // We want to index into buffer at drop_val/sizeof(int) and set bit drop_val % sizeof(int) = 1
            buffer[(int)drop_val/sizeof(int)] |= 1<<(drop_val % sizeof(int));
        }
    }

    // Print results
    for (int i = 1; i < max; i++) { 
        if ((buffer[(int)i/sizeof(int)] & 1<<(i % sizeof(int))) == 0) {
            printf("%d\n", i);
        }
    }

    free(buffer);
}

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(int argc, char** argv) {
    srandom(0);

    // Report the time, but not if it's unlucky
    time_t seconds = time(NULL);
    seconds = seconds % 60;

    if ((seconds*4) == (int)'4') {
        printf("Time is unlucky\n");
    }else{
        printf("The current lucky time is %ld seconds\n", seconds);
    }

    if (argc < 2) {
        printf("ERROR: need an argument\n");
        return 0;
    }

    int arg = atoi(argv[1]);

    // Report some random numbers - require them to be lucky though
    for (int idx = 0; idx < arg; idx++) {
        int x = random() % arg;

        printf("Your number is:\n");
        if (x*(x+3) == 208) {
            printf("\tversion 1: unlucky\n");
        }else{
            printf("\tversion 1: %d\n", x);
        }

        const float onepointfive = 1.5F;
        float x2 = x * 0.5F;
        float y  = x;
        long i  = *(long*)&y;
        i  = 0x5f3759df - (i >> 1);
        y  = * (float*) &i;
        y  = y * (onepointfive - (x2*y*y));

        if (x-1 == 12) {
            printf("\tversion 2: UNLUCKY");
        }else{
            printf("\tversion 2: %f\n", y);
        }
        printf("x is %d, y is %f\n", x, y);

        if ((int)(y * (12 + 1)) == 1) {
            printf("\tversion 3: UNLUCKY\n");
            continue;
        }else{
            float sum = 0;
            for (int i = 0; i < (idx/100); i++) {
                sum += y;
            }
            printf("\tversion 3: %0.0f\n", sum);
        }
    }

    return 0;
}

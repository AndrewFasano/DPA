#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#define N_CMDS 10

short debug = 0;

void countdown() {
    printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
    printf("start the countdown sequence\n");
    printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
}

int add(int x, int y) {
    if (debug) printf("ADD %d and %d to get %d\n", x, y&0xff, x+(y&0xff));
    return x + (y&0xff);
}

int sub(int x, int y) {
    if (debug) printf("SUB %d and %d to get %d\n", x, y&0xff, x-(y&0xff));
    return x-(y&0xff);
}

int mul(int x, int y) {
    if (debug) printf("MUL %d and %d to get %d\n", x, y&0xff, x*(y&0xff));
    return x * (y&0xff);
}

void bkp(int x, int y) {
    if (debug) printf("BKPT\n");
    __asm__("int3");
}

void quit(int x, int y) {
    printf("BOOM\n");
    exit(2);
}

void need_more_args() {
    printf("BOOM\n");
    exit(1);
}
    


int main(int argc, char**argv) {
    printf("Welcome to the bomb. Can you defuse me?\n");

    if (argc < N_CMDS+2) {
        need_more_args();
    }

    typedef  (*op)(int, int);
    op commands[N_CMDS];
    op f;

    printf("Connecting internal wiring...\n");
    srand(time(NULL));
    for (int idx=0 ; idx < N_CMDS; idx++) {
        int sel = (rand() % 4);

        if (sel == 0) {
            if (debug) printf("idx=%d, f=add\n", idx);
            f = &add;
        } else if (sel == 1) {
            if (debug) printf("idx=%d, f=sub\n", idx);
            f = &sub;
        } else if (sel == 2) {
            if (debug) printf("idx=%d, f=mul\n", idx);
            f = &mul;
        } else if (sel == 3) {
            if (debug) printf("idx=%d, f=quit\n", idx);
            f = (int*)&quit;
        } else if (sel == 4) {
            if (debug) printf("idx=%d, f=break\n", idx);
            f = (int*)&bkp;
        }

        if (debug) printf("Set commands[%d] = %p\n", idx, &f);
        commands[idx] = f;
    }

    countdown();

    int accumulator = 0;
    for (int idx=0; idx < N_CMDS; idx++ ) {
        printf(".");
        f = commands[idx];
        accumulator = f(accumulator, atoi(argv[idx+2]));
        if (debug) printf("After %d, accum=0x%x\n", idx, accumulator);
    }
    printf("Time's up!\n");

    char out[4];
    out[0] = 0x64 ^ (accumulator & 0x00ff0000) >> 16;
    out[1] = 0x7a ^ (accumulator & 0x0000ff00) >> 8;
    out[2] = 0x59 ^ accumulator & 0x000000ff;
    out[3] = 0;

    char buf[16];
    snprintf(buf, 16, "You %s!!!\n", out);

    if (accumulator == 0x133337) {
        puts(buf);
    }else{
        printf("BOOM");
    }
}

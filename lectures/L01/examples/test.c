#include <stdio.h>

int main(int argc, char** argv, char** envp) {
    printf("Argc is %d\n", argc);

    argv[argc+1] = 1;
    argv[argc+2] = 2;

    return argc;
}

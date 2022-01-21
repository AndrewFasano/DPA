#include <stdio.h>

int foo() {
    return 7;
}

int main(int argc, char** argv, char** envp) {
    printf("Argc is %d\n", argc);

    if (argc == 2)
        foo();

    argv[argc+1] = 1;
    argv[argc+2] = 2;

    return argc;
}

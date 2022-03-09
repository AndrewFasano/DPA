#include <stdio.h>
#include <string.h>

int main(int argc, char** argv)  {
    if (argc != 2) {
        puts("USAGE: crackme [password]\n");
        return 1;
    }

    if (strcmp(argv[1], "supersecretpassword") == 0) {
        puts("nobody cares about that password\n");
    }

    if (strcmp(argv[1], "this aint dynamic") == 0) {
        puts("Correct!\n");
        return 0;
    }

    puts("WRONG\n");
    return 1;
}

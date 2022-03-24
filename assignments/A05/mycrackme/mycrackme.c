#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#define PASS "P@SS-4-CS4910"
#define PASSLEN 13

extern "C" int my_asm_func(char*, int);

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Error: must run with a password: %s [pass]\n", argv[0]);
        return 1;
    }

    // Copy pass onto the heap so it can be mutated by my_asm_func
    char *pass = strndup(PASS, PASSLEN);

    char *guess = argv[1];

    // Call into assembly code to do some shenanigans on the password
    // or you can change this to something else
    my_asm_func(pass, PASSLEN);

    if (strcmp(pass, guess) == 0) {
        printf("GOOD PASSWORD\n");
    }else{
        printf("WRONG PASSWORD\n");
        // Just for debugging:
        printf("\t answer was %s\n", pass);
    }

    free(pass);
    return 0;
}

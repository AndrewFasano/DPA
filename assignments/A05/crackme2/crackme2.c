#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#define PASS "dynamicwhynamic"
#define PASSLEN 15

extern "C" int nothing(void*, char*, char*, void*);
extern "C" void __setup(void);
void calc(char*, char*);
char* scratch=NULL;
char* pass=NULL;

void __setup() {
    for (int i=0; i < PASSLEN; i++) {
        pass[i]++;
    }
    nothing((void*)&calc-1, scratch, pass, (void*)&__setup);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Error: must run with a password: %s [pass]\n", argv[0]);
        return 1;
    }
    pass = strndup(PASS, PASSLEN);

    int len = strlen(argv[1]);
    int hash = 0;
    for (int i=0; i < len; i++) {
        hash += (i*(int)argv[1][i]);
    }

    scratch=argv[1];

    if (strlen(scratch) >= PASSLEN) {
        nothing((void*)(&__setup)-1, argv[0], NULL, (void*)&exit);
    }

    printf("Crackme... if you can!");

    for (int i=0; i < PASSLEN; i++) {
        memcpy((char*)&(PASS)+i,(char*)&PASS+i+1, PASSLEN);
    }

    calc(
        (char*)nothing((char*)&argv[3]+4, argv[1], pass, (void*)&strcmp),              pass);
}

void calc(char *argv, char * pass) {

    for (int i=0; i<=PASSLEN; i++) {
        if (i == 4) {
            argv[i] = (char)argv[i] + 1;
        }

        if (argv[i] != pass[i]) {
            break;
        }

        if (i==PASSLEN-1 && argv[i+1] == 0) {
            printf("GOOD PASSWORD\n");
            exit(0);
        }
    }
    printf("WRONG PASSWORD\n");
    exit(1);
}

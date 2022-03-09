#include <stdio.h>
#include <string.h>

#define PASSWORD "isthis1harder2guess"
#define PWLEN 37
#define ONETIMEPAD "alhsgasdhu8hwetadsoiewtaoiyasdf"

int main(int argc, char** argv)  {
    if (argc != 2) {
        puts("USAGE: harder [password]\n");
        return 1;
    }

    char enc_pw[PWLEN] = {0};
    for (int i=0; i < PWLEN; i++) {
        enc_pw[i] = PASSWORD[i] ^ ONETIMEPAD[i];
        if (enc_pw[i] < 0x20) {
            enc_pw[i] += 0x20;
        }

        if (enc_pw[i] > 0x7E) {
            enc_pw[i] = 0x7E;
        }
    }

    printf("Analyzing your password: %s\n", argv[1]);

    if (strncmp(argv[1], enc_pw, PWLEN) == 0) {
        puts("Correct!\n");
        return 0;
    }



    puts("WRONG\n");
    return 1;
}

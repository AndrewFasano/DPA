#include <stdio.h>
#include <unistd.h>
#include <pwd.h>
#include <signal.h>
#include <stdlib.h>



int main() {
    signal(SIGALRM, _exit);
    alarm(5);

    printf("PROGRAM starts\n");
    sleep(1);

    int i, j;
    for (i=0; i < 10; i++) {
        for (j = 0; j < i; j++)
            printf(" ");
        printf("*");
        for (j = 10; j > i; j--)
            printf(" ");
        printf("|");
        for (j = 10; j > i; j--)
            printf(" ");
        printf("*\n");
    }
    printf("          THE\n");
    printf("          END\n");

    int uid = geteuid();
    register struct passwd *pw = getpwuid(uid);
    if (pw) {
        printf("PROGRAM says goodbye to %s\n\n", pw->pw_name);
    }else{
        printf("PROGRAM syays Goodbye to nobody\n\n");
    }
    return 0;
}

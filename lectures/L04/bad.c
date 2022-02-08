#include <stdio.h>

int main() {
    int a;
    printf("Nobody knows what this is %d\n", a);

    char msg[] = {'h', 'e', 'l', 'l', 'o', 0};
    strcpy(&msg, "this is a bit too long");
    puts(msg);

    return 0;
}

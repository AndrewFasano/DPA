#include <stdio.h>

int b() {
    return 4;
}

int a() {
    return b();
}

int main() {
    printf("Main at %p, a at %p, b at %p\n", &main, &a, &b);
    return a();
}

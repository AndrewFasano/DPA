#include <stdio.h>

int main() {
    int a[] = {1,2,3,4,5};
    printf("Data: %d\n", a[5]);

    if (a[5] % 4 == 0) {
        return 1;
    }
    return 0;
}

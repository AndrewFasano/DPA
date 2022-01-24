// From https://systemoverlord.com/2014/01/13/ld_preload-for-binary-analysis/
#include <time.h>
#include <stdio.h>

int main(int argc, char **argv){
    if (time(NULL) % 86400 == 0) {
        puts("Win!\n");
        return 0;
    }
    puts("Lose\n");
    return 1;
}

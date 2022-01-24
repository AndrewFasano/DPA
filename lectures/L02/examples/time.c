// From https://systemoverlord.com/2014/01/13/ld_preload-for-binary-analysis/
#include <time.h>
#include <stdlib.h>

time_t time(time_t *out){
    char *tstr = getenv("TIME");
    if (tstr)
        return (time_t)atol(tstr);
    return (time_t)0;
}

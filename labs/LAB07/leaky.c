#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

// This program examines how cool your machine is.
// It does this by analyzing the usernames in /etc/passwd
// and then it produces a coolness score

#define BUF_SZ 32


int calc_name_score(char* name) {
    // Calculate the coolness score for a name. Case insensitive.
    // Score is calculated by looking across the string and counting as follows:
    // Each vowel [aeiouy] adds 10 points, other chars decrement 3
    // The letter "o" is a special case. When you see it, look 2 characters ahead.
    // If that's a valid access, calculate the score from there through 2 more chracters
    // and triple that score.
    //
    // For example: with helloworld you would calculate it as follows:
    // h: -3
    // e: 10
    // l: -3
    // l: -3
    // o: 10 + calc_name_score("orld") aka (10 - 5)
    // w: -3
    // o: 10 + calc_name_score("ld") (aka 10 - 6)
    // r: -3
    // l: -3
    // d: -3

    int score = 0;
    for (int i = 0; i < strlen(name); i++) {
        if (name[i] == 'a' || name[i] == 'e' || name[i] == 'i' ||
                name[i] == 'o' || name[i] == 'u' || name[i] == 'y') {
           score += 10;
        } else {
           score -= 3;
        }

        if (name[i] == 'o') {
            score += calc_name_score(&name[i+3]);
        }
    }
    return score;

}

int calc_score(char* buffer) {
    // First we need to split the lines and get usernames. Store each in names
    char *names[64] = {0};
    char *name;
    char scratch[256] = {0};

    int i = 0;

    while (*buffer != 0) {
        // Copy the current line into our scratch buffer and extract up to the : with strtok
        strncpy(scratch, buffer, 256);
        name = strtok((char*)&scratch, ":");

        // If strtok didn't find a colon, bail
        if (name == NULL) break;

        // Save the output in our names array
        names[i++] = strdup(name);

        // Advance our pointer into buffer until just after the next newline
        // or the end
        while (*buffer != 0 && *buffer != '\n')
            buffer++;
        if (*buffer == '\n')
            buffer ++;
    }

    // For each name, calculate its score
    int score = 0;
    for (i = 0; i < 64; i++) {
        if (names[i] == 0) break;
        score += calc_name_score(names[i]);
    }
    return score;
}

int main() {
    const char filename[] = "/etc/passwd";
    int fd;

    fd = open(filename, O_RDONLY);


    // Fixed size buffer for chunks of text we read
    char partialbuf[BUF_SZ];
    int bytes_read;

    int cur_size = 0;
    // Dynamic sized buffer
    char *fullbuf = (char*)malloc(sizeof(char*) * BUF_SZ);
    char *oldbuf = NULL;

    while (1) {
        bytes_read = read(fd, partialbuf, BUF_SZ);
        if (bytes_read <= 0) {
            break;
        }

        // Save old buf
        oldbuf = fullbuf;
        // allocate a new buffer big enough for everything we have
        cur_size += bytes_read;
        fullbuf = (char*)malloc(cur_size);
        // Copy old buf + this line into the new buffer
        strcat(fullbuf, oldbuf);
        strcat(fullbuf, partialbuf);
    }

    int score = calc_score(fullbuf);
    free(fullbuf);

    printf("Your system's cool score is %d\n", score);
    return 0;
}

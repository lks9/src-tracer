#include <stdlib.h>
#include <stdio.h>

#include "src_tracer/ghost.h"

int count(int a[10][100]) {
    int res = 0;
    for (int i = 0; i < 10; i++) {
        for (int v = 0; a[i][v] != 0; v++) {
            res ++;
        }
    }
    RETRO_ASSERT(res == 140);
    return res;
}

int a[10][100];

int main (void) {
    for (int i=0; i < 140; i++) {
        int n = random() % 10;
        int j;
        for (j = 0; a[n][j] != 0; j++) {
            if (j == 98) {
                j = -1;
                n += 1;
                n %= 10;
            }
        }
        a[n][j] = 1;
    }
    printf("count = %d\n", count(a));
}

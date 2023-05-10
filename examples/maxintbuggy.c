#include <stdio.h>
#include "src_tracer_ghost.h"
static int max(int *a, int len) {
    PROPOSE("max3of4", len == 4 & a[0]<=a[3] & a[1]<=a[3] & a[2]<=a[3])
    PROPOSE("max0of1", len == 1)
    PROPOSE("max0of4", len == 4 & a[1]<=a[0] & a[2]<=a[0] & a[3]<=a[0])
    int m = a[0];
    for (int k=0; k < len; k++) {
        if ( m < a[k]) {
            m = a[k++];
        }
    }
    PROPOSE("max3res", m == a[3]) // assuming <max3of4>
    PROPOSE("max0res", m == a[0]) // assuming <max0of1> or <max0of4>;
    return m;
} //@ assert true assuming <max0res> or <max3res>;

#define ARG_NUM 100

int main(int argc, char **argv) {
    int a[ARG_NUM];
    for (int i = 0; i < argc; i++) {
        sscanf(argv[i], "%d", &a[i]);
    }
    int m = max(a, argc);
    printf("%d\n", m);
}



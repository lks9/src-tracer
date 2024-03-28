#include <setjmp.h>

static jmp_buf setjmp_env;

void bar (void) {
    longjmp(setjmp_env, 1);
}

void foo (void) {
    bar();
}

int main (int argc, char **argv) {
    if (setjmp(setjmp_env) == 0) {
        foo();
    }
}

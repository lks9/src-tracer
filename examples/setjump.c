/* setjump.c
 *
 * For retracing with angr, compile together with setjmp.s and longjmp.s in folder src/setjmp/YOUR_ARCH/
 * of musl-libc! Download from: https://musl.libc.org/
 *
 * gcc -D_RETRACE_MODE -L../lib -I../include setjump_inst.c setjmp.s longjmp.s -o setjump_retrace -lsrc_tracer
 *
 * Retracing with angr without compiled-in setjmp.s and longjmp.s would make "YOUR ASSERTION" simply
 * unreachable, since angr treats longjmp as noreturn (as of version 9.2.96). Retracing with cbmc
 * currently would produce "longjmp requires instrumentation".
 */

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
    /* YOUR ASSERTION HERE */
}

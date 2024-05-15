/*
   src_tracer/syscalls.h
   use direct syscalls instead of stdlib, to make recording of stdlib possible
*/
#ifndef SRC_TRACER_SYSCALLS_H
#define SRC_TRACER_SYSCALLS_H

#include <sys/syscall.h>

// taken from musl (arch/x86_64/syscall_arch.h)
static inline __attribute__((always_inline)) long syscall_0(long n)
{
    unsigned long ret;
    __asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n) : "rcx", "r11", "memory");
    return ret;
}

static inline __attribute__((always_inline)) long syscall_1(long n, long a1)
{
    unsigned long ret;
    __asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1) : "rcx", "r11", "memory");
    return ret;
}

static inline __attribute__((always_inline)) long syscall_2(long n, long a1, long a2)
{
    unsigned long ret;
    __asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2)
                          : "rcx", "r11", "memory");
    return ret;
}

static inline __attribute__((always_inline)) long syscall_3(long n, long a1, long a2, long a3)
{
    unsigned long ret;
    __asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2),
                          "d"(a3) : "rcx", "r11", "memory");
    return ret;
}

static inline __attribute__((always_inline)) long syscall_4(long n, long a1, long a2, long a3, long a4)
{
    unsigned long ret;
    register long r10 __asm__("r10") = a4;
    __asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2),
                          "d"(a3), "r"(r10): "rcx", "r11", "memory");
    return ret;
}

static inline __attribute__((always_inline)) long syscall_6(long n, long a1, long a2, long a3, long a4, long a5, long a6)
{
    unsigned long ret;
    register long r10 __asm__("r10") = a4;
    register long r8 __asm__("r8") = a5;
    register long r9 __asm__("r9") = a6;
    __asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2),
                          "d"(a3), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
    return ret;
}

// end musl code

#endif // SRC_TRACER_SYSCALLS_H

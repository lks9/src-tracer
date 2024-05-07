/*
   src_tracer/syscalls.h
   use direct syscalls instead of stdlib, to make recording of stdlib possible
*/
#ifndef SRC_TRACER_SYSCALLS_H
#define SRC_TRACER_SYSCALLS_H

// taken from musl (arch/x86_64/syscall_arch.h)
static __inline long syscall_0(long n)
{
    unsigned long ret;
    __asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n) : "rcx", "r11", "memory");
    return ret;
}

static __inline long syscall_1(long n, long a1)
{
    unsigned long ret;
    __asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1) : "rcx", "r11", "memory");
    return ret;
}

static __inline long syscall_2(long n, long a1, long a2)
{
	unsigned long ret;
	__asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2)
						  : "rcx", "r11", "memory");
	return ret;
}

static __inline long syscall_3(long n, long a1, long a2, long a3)
{
	unsigned long ret;
	__asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2),
						  "d"(a3) : "rcx", "r11", "memory");
	return ret;
}

static __inline long syscall_4(long n, long a1, long a2, long a3, long a4)
{
       unsigned long ret;
       register long r10 __asm__("r10") = a4;
       __asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2),
                                                 "d"(a3), "r"(r10): "rcx", "r11", "memory");
       return ret;
}

#define SYS_write           1
#define SYS_madvise        28
#define SYS_nanosleep      35
#define SYS_getppid       110
#define SYS_fork           57
#define SYS_timer_create  222
#define SYS_timer_settime 223
#define SYS_timer_gettime 224
// end musl code

#endif // SRC_TRACER_SYSCALLS_H

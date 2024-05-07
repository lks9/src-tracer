/*
   src_tracer/syscalls.h
   use direct syscalls instead of stdlib, to make recording of stdlib possible
*/
#ifndef SRC_TRACER_SYSCALLS_H
#define SRC_TRACER_SYSCALLS_H

// taken from musl (arch/x86_64/syscall_arch.h)
static __inline long __syscall3(long n, long a1, long a2, long a3)
{
	unsigned long ret;
	__asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2),
						  "d"(a3) : "rcx", "r11", "memory");
	return ret;
}
#define SYS_write				1
// end musl code

#endif // SRC_TRACER_SYSCALLS_H

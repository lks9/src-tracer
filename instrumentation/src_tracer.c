#include "src_tracer.h"

#include <stdbool.h>
#include <fcntl.h>

int _trace_fd;
bool _trace_writing = false;

unsigned char _trace_if_byte;
int _trace_if_count;

// taken from musl (arch/x86_64/syscall_arch.h)
static __inline long __syscall1(long n, long a1)
{
	unsigned long ret;
	__asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1) : "rcx", "r11", "memory");
	return ret;
}
static __inline long __syscall3(long n, long a1, long a2, long a3)
{
	unsigned long ret;
	__asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2),
						  "d"(a3) : "rcx", "r11", "memory");
	return ret;
}
#define SYS_read				0
#define SYS_write				1
#define SYS_open				2
#define SYS_close				3
#define O_LARGEFILE 0100000
// end musl code


void _trace_write(const void *buf, int count) {
    if (_trace_writing) {
        _trace_writing = false;
        if (__syscall3(SYS_write, (long)_trace_fd, (long)buf, (long)count) == -1) {
            // some write error occured
            // do not reset _trace_writing, instead abort trace recording
            return;
        }
        _trace_writing = true;
    }
}

// same as the macro version
// but returns num
// can be used inside switch conditions
unsigned int _trace_num(char type, unsigned int num) {
    _TRACE_NUM(type, num)
    return num;
}

void _trace_open(const char *fname) {
    _trace_fd = __syscall3(SYS_open, (long)fname, (long)(O_WRONLY | O_CREAT | O_TRUNC | O_LARGEFILE), (long)0644);
    _trace_if_count = 0;
    _trace_if_byte = _TRACE_SET_IE;
    _trace_writing = true;
}

void _trace_close(void) {
    if (_trace_if_count != 0) {
        _TRACE_NUM(_TRACE_SET_FUNC, 0);
        _TRACE_PUT(_trace_if_byte);
    }
    _trace_writing = false;
    __syscall1(SYS_close, (long)_trace_fd);
}


// for retracing
int _retrace_fun_num;
bool _retrace_assert_values[256];
char _retrace_assert_label[256];

// only retrace.py should write in here
int _retrace_assert_index;

void _retrace_if(void) {}

void _retrace_else(void) {}

void _retrace_fun_call(void) {}

void _retrace_return(void) {}

void _retrace_assert_passed(void) {};

unsigned int _retrace_int;

void _retrace_wrote_int(void) {}

unsigned int _retrace_num(unsigned int num) {
    _retrace_int = num;
    _retrace_wrote_int();
    return num;
}

void _retrace_assert(char label[], _Bool a) {
    int i;
    for (i = 0; label[i] != '\0'; i++) {
        _retrace_assert_label[i] = label[i];
    }
    _retrace_assert_label[i] = '\0';
    _retrace_assert_passed();
    // Save the negation of the result (makes initialization simpler)
    _retrace_assert_values[_retrace_assert_index] = !a;
}

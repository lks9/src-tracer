#include "src_tracer.h"
#include "src_tracer_ghost.h"

#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <stdio.h>

#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif

int _trace_fd = 0;

unsigned char _trace_if_byte = _TRACE_SET_IE;
int _trace_if_count = 0;

#ifndef _TRACE_USE_POSIX_WRITE
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
#endif

unsigned char _trace_buf[TRACE_BUF_SIZE];
int _trace_buf_pos = 0;

void _trace_write(const void *buf, int count) {
    const char *ptr = buf;
    while (_trace_fd > 0) {
#ifdef _TRACE_USE_POSIX_WRITE
        ssize_t written = write(_trace_fd, ptr, count);
#else
        // Use __syscall3 to avoid recursive calls
        long written = __syscall3(SYS_write, (long)_trace_fd, (long)ptr, (long)count);
#endif
        if (written < 0) {
            // some write error occured
            // abort trace recording
            int fd = _trace_fd;
            _trace_fd = 0;
            close(fd);
            return;
        } else if (written == count) {
            return;
        }
        ptr = &ptr[written];
        count -= written;
    }
}

// same as the macro version
// but returns num
// can be used inside switch conditions
unsigned int _trace_num(char type, unsigned int num) {
    _TRACE_NUM(type, num);
    return num;
}

unsigned int _trace_num_text(char type, unsigned int num) {
    _TRACE_NUM_TEXT(type, num);
    return num;
}

bool _trace_condition(bool cond) {
    _TRACE_IE(cond);
    return cond;
}

void _trace_open(const char *fname) {
    if (_trace_fd > 0) {
        // already opened
        return;
    }
    // Make the file name time dependent
    char timed_fname[200];
    char nano_fname[200];
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now) < 0) {
        return;
    }
    strftime(timed_fname, 200, fname, gmtime(&now.tv_sec));
    snprintf(nano_fname, 200, timed_fname, now.tv_nsec);

    int lowfd = open(nano_fname, O_WRONLY | O_CREAT | O_EXCL | O_LARGEFILE, S_IRUSR | S_IWUSR);

    // The posix standard specifies that open always returns the lowest-numbered unused fd.
    // It is possbile that the traced software relies on that behavior and expects a particalur fd number
    // for a subsequent open call, how ugly this might be (busybox unzip expects fd number 3).
    // The workaround is to increase the trace fd number by 42.
    int fd = dup2(lowfd, lowfd + 42);
    close(lowfd);

    atexit(_trace_close);

    // now the tracing can start (guarded by _trace_fd > 0)
    _trace_fd = fd;
    _trace_buf_pos = 0;
    _trace_if_count = 0;
    _trace_if_byte = _TRACE_SET_IE;
}

void _trace_close(void) {
    if (_trace_fd <= 0) {
        // already closed or never successfully opened
        return;
    }
    if (_trace_if_count != 0) {
        _TRACE_NUM(_TRACE_SET_FUNC, 0);
        _TRACE_PUT(_trace_if_byte);
    }
    if (_trace_buf_pos != 0) {
        _trace_write(_trace_buf, _trace_buf_pos);
    }
    // stop tracing
    int fd = _trace_fd;
    _trace_fd = 0;
    // now we call a library function without being traced
    close(fd);
}


// text trace
bool _text_trace_condition(bool cond) {
    if (cond) {
        _TRACE_PUT_TEXT('T');
    } else {
        _TRACE_PUT_TEXT('N');
    }
    return cond;
}

int _text_trace_switch(int num, const char *num_str) {
    _TRACE_PUT_TEXT('D');
    for (const char *ptr = &num_str[2]; *ptr != '\0'; ptr = &ptr[1]) {
        _TRACE_PUT_TEXT(*ptr);
    }
    return num;
}

// for retracing
int _retrace_fun_num;


void _retrace_if(void) {}

void _retrace_else(void) {}

bool _retrace_condition(bool cond) {
    if (cond) {
        _retrace_if();
    } else {
        _retrace_else();
    }
    return cond;
}

void _retrace_fun_call(void) {}

void _retrace_return(void) {}

unsigned int _retrace_int;

void _retrace_wrote_int(void) {}

unsigned int _retrace_num(unsigned int num) {
    _retrace_int = num;
    _retrace_wrote_int();
    return num;
}

// ghost code
void _retrace_ghost_start(void) {}
void _retrace_ghost_end(void) {}

char *_retrace_assert_names[ASSERT_BUF_SIZE];
bool  _retrace_asserts[ASSERT_BUF_SIZE];
int   _retrace_assert_idx;
void  _retrace_assert_passed(void) {}

char *_retrace_assume_name;
bool  _retrace_assume;
void  _retrace_assume_passed(void) {}

void _retrace_prop_start(void) {}
bool _retrace_prop_is_assert;
bool _retrace_prop_is_assume;
void _retrace_prop_passed(void) {}

char *_retrace_dump_names[GHOST_DUMP_BUF_SIZE];
void *_retrace_dumps[GHOST_DUMP_BUF_SIZE];
int   _retrace_dump_idx;
void  _retrace_dump_passed(void) {}

// for both
bool _is_retrace_mode = false;

bool _is_retrace_condition(bool cond) {
    if (cond) {
        _IS_RETRACE(_retrace_if(), _TRACE_IE(1));
    } else {
        _IS_RETRACE(_retrace_else(), _TRACE_IE(0));
    }
    return cond;
}


/* This can be used for switch:
 *    switch(        num ) { ... }
 * Annotated:
 *    switch(_SWITCH(num)) { ... }
 * The makro _SWITCH might translate to _is_retrace_switch.
 */
unsigned int _is_retrace_switch(unsigned int num) {
    _IS_RETRACE(_RETRACE_NUM(num),
                _TRACE_NUM(_TRACE_SET_DATA, num)
    )
    return num;
}

#include <src_tracer/constants.h>
#include <src_tracer/mode_common.h>

#include <stdbool.h>

/* try/catch/setjmp count */
unsigned long long int _trace_setjmp_idx = 0;

/* fork count */
int _trace_fork_count = 0;

/* Pointer calls */
bool _trace_pointer_call = false;

// for both tracing and retracing
volatile bool _is_retrace_mode = false;

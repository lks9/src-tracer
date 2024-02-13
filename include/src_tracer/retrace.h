// retrace.h
//
// Trace representation to be used for the assume(...)-approach to
// symbolic execution replay.


/*
 * trace array for symbolic replay using assume(retrace_arr[retrace_i++] == ...)
 * Used in _CBMC_MODE
 */
struct retrace_elem {
    char letter;
    int num;
};

#define RETRACE_ARR_LEN_MAX 4096
extern int retrace_i;

// to be defined for the respective trace
extern struct retrace_elem retrace_arr[RETRACE_ARR_LEN_MAX];
extern int retrace_arr_len;

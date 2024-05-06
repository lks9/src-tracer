/*
   src_tracer/_stdinc_replace.h
   replace any standard libray headers we can't include when already pre-processed
*/
#ifndef SRC_TRACER_STDINC_REPLACE_H
#define SRC_TRACER_STDINC_REPLACE_H

// stdbool.h
#ifndef __cplusplus
    // bool is available in C++ but not in C without stdbool.h
    #ifndef bool
        #define bool _Bool
    #endif
#endif

#endif // SRC_TRACER_STDINC_REPLACE_H

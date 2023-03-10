# Source Tracer

This is a draft of a control flow tracer based on source code instrumentation with a low overhead.
Instrument your software with `instrumenter.py`. When running instrumented software, the trace is written into a file.
The format is basically one character (plus an optional number)
for each source code block on the trace.
For accurate retracing, `replay_trace.py` uses symbolic execution.

## Which Software to Trace

Any software which is written in C, with the source code available.

## Dependencies
### For the Instrumentation

* python3
* libclang (`pip install libclang`)

### For the Trace Recording

* C compiler (or your build system at choice) to compile the instrumented software

### For the Symbolic Replayer

* C compiler (or your build system at choice) to compile the instrumented software
* python3
* [angr](https://angr.io) for symbolic execution (`pip install angr`)

## Instrumentation

1. Add to each source file
   ```C
   #include "cflow_inst.h"
   ```
2. Add macros to the respective code blocks. A list of all macros is given below.
3. Add a wrapper for the main function to call `_cflow_open` and `_cflow_close`.

For an example instrumentation, run the `instrumenter.py` on
the original `checksum.c` (instructions below).
The `instrumenter.py` also creates a list of all functions together with their
`num` as `cflow_functions.json`.

### Trace Format

The instrumentation consists of macros added to the source code.
Each element consists of one capital letter + an optional hex `num` in lower case.
Elements are written sequentially without any separator.

| Macro                | Emits       | Explanation                                             |
|----------------------|-------------|---------------------------------------------------------|
| `_FUNC(num)`         | `F` + `num` | Function call, use `num` to distinguish functions       |
| `_IF`                | `T`         | The if-branch of an if-clause is taken                  |
| `_ELSE`              | `N`         | The else-branch of an if-clause is taken                |
| `_SWITCH(num)`       | `D` + `num` | Jump to case indicated with `num` in a switch-clause    |
| `_LOOP_START(id)`    |             | Beginning of a loop (for, while etc.)                   |
| `_LOOP_BODY(id)`     | `T`         | Loop iteration, nothing is emitted                      |
| `_LOOP_END(id)`      | `N`         | End of a loop, `num` indicates the number of iterations |
| `_cflow_open(fname)` |             | Initialize, write trace to file named `fname`           |
| `_cflow_close()`     | `F0`        | Close the cflow tracer                                  |

An example trace is `F2NF1TTNT`, which includes sub-traces, for example `F1TTN` or `TTN`.

Note that function number `0` is reserved, and `F0` simply markes the end of a trace
(as emmitted by `_cflow_close()`).

There was another variant which emitted `I` or `E` for if-clauses, and
`L` + (inner loop) + `P` + `num` for loops. A `P` + `num` can take logarithmically less
space then a sequence of `T` and `N`. However, we observed that the number
of loop iterations for most loops is not high enough to make it significant.
Moreover, a sequence of `T` and `N` can be stored more efficient in the binary trace format.

## Example `checksum.c`

* Compile it first using the flag `-save-temps` (works for gcc and clang)
  ```
  cd examples/
  gcc -save-temps checksum.c -o checksum
  cd ..
  ```
### Recording
* Copy the source directory, add `cflow_inst.h` and `cflow_inst.c`
  ```
  cp -Tr examples/ examples_record/
  cp inst_record/cflow_inst.h examples_record/
  cp inst_record/cflow_inst.c examples_record/
  ```
* Change into the new directory
  ```
  cd examples_record
  ```
* Overwrite the `*.c` files with their pre-processor output
  (generated by `-save-temps` before)
  ```
  mv checksum.i checksum.c
  ```
* Instrument it (the pre-processed version)
  ```
  python ../instrumenter.py checksum.c
  ```
  For a list of functions together with the `num` generated by the instrumenter,
  have a look at the newly created `cflow_functions.json`.
* Compile it (you might want different compiler optimizations for recording/replaying)
  ```
  gcc -O3 checksum.c cflow_inst.c -o checksum
  ```
* Run it (replace `42` to get another trace) 
  ```
  ./checksum 42
  ```
* Display the trace
  ```
  python ../print_trace.py checksum.c.trace
  cd ..
  ```
### Retracing
* Copy the source directory, add `cflow_inst.h` and `cflow_inst.c`
  ```
  cp -Tr examples_record/ examples_replay/
  cp inst_replay/cflow_inst.h examples_replay/
  cp inst_replay/cflow_inst.c examples_replay/
  ```
* Change into the new directory
  ```
  cd examples_replay
  ```
* Compile it (you might want different compiler optimizations for recording/replaying)
  ```
  gcc -g checksum.c cflow_inst.c -o checksum
  ```
* Retrace it (use `python -i` to work with the traced `state` in the interactive shell)
  ```
  python ../replay_trace.py checksum main checksum.c.trace
  echo "F1TTN" > sub.trace.txt
  python ../replay_trace.py checksum checksum sub.trace.txt
  ```
  The last one just retraces function `checksum`.

## Other Software

This is the same as for the `checksum.c` example.

Recording:
  ```sh
  # Compile
  MAKE/GCC/etc. with -save-temps
  # Copy sources
  cp -Tr SRCDIR/ SRCDIR_record/
  cp inst_record/cflow_inst.h SRCDIR_record/
  cp inst_record/cflow_inst.c SRCDIR_record/
  for file in $(find SRCDIR_record/ -name "*.i")
    do
      # Rename *.i into *.c
      mv "${file}" "${file%.i}.c"
      # Instrument *.c
      python instrumenter.py "${file%.i}.c"
    done
  # Now compile the sources & link them with cflow_inst.c
  MAKE/GCC/etc.
  # Run your instrumented software
  ./APP WITH ARGUMENTS
  # Display the trace
  python print_trace.py APP.c.trace
  ```
Retracing:
  ```sh
  # Copy sources
  cp -Tr SRCDIR_record/ SRCDIR_replay/
  cp inst_replay/cflow_inst.h SRCDIR_replay/
  cp inst_replay/cflow_inst.c SRCDIR_replay/
  # Now compile the sources & link them with cflow_inst.c
  MAKE/GCC/etc.
  # Retrace
  python replay_trace.py APP main APP.c.trace
  ```

If you instrument an application and together with dependent libraries, make
sure they share the same `cflow_functions.json` (e.g. by copying or using a
file link). It can be a bit tricky to get the binary linking correctly,
make sure that the record/replay executable includes the record/replay
version of the app and its libraries.

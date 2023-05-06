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
   #include "src_tracer.h"
   ```
2. Add macros to the respective code blocks. A list of all macros is given below.
3. Add `_TRACE_OPEN(fname)` and optionally `_TRACE_CLOSE` to the main function.

For an example instrumentation, run the `instrumenter.py` on
the original `checksum.c` (instructions below).
The `instrumenter.py` also creates a sqlite database to store all functions together with their
`num` as `cflow_functions.db`.

### Assertion Checking

You can add assertions anywhere to the sources, either to the original files
or after the instrumentation process. Assertions have the form:

```
_RETRACE_ASSERT("some name", bool_expr);
```

Assertions are checked when retracing and are ignored otherwise.


### Trace Format

The instrumentation consists of macros added to the source code.
Each element consists of one capital letter + an optional hex `num` in lower case.
Elements are written sequentially without any separator.

| Macro                | Emits       | Explanation                                             |
|----------------------|-------------|---------------------------------------------------------|
| `_FUNC(num)`         | `F` + `num` | Function call, use `num` to distinguish functions       |
| `_RETURN`            | `R`         | Function return                                         |
| `_IF`                | `T`         | The if-branch of an if-clause is taken                  |
| `_ELSE`              | `N`         | The else-branch of an if-clause is taken                |
| `_SWITCH(num)`       | `D` + `num` | Jump to case indicated with `num` in a switch-clause    |
| `_LOOP_START(id)`    |             | Beginning of a loop (for, while etc.)                   |
| `_LOOP_BODY(id)`     | `T`         | Loop iteration, nothing is emitted                      |
| `_LOOP_END(id)`      | `N`         | End of a loop, `num` indicates the number of iterations |
| `_TRACE_OPEN(fname)` |             | Initialize, write trace to file named `fname`           |
| `_TRACE_CLOSE`       | `F0`        | Close the cflow tracer                                  |

An example trace is `F2NF1TTNT`, which includes sub-traces, for example `F1TTN` or `TTN`.

Note that function number `0` is reserved, and `F0` simply markes the end of a trace
(as emmitted by `_TRACE_CLOSE`).

There was another variant which emitted `I` or `E` for if-clauses, and
`L` + (inner loop) + `P` + `num` for loops. A `P` + `num` can take logarithmically less
space then a sequence of `T` and `N`. However, we observed that the number
of loop iterations for most loops is not high enough to make it significant.
Moreover, a sequence of `T` and `N` can be stored more efficient in the binary trace format.

## Example `checksum.c`

* First run the pre-processor
  ```
  cd examples/
  cpp checksum.c -o checksum_inst.c
  ```
* Instrument it (the pre-processed version)
  ```
  python ../instrumenter.py checksum_inst.c
  ```
  For a list of functions together with the `num` generated by the instrumenter,
  have a look at the newly created `cflow_functions.db`.
* Add `src_tracer.h` and `src_tracer.c` to the examples directory:
  ```
  cp ../instrumentation/src_tracer.h .
  cp ../instrumentation/src_tracer.c .
  ```
### Recording
* Compile it with `_TRACE_MODE` (you might also want different compiler optimizations for recording/replaying)
  ```
  gcc -D_TRACE_MODE -O3 checksum_inst.c src_tracer.c -o checksum_trace
  ```
* Run it (replace `42` to get another trace) 
  ```
  ./checksum_trace 42
  ```
  The name of the recorded trace corresponds to the current time, e.g. `2023-04-28-143402-checksum.c.trace`.
* Display the trace (replace the trace name with the correct one!)
  ```
  python ../print_trace.py 2023-04-28-143402-checksum.c.trace
  ```
### Retracing
* Compile it with `_RETRACE_MODE` (you might also want different compiler optimizations for recording/replaying)
  ```
  gcc -D_RETRACE_MODE -g checksum_inst.c src_tracer.c -o checksum_retrace
  ```
* Retrace it (use `python -i` to work with the traced `state` in the interactive shell)
  ```
  python ../replay_trace.py checksum_retrace 2023-04-28-143402-checksum.c.trace
  echo "F1TTN" > sub.trace.txt
  python ../replay_trace.py checksum_retrace sub.trace.txt
  ```
  The last one just retraces function `checksum`.

## Busybox with musl-libc

Tested: busybox v1.34 and musl v1.2.3

* Set flags and configure musl:

  ```bash
  export SRC_TRACER_DIR=<path-to>/src-tracer/
  export CFLAGS="-Wno-error -O3 -L${SRC_TRACER_DIR}/instrumentation -no-integrated-cpp -B${SRC_TRACER_DIR}/cc_wrapper"
  export SRC_TRACER=""

  ./configure
  ```

* Patch musl: In `config.mak` add `-lsrc_tracer` to `LIBCC`.
In `src/string/strlen.c`, `src/string/strchrnul.c` and
`src/string/stpcpy.c` replace `#ifdef __GNUC__` by `#if false`.
The latter is a workaround for angr to ignore address alignments (see angr/angr#3883).

* Make (text trace mode) and install:
  ```bash
  export SRC_TRACER="-D_TRACE_MODE"
  make
  sudo make install
  ```

* Follow steps 2 and 3 from https://www.openwall.com/lists/musl/2014/08/08/13
to configure busybox to compile statically linked against musl.

* Before you run `make`, add `src_tracer` to the `CONFIG_EXTRA_LDLIBS`
in `.config`:

  ```
  CONFIG_EXTRA_LDLIBS="src_tracer"
  ```

* Run:

  ```bash
  make
  ```

  When you get a lot of

  ```
  warning: ISO C90 forbids mixed declarations and code [-Wdeclaration-after-statement]
  ```
  then the instrumatation is working as it should! You could silent these by
  commenting out the following line in `Makefile.flags`:
  ```
  CFLAGS += $(call cc-option,-Wdeclaration-after-statement,)
  ```
  Note that the instrumentation might fail at any point due to
  a known issue [#30](https://github.com/lks9/src-tracer/issues/30).
  As workaround simply start `make` again until it succeeds.

* Once we compiled it successfully, you don't need the stripped version.
  So just rename:

  ```bash
  mv busybox_unstripped busybox_trace
  ```

* Et voila!

* To record some trace:

  ```bash
  ./busybox_trace echo hello
  ```

  The trace will be somewhere, in my case `~/.src_tracer/2023-04-28-153959-appletlib.c.trace`.

* Print the trace into a file:

  ```bash
  ${SRC_TRACER_DIR}/print_trace.py ~/.src_tracer/2023-04-28-153959-appletlib.c.trace > ~/.src_tracer/echo.trace.txt
  ```

* Now we are back to compile musl in retrace mode (same `CFLAGS` but with `-mbranch-cost=5` to the maximum
  because state splitting _really_ slows down retracing):

  ```bash
  export SRC_TRACER_DIR=<path-to>/src-tracer/
  export CFLAGS="-Wno-error -O3 -mbranch-cost=5 -L${SRC_TRACER_DIR}/instrumentation -no-integrated-cpp -B${SRC_TRACER_DIR}/cc_wrapper"
  export SRC_TRACER=""
  ./configure
  ```
  Then in `config.mak` add `-lsrc_tracer` to `LIBCC`.
  ```bash
  export SRC_TRACER="-D_RETRACE_MODE"
  make clean
  make
  sudo make install
  ```

* Compile busybox in retrace mode:

  ```bash
  make clean
  make
  mv busybox_unstripped busybox_retrace
  ```

* Replay trace:

  ```bash
  ${SRC_TRACER_DIR}/replay_trace.py busybox_retrace ~/.src_tracer/echo.trace.txt
  ```

  Retracing took 42 min on my computer.

## Other Software

You can do it manually as for the `checksum.c` example.

For a more automatic way that works well with make scripts, make use of `cc_wrapper/`.
As a prerequesite, you also need `libsrc_tracer.a`. Build `libsrc_tracer.a` using `make` in the `instrumentation` folder:

```
  cd instrumentation
  make
```

### Recording
* Set some envirenmental variables. There are some variations, for example you might also add `-save-temps` to `CFLAGS`.
```
  export SRC_TRACER_DIR=.........
  export CC="gcc"
  export CFLAGS="-Wno-error -L${SRC_TRACER_DIR}/instrumentation -no-integrated-cpp -B${SRC_TRACER_DIR}/cc_wrapper"
  export LIBS="-lsrc_tracer"
  export SRC_TRACER=""
```
* Now you can ./configure your project...
* You can copy the build directory here, if you want to reuse the configuration for retracing.
* Before the actual compilation:
```
  export SRC_TRACER="-D_TRACE_MODE"
```
* Then build your project with make, gcc, whatever

### Retracing
* Copy the `cflow_functions.json` from the recording step.
* Same envirenmental variables as before. Only if you want to change some variables (e.g. `CFLAGS` with `-g`) make sure
to set `SRC_TRACER_INSTRUMENT=` (as empty string) before you `./configure` your project again.
* Before the actual compilation:
```
  export SRC_TRACER="-D_RETRACE_MODE"
```
* Then build your project with make, gcc, whatever

It can be a bit tricky to get the binary linking correctly,
make sure that the record/replay executable includes the record/replay
version of the app and its libraries.

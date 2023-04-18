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
3. Add a wrapper for the main function to call `_trace_open` and `_trace_close`.

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
| `_RETURN`            | `R`         | Function return                                         |
| `_IF`                | `T`         | The if-branch of an if-clause is taken                  |
| `_ELSE`              | `N`         | The else-branch of an if-clause is taken                |
| `_SWITCH(num)`       | `D` + `num` | Jump to case indicated with `num` in a switch-clause    |
| `_LOOP_START(id)`    |             | Beginning of a loop (for, while etc.)                   |
| `_LOOP_BODY(id)`     | `T`         | Loop iteration, nothing is emitted                      |
| `_LOOP_END(id)`      | `N`         | End of a loop, `num` indicates the number of iterations |
| `_trace_open(fname)` |             | Initialize, write trace to file named `fname`           |
| `_trace_close()`     | `F0`        | Close the cflow tracer                                  |

An example trace is `F2NF1TTNT`, which includes sub-traces, for example `F1TTN` or `TTN`.

Note that function number `0` is reserved, and `F0` simply markes the end of a trace
(as emmitted by `_trace_close()`).

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
  have a look at the newly created `cflow_functions.json`.
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
* Display the trace
  ```
  python ../print_trace.py checksum_inst.c.trace
  ```
### Retracing
* Compile it with `_RETRACE_MODE` (you might also want different compiler optimizations for recording/replaying)
  ```
  gcc -D_RETRACE_MODE -g checksum_inst.c src_tracer.c -o checksum_retrace
  ```
* Retrace it (use `python -i` to work with the traced `state` in the interactive shell)
  ```
  python ../replay_trace.py checksum_retrace main checksum_inst.c.trace
  echo "F1TTN" > sub.trace.txt
  python ../replay_trace.py checksum_retrace checksum sub.trace.txt
  ```
  The last one just retraces function `checksum`.

## Busybox with musl-libc

Tested: busybox ... and musl v1.2.3

* Set flags and configure musl:

```bash
  export SRC_TRACER_DIR=<path-to>/src-tracer/
  export CFLAGS="-Wno-error -L${SRC_TRACER_DIR}/instrumentation -no-integrated-cpp -B${SRC_TRACER_DIR}/cc_wrapper"
  export SRC_TRACER=""

  ./configure
```

* Patch musl: In `config.mak` add `-lsrc_tracer` to `LIBCC`.
In `src/string/strlen.c`, `src/string/strchrnul.c` and
`src/string/stpcpy.c` replace `#ifdef __GNUC__` by `#if false`.
The latter is a workaround for angr to ignore address alignments (see angr/angr#3883).

* Make (text trace mode) and install:
```bash
  export SRC_TRACER="-D_TEXT_TRACE_MODE"
  make
  sudo make install
```

* Copy the generated `cflow_file.json` to the busybox dirctory:

```bash
cd ..
  cp musl/cflow_file.json busybox/cflow_file.json
  cd busybox
```

* Follow step 2 from https://www.openwall.com/lists/musl/2014/08/08/13
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
then the instrumatation is working as it should!

* Once we compiled it successfully, you don't need the stripped version.
So just rename:

```bash
  mv busybox_unstripped busybox
```

* Et voila!

* To record some trace:

```bash
  ./busybox echo hello
```

The trace will be somewhere, in my case `/tmp/ccQacmv1.i.trace.txt`.

* Print the trace into a file:

```bash
  ${SRC_TRACER_DIR}/print_trace.py /tmp/ccQacmv1.i.trace.txt > echo.trace.txt
```

* Replay trace:

```bash
  ${SRC_TRACER_DIR}/replay_text_trace.py busybox main echo.trace.txt
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
  export CFLAGS="-Wno-error -O0 -L${SRC_TRACER_DIR}/instrumentation -no-integrated-cpp -B${SRC_TRACER_DIR}/cc_wrapper"
  export LIBS="-lsrc_tracer"
  export SRC_TRACER_INSTRUMENT=
```
* Now you can ./configure your project...
* You can copy the build directory here, if you want to reuse the configuration for retracing.
* Before the actual compilation:
```
  export SRC_TRACER_INSTRUMENT=_TRACE_MODE
```
* Then build your project with make, gcc, whatever

### Retracing
* Copy the `cflow_functions.json` from the recording step.
* Same envirenmental variables as before. Only if you want to change some variables (e.g. `CFLAGS` with `-g`) make sure
to set `SRC_TRACER_INSTRUMENT=` (as empty string) before you `./configure` your project again.
* Before the actual compilation:
```
  export SRC_TRACER_INSTRUMENT=_RETRACE_MODE
```
* Then build your project with make, gcc, whatever

If you instrument an application and together with dependent libraries, make
sure they share the same `cflow_functions.json` (e.g. by copying or using a
file link). It can be a bit tricky to get the binary linking correctly,
make sure that the record/replay executable includes the record/replay
version of the app and its libraries.

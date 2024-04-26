# Maxbuggy example

* `maxbuggy.c` (uninstrumented, buggy version)
* `maxbuggy_assert.c` (uninstrumented with assertion, buggy version)
* `maxfixed_assert.c` (uninstrumented with assertion, fixed version)
* `random_arrarys.h` (100 random-generated input arrays for max)

## Prerequisites

See installation instructions in top-level README.md.

## Compilation

* First run the pre-processor
  ```
  cpp -I../../include maxbuggy_assert.c -o maxbuggy_instru.c
  ```
* Instrument it (the pre-processed version)
  ```
  ../../instrumenter.py maxbuggy_instru.c --record max --close
  ```
* Compile for recording with `_TRACE_MODE`
  ```
  gcc -D_TRACE_MODE -O3 -I../../include -L../../lib maxbuggy_instru.c -o maxbuggy_trace -lsrc_tracer
  ```
* Compile for retracing it with `_RETRACE_MODE`
  ```
  gcc -D_RETRACE_MODE -O3 -I../../include -L../../lib maxbuggy_instru.c -o maxbuggy_retrace -lsrc_tracer
  ```

## Recording
  ```
  ./maxbuggy_trace
  ```
  Now there should be 100 `*maxbuggy_assert.c.trace` files containing traces.

## Retro Assertion Checking
  Don't ask me why `CONSERVATIVE_...` is needed here.
  ```
  ../../retrace.py maxbuggy_retrace xxxx.maxbuggy_assert.c.trace --remove-options CONSERVATIVE_READ_STRATEGY CONSERVATIVE_WRITE_STRATEGY --assertions
  ```
  Replace `xxxx` with the filename of the trace. You can also evaluate it in a for loop:
  ```
  for file in *maxbuggy_assert.c.trace;
      do ../../retrace.py maxfixed_retrace $file --remove-options CONSERVATIVE_READ_STRATEGY CONSERVATIVE_WRITE_STRATEGY --assertions;
  done
  ```
  The result should look like this:
```
DEBUG    | src_tracer.retrace | Starting with function "max"
DEBUG    | src_tracer.retrace | F1 max --count 0
DEBUG    | src_tracer.retrace | T
DEBUG    | src_tracer.retrace | N
DEBUG    | src_tracer.retrace | T
DEBUG    | src_tracer.retrace | T
DEBUG    | src_tracer.retrace | N
DEBUG    | src_tracer.retrace | Assertion "maxbuggy_assert.c:14" with index 0
DEBUG    | src_tracer.retrace | Assertion "maxbuggy_assert.c:14" with index 0
DEBUG    | src_tracer.retrace | Assertion "maxbuggy_assert.c:14" with index 0
DEBUG    | src_tracer.retrace | R --count 2 (found 3)
WARNING  | src_tracer.retrace | Could not find T at all in simgr <SimulationManager with 3 deadended>
DEBUG    | src_tracer.retrace | Assertion "maxbuggy_assert.c:14": PASSED
DEBUG    | src_tracer.retrace | Assertion "maxbuggy_assert.c:14": VIOLATED
DEBUG    | src_tracer.retrace | Assertion "maxbuggy_assert.c:14": PASSED

Final assertion check result: POSSIBLY_VIOLATED
```

  Or like this:
```
DEBUG    | src_tracer.retrace | Starting with function "max"
DEBUG    | src_tracer.retrace | F1 max --count 0
DEBUG    | src_tracer.retrace | T
DEBUG    | src_tracer.retrace | N
DEBUG    | src_tracer.retrace | T
DEBUG    | src_tracer.retrace | N
DEBUG    | src_tracer.retrace | N
DEBUG    | src_tracer.retrace | Assertion "maxbuggy_assert.c:14" with index 0
DEBUG    | src_tracer.retrace | R --count 2
WARNING  | src_tracer.retrace | Could not find T at all in simgr <SimulationManager with 1 deadended>
DEBUG    | src_tracer.retrace | Assertion "maxbuggy_assert.c:14": PASSED

Final assertion check result: PASSED
```

## Definite Results when Recording More
It happens that the symbolic execution splits while evaluating the assertion
and that the assertion is violated on some paths, while satisfied on the others.
We call such assertion check result `POSSIBLY_VIOLATED`.
In these cases, we don't know which execution path corresponds to the program
run we recorded and whether the assertion would be passed or violated on that
program run.

How to be sure about actual violations? By starting to record the `proc()`
instead of the `max()` function, the recorded traces get a bit longer. To do this, redo all
the compilation steps but with `--record proc` instead of `--record max`:
```
../../instrumenter.py maxbuggy_instru.c --record max
```
Before executing
```
./maxbuggy_trace
```
it might be wise to remove all the old `*maxbuggy_assert.c.trace` files.
But as the file names depend on the current time, you might do as you like.

For the new trace recordings, most of the assertion check results should
either be `PASSED` or `VIOLATED`:
```
DEBUG    | src_tracer.retrace | Starting with function "proc"
DEBUG    | src_tracer.retrace | F2 proc --count 0
DEBUG    | src_tracer.retrace | F1 max --count 1
DEBUG    | src_tracer.retrace | T
DEBUG    | src_tracer.retrace | N
DEBUG    | src_tracer.retrace | T
DEBUG    | src_tracer.retrace | T
DEBUG    | src_tracer.retrace | N
DEBUG    | src_tracer.retrace | Assertion "maxbuggy_assert.c:14" with index 0
DEBUG    | src_tracer.retrace | Assertion "maxbuggy_assert.c:14" with index 0
DEBUG    | src_tracer.retrace | Assertion "maxbuggy_assert.c:14" with index 0
DEBUG    | src_tracer.retrace | R --count 3 (found 3)
DEBUG    | src_tracer.retrace | T (found 3)
DEBUG    | src_tracer.retrace | T (found 3)
DEBUG    | src_tracer.retrace | T (found 2)
DEBUG    | src_tracer.retrace | T
DEBUG    | src_tracer.retrace | N
DEBUG    | src_tracer.retrace | R --count 5
WARNING  | src_tracer.retrace | Could not find T at all in simgr <SimulationManager with 1 deadended>
DEBUG    | src_tracer.retrace | Assertion "maxbuggy_assert.c:14": VIOLATED

Final assertion check result: VIOLATED
```

So instead of `POSSIBLE_...` we get the definite result, because two symbolic
execution paths with assertion result `PASSED` in `max()` get unsatisfiable
later with the recorded trace in `proc()`.

## Fixed Version

Now, do the same (instrumentation, compiling, recording, retro assertion checking)
with `maxfixed_assert.c`. There, the bug is fixed, and there are no longer any assertion
violations or `POSSIBLY_VIOLATED` results.

## Results

| Version                     | buggy | buggy  | fixed | fixed  |
|-----------------------------|-------|--------|-------|--------|
| Subtrace of                 |`max()`|`proc()`|`max()`|`proc()`|
| Trace count                 |  100  |  100   |  100  |  100   |
| Assertion passed            |   48  |   88   |  100  |  100   |
| Assertion possibly violated |   52  |    2   |    0  |    0   |
| Assertion violated          |    0  |   10   |    0  |    0   |

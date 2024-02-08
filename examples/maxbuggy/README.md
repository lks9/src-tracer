# Maxbuggy example

* `maxbuggy.c` (uninstrumented)
* `maxbuggy_assert.c` (uninstrumented with assertion)

## Compilation

* First run the pre-processor
  ```
  cpp -I../../include maxbuggy_assert.c -o maxbuggy_instru.c
  ```
* Instrument it (the pre-processed version)
  ```
  ../../instrumenter.py maxbuggy_instru.c --record max
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

Final assertion check result: UNSURE
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

In the first case, the symbolic execution splits while evaluting the assertion.
On one of the three states, the assertion is violated. But as we don't know which
state corresponds to the program run we recorded, the result is `UNSURE`.

Now, do the same (instrumentation, compiling, recording, retro assertion checking)
with `maxfixed_assert.c`. There, the bug is fixed, and there are no longer any assertion
violations or `UNSURE` results.

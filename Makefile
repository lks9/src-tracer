all: lib/libsrc_tracer.a

lib/libsrc_tracer.a: lib/src_tracer/trace_buf.o lib/src_tracer/common.o lib/src_tracer/retrace_mode.o
	ar rcs $@ $^

lib/src_tracer/trace_buf.i: lib/src_tracer/trace_buf.c lib/src_tracer/syscalls.h include/src_tracer/constants.h include/src_tracer/trace_elem.h include/src_tracer/trace_buf.h include/src_tracer/mode_common.h include/src_tracer/trace_mode.h include/src_tracer/ghost.h
	gcc -E -Wall -fPIC -Iinclude -c -nostdlib -O0 -o $@ $<

lib/src_tracer/trace_buf.o: lib/src_tracer/trace_buf.i
	gcc -Wall -fPIC -c -nostdlib -O3 -o $@ $<

lib/src_tracer/common.i: lib/src_tracer/common.c include/src_tracer/constants.h include/src_tracer/mode_common.h include/src_tracer/ghost.h
	gcc -E -Wall -fPIC -Iinclude -c -nostdlib -O0 -o $@ $<

lib/src_tracer/common.o: lib/src_tracer/common.i
	gcc -Wall -fPIC -c -nostdlib -O3 -o $@ $<

lib/src_tracer/retrace_mode.i: lib/src_tracer/retrace_mode.c include/src_tracer/constants.h include/src_tracer/mode_common.h include/src_tracer/retrace_mode.h include/src_tracer/ghost.h
	gcc -E -Wall -fPIC -Iinclude -c -nostdlib -O0 -o $@ $<

lib/src_tracer/retrace_mode.o: lib/src_tracer/retrace_mode.i
	gcc -Wall -fPIC -c -nostdlib -O3 -o $@ $<

clean:
	rm -f lib/*.o lib/*.a lib/*.i lib/src_tracer/*.o lib/src_tracer/*.i

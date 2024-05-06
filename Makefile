all: lib/libsrc_tracer.a

lib/libsrc_tracer.a: lib/src_tracer.o
	ar rcs $@ $^

lib/src_tracer.i: lib/src_tracer.c include/src_tracer/constants.h include/src_tracer/trace_elem.h include/src_tracer/trace_buf.h include/src_tracer/mode_common.h include/src_tracer/trace_mode.h include/src_tracer/retrace_mode.h include/src_tracer/ghost.h
	gcc -E -Wall -fPIC -Iinclude -c -nostdlib -O0 -o $@ $<

lib/src_tracer.o: lib/src_tracer.i
	gcc -Wall -fPIC -c -nostdlib -O3 -o $@ $<

clean:
	rm -f lib/*.o lib/*.a lib/*.i

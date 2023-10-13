all: lib/libsrc_tracer.a lib/byte_to_bit_trace

lib/libsrc_tracer.a: lib/src_tracer.o lib/mmap_to_trace.o
	ar rcs $@ $^

lib/src_tracer.i: lib/src_tracer.c include/src_tracer/_after_instrument.h include/src_tracer/ghost.h
	gcc -E -Wall -fPIC -Iinclude -c -nostdlib -O0 -o $@ $<

lib/src_tracer.o: lib/src_tracer.i
	gcc -Wall -fPIC -c -nostdlib -O3 -o $@ $<

lib/byte_to_bit_trace: lib/byte_to_bit_trace.c
	gcc -fwhole-program -Wall -Iinclude -O3 -o $@ $<

lib/mmap_to_trace.o: lib/mmap_to_trace.c
	gcc -Wall -fPIC -c -Iinclude -O3 -o $@ $<

clean:
	rm -f lib/*.o lib/*.a

TARGET = lib/libsrc_tracer.a

$(TARGET): lib/src_tracer.o
	ar rcs $@ $^

lib/src_tracer.i: lib/src_tracer.c include/src_tracer/_after_instrument.h include/src_tracer/ghost.h
	gcc -E -Wall -fPIC -Iinclude -c -nostdlib -O0 -o $@ $<

lib/src_tracer.o: lib/src_tracer.i
	gcc -Wall -fPIC -c -nostdlib -O3 -o $@ $<

clean:
	rm -f *.o *.a
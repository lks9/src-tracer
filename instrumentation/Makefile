TARGET = libsrc_tracer.a

$(TARGET): src_tracer.o
	ar rcs $@ $^

src_tracer.i: src_tracer.c src_tracer.h src_tracer_ghost.h
	gcc -E -Wall -fPIC -c -nostdlib -O0 -o $@ $<

src_tracer.o: src_tracer.i
	gcc -Wall -fPIC -c -nostdlib -O3 -o $@ $<

clean:
	rm -f *.o *.a

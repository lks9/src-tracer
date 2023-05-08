TARGET = libsrc_tracer.a

$(TARGET): src_tracer.o
	ar rcs $@ $^

src_tracer.o: src_tracer.c src_tracer.h
	gcc -Wall -g -fPIC -c -nostdlib -O0 -o $@ $<

clean:
	rm -f *.o *.a

TARGET = libsrc_tracer.a

$(TARGET): src_tracer.o
	ar rcs $@ $^

src_tracer.o: src_tracer.c
	gcc -fPIC -c -nostdlib -o $@ $<

clean:
	rm -f *.o *.a

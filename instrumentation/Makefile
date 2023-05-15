TARGET = libsrc_tracer.a

$(TARGET): src_tracer.o
	ar rcs $@ $^

src_tracer.o: src_tracer.c src_tracer.h
	gcc -Wall -O3 -DEFFICIENT_TEXT_TRACE -fPIC -c -nostdlib -o $@ $<

clean:
	rm -f *.o *.a

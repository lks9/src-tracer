int foo(int i) {
    if (0) /* nothing here */;
    return i;
}

int (*ptr)(int) = *foo;

typedef int (*function_ptr)(int);

function_ptr meta (void) {
    if (1) /* nothing here */;
    return ptr;
}

int main(void) {
    ptr(1);
    ptr(ptr(1));
    foo(ptr(1));
    ptr(foo(1));
    meta()(1);
    meta()(foo(1));
}

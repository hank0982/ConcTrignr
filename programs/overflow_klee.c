#include <stdio.h>

int check(char* s) {
    int a = 2147483640;
    int c = 3;
    int b = atoi(s);

    if (c * b < 0 && b > 0)
        return 1;
    else if (a + b < 0 && b > 0)
        return 2;
    else
        return 0;
}

int main(int argc, char** argv) {
    char i[11];

    klee_make_symbolic(&i, sizeof(i), "i");
    klee_assume(i[10] == '\0');

    return check(i);
}

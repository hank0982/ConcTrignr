#include <stdio.h>

int check(char* s) {
    int a[] = {1, 2, 3, 4, 5, 6};
    int i = atoi(s);

    if (a[i] > 6) {
        a[i] = 1;
        return 1;
    }
    else {
        return 0;
    }
}

int main(int argc, char** argv) {
    char i[2];
    klee_make_symbolic(&i, sizeof(i), "i");
    klee_assume(i[1] == '\0');

    return check(i);
}

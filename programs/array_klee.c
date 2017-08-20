#include <stdio.h>

int check(int i) {
    int a[] = {1, 2, 3, 4, 5, 6};

    if (a[i] > 6) {
        a[i] = 0;
        return 1;
    }
    else {
        a[i] = 1;
        return 0;
    }
}

int main() {
    int i;
    klee_make_symbolic(&i, sizeof(i), "i");
    return check(i);
}

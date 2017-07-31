#include <stdio.h>

int main(int argc, char**argv) {
    int a[] = {1, 2, 3, 4, 5, 6};
    int i = atoi(argv[1]);

    printf("%d\n", a[i]);

    if (i >= 0 && i < 6 && a[i] > 6) {
        // a[i] = 0;
        return 1;
    }
    else {
        // a[i] = 1;
        return 0;
    }
}
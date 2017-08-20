#include <stdio.h>

int check(int i) {
    int a[] = {1, 2, 3, 4, 5, 6};

    if (a[i] > 6) {
        a[i] = 1;
        return 1;
    }
    else {
        return 0;
    }

}

int main(int argc, char**argv) {
    int i = atoi(argv[1]);

    return check(i);
}
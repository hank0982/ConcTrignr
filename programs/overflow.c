#include <stdio.h>

int check(int b) {
    int a = 2147483640;
    int c = 3;

    if (c * b < 0 && b > 0)
        return 1;
    else if (a + b < 0 && b > 0)
        return 2;
    else
        return 0;
}

int main(int argc, char** argv) {
    int i = atoi(argv[1]);

    return check(i);
}

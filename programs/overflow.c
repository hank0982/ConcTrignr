#include <stdio.h>

int main(int argc, char** argv) {
    int a = 2147483640;
    int b = atoi(argv[1]);
    int c = 3;

    // if (a + b < 0 && b > 0)
    //     return 2;
    // else
    if (c * b < 0 && b > 0)
        return 1;
    else if (a + b < 0 && b > 0)
        return 2;
    else
        return 0;
}

#include <stdio.h>

int check(int b, int a) {
    if (b > 0 && 2 * b < 0)
        return 1;
    else
        return 0;
}

int main(int argc, char** argv) {
    printf("In main\n");
    int i = atoi(argv[1]);

    printf("%d\n", i);

    return check(i, 0);
}
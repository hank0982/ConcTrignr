int check(char* str) {
    int a[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    int i;

    if (a[i] > 4)
        return 1;
    else
        return 0;
}

int main(int argc, char**argv) {
    int a[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    int i = atoi(argv[1]);

    if (a[i] > 10)
        return 1;
    else
        return 0;
}
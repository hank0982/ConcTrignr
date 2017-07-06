int main(int argc, char**argv) {
    int a[] = {1, 2, 3, 4, 5, 6};

    if (argc != 2)
        return -1;

    int index = atoi(argv[1]);
    int x = a[index];

    if (x > 3)
        return 0;
    else
        return 1;
}
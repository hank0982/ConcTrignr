#include <pthread.h>

void* inc(void* i) {
    // int* j = (int*)i;
    // *j += 1;
}

int main(int argc, char** argv) {
    pthread_t thread;
    int i = 1;
    int rc = pthread_create(&thread, NULL, inc, (void*)&i);

    rc = pthread_join(thread, NULL);

    return 0;
}
#include <pthread.h>
#include <time.h>
#include <unistd.h>


void* inc(void* i) {
    long long* j = (long long*)i;
    unsigned long start = (unsigned long)time(NULL);

    while ((unsigned long)time(NULL) - start < 2)
        *j += 1;
}

void* dec(void* i) {
    long long* j = (long long*)i;
    unsigned long start = (unsigned long)time(NULL);

    while ((unsigned long)time(NULL) - start < 2)
        *j -= 1;
}

int check(long long* i) {
    pthread_t thread1, thread2;
    int rc1 = pthread_create(&thread1, NULL, inc, (void*)i);
    int rc2 = pthread_create(&thread2, NULL, dec, (void*)i);
    int flag;

    sleep(1);
    printf("%lld", *i);

    if (*i > 0)
        flag = 1;
    else
        flag = 0;

    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);

    return flag;
}

int main(int argv, char** argc) {
    long long i;
    klee_make_symbolic(&i, sizeof(i), "i");
    return check(&i);
}
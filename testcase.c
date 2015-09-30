/*
 * A simple program that is not instrumented by American Fuzzy Lop, but behaves
 * as if it was.
 */

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/shm.h>

int main() {
    char* shmid_c = getenv("__AFL_SHM_ID");
    if (shmid_c == NULL) {
        printf("__AFL_SHM_ID not set.\n");
        exit(2);
    }
    int shmid = atoi(shmid_c);
    char* x = shmat(shmid, 0, 0);
    if (x == (char *)-1)
        exit(1);
    x[0] = 1;
    exit(0);
}

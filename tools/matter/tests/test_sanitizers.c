/* Deliberate failures, each executed in a separate process by run_tests.ps1. */
#include <limits.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    if (!strcmp(argv[1], "asan")) {
        volatile int* value = malloc(sizeof(*value));
        if (!value) return 2;
        *value = 7;
        int result = value[1]; /* Must produce heap-buffer-overflow. */
        free((void*)value);
        return result;
    }
    if (!strcmp(argv[1], "ubsan")) {
        volatile int value = INT_MAX;
        return value + 1; /* Must produce signed integer overflow. */
    }
    return 2;
}

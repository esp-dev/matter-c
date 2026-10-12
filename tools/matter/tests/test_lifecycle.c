#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include "matter.h"

#ifdef MATTER_TEST_ALLOC
#include "alloc.h"

static size_t live_allocations;
static size_t last_allocation_bytes;
static bool fail_next_allocation;

void* matter_test_calloc(size_t count, size_t size) {
    void* ptr;
    last_allocation_bytes = count * size;
    if (fail_next_allocation) {
        fail_next_allocation = false;
        return NULL;
    }
    ptr = calloc(count, size);
    if (ptr) ++live_allocations;
    return ptr;
}

void matter_test_free(void* ptr) {
    if (ptr) {
        if (!live_allocations) abort();
        --live_allocations;
    }
    free(ptr);
}
#endif

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s: %s\n", __FILE__, __LINE__, __func__, #condition); \
        goto done; \
    } \
} while (0)

typedef struct {
    Matter_T matter;
    unsigned calls;
    unsigned violations;
    Matter_State_T last_state;
    bool try_reentry;
} Observer;

static void state_changed(void* user, Matter_State_T state) {
    Observer* observer = user;
    ++observer->calls;
    observer->last_state = state;
    if (matter_get_state(observer->matter) != state) ++observer->violations;
    if (observer->try_reentry) {
        if (matter_start(observer->matter) != MATTER_BUSY) ++observer->violations;
        if (matter_stop(observer->matter) != MATTER_BUSY) ++observer->violations;
        if (matter_delete(observer->matter) != MATTER_BUSY) ++observer->violations;
        if (matter_get_state(observer->matter) != state) ++observer->violations;
    }
}

static void cleanup(Matter_T matter) {
    matter_stop(matter);
    matter_delete(matter);
}

static bool test_null_and_optional_port(void) {
    bool passed = false;
    Matter_T matter = NULL;
    Matter_Port_T empty_port = {0};
    CHECK(matter_get_state(NULL) == MATTER_STATE_INVALID);
    CHECK(matter_start(NULL) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_stop(NULL) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_delete(NULL) == MATTER_OK);
    matter = matter_new(NULL);
    CHECK(matter != NULL);
    CHECK(matter_get_state(matter) == MATTER_STATE_STOPPED);
    CHECK(matter_start(matter) == MATTER_OK);
    CHECK(matter_stop(matter) == MATTER_OK);
    CHECK(matter_delete(matter) == MATTER_OK);
    matter = matter_new(&empty_port);
    CHECK(matter != NULL);
    CHECK(matter_delete(matter) == MATTER_OK);
    matter = NULL;
    passed = true;
done:
    cleanup(matter);
    return passed;
}

static bool test_transitions_and_restart(void) {
    bool passed = false;
    Observer observer = {0};
    Matter_Port_T port = {&observer, state_changed};
    observer.matter = matter_new(&port);
    CHECK(observer.matter != NULL);
    CHECK(observer.calls == 0);
    CHECK(matter_stop(observer.matter) == MATTER_OK);
    CHECK(observer.calls == 0);
    CHECK(matter_start(observer.matter) == MATTER_OK);
    CHECK(observer.calls == 1 && observer.last_state == MATTER_STATE_RUNNING);
    CHECK(matter_start(observer.matter) == MATTER_OK);
    CHECK(observer.calls == 1);
    CHECK(matter_delete(observer.matter) == MATTER_INVALID_STATE);
    CHECK(matter_get_state(observer.matter) == MATTER_STATE_RUNNING);
    CHECK(observer.calls == 1);
    CHECK(matter_stop(observer.matter) == MATTER_OK);
    CHECK(observer.calls == 2 && observer.last_state == MATTER_STATE_STOPPED);
    CHECK(matter_stop(observer.matter) == MATTER_OK);
    CHECK(observer.calls == 2);
    CHECK(matter_start(observer.matter) == MATTER_OK);
    CHECK(observer.calls == 3 && observer.last_state == MATTER_STATE_RUNNING);
    CHECK(matter_stop(observer.matter) == MATTER_OK);
    CHECK(observer.calls == 4 && observer.last_state == MATTER_STATE_STOPPED);
    CHECK(observer.violations == 0);
    CHECK(matter_delete(observer.matter) == MATTER_OK);
    observer.matter = NULL;
    CHECK(observer.calls == 4);
    passed = true;
done:
    cleanup(observer.matter);
    return passed;
}

/* The port storage expires on return: only user belongs to the caller. */
static Matter_T create_observed(Observer* observer) {
    Matter_Port_T port = {observer, state_changed};
    return matter_new(&port);
}

static bool test_two_instances_and_port_copy(void) {
    bool passed = false;
    Observer first = {0}, second = {0};
    Matter_Port_T port = {&first, state_changed};
    first.matter = matter_new(&port);
    second.matter = create_observed(&second);
    CHECK(first.matter && second.matter && first.matter != second.matter);
    /* Mutating caller's port must not change the copy owned by first. */
    port.user = &second;
    port.state_changed = NULL;
    CHECK(matter_start(first.matter) == MATTER_OK);
    CHECK(first.calls == 1 && second.calls == 0);
    CHECK(matter_get_state(second.matter) == MATTER_STATE_STOPPED);
    CHECK(matter_start(second.matter) == MATTER_OK);
    CHECK(matter_stop(first.matter) == MATTER_OK);
    CHECK(first.calls == 2 && second.calls == 1);
    CHECK(matter_get_state(second.matter) == MATTER_STATE_RUNNING);
    CHECK(matter_delete(first.matter) == MATTER_OK);
    first.matter = NULL;
    CHECK(matter_stop(second.matter) == MATTER_OK);
    CHECK(matter_start(second.matter) == MATTER_OK);
    CHECK(matter_stop(second.matter) == MATTER_OK);
    CHECK(second.calls == 4 && second.last_state == MATTER_STATE_STOPPED);
    CHECK(first.violations == 0 && second.violations == 0);
    CHECK(matter_delete(second.matter) == MATTER_OK);
    second.matter = NULL;
    passed = true;
done:
    cleanup(first.matter);
    cleanup(second.matter);
    return passed;
}

static bool test_reentrant_mutation_rejected(void) {
    bool passed = false;
    Observer observer = {0};
    observer.try_reentry = true;
    observer.matter = create_observed(&observer);
    CHECK(observer.matter != NULL);
    CHECK(matter_start(observer.matter) == MATTER_OK);
    CHECK(observer.calls == 1 && observer.violations == 0);
    CHECK(matter_stop(observer.matter) == MATTER_OK);
    CHECK(observer.calls == 2 && observer.violations == 0);
    CHECK(matter_get_state(observer.matter) == MATTER_STATE_STOPPED);
    /* The rejected delete was not queued: caller still owns the context. */
    CHECK(matter_start(observer.matter) == MATTER_OK);
    CHECK(matter_stop(observer.matter) == MATTER_OK);
    CHECK(observer.calls == 4 && observer.violations == 0);
    CHECK(matter_delete(observer.matter) == MATTER_OK);
    observer.matter = NULL;
    passed = true;
done:
    cleanup(observer.matter);
    return passed;
}

static bool test_repeated_lifecycle(void) {
    bool passed = false;
    Matter_T matter = NULL;
    for (unsigned i = 0; i < 1000; ++i) {
        matter = matter_new(NULL);
        CHECK(matter != NULL);
        for (unsigned restart = 0; restart < 3; ++restart) {
            CHECK(matter_start(matter) == MATTER_OK);
            CHECK(matter_get_state(matter) == MATTER_STATE_RUNNING);
            CHECK(matter_stop(matter) == MATTER_OK);
            CHECK(matter_get_state(matter) == MATTER_STATE_STOPPED);
        }
        CHECK(matter_delete(matter) == MATTER_OK);
        matter = NULL;
#ifdef MATTER_TEST_ALLOC
        CHECK(live_allocations == 0);
#endif
    }
    passed = true;
done:
    cleanup(matter);
    return passed;
}

#ifdef MATTER_TEST_ALLOC
static void pool_cancel(void* user, Matter_Operation_Id_T id) {
    unsigned* cancels = user;
    (void)id;
    ++*cancels;
}

static bool test_pool_no_allocations(void) {
    bool passed = false;
    Matter_T matter = matter_new(NULL);
    Matter_Operation_Id_T ids[MATTER_OPERATION_CAPACITY] = {0};
    unsigned cancels = 0;
    Matter_Operation_Port_T port = {&cancels, pool_cancel, NULL};
    CHECK(matter && live_allocations == 1);
    printf("Matter context allocation: %zu bytes\n", last_allocation_bytes);
    CHECK(matter_start(matter) == MATTER_OK);
    fail_next_allocation = true;
    for (size_t i = 0; i < MATTER_OPERATION_CAPACITY; ++i)
        CHECK(matter_operation_begin(matter, &port, &ids[i]) == MATTER_OK);
    CHECK(matter_stop(matter) == MATTER_PENDING && cancels == MATTER_OPERATION_CAPACITY);
    for (size_t i = 0; i < MATTER_OPERATION_CAPACITY; ++i) {
        CHECK(matter_operation_complete(matter, ids[i], MATTER_OPERATION_CANCELLED) == MATTER_OK);
        ids[i] = 0;
    }
    CHECK(fail_next_allocation && live_allocations == 1);
    CHECK(matter_delete(matter) == MATTER_OK);
    matter = NULL;
    CHECK(live_allocations == 0);
    passed = true;
done:
    fail_next_allocation = false;
    matter_stop(matter);
    for (size_t i = 0; i < MATTER_OPERATION_CAPACITY; ++i)
        if (ids[i]) matter_operation_complete(matter, ids[i], MATTER_OPERATION_CANCELLED);
    cleanup(matter);
    return passed;
}

static bool test_allocation_failure_and_recovery(void) {
    bool passed = false;
    Observer first = {0}, second = {0};
    first.matter = create_observed(&first);
    CHECK(first.matter != NULL);
    CHECK(matter_start(first.matter) == MATTER_OK);
    CHECK(live_allocations == 1);
    fail_next_allocation = true;
    second.matter = create_observed(&second);
    CHECK(second.matter == NULL && !fail_next_allocation);
    CHECK(second.calls == 0 && live_allocations == 1);
    CHECK(matter_get_state(first.matter) == MATTER_STATE_RUNNING);
    CHECK(first.calls == 1);
    second.matter = create_observed(&second);
    CHECK(second.matter != NULL && live_allocations == 2);
    CHECK(matter_start(second.matter) == MATTER_OK);
    CHECK(matter_stop(second.matter) == MATTER_OK);
    CHECK(matter_delete(second.matter) == MATTER_OK);
    second.matter = NULL;
    CHECK(live_allocations == 1);
    CHECK(matter_stop(first.matter) == MATTER_OK);
    CHECK(matter_delete(first.matter) == MATTER_OK);
    first.matter = NULL;
    CHECK(live_allocations == 0);
    CHECK(first.violations == 0 && second.violations == 0);
    passed = true;
done:
    fail_next_allocation = false;
    cleanup(first.matter);
    cleanup(second.matter);
    return passed;
}
#endif

int main(void) {
    const struct { const char* name; bool (*run)(void); } tests[] = {
        {"null and optional port", test_null_and_optional_port},
        {"transitions and restart", test_transitions_and_restart},
        {"two instances and port copy", test_two_instances_and_port_copy},
        {"reentrant mutation rejected", test_reentrant_mutation_rejected},
        {"repeated lifecycle", test_repeated_lifecycle},
#ifdef MATTER_TEST_ALLOC
        {"allocation failure and recovery", test_allocation_failure_and_recovery},
        {"pool has no per-operation allocation", test_pool_no_allocations},
#endif
    };
    unsigned failures = 0;
    const size_t count = sizeof(tests) / sizeof(tests[0]);
    for (size_t i = 0; i < count; ++i) {
        bool passed = tests[i].run();
#ifdef MATTER_TEST_ALLOC
        if (live_allocations) {
            fprintf(stderr, "Unreleased lifecycle allocations: %zu\n", live_allocations);
            passed = false;
        }
#endif
        printf("%s lifecycle: %s\n", passed ? "PASS" : "FAIL", tests[i].name);
        if (!passed) ++failures;
    }
    printf("%zu/%zu lifecycle tests passed\n", count - failures, count);
    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}

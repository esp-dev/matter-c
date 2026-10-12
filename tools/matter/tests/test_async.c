#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include "matter.h"

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s: %s\n", __FILE__, __LINE__, __func__, #condition); \
        goto done; \
    } \
} while (0)

/* Single backend request, not an mDNS implementation or a production queue.
 * Queued test events carry IDs, never copies of the core pointer. The backend
 * routing target is detached before terminal delivery, and can outlive owner.
 */
typedef struct {
    Matter_T owner;
    Matter_T target;
    Matter_Operation_Id_T id;
    Matter_Operation_Id_T other_id;
    unsigned cancels, completions, states, violations;
    Matter_Operation_Result_T result;
    Matter_State_T completion_state, last_state;
} Fake;

static void cancel(void* user, Matter_Operation_Id_T id);

static void probe_reentry(Fake* fake) {
    Matter_Operation_Id_T id = 77;
    Matter_Operation_Port_T port = {fake, cancel, NULL};
    if (matter_start(fake->owner) != MATTER_BUSY) ++fake->violations;
    if (matter_stop(fake->owner) != MATTER_BUSY) ++fake->violations;
    if (matter_delete(fake->owner) != MATTER_BUSY) ++fake->violations;
    if (matter_operation_begin(fake->owner, &port, &id) != MATTER_BUSY || id != 77)
        ++fake->violations;
    if (matter_operation_cancel(fake->owner, fake->id) != MATTER_BUSY) ++fake->violations;
    if (matter_operation_complete(fake->owner, fake->id, MATTER_OPERATION_SUCCEEDED) != MATTER_BUSY)
        ++fake->violations;
    if (fake->other_id) {
        if (matter_operation_cancel(fake->owner, fake->other_id) != MATTER_BUSY) ++fake->violations;
        if (matter_operation_complete(fake->owner, fake->other_id, MATTER_OPERATION_FAILED) != MATTER_BUSY)
            ++fake->violations;
    }
}

static void changed(void* user, Matter_State_T state) {
    Fake* fake = user;
    ++fake->states;
    fake->last_state = state;
    if (matter_get_state(fake->owner) != state) ++fake->violations;
    probe_reentry(fake);
}

static void cancel(void* user, Matter_Operation_Id_T id) {
    Fake* fake = user;
    ++fake->cancels;
    if (id != fake->id || !fake->target) ++fake->violations;
    /* No inline completion, even if the underlying backend cancels at once. */
    probe_reentry(fake);
}

static void completed(void* user, Matter_Operation_Id_T id, Matter_Operation_Result_T result) {
    Fake* fake = user;
    ++fake->completions;
    fake->result = result;
    fake->completion_state = matter_get_state(fake->owner);
    if (id != fake->id || fake->target) ++fake->violations;
    probe_reentry(fake);
}

static bool create(Fake* fake) {
    Matter_Port_T port = {fake, changed};
    fake->owner = matter_new(&port);
    return fake->owner != NULL;
}

static Matter_Result_T submit(Fake* fake) {
    Matter_Operation_Port_T port = {fake, cancel, completed};
    Matter_Result_T result = matter_operation_begin(fake->owner, &port, &fake->id);
    if (result == MATTER_OK) fake->target = fake->owner;
    return result;
}

static bool deliver(Fake* fake, Matter_Operation_Id_T id, Matter_Operation_Result_T result) {
    if (!fake->target || id != fake->id) return false;
    Matter_T target = fake->target;
    fake->target = NULL; /* Drain routing BEFORE calling the core. */
    if (matter_operation_complete(target, id, result) != MATTER_OK) {
        fake->target = target;
        return false;
    }
    return true;
}

static void cleanup(Fake* fake) {
    matter_stop(fake->owner);
    if (fake->target && !deliver(fake, fake->id, MATTER_OPERATION_CANCELLED)) abort();
    if (matter_delete(fake->owner) != MATTER_OK) abort();
    fake->owner = NULL;
}

static bool test_validation(void) {
    bool passed = false;
    Fake fake = {0};
    Matter_Operation_Id_T id = 99;
    Matter_Operation_Port_T invalid = {0};
    Matter_Operation_Port_T port = {&fake, cancel, completed};
    CHECK(matter_operation_begin(NULL, &port, &id) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_operation_cancel(NULL, 1) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_operation_complete(NULL, 1, MATTER_OPERATION_FAILED) == MATTER_INVALID_ARGUMENT);
    CHECK(create(&fake));
    CHECK(matter_operation_begin(fake.owner, &port, &id) == MATTER_INVALID_STATE && id == 99);
    CHECK(matter_start(fake.owner) == MATTER_OK);
    CHECK(matter_operation_begin(fake.owner, NULL, &id) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_operation_begin(fake.owner, &invalid, &id) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_operation_begin(fake.owner, &port, NULL) == MATTER_INVALID_ARGUMENT);
    CHECK(id == 99 && fake.cancels == 0 && fake.completions == 0);
    CHECK(matter_operation_cancel(fake.owner, 0) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_operation_cancel(fake.owner, 1) == MATTER_INVALID_STATE);
    CHECK(submit(&fake) == MATTER_OK && fake.id != 0);
    CHECK(matter_operation_cancel(fake.owner, fake.id + 1) == MATTER_INVALID_STATE);
    CHECK(matter_operation_complete(fake.owner, 0, MATTER_OPERATION_SUCCEEDED) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_operation_complete(fake.owner, fake.id, (Matter_Operation_Result_T)99) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_operation_complete(fake.owner, fake.id + 1, MATTER_OPERATION_SUCCEEDED) == MATTER_INVALID_STATE);
    CHECK(fake.completions == 0 && fake.cancels == 0);
    CHECK(deliver(&fake, fake.id, MATTER_OPERATION_SUCCEEDED));
    CHECK(fake.completions == 1 && fake.violations == 0);
    passed = true;
done:
    cleanup(&fake);
    return passed;
}

static bool test_success_error_cancel_and_copy(void) {
    bool passed = false;
    Fake fake = {0};
    Matter_Operation_Port_T port = {&fake, cancel, completed};
    CHECK(create(&fake) && matter_start(fake.owner) == MATTER_OK);
    CHECK(matter_operation_begin(fake.owner, &port, &fake.id) == MATTER_OK);
    fake.target = fake.owner;
    port.user = NULL;
    port.cancel = NULL;
    port.completed = NULL;
    CHECK(matter_operation_cancel(fake.owner, fake.id) == MATTER_OK);
    CHECK(matter_operation_cancel(fake.owner, fake.id) == MATTER_OK);
    CHECK(fake.cancels == 1 && fake.completions == 0);
    CHECK(deliver(&fake, fake.id, MATTER_OPERATION_CANCELLED));
    CHECK(fake.completions == 1 && fake.result == MATTER_OPERATION_CANCELLED);
    CHECK(fake.completion_state == MATTER_STATE_RUNNING);
    CHECK(submit(&fake) == MATTER_OK);
    CHECK(deliver(&fake, fake.id, MATTER_OPERATION_FAILED));
    CHECK(fake.completions == 2 && fake.result == MATTER_OPERATION_FAILED);
    CHECK(submit(&fake) == MATTER_OK);
    CHECK(deliver(&fake, fake.id, MATTER_OPERATION_SUCCEEDED));
    CHECK(fake.completions == 3 && fake.result == MATTER_OPERATION_SUCCEEDED);
    CHECK(matter_operation_complete(fake.owner, fake.id, MATTER_OPERATION_FAILED) == MATTER_INVALID_STATE);
    CHECK(matter_operation_cancel(fake.owner, fake.id) == MATTER_INVALID_STATE);
    CHECK(fake.completions == 3 && fake.violations == 0);
    passed = true;
done:
    cleanup(&fake);
    return passed;
}

static bool test_stop_drains_and_restart_rejects_old_id(void) {
    bool passed = false;
    Fake fake = {0};
    Matter_Operation_Id_T old_id;
    CHECK(create(&fake) && matter_start(fake.owner) == MATTER_OK);
    CHECK(submit(&fake) == MATTER_OK);
    old_id = fake.id;
    CHECK(matter_stop(fake.owner) == MATTER_PENDING);
    CHECK(fake.last_state == MATTER_STATE_STOPPING && fake.states == 2);
    CHECK(matter_stop(fake.owner) == MATTER_PENDING && fake.cancels == 1);
    CHECK(matter_delete(fake.owner) == MATTER_INVALID_STATE);
    CHECK(matter_start(fake.owner) == MATTER_INVALID_STATE);
    CHECK(submit(&fake) == MATTER_INVALID_STATE && fake.id == old_id);
    CHECK(fake.completions == 0 && matter_get_state(fake.owner) == MATTER_STATE_STOPPING);
    CHECK(deliver(&fake, old_id, MATTER_OPERATION_CANCELLED));
    CHECK(fake.completion_state == MATTER_STATE_STOPPING);
    CHECK(fake.last_state == MATTER_STATE_STOPPED && fake.states == 3);
    CHECK(matter_stop(fake.owner) == MATTER_OK && fake.states == 3);
    CHECK(matter_start(fake.owner) == MATTER_OK);
    CHECK(submit(&fake) == MATTER_OK && fake.id > old_id);
    CHECK(!deliver(&fake, old_id, MATTER_OPERATION_SUCCEEDED));
    CHECK(matter_operation_complete(fake.owner, old_id, MATTER_OPERATION_SUCCEEDED) == MATTER_INVALID_STATE);
    CHECK(fake.completions == 1 && fake.target == fake.owner);
    CHECK(deliver(&fake, fake.id, MATTER_OPERATION_SUCCEEDED));
    CHECK(fake.completions == 2 && fake.violations == 0);
    passed = true;
done:
    cleanup(&fake);
    return passed;
}

static bool test_cancel_races_terminal_result(void) {
    bool passed = false;
    Fake fake = {0};
    const Matter_Operation_Result_T outcomes[] = {
        MATTER_OPERATION_SUCCEEDED, MATTER_OPERATION_FAILED, MATTER_OPERATION_CANCELLED
    };
    CHECK(create(&fake));
    for (size_t i = 0; i < sizeof(outcomes) / sizeof(outcomes[0]); ++i) {
        CHECK(matter_start(fake.owner) == MATTER_OK);
        CHECK(submit(&fake) == MATTER_OK);
        CHECK(matter_operation_cancel(fake.owner, fake.id) == MATTER_OK);
        CHECK(matter_stop(fake.owner) == MATTER_PENDING);
        CHECK(fake.cancels == i + 1);
        CHECK(deliver(&fake, fake.id, outcomes[i]));
        CHECK(fake.result == outcomes[i] && fake.completions == i + 1);
        CHECK(fake.completion_state == MATTER_STATE_STOPPING);
        CHECK(matter_get_state(fake.owner) == MATTER_STATE_STOPPED);
    }
    CHECK(fake.violations == 0);
    passed = true;
done:
    cleanup(&fake);
    return passed;
}

static bool test_two_instances_and_event_after_delete(void) {
    bool passed = false;
    Fake first = {0}, second = {0};
    Matter_Operation_Id_T late_event;
    CHECK(create(&first) && create(&second));
    CHECK(matter_start(first.owner) == MATTER_OK && matter_start(second.owner) == MATTER_OK);
    CHECK(submit(&first) == MATTER_OK && submit(&second) == MATTER_OK);
    late_event = first.id;
    CHECK(matter_stop(first.owner) == MATTER_PENDING);
    CHECK(first.cancels == 1 && second.cancels == 0);
    CHECK(matter_get_state(second.owner) == MATTER_STATE_RUNNING);
    CHECK(deliver(&first, late_event, MATTER_OPERATION_CANCELLED));
    CHECK(matter_delete(first.owner) == MATTER_OK);
    first.owner = NULL;
    /* Backend outlives the deleted context and safely discards a queued event. */
    CHECK(!deliver(&first, late_event, MATTER_OPERATION_SUCCEEDED));
    CHECK(first.completions == 1 && first.target == NULL);
    CHECK(second.completions == 0 && second.target == second.owner);
    CHECK(deliver(&second, second.id, MATTER_OPERATION_SUCCEEDED));
    CHECK(second.completions == 1);
    CHECK(first.violations == 0 && second.violations == 0);
    passed = true;
done:
    cleanup(&first);
    cleanup(&second);
    return passed;
}

static bool test_optional_completion(void) {
    bool passed = false;
    Fake fake = {0};
    Matter_Operation_Port_T port = {&fake, cancel, NULL};
    CHECK(create(&fake) && matter_start(fake.owner) == MATTER_OK);
    CHECK(matter_operation_begin(fake.owner, &port, &fake.id) == MATTER_OK);
    fake.target = fake.owner;
    CHECK(matter_stop(fake.owner) == MATTER_PENDING);
    CHECK(deliver(&fake, fake.id, MATTER_OPERATION_CANCELLED));
    CHECK(matter_get_state(fake.owner) == MATTER_STATE_STOPPED);
    CHECK(fake.completions == 0 && fake.cancels == 1 && fake.violations == 0);
    passed = true;
done:
    cleanup(&fake);
    return passed;
}

/* Multiple independent backend requests share one owner; fixture stays on heap. */
typedef struct { Fake observer, operations[MATTER_OPERATION_CAPACITY]; } Pool;

static Pool* pool_new(void) {
    Pool* pool = calloc(1, sizeof(*pool));
    if (!pool) return NULL;
    if (!create(&pool->observer)) { free(pool); return NULL; }
    for (size_t i = 0; i < MATTER_OPERATION_CAPACITY; ++i)
        pool->operations[i].owner = pool->observer.owner;
    return pool;
}

static void pool_delete(Pool* pool) {
    if (!pool) return;
    matter_stop(pool->observer.owner);
    for (size_t i = 0; i < MATTER_OPERATION_CAPACITY; ++i) {
        Fake* fake = &pool->operations[i];
        if (fake->target && !deliver(fake, fake->id, MATTER_OPERATION_CANCELLED)) abort();
    }
    cleanup(&pool->observer);
    free(pool);
}

static bool test_pool_capacity_reuse_and_isolation(void) {
    bool passed = false;
    Pool* first = pool_new();
    Pool* second = pool_new();
    CHECK(first && second);
    Matter_T owner = first->observer.owner;
    CHECK(matter_start(owner) == MATTER_OK && matter_start(second->observer.owner) == MATTER_OK);
    for (size_t i = 0; i < MATTER_OPERATION_CAPACITY; ++i) {
        CHECK(submit(&first->operations[i]) == MATTER_OK);
        if (i) CHECK(first->operations[i].id > first->operations[i-1].id);
    }
    Matter_Operation_Id_T sentinel = 99;
    Matter_Operation_Port_T port = {&first->operations[0], cancel, completed};
    CHECK(matter_operation_begin(owner, &port, &sentinel) == MATTER_BUSY && sentinel == 99);
    CHECK(submit(&second->operations[0]) == MATTER_OK); /* Separate pool despite first full. */
    Matter_Operation_Id_T old_id = first->operations[1].id;
    Matter_Operation_Id_T last_id = first->operations[MATTER_OPERATION_CAPACITY-1].id;
    CHECK(deliver(&first->operations[1], old_id, MATTER_OPERATION_FAILED));
    CHECK(first->operations[1].completion_state == MATTER_STATE_RUNNING);
    CHECK(submit(&first->operations[1]) == MATTER_OK && first->operations[1].id > last_id);
    CHECK(matter_operation_complete(owner, old_id, MATTER_OPERATION_SUCCEEDED) == MATTER_INVALID_STATE);
    CHECK(matter_operation_cancel(owner, old_id) == MATTER_INVALID_STATE);
    CHECK(matter_operation_begin(owner, &port, &sentinel) == MATTER_BUSY && sentinel == 99);
    CHECK(matter_stop(owner) == MATTER_PENDING);
    CHECK(second->operations[0].cancels == 0 && matter_get_state(second->observer.owner) == MATTER_STATE_RUNNING);
    /* Descending slots, independent of issued IDs. */
    for (size_t i = MATTER_OPERATION_CAPACITY; i-- > 0;) {
        CHECK(first->operations[i].cancels == 1 && first->operations[i].violations == 0);
        CHECK(deliver(&first->operations[i], first->operations[i].id, MATTER_OPERATION_CANCELLED));
        CHECK(first->operations[i].completion_state == MATTER_STATE_STOPPING);
        CHECK(matter_get_state(owner) == (i ? MATTER_STATE_STOPPING : MATTER_STATE_STOPPED));
    }
    CHECK(first->observer.states == 3 && first->observer.violations == 0);
    CHECK(second->operations[0].completions == 0 && second->operations[0].target == second->observer.owner);
    CHECK(deliver(&second->operations[0], second->operations[0].id, MATTER_OPERATION_SUCCEEDED));
    CHECK(second->operations[0].violations == 0);
    passed = true;
done:
    pool_delete(first); pool_delete(second);
    return passed;
}

static bool test_pool_all_drain_orders(void) {
    bool passed = false;
    Pool* pool = pool_new();
    CHECK(pool && MATTER_OPERATION_CAPACITY == 4);
    Matter_T owner = pool->observer.owner;
    unsigned rounds = 0;
    Matter_Operation_Id_T previous = 0;
    /* All 24 permutations of four terminal events, without a recursive helper. */
    for (unsigned code = 0; code < 256; ++code) {
        unsigned order[4], seen = 0, value = code;
        for (unsigned i = 0; i < 4; ++i) { order[i] = value % 4; value /= 4; seen |= 1u << order[i]; }
        if (seen != 15) continue;
        CHECK(matter_start(owner) == MATTER_OK);
        for (unsigned i = 0; i < 4; ++i) {
            CHECK(submit(&pool->operations[i]) == MATTER_OK && pool->operations[i].id > previous);
            previous = pool->operations[i].id;
        }
        for (unsigned i = 0; i < 4; ++i) pool->operations[i].other_id = pool->operations[(i+1)%4].id;
        pool->observer.other_id = pool->operations[0].id;
        CHECK(matter_operation_cancel(owner, pool->operations[0].id) == MATTER_OK);
        CHECK(matter_operation_cancel(owner, pool->operations[0].id) == MATTER_OK);
        CHECK(matter_stop(owner) == MATTER_PENDING && matter_stop(owner) == MATTER_PENDING);
        CHECK(matter_start(owner) == MATTER_INVALID_STATE && matter_delete(owner) == MATTER_INVALID_STATE);
        Matter_Operation_Id_T id = pool->operations[0].id;
        CHECK(submit(&pool->operations[0]) == MATTER_INVALID_STATE && pool->operations[0].id == id);
        for (unsigned i = 0; i < 4; ++i) {
            Fake* fake = &pool->operations[order[i]];
            CHECK(fake->cancels == rounds+1);
            Matter_Operation_Result_T outcome = (Matter_Operation_Result_T)(i%3);
            CHECK(deliver(fake, fake->id, outcome));
            CHECK(fake->result == outcome && fake->completion_state == MATTER_STATE_STOPPING);
            CHECK(fake->completions == rounds+1 && fake->violations == 0);
            CHECK(matter_operation_complete(owner, fake->id, outcome) == MATTER_INVALID_STATE);
            CHECK(matter_operation_cancel(owner, fake->id) == MATTER_INVALID_STATE);
            if (i < 3) {
                CHECK(matter_get_state(owner) == MATTER_STATE_STOPPING);
                CHECK(matter_stop(owner) == MATTER_PENDING && matter_delete(owner) == MATTER_INVALID_STATE);
            }
        }
        ++rounds;
        CHECK(matter_get_state(owner) == MATTER_STATE_STOPPED);
        CHECK(pool->observer.states == rounds*3 && pool->observer.violations == 0);
    }
    CHECK(rounds == 24);
    passed = true;
done:
    pool_delete(pool);
    return passed;
}

int main(void) {
    const struct { const char* name; bool (*run)(void); } tests[] = {
        {"validation", test_validation},
        {"success/error/cancel and port copy", test_success_error_cancel_and_copy},
        {"stop drain and restart", test_stop_drains_and_restart_rejects_old_id},
        {"cancel races terminal result", test_cancel_races_terminal_result},
        {"two instances and event after delete", test_two_instances_and_event_after_delete},
        {"optional completion", test_optional_completion},
        {"pool capacity, reuse and isolation", test_pool_capacity_reuse_and_isolation},
        {"pool all 24 drain orders", test_pool_all_drain_orders},
    };
    unsigned failures = 0;
    const size_t count = sizeof(tests) / sizeof(tests[0]);
    for (size_t i = 0; i < count; ++i) {
        bool passed = tests[i].run();
        printf("%s async: %s\n", passed ? "PASS" : "FAIL", tests[i].name);
        if (!passed) ++failures;
    }
    printf("%zu/%zu async tests passed\n", count - failures, count);
    return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}

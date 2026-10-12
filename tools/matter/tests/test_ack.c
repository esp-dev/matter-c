#include <stdio.h>
#include <stdlib.h>
#include "transport/matter_ack.h"

#ifdef MATTER_TEST_ALLOC
static size_t live, allocations, last_size;
static bool fail_next;
void* matter_test_calloc(size_t count, size_t size) {
    if (fail_next) { fail_next = false; return NULL; }
    void* p = calloc(count, size);
    if (p) { ++live; ++allocations; last_size = count * size; }
    return p;
}
void matter_test_free(void* p) {
    if (p) { if (!live) abort(); --live; }
    free(p);
}
#endif

#define CHECK(c) do { if (!(c)) { \
    fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #c); goto done; } } while (0)

typedef struct {
    Matter_Ack_Table_T a, b;
    Matter_Ack_Request_T request, other;
} Fixture;

static Fixture* create(void) {
    Fixture* f = calloc(1, sizeof(*f));
    if (f) { f->a = matter_ack_new(); f->b = matter_ack_new(); }
    return f;
}

/* No actual backend in this test: drain simulated sends even on assertion failure. */
static void drain(Matter_Ack_Table_T table, uint64_t last) {
    if (!table) return;
    if (last) matter_ack_complete(table, last, MATTER_OPERATION_FAILED);
    unsigned count = 0;
    while (matter_ack_stop(table) == MATTER_PENDING) {
        Matter_Ack_Request_T request;
        if (++count > MATTER_ACK_CAPACITY + 1 ||
            matter_ack_next(table, UINT64_MAX, &request) != MATTER_OK ||
            matter_ack_complete(table, request.id, MATTER_OPERATION_SUCCEEDED) != MATTER_OK) abort();
    }
    if (matter_ack_delete(table) != MATTER_OK) abort();
}

static void cleanup(Fixture* f) {
    if (!f) return;
    drain(f->a, f->request.id); drain(f->b, f->other.id); free(f);
}

static bool deadlines(void) {
    bool ok = false;
    Fixture* f = create();
    Matter_Exchange_Info_T key = {1, 0, false}, second = {1, 1, false};
    CHECK(f && f->a && f->b);
    CHECK(MATTER_ACK_TIMEOUT_MS == 200);
    CHECK(matter_ack_record(f->a, &key, 0, 100) == MATTER_OK);
    CHECK(matter_ack_record(f->a, &second, UINT32_MAX, 110) == MATTER_OK);
    CHECK(matter_ack_next(f->a, 299, &f->request) == MATTER_WOULD_BLOCK && !f->request.id);
    /* Retrying a recorded counter cannot postpone its original deadline. */
    CHECK(matter_ack_record(f->a, &key, 0, 299) == MATTER_OK);
    CHECK(matter_ack_next(f->a, 300, &f->request) == MATTER_OK);
    CHECK(f->request.counter == 0 && f->request.exchange.exchange_id == 0 && f->request.standalone);
    CHECK(matter_ack_next(f->a, 310, &f->other) == MATTER_WOULD_BLOCK && !f->other.id);
    CHECK(matter_ack_complete(f->a, f->request.id, MATTER_OPERATION_SUCCEEDED) == MATTER_OK);
    CHECK(matter_ack_next(f->a, 310, &f->request) == MATTER_OK);
    CHECK(f->request.counter == UINT32_MAX && f->request.exchange.exchange_id == 1);
    CHECK(matter_ack_complete(f->a, f->request.id, MATTER_OPERATION_SUCCEEDED) == MATTER_OK);
    CHECK(matter_ack_next(f->a, 1000, &f->request) == MATTER_WOULD_BLOCK);
    /* Standalone success keeps the entry available for piggyback. */
    CHECK(matter_ack_delete(f->a) == MATTER_INVALID_STATE);
    CHECK(matter_ack_piggyback(f->a, &key, &f->request) == MATTER_OK && !f->request.standalone);
    CHECK(matter_ack_complete(f->a, f->request.id, MATTER_OPERATION_SUCCEEDED) == MATTER_OK);
    CHECK(matter_ack_piggyback(f->a, &key, &f->request) == MATTER_INVALID_STATE);
    /* Overflow saturates, then sends at MAX, never rolls the deadline to zero. */
    CHECK(matter_ack_record(f->b, &key, 9, UINT64_MAX - 10) == MATTER_OK);
    CHECK(matter_ack_next(f->b, UINT64_MAX - 1, &f->other) == MATTER_WOULD_BLOCK);
    CHECK(matter_ack_next(f->b, UINT64_MAX, &f->other) == MATTER_OK);
    CHECK(matter_ack_complete(f->b, f->other.id, MATTER_OPERATION_SUCCEEDED) == MATTER_OK);
    ok = true;
done: cleanup(f); return ok;
}

static bool flush_and_failures(void) {
    bool ok = false;
    Fixture* f = create();
    Matter_Exchange_Info_T key = {7, 21, true}, second = {7, 22, true};
    CHECK(f && f->a && f->b);
    CHECK(matter_ack_record(f->a, &key, 10, 0) == MATTER_OK);
    CHECK(matter_ack_record(f->a, &key, 11, 5) == MATTER_WOULD_BLOCK);
    CHECK(matter_ack_next(f->a, 5, &f->request) == MATTER_OK && f->request.counter == 10);
    uint64_t rejected = f->request.id;
    /* Rejected transport submission is NOT a sent ACK. */
    CHECK(matter_ack_complete(f->a, rejected, MATTER_OPERATION_FAILED) == MATTER_OK);
    CHECK(matter_ack_record(f->a, &key, 11, 6) == MATTER_WOULD_BLOCK);
    CHECK(matter_ack_next(f->a, 6, &f->request) == MATTER_OK && f->request.id > rejected);
    CHECK(matter_ack_complete(f->a, rejected, MATTER_OPERATION_SUCCEEDED) == MATTER_INVALID_STATE);
    CHECK(matter_ack_record(f->a, &key, 12, 6) == MATTER_WOULD_BLOCK);
    CHECK(matter_ack_record(f->a, &second, 13, 6) == MATTER_OK);
    CHECK(matter_ack_complete(f->a, f->request.id, MATTER_OPERATION_CANCELLED) == MATTER_OK);
    CHECK(matter_ack_next(f->a, 6, &f->request) == MATTER_OK && f->request.counter == 10);
    CHECK(matter_ack_complete(f->a, f->request.id, MATTER_OPERATION_SUCCEEDED) == MATTER_OK);
    CHECK(matter_ack_record(f->a, &key, 11, 6) == MATTER_OK);
    CHECK(matter_ack_next(f->a, 205, &f->request) == MATTER_WOULD_BLOCK);
    CHECK(matter_ack_next(f->a, 206, &f->request) == MATTER_OK && f->request.counter == 11);
    CHECK(matter_ack_complete(f->a, f->request.id, MATTER_OPERATION_SUCCEEDED) == MATTER_OK);
    /* Delayed retry preserves RX time; draining the previous ACK cannot grant
     * another 200 ms starting at the time the transport becomes available. */
    CHECK(matter_ack_record(f->b, &key, 20, 0) == MATTER_OK);
    CHECK(matter_ack_record(f->b, &key, 21, 5) == MATTER_WOULD_BLOCK);
    CHECK(matter_ack_next(f->b, 250, &f->other) == MATTER_OK && f->other.counter == 20);
    CHECK(matter_ack_complete(f->b, f->other.id, MATTER_OPERATION_SUCCEEDED) == MATTER_OK);
    CHECK(matter_ack_record(f->b, &key, 21, 5) == MATTER_OK);
    CHECK(matter_ack_next(f->b, 250, &f->other) == MATTER_OK && f->other.counter == 21);
    CHECK(matter_ack_complete(f->b, f->other.id, MATTER_OPERATION_SUCCEEDED) == MATTER_OK);
    ok = true;
done: cleanup(f); return ok;
}

static bool immediate(void) {
    bool ok = false;
    Fixture* f = create();
    Matter_Exchange_Info_T key = {8, 33, false}, unknown = {9, UINT16_MAX, true};
    CHECK(f && f->a && f->b);
    CHECK(matter_ack_record(f->a, &key, 101, 10) == MATTER_OK);
    CHECK(matter_ack_immediate(f->a, &key, 100) == MATTER_OK);
    CHECK(matter_ack_immediate(f->a, &key, 100) == MATTER_WOULD_BLOCK);
    CHECK(matter_ack_next(f->a, 10, &f->request) == MATTER_OK && f->request.counter == 100);
    CHECK(matter_ack_record(f->a, &key, 102, 10) == MATTER_WOULD_BLOCK);
    CHECK(matter_ack_immediate(f->a, &unknown, 1) == MATTER_WOULD_BLOCK);
    CHECK(matter_ack_complete(f->a, f->request.id, MATTER_OPERATION_FAILED) == MATTER_OK);
    CHECK(matter_ack_next(f->a, 10, &f->request) == MATTER_OK && f->request.counter == 100);
    CHECK(matter_ack_complete(f->a, f->request.id, MATTER_OPERATION_SUCCEEDED) == MATTER_OK);
    CHECK(matter_ack_next(f->a, 210, &f->request) == MATTER_OK && f->request.counter == 101);
    CHECK(matter_ack_complete(f->a, f->request.id, MATTER_OPERATION_FAILED) == MATTER_OK);
    /* A duplicate of current counter satisfies the normal standalone duty too. */
    CHECK(matter_ack_immediate(f->a, &key, 101) == MATTER_OK);
    CHECK(matter_ack_next(f->a, 210, &f->request) == MATTER_OK);
    CHECK(matter_ack_complete(f->a, f->request.id, MATTER_OPERATION_SUCCEEDED) == MATTER_OK);
    CHECK(matter_ack_next(f->a, 210, &f->request) == MATTER_WOULD_BLOCK);
    /* Even after a successful standalone ACK, a new duplicate gets another. */
    CHECK(matter_ack_immediate(f->a, &key, 101) == MATTER_OK);
    CHECK(matter_ack_next(f->a, 210, &f->request) == MATTER_OK && f->request.standalone);
    CHECK(matter_ack_complete(f->a, f->request.id, MATTER_OPERATION_SUCCEEDED) == MATTER_OK);
    CHECK(matter_ack_immediate(f->a, &unknown, 0) == MATTER_OK);
    CHECK(matter_ack_close(f->a, &unknown) == MATTER_PENDING);
    CHECK(matter_ack_next(f->a, 210, &f->request) == MATTER_OK);
    CHECK(f->request.exchange.session == 9 && f->request.exchange.initiator && f->request.counter == 0);
    CHECK(matter_ack_complete(f->a, f->request.id, MATTER_OPERATION_SUCCEEDED) == MATTER_OK);
    CHECK(matter_ack_close(f->a, &unknown) == MATTER_OK);
    /* A duplicate arriving during piggyback must survive its completion. */
    CHECK(matter_ack_piggyback(f->a, &key, &f->request) == MATTER_OK);
    CHECK(matter_ack_immediate(f->a, &key, 101) == MATTER_OK);
    CHECK(matter_ack_close(f->a, &key) == MATTER_PENDING);
    CHECK(matter_ack_complete(f->a, f->request.id, MATTER_OPERATION_SUCCEEDED) == MATTER_OK);
    CHECK(matter_ack_close(f->a, &key) == MATTER_PENDING);
    CHECK(matter_ack_next(f->a, 210, &f->request) == MATTER_OK && f->request.counter == 101);
    CHECK(matter_ack_complete(f->a, f->request.id, MATTER_OPERATION_SUCCEEDED) == MATTER_OK);
    CHECK(matter_ack_close(f->a, &key) == MATTER_OK);
    ok = true;
done: cleanup(f); return ok;
}

static bool capacity_and_identity(void) {
    bool ok = false;
    Fixture* f = create();
    Matter_Exchange_Info_T key = {1, 0, false};
    CHECK(f && f->a && f->b);
    for (unsigned i = 0; i < MATTER_ACK_CAPACITY; ++i) {
        key.session = 1 + i / 4; key.exchange_id = (uint16_t)((i / 2) % 2); key.initiator = (i % 2) != 0;
        CHECK(matter_ack_record(f->a, &key, i, 0) == MATTER_OK);
        CHECK(matter_ack_record(f->b, &key, 100 + i, 0) == MATTER_OK);
    }
    key = (Matter_Exchange_Info_T){3, 0, false};
    CHECK(matter_ack_record(f->a, &key, 99, 0) == MATTER_LIMIT_REACHED);
    CHECK(matter_ack_immediate(f->a, &key, 99) == MATTER_OK); /* separate bounded slot */
    CHECK(matter_ack_next(f->a, 200, &f->request) == MATTER_OK && f->request.counter == 99);
    CHECK(matter_ack_complete(f->a, f->request.id, MATTER_OPERATION_SUCCEEDED) == MATTER_OK);
    for (unsigned i = 0; i < MATTER_ACK_CAPACITY; ++i) {
        key.session = 1 + i / 4; key.exchange_id = (uint16_t)((i / 2) % 2); key.initiator = (i % 2) != 0;
        CHECK(matter_ack_piggyback(f->a, &key, &f->request) == MATTER_OK && f->request.counter == i);
        CHECK(matter_ack_complete(f->a, f->request.id, MATTER_OPERATION_SUCCEEDED) == MATTER_OK);
        CHECK(matter_ack_piggyback(f->b, &key, &f->other) == MATTER_OK && f->other.counter == 100 + i);
        CHECK(matter_ack_complete(f->b, f->other.id, MATTER_OPERATION_SUCCEEDED) == MATTER_OK);
    }
    CHECK(matter_ack_record(f->a, &key, 99, 200) == MATTER_OK); /* slot reuse */
    CHECK(matter_ack_next(f->b, 200, &f->other) == MATTER_WOULD_BLOCK);
    ok = true;
done: cleanup(f); return ok;
}

static bool close_and_stop(void) {
    bool ok = false;
    Fixture* f = create();
    Matter_Exchange_Info_T key = {1, 1, false}, second = {1, 2, false};
    CHECK(f && f->a && f->b);
    CHECK(matter_ack_record(f->a, &key, 1, 0) == MATTER_OK);
    CHECK(matter_ack_piggyback(f->a, &key, &f->request) == MATTER_OK);
    CHECK(matter_ack_close(f->a, &key) == MATTER_PENDING);
    CHECK(matter_ack_record(f->a, &key, 2, 0) == MATTER_INVALID_STATE);
    CHECK(matter_ack_complete(f->a, f->request.id, MATTER_OPERATION_FAILED) == MATTER_OK);
    CHECK(matter_ack_close(f->a, &key) == MATTER_PENDING);
    CHECK(matter_ack_piggyback(f->a, &key, &f->request) == MATTER_INVALID_STATE);
    CHECK(matter_ack_next(f->a, 0, &f->request) == MATTER_OK && f->request.standalone);
    CHECK(matter_ack_complete(f->a, f->request.id, MATTER_OPERATION_SUCCEEDED) == MATTER_OK);
    CHECK(matter_ack_close(f->a, &key) == MATTER_OK);
    CHECK(matter_ack_record(f->a, &key, 3, 0) == MATTER_OK);
    CHECK(matter_ack_piggyback(f->a, &key, &f->request) == MATTER_OK);
    CHECK(matter_ack_immediate(f->a, &second, 4) == MATTER_OK);
    CHECK(matter_ack_record(f->b, &key, 9, 0) == MATTER_OK);
    CHECK(matter_ack_stop(f->a) == MATTER_PENDING);
    CHECK(matter_ack_delete(f->a) == MATTER_INVALID_STATE);
    CHECK(matter_ack_immediate(f->a, &key, 3) == MATTER_INVALID_STATE);
    CHECK(matter_ack_record(f->a, &second, 5, 0) == MATTER_INVALID_STATE);
    CHECK(matter_ack_piggyback(f->a, &second, &f->request) == MATTER_INVALID_STATE);
    CHECK(matter_ack_complete(f->a, f->request.id, MATTER_OPERATION_SUCCEEDED) == MATTER_OK);
    CHECK(matter_ack_stop(f->a) == MATTER_PENDING);
    CHECK(matter_ack_next(f->a, 0, &f->request) == MATTER_OK && f->request.counter == 4);
    CHECK(matter_ack_complete(f->a, f->request.id, MATTER_OPERATION_CANCELLED) == MATTER_OK);
    CHECK(matter_ack_stop(f->a) == MATTER_PENDING);
    CHECK(matter_ack_next(f->a, 0, &f->request) == MATTER_OK && f->request.counter == 4);
    CHECK(matter_ack_complete(f->a, f->request.id, MATTER_OPERATION_SUCCEEDED) == MATTER_OK);
    CHECK(matter_ack_stop(f->a) == MATTER_OK && matter_ack_stop(f->a) == MATTER_OK);
    CHECK(matter_ack_piggyback(f->b, &key, &f->other) == MATTER_OK && f->other.counter == 9);
    CHECK(matter_ack_complete(f->b, f->other.id, MATTER_OPERATION_SUCCEEDED) == MATTER_OK);
    ok = true;
done: cleanup(f); return ok;
}

static bool arguments_and_piggyback(void) {
    bool ok = false;
    Fixture* f = create();
    Matter_Exchange_Info_T key = {1, 1, true}, invalid = {0};
    CHECK(f && f->a && f->b);
    CHECK(matter_ack_delete(NULL) == MATTER_OK);
    CHECK(matter_ack_stop(NULL) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_ack_close(NULL, &key) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_ack_close(f->a, &invalid) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_ack_record(NULL, &key, 0, 0) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_ack_record(f->a, NULL, 0, 0) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_ack_record(f->a, &invalid, 0, 0) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_ack_immediate(NULL, &key, 0) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_ack_immediate(f->a, NULL, 0) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_ack_immediate(f->a, &invalid, 0) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_ack_next(NULL, 0, &f->request) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_ack_next(f->a, 0, NULL) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_ack_piggyback(NULL, &key, &f->request) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_ack_piggyback(f->a, NULL, &f->request) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_ack_piggyback(f->a, &key, NULL) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_ack_complete(NULL, 1, MATTER_OPERATION_SUCCEEDED) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_ack_complete(f->a, 0, MATTER_OPERATION_SUCCEEDED) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_ack_complete(f->a, 1, (Matter_Operation_Result_T)99) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_ack_complete(f->a, 1, MATTER_OPERATION_SUCCEEDED) == MATTER_INVALID_STATE);
    CHECK(matter_ack_record(f->a, &key, 5, 50) == MATTER_OK);
    CHECK(matter_ack_record(f->a, &key, 5, 49) == MATTER_OK);
    CHECK(matter_ack_piggyback(f->a, &key, &f->request) == MATTER_OK && f->request.counter == 5);
    CHECK(matter_ack_complete(f->a, f->request.id, MATTER_OPERATION_FAILED) == MATTER_OK);
    uint64_t saved_id = f->request.id;
    CHECK(matter_ack_next(f->a, 49, &f->request) == MATTER_INVALID_ARGUMENT);
    CHECK(f->request.id == saved_id && f->request.counter == 5 && !f->request.standalone);
    CHECK(matter_ack_next(f->a, 249, &f->request) == MATTER_WOULD_BLOCK && f->request.id == saved_id);
    CHECK(matter_ack_next(f->a, 250, &f->request) == MATTER_OK && f->request.standalone);
    CHECK(matter_ack_complete(f->a, saved_id, MATTER_OPERATION_SUCCEEDED) == MATTER_INVALID_STATE);
    CHECK(matter_ack_complete(f->a, f->request.id, MATTER_OPERATION_SUCCEEDED) == MATTER_OK);
    CHECK(matter_ack_piggyback(f->a, &key, &f->request) == MATTER_OK);
    /* Failed piggyback of an already sent ACK must not arm another standalone. */
    CHECK(matter_ack_complete(f->a, f->request.id, MATTER_OPERATION_FAILED) == MATTER_OK);
    CHECK(matter_ack_next(f->a, 1000, &f->request) == MATTER_WOULD_BLOCK);
    CHECK(matter_ack_close(f->a, &key) == MATTER_OK);
    /* Already-sent entry closed during a failed piggyback needs only drain,
     * not another ACK. The active reservation still prevents early deletion. */
    CHECK(matter_ack_record(f->a, &key, 6, 1000) == MATTER_OK);
    CHECK(matter_ack_next(f->a, 1200, &f->request) == MATTER_OK);
    CHECK(matter_ack_complete(f->a, f->request.id, MATTER_OPERATION_SUCCEEDED) == MATTER_OK);
    CHECK(matter_ack_piggyback(f->a, &key, &f->request) == MATTER_OK);
    CHECK(matter_ack_stop(f->a) == MATTER_PENDING);
    CHECK(matter_ack_delete(f->a) == MATTER_INVALID_STATE);
    CHECK(matter_ack_complete(f->a, f->request.id, MATTER_OPERATION_FAILED) == MATTER_OK);
    CHECK(matter_ack_stop(f->a) == MATTER_OK);
    ok = true;
done: cleanup(f); return ok;
}

#ifdef MATTER_TEST_ALLOC
static bool allocation(void) {
    bool ok = false;
    Fixture* f = NULL;
    CHECK(live == 0);
    fail_next = true;
    CHECK(matter_ack_new() == NULL && live == 0);
    f = create();
    CHECK(f && f->a && f->b && live == 2);
    printf("ACK context: %zu bytes\n", last_size);
    size_t before = allocations;
    Matter_Exchange_Info_T key = {1, 1, false};
    for (unsigned i = 0; i < 1000; ++i) {
        CHECK(matter_ack_record(f->a, &key, i, i) == MATTER_OK);
        CHECK(matter_ack_piggyback(f->a, &key, &f->request) == MATTER_OK);
        CHECK(matter_ack_complete(f->a, f->request.id, MATTER_OPERATION_SUCCEEDED) == MATTER_OK);
        CHECK(matter_ack_immediate(f->b, &key, i) == MATTER_OK);
        CHECK(matter_ack_next(f->b, i, &f->other) == MATTER_OK);
        CHECK(matter_ack_complete(f->b, f->other.id, MATTER_OPERATION_SUCCEEDED) == MATTER_OK);
    }
    CHECK(allocations == before);
    ok = true;
done: cleanup(f); return ok && live == 0;
}
#endif

int main(void) {
    unsigned passed = 0;
#define RUN(t) do { if (!(t)()) return 1; ++passed; } while (0)
    RUN(deadlines); RUN(flush_and_failures); RUN(immediate);
    RUN(capacity_and_identity); RUN(close_and_stop); RUN(arguments_and_piggyback);
#ifdef MATTER_TEST_ALLOC
    RUN(allocation);
    if (live) return 1;
#endif
    printf("PASS ACK: %u groups\n", passed);
    return 0;
}

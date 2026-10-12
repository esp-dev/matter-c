#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "transport/matter_exchange.h"
#include "codec/matter_protocol_header.h"

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
    Matter_T owner;
    Matter_Exchange_Table_T table;
    Matter_Exchange_Handle_T handles[MATTER_EXCHANGE_CAPACITY];
    Matter_Operation_Id_T operations[MATTER_OPERATION_CAPACITY];
    unsigned cancels, probes, violations;
    bool probe;
} Fixture;

static void changed(void* user, Matter_State_T state) {
    Fixture* f = user;
    if (!f->probe || state != MATTER_STATE_STOPPED) return;
    ++f->probes;
    Matter_Exchange_Handle_T handle = 99;
    Matter_Exchange_Info_T info = {88, 77, false};
    if (matter_exchange_delete(f->table) != MATTER_BUSY) ++f->violations;
    if (matter_exchange_start(f->table) != MATTER_BUSY) ++f->violations;
    if (matter_exchange_stop(f->table) != MATTER_BUSY) ++f->violations;
    if (matter_exchange_process(f->table) != MATTER_BUSY) ++f->violations;
    if (matter_exchange_check(f->table) != MATTER_BUSY) ++f->violations;
    if (matter_exchange_initiate(f->table, 1, &handle) != MATTER_BUSY) ++f->violations;
    if (matter_exchange_accept(f->table, 1, 0, &handle) != MATTER_BUSY) ++f->violations;
    if (matter_exchange_match(f->table, 1, 0, true, &handle) != MATTER_BUSY) ++f->violations;
    if (matter_exchange_get(f->table, 1, &info) != MATTER_BUSY) ++f->violations;
    if (matter_exchange_release(f->table, 1) != MATTER_BUSY) ++f->violations;
    if (matter_exchange_release_session(f->table, 1) != MATTER_BUSY) ++f->violations;
    if (handle != 99 || info.session != 88 || info.exchange_id != 77 || info.initiator) ++f->violations;
}
static bool create(Fixture* f, uint16_t seed) {
    Matter_Port_T port = {f, changed};
    f->owner = matter_new(&port);
    if (!f->owner) return false;
    f->table = matter_exchange_new(f->owner, seed);
    return f->table != NULL && matter_start(f->owner) == MATTER_OK;
}
static void cancel(void* user, Matter_Operation_Id_T id) {
    Fixture* f = user;
    (void)id;
    ++f->cancels;
}
static void cleanup(Fixture* f) {
    f->probe = false;
    matter_exchange_stop(f->table);
    matter_exchange_process(f->table);
    if (matter_exchange_delete(f->table) != MATTER_OK) abort();
    for (size_t i = 0; i < MATTER_OPERATION_CAPACITY; ++i)
        if (f->operations[i]) matter_operation_complete(f->owner, f->operations[i], MATTER_OPERATION_CANCELLED);
    matter_stop(f->owner);
    if (matter_delete(f->owner) != MATTER_OK) abort();
}

static bool identity(void) {
    bool ok = false;
    Fixture* f = calloc(1, sizeof(*f));
    if (!f) return false;
    Matter_Exchange_Handle_T matched = 999;
    Matter_Exchange_Info_T info;
    CHECK(create(f, 0x1234) && matter_exchange_start(f->table) == MATTER_OK);
    CHECK(matter_exchange_initiate(f->table, 10, &f->handles[0]) == MATTER_OK);
    CHECK(matter_exchange_accept(f->table, 10, 0x1234, &f->handles[1]) == MATTER_OK);
    CHECK(matter_exchange_accept(f->table, 20, 0x1234, &f->handles[2]) == MATTER_OK);
    CHECK(f->handles[0] != f->handles[1] && f->handles[1] != f->handles[2]);
    /* Literal protocol header, I toggled independently of table insertion.
     * Iterate all flags: only I affects matching, other policy is not here. */
    uint8_t wire[12] = {0, 1, 0x34, 0x12, 0, 0, 0, 0, 0, 0, 0, 0};
    for (unsigned flags = 0; flags < 256; ++flags) {
        if (flags & MATTER_PROTOCOL_EXTENSIONS) continue; /* SX syntax tested in codec. */
        wire[0] = (uint8_t)flags;
        Matter_Protocol_Header_T header;
        size_t consumed = 0;
        CHECK(matter_protocol_header_read(wire, sizeof(wire), &header, &consumed) == MATTER_MESSAGE_OK);
        bool incoming = (header.exchange_flags & MATTER_PROTOCOL_INITIATOR) != 0;
        CHECK(matter_exchange_match(f->table, 10, header.exchange_id, incoming, &matched) == MATTER_OK);
        CHECK(matched == f->handles[incoming ? 1 : 0]);
    }
    CHECK(matter_exchange_match(f->table, 20, 0x1234, true, &matched) == MATTER_OK && matched == f->handles[2]);
    matched = 999;
    CHECK(matter_exchange_match(f->table, 20, 0x1234, false, &matched) == MATTER_INVALID_STATE && matched == 999);
    CHECK(matter_exchange_match(f->table, 30, 0x1234, true, &matched) == MATTER_INVALID_STATE && matched == 999);
    CHECK(matter_exchange_match(f->table, 10, 0x1235, true, &matched) == MATTER_INVALID_STATE && matched == 999);
    CHECK(matter_exchange_accept(f->table, 10, 0x1234, &matched) == MATTER_BUSY && matched == 999);
    CHECK(matter_exchange_release_session(f->table, 10) == MATTER_OK);
    CHECK(matter_exchange_get(f->table, f->handles[0], &info) == MATTER_INVALID_STATE);
    CHECK(matter_exchange_get(f->table, f->handles[1], &info) == MATTER_INVALID_STATE);
    CHECK(matter_exchange_get(f->table, f->handles[2], &info) == MATTER_OK && info.session == 20);
    CHECK(matter_exchange_release_session(f->table, 10) == MATTER_OK);
    CHECK(matter_exchange_accept(f->table, 11, 0x1234, &matched) == MATTER_OK && matched > f->handles[2]);
    CHECK(matter_exchange_match(f->table, 10, 0x1234, true, &matched) == MATTER_INVALID_STATE);
    CHECK(matter_exchange_accept(f->table, 11, 0, &matched) == MATTER_OK);
    CHECK(matter_exchange_accept(f->table, 11, UINT16_MAX, &matched) == MATTER_OK);
    ok = true;
done:
    cleanup(f); free(f); return ok;
}

static bool limits(void) {
    bool ok = false;
    Fixture* f = calloc(1, sizeof(*f));
    if (!f) return false;
    Matter_Exchange_Handle_T handle = 999;
    Matter_Exchange_Info_T info;
    CHECK(create(f, 100) && matter_exchange_start(f->table) == MATTER_OK);
    for (size_t i = 0; i < MATTER_EXCHANGE_INITIATORS_PER_SESSION; ++i) {
        CHECK(matter_exchange_initiate(f->table, 1, &f->handles[i]) == MATTER_OK);
        CHECK(matter_exchange_get(f->table, f->handles[i], &info) == MATTER_OK && info.exchange_id == 100+i);
    }
    CHECK(matter_exchange_initiate(f->table, 1, &handle) == MATTER_LIMIT_REACHED && handle == 999);
    CHECK(matter_exchange_initiate(f->table, 2, &f->handles[5]) == MATTER_OK);
    CHECK(matter_exchange_get(f->table, f->handles[5], &info) == MATTER_OK && info.exchange_id == 105);
    CHECK(matter_exchange_accept(f->table, 1, 100, &f->handles[6]) == MATTER_OK);
    CHECK(matter_exchange_accept(f->table, 1, 101, &f->handles[7]) == MATTER_OK);
    CHECK(matter_exchange_accept(f->table, 2, 102, &handle) == MATTER_LIMIT_REACHED && handle == 999);
    CHECK(matter_exchange_initiate(f->table, 2, &handle) == MATTER_LIMIT_REACHED && handle == 999);
    CHECK(matter_exchange_release(f->table, f->handles[0]) == MATTER_OK);
    CHECK(matter_exchange_initiate(f->table, 1, &handle) == MATTER_OK && handle > f->handles[7]);
    CHECK(matter_exchange_get(f->table, handle, &info) == MATTER_OK && info.exchange_id == 106);
    CHECK(matter_exchange_release(f->table, f->handles[0]) == MATTER_INVALID_STATE);
    CHECK(matter_exchange_get(f->table, f->handles[0], &info) == MATTER_INVALID_STATE);
    ok = true;
done:
    cleanup(f); free(f); return ok;
}

static bool wrap(void) {
    bool ok = false;
    Fixture* f = calloc(1, sizeof(*f));
    if (!f) return false;
    Matter_Exchange_Handle_T handle = 999;
    Matter_Exchange_Info_T info;
    CHECK(create(f, 0) && matter_exchange_start(f->table) == MATTER_OK);
    CHECK(matter_exchange_initiate(f->table, 1, &f->handles[0]) == MATTER_OK);
    /* Hold ID 0 live while cycling all other wire IDs on another session. */
    for (uint32_t i = 1; i <= UINT16_MAX; ++i) {
        CHECK(matter_exchange_initiate(f->table, 2, &handle) == MATTER_OK);
        CHECK(matter_exchange_get(f->table, handle, &info) == MATTER_OK && info.exchange_id == i);
        CHECK(matter_exchange_release(f->table, handle) == MATTER_OK);
    }
    handle = 999;
    CHECK(matter_exchange_initiate(f->table, 1, &handle) == MATTER_BUSY && handle == 999);
    CHECK(matter_exchange_initiate(f->table, 1, &handle) == MATTER_BUSY && handle == 999);
    CHECK(matter_exchange_accept(f->table, 1, 0, &f->handles[1]) == MATTER_OK);
    CHECK(matter_exchange_release(f->table, f->handles[0]) == MATTER_OK);
    CHECK(matter_exchange_initiate(f->table, 1, &handle) == MATTER_OK && handle > UINT16_MAX);
    CHECK(matter_exchange_get(f->table, handle, &info) == MATTER_OK && info.exchange_id == 0);
    CHECK(matter_exchange_initiate(f->table, 2, &handle) == MATTER_OK);
    CHECK(matter_exchange_get(f->table, handle, &info) == MATTER_OK && info.exchange_id == 1);
    CHECK(matter_exchange_get(f->table, f->handles[0], &info) == MATTER_INVALID_STATE);
    ok = true;
done:
    cleanup(f); free(f); return ok;
}

static bool lifecycle(void) {
    bool ok = false;
    Fixture* f = calloc(2, sizeof(*f));
    if (!f) return false;
    Matter_Exchange_Info_T info;
    CHECK(create(&f[0], 7) && create(&f[1], 7));
    Matter_Operation_Port_T port = {&f[0], cancel, NULL};
    for (size_t i = 0; i < MATTER_OPERATION_CAPACITY; ++i)
        CHECK(matter_operation_begin(f[0].owner, &port, &f[0].operations[i]) == MATTER_OK);
    CHECK(matter_exchange_start(f[0].table) == MATTER_BUSY);
    CHECK(matter_operation_complete(f[0].owner, f[0].operations[0], MATTER_OPERATION_SUCCEEDED) == MATTER_OK);
    f[0].operations[0] = 0;
    CHECK(matter_exchange_start(f[0].table) == MATTER_OK && matter_exchange_start(f[0].table) == MATTER_OK);
    CHECK(matter_exchange_start(f[1].table) == MATTER_OK);
    CHECK(matter_exchange_initiate(f[0].table, 1, &f[0].handles[0]) == MATTER_OK);
    CHECK(matter_exchange_initiate(f[1].table, 1, &f[1].handles[0]) == MATTER_OK);
    for (size_t i = 1; i < MATTER_EXCHANGE_CAPACITY; ++i)
        CHECK(matter_exchange_accept(f[0].table, 2, (uint16_t)i, &f[0].handles[i]) == MATTER_OK);
    CHECK(matter_exchange_delete(f[0].table) == MATTER_INVALID_STATE);
    CHECK(matter_stop(f[0].owner) == MATTER_PENDING && f[0].cancels == 3);
    CHECK(matter_exchange_start(f[0].table) == MATTER_INVALID_STATE);
    CHECK(matter_exchange_get(f[0].table, f[0].handles[0], &info) == MATTER_INVALID_STATE);
    CHECK(matter_exchange_initiate(f[0].table, 1, &f[0].handles[0]) == MATTER_INVALID_STATE);
    CHECK(matter_exchange_match(f[0].table, 1, 7, false, &f[0].handles[0]) == MATTER_INVALID_STATE);
    CHECK(matter_exchange_get(f[1].table, f[1].handles[0], &info) == MATTER_OK);
    for (size_t i = 1; i < MATTER_OPERATION_CAPACITY; ++i) {
        CHECK(matter_operation_complete(f[0].owner, f[0].operations[i], MATTER_OPERATION_CANCELLED) == MATTER_OK);
        f[0].operations[i] = 0;
    }
    CHECK(matter_get_state(f[0].owner) == MATTER_STATE_STOPPING);
    f[0].probe = true;
    CHECK(matter_exchange_process(f[0].table) == MATTER_OK && f[0].probes == 1 && !f[0].violations);
    f[0].probe = false;
    CHECK(matter_get_state(f[0].owner) == MATTER_STATE_STOPPED);
    CHECK(matter_start(f[0].owner) == MATTER_OK && matter_exchange_start(f[0].table) == MATTER_OK);
    for (size_t i = 0; i < MATTER_EXCHANGE_CAPACITY; ++i)
        CHECK(matter_exchange_get(f[0].table, f[0].handles[i], &info) == MATTER_INVALID_STATE);
    CHECK(matter_exchange_initiate(f[0].table, 3, &f[0].handles[0]) == MATTER_OK);
    CHECK(f[0].handles[0] > MATTER_EXCHANGE_CAPACITY);
    CHECK(matter_exchange_get(f[0].table, f[0].handles[0], &info) == MATTER_OK && info.exchange_id == 8);
    CHECK(matter_exchange_stop(f[0].table) == MATTER_PENDING);
    CHECK(matter_exchange_stop(f[0].table) == MATTER_PENDING);
    CHECK(matter_exchange_process(f[0].table) == MATTER_OK);
    CHECK(matter_get_state(f[0].owner) == MATTER_STATE_RUNNING);
    CHECK(matter_exchange_process(f[0].table) == MATTER_OK);
    CHECK(matter_exchange_get(f[1].table, f[1].handles[0], &info) == MATTER_OK && info.exchange_id == 7);
    ok = true;
done:
    cleanup(&f[0]); cleanup(&f[1]); free(f); return ok;
}

static bool validation(void) {
    bool ok = false;
    Fixture* f = calloc(1, sizeof(*f));
    if (!f) return false;
    Matter_Exchange_Handle_T handle = 999;
    Matter_Exchange_Info_T info = {88, 77, true};
    CHECK(!matter_exchange_new(NULL, 0) && matter_exchange_delete(NULL) == MATTER_OK);
    CHECK(matter_exchange_start(NULL) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_exchange_stop(NULL) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_exchange_process(NULL) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_exchange_check(NULL) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_exchange_initiate(NULL, 1, &handle) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_exchange_accept(NULL, 1, 1, &handle) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_exchange_match(NULL, 1, 1, true, &handle) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_exchange_get(NULL, 1, &info) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_exchange_release(NULL, 1) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_exchange_release_session(NULL, 1) == MATTER_INVALID_ARGUMENT);
    CHECK(create(f, UINT16_MAX));
    CHECK(matter_stop(f->owner) == MATTER_OK);
    CHECK(matter_exchange_start(f->table) == MATTER_INVALID_STATE);
    CHECK(matter_exchange_check(f->table) == MATTER_INVALID_STATE);
    CHECK(matter_exchange_initiate(f->table, 1, &handle) == MATTER_INVALID_STATE);
    CHECK(matter_exchange_stop(f->table) == MATTER_OK);
    CHECK(matter_start(f->owner) == MATTER_OK && matter_exchange_start(f->table) == MATTER_OK);
    CHECK(matter_exchange_check(f->table) == MATTER_OK);
    CHECK(matter_exchange_initiate(f->table, 0, &handle) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_exchange_initiate(f->table, 1, NULL) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_exchange_accept(f->table, 0, 0, &handle) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_exchange_accept(f->table, 1, 0, NULL) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_exchange_match(f->table, 0, 0, true, &handle) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_exchange_match(f->table, 1, 0, true, NULL) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_exchange_get(f->table, 0, &info) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_exchange_get(f->table, 1, NULL) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_exchange_release(f->table, 0) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_exchange_release_session(f->table, 0) == MATTER_INVALID_ARGUMENT);
    CHECK(handle == 999 && info.session == 88 && info.exchange_id == 77 && info.initiator);
    CHECK(matter_exchange_initiate(f->table, 1, &handle) == MATTER_OK);
    CHECK(matter_exchange_get(f->table, handle, &info) == MATTER_OK && info.exchange_id == UINT16_MAX);
    CHECK(matter_exchange_initiate(f->table, 1, &handle) == MATTER_OK);
    CHECK(matter_exchange_get(f->table, handle, &info) == MATTER_OK && info.exchange_id == 0);
    ok = true;
done:
    cleanup(f); free(f); return ok;
}

#ifdef MATTER_TEST_ALLOC
static bool allocation(void) {
    bool ok = false;
    Fixture* f = calloc(1, sizeof(*f));
    if (!f) return false;
    f->owner = matter_new(NULL);
    CHECK(f->owner);
    size_t baseline = live;
    fail_next = true;
    CHECK(!matter_exchange_new(f->owner, 0) && live == baseline && !fail_next);
    f->table = matter_exchange_new(f->owner, 0);
    CHECK(f->table && live == baseline + 1);
    printf("Exchange table allocation: %zu bytes\n", last_size);
    baseline = allocations;
    fail_next = true;
    CHECK(matter_start(f->owner) == MATTER_OK && matter_exchange_start(f->table) == MATTER_OK);
    for (unsigned i = 0; i < 100; ++i) {
        CHECK(matter_exchange_initiate(f->table, 1, &f->handles[0]) == MATTER_OK);
        CHECK(matter_exchange_release(f->table, f->handles[0]) == MATTER_OK);
    }
    CHECK(allocations == baseline && fail_next);
    ok = true;
done:
    fail_next = false;
    cleanup(f); free(f); return ok && live == 0;
}
#endif

int main(void) {
    const struct { const char* name; bool (*run)(void); } tests[] = {
        {"session/ID/role matching and retirement", identity},
        {"capacity, per-session limit and stale handles", limits},
        {"all wire IDs, wrap collision and retry", wrap},
        {"owner pool, shutdown, restart and isolation", lifecycle},
        {"arguments, unchanged outputs and ID boundaries", validation},
#ifdef MATTER_TEST_ALLOC
        {"OOM and no per-entry allocation", allocation},
#endif
    };
    for (size_t i = 0; i < sizeof(tests)/sizeof(tests[0]); ++i) {
        if (!tests[i].run()) return 1;
        printf("PASS exchange: %s\n", tests[i].name);
    }
#ifdef MATTER_TEST_ALLOC
    if (live) return 1;
#endif
    return 0;
}

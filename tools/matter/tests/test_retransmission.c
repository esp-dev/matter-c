#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "transport/matter_retransmission.h"
#include "transport/matter_rx.h"

#ifdef MATTER_TEST_ALLOC
static size_t live, calls, last_size;
static bool fail_next;
void* matter_test_calloc(size_t n, size_t size) {
    ++calls;
    if (fail_next) { fail_next = false; return NULL; }
    void* p = calloc(n, size);
    if (p) { ++live; last_size = n * size; }
    return p;
}
void matter_test_free(void* p) { if (p) { if (!live) abort(); --live; } free(p); }
#endif

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #c); goto done; } } while (0)

static const Matter_Exchange_Info_T key = {1, 0x1234, true};
static const Matter_Retransmission_Parameters_T active = {500, 300, true};
static const Matter_Retransmission_Parameters_T idle = {500, 300, false};

typedef struct {
    Matter_Retransmission_T a, b;
    Matter_Retransmission_Request_T request, other;
    Matter_Retransmission_Message_T message;
    Matter_Retransmission_Result_T result;
    uint8_t bytes[1233];
    uint64_t ids[8];
} Fixture;

static Fixture* create(uint8_t maximum) {
    Fixture* f = calloc(1, sizeof(*f));
    if (f) { f->a = matter_retransmission_new(maximum); f->b = matter_retransmission_new(maximum); }
    return f;
}
static void drain(Matter_Retransmission_T table, uint64_t pending) {
    if (!table) return;
    if (pending) matter_retransmission_complete(table, pending, MATTER_RETRANSMISSION_FATAL);
    unsigned steps = 0;
    while (matter_retransmission_stop(table) == MATTER_PENDING) {
        if (++steps > 32) abort();
        Matter_Retransmission_Message_T message;
        Matter_Retransmission_Request_T request;
        Matter_Retransmission_Result_T result;
        if (matter_retransmission_next(table, UINT64_MAX, &message) == MATTER_OK) {
            if (matter_retransmission_prepare(table, message.id, &active, 0, UINT64_MAX, &request) != MATTER_OK ||
                matter_retransmission_complete(table, request.id, MATTER_RETRANSMISSION_FATAL) != MATTER_OK) abort();
        }
        while (matter_retransmission_take(table, &result) == MATTER_OK) {}
    }
    if (matter_retransmission_delete(table) != MATTER_OK) abort();
}
static void cleanup(Fixture* f) {
    if (!f) return;
    drain(f->a, f->request.id); drain(f->b, f->other.id); free(f);
}

/* Table 21 per-attempt times, rounded up to whole ms, independent literals. */
static bool normative_backoff(void) {
    bool ok = false;
    Fixture* f = create(5);
    static const uint64_t minimum[] = {330, 330, 528, 845, 1352};
    static const uint64_t maximum[] = {413, 413, 660, 1056, 1690};
    CHECK(f && f->a && f->b);
    CHECK(matter_retransmission_add(f->a, &key, 0, f->bytes, 16, &f->ids[0]) == MATTER_OK);
    CHECK(matter_retransmission_add(f->b, &key, 0, f->bytes, 16, &f->ids[1]) == MATTER_OK);
    uint64_t a = 0, b = 0, deadline = 999;
    for (unsigned n = 0; n < 5; ++n) {
        CHECK(matter_retransmission_next(f->a, a, &f->message) == MATTER_OK && f->message.id == f->ids[0]);
        CHECK(matter_retransmission_prepare(f->a, f->ids[0], &active, 0, a, &f->request) == MATTER_OK);
        CHECK(matter_retransmission_prepare(f->b, f->ids[1], &active, UINT16_MAX, b, &f->other) == MATTER_OK);
        CHECK(f->request.deadline_ms == a + minimum[n] && f->other.deadline_ms == b + maximum[n]);
        CHECK(f->request.attempt == n + 1 && f->other.attempt == n + 1);
        CHECK(f->request.message.data == f->bytes && f->request.message.counter == 0 && f->request.message.size == 16);
        a = f->request.deadline_ms; b = f->other.deadline_ms;
        CHECK(matter_retransmission_complete(f->a, f->request.id, MATTER_RETRANSMISSION_SENT) == MATTER_OK);
        CHECK(matter_retransmission_complete(f->b, f->other.id, MATTER_RETRANSMISSION_SENT) == MATTER_OK);
        CHECK(matter_retransmission_deadline(f->a, &deadline) == MATTER_OK && deadline == a);
        CHECK(matter_retransmission_next(f->a, a - 1, &f->message) == MATTER_WOULD_BLOCK);
        CHECK(matter_retransmission_take(f->a, &f->result) == MATTER_WOULD_BLOCK);
    }
    CHECK(a == 3385 && b == 4232); /* Ceil EACH attempt; Table 21 max-total uses fractional times. */
    CHECK(matter_retransmission_next(f->a, a, &f->message) == MATTER_WOULD_BLOCK);
    CHECK(matter_retransmission_take(f->a, &f->result) == MATTER_OK && f->result.outcome == MATTER_RETRANSMISSION_TIMEOUT);
    CHECK(f->result.attempts == 5 && f->result.message.data == f->bytes);
    /* Last attempt still accepts ACK before its final timeout. */
    CHECK(matter_retransmission_ack(f->b, &key, 0) == MATTER_OK);
    CHECK(matter_retransmission_take(f->b, &f->result) == MATTER_OK && f->result.outcome == MATTER_RETRANSMISSION_ACKNOWLEDGED);
    CHECK(f->result.attempts == 5);
    ok = true;
done: cleanup(f); return ok;
}

static bool inflight_ack_and_cancel(void) {
    bool ok = false;
    Fixture* f = create(5);
    CHECK(f && f->a && f->b);
    CHECK(matter_retransmission_add(f->a, &key, UINT32_MAX, f->bytes, 20, &f->ids[0]) == MATTER_OK);
    CHECK(matter_retransmission_ack(f->a, &key, UINT32_MAX) == MATTER_OK); /* no attempt, ignore */
    CHECK(matter_retransmission_take(f->a, &f->result) == MATTER_WOULD_BLOCK);
    CHECK(matter_retransmission_prepare(f->a, f->ids[0], &idle, 0, 10, &f->request) == MATTER_OK);
    CHECK(f->request.deadline_ms == 560);
    for (unsigned wrong = 0; wrong < 4; ++wrong) {
        Matter_Exchange_Info_T k = key;
        if (wrong == 0) ++k.session;
        if (wrong == 1) ++k.exchange_id;
        if (wrong == 2) k.initiator = false;
        CHECK(matter_retransmission_ack(f->a, &k, wrong == 3 ? 0 : UINT32_MAX) == MATTER_OK);
    }
    CHECK(matter_retransmission_complete(f->a, f->request.id, MATTER_RETRANSMISSION_SENT) == MATTER_OK);
    CHECK(matter_retransmission_take(f->a, &f->result) == MATTER_WOULD_BLOCK); /* all wrong ACKs ignored */
    CHECK(matter_retransmission_prepare(f->a, f->ids[0], &active, 0, 560, &f->request) == MATTER_OK);
    CHECK(matter_retransmission_ack(f->a, &key, UINT32_MAX) == MATTER_OK);
    CHECK(matter_retransmission_cancel(f->a, f->ids[0]) == MATTER_PENDING); /* ACK wins */
    CHECK(matter_retransmission_next(f->a, 10000, &f->message) == MATTER_WOULD_BLOCK);
    CHECK(matter_retransmission_take(f->a, &f->result) == MATTER_WOULD_BLOCK);
    CHECK(matter_retransmission_drained(f->a, &key) == MATTER_PENDING);
    CHECK(matter_retransmission_stop(f->a) == MATTER_PENDING && matter_retransmission_delete(f->a) == MATTER_INVALID_STATE);
    CHECK(matter_retransmission_complete(f->a, f->request.id + 1, MATTER_RETRANSMISSION_SENT) == MATTER_INVALID_STATE);
    CHECK(matter_retransmission_complete(f->a, f->request.id, MATTER_RETRANSMISSION_FATAL) == MATTER_OK);
    CHECK(matter_retransmission_drained(f->a, &key) == MATTER_PENDING); /* result must be taken */
    CHECK(matter_retransmission_take(f->a, &f->result) == MATTER_OK && f->result.outcome == MATTER_RETRANSMISSION_ACKNOWLEDGED);
    CHECK(f->result.attempts == 2 && f->result.message.data == f->bytes);
    CHECK(matter_retransmission_stop(f->a) == MATTER_OK && matter_retransmission_drained(f->a, &key) == MATTER_OK);
    CHECK(matter_retransmission_add(f->b, &key, 1, f->bytes, 1, &f->ids[1]) == MATTER_OK);
    CHECK(matter_retransmission_prepare(f->b, f->ids[1], &active, 0, 0, &f->other) == MATTER_OK);
    CHECK(matter_retransmission_cancel(f->b, f->ids[1]) == MATTER_PENDING);
    CHECK(matter_retransmission_ack(f->b, &key, 1) == MATTER_OK); /* cancel wins */
    CHECK(matter_retransmission_complete(f->b, f->other.id, MATTER_RETRANSMISSION_SENT) == MATTER_OK);
    CHECK(matter_retransmission_take(f->b, &f->result) == MATTER_OK && f->result.outcome == MATTER_RETRANSMISSION_CANCELLED);
    CHECK(matter_retransmission_complete(f->b, f->other.id, MATTER_RETRANSMISSION_SENT) == MATTER_INVALID_STATE);
    ok = true;
done: cleanup(f); return ok;
}

static bool retry_errors_and_updates(void) {
    bool ok = false;
    Fixture* f = create(2);
    CHECK(f && f->a && f->b);
    CHECK(matter_retransmission_add(f->a, &key, 7, f->bytes, 4, &f->ids[0]) == MATTER_OK);
    CHECK(matter_retransmission_prepare(f->a, f->ids[0], &active, 0, 100, &f->request) == MATTER_OK);
    CHECK(matter_retransmission_complete(f->a, f->request.id, MATTER_RETRANSMISSION_RETRYABLE) == MATTER_OK);
    CHECK(matter_retransmission_next(f->a, 429, &f->message) == MATTER_WOULD_BLOCK);
    CHECK(matter_retransmission_next(f->a, 430, &f->message) == MATTER_OK);
    uint64_t old = f->request.id;
    Matter_Retransmission_Parameters_T updated = {900, 600, true};
    CHECK(matter_retransmission_stop(f->a) == MATTER_PENDING); /* stop still permits the remaining retry */
    CHECK(matter_retransmission_prepare(f->a, f->ids[0], &updated, UINT16_MAX, 430, &f->request) == MATTER_OK);
    CHECK(f->request.id > old && f->request.attempt == 2 && f->request.deadline_ms == 1255);
    CHECK(matter_retransmission_complete(f->a, old, MATTER_RETRANSMISSION_FATAL) == MATTER_INVALID_STATE);
    CHECK(matter_retransmission_stop(f->a) == MATTER_PENDING);
    /* Deferred local completion must not rearm the timer at completion time. */
    CHECK(matter_retransmission_next(f->a, 2000, &f->message) == MATTER_WOULD_BLOCK);
    CHECK(matter_retransmission_take(f->a, &f->result) == MATTER_WOULD_BLOCK);
    CHECK(matter_retransmission_complete(f->a, f->request.id, MATTER_RETRANSMISSION_RETRYABLE) == MATTER_OK);
    CHECK(matter_retransmission_next(f->a, 2000, &f->message) == MATTER_WOULD_BLOCK);
    CHECK(matter_retransmission_take(f->a, &f->result) == MATTER_OK && f->result.outcome == MATTER_RETRANSMISSION_TIMEOUT);
    CHECK(f->result.attempts == 2);
    CHECK(matter_retransmission_add(f->b, &key, 8, f->bytes, 4, &f->ids[0]) == MATTER_OK);
    CHECK(matter_retransmission_prepare(f->b, f->ids[0], &active, 0, 0, &f->other) == MATTER_OK);
    CHECK(matter_retransmission_complete(f->b, f->other.id, MATTER_RETRANSMISSION_FATAL) == MATTER_OK);
    CHECK(matter_retransmission_take(f->b, &f->result) == MATTER_OK && f->result.outcome == MATTER_RETRANSMISSION_FAILED);
    ok = true;
done: cleanup(f); return ok;
}

static bool capacity_and_reordering(void) {
    bool ok = false;
    Fixture* f = create(1);
    uint64_t id = 999;
    CHECK(f && f->a && f->b);
    for (unsigned i = 0; i < 8; ++i) {
        Matter_Exchange_Info_T k = {1 + i / 4, (uint16_t)(i / 2), (i & 1) != 0};
        CHECK(matter_retransmission_add(f->a, &k, i % 4, f->bytes, 1, &f->ids[i]) == MATTER_OK);
    }
    Matter_Exchange_Info_T k = {3, 9, false};
    CHECK(matter_retransmission_add(f->a, &k, 0, f->bytes, 1, &id) == MATTER_LIMIT_REACHED && id == 999);
    k = (Matter_Exchange_Info_T){1, 0, false};
    CHECK(matter_retransmission_add(f->a, &k, 9, f->bytes, 1, &id) == MATTER_BUSY && id == 999);
    k.exchange_id = 10;
    CHECK(matter_retransmission_add(f->a, &k, 1, f->bytes, 1, &id) == MATTER_BUSY && id == 999);
    CHECK(matter_retransmission_next(f->a, 0, &f->message) == MATTER_OK && f->message.id == f->ids[0]);
    CHECK(matter_retransmission_prepare(f->a, f->ids[0], &active, 0, 0, &f->request) == MATTER_OK);
    CHECK(matter_retransmission_complete(f->a, f->request.id, MATTER_RETRANSMISSION_SENT) == MATTER_OK);
    CHECK(matter_retransmission_prepare(f->a, f->ids[1], &idle, 0, 1, &f->request) == MATTER_OK);
    CHECK(matter_retransmission_next(f->a, 330, &f->message) == MATTER_WOULD_BLOCK);
    CHECK(matter_retransmission_take(f->a, &f->result) == MATTER_OK && f->result.message.id == f->ids[0]);
    CHECK(f->result.outcome == MATTER_RETRANSMISSION_TIMEOUT); /* expire another entry while TX occupied */
    k = (Matter_Exchange_Info_T){1, 0, true};
    CHECK(matter_retransmission_ack(f->a, &k, 1) == MATTER_OK);
    CHECK(matter_retransmission_ack(f->a, &k, 1) == MATTER_OK); /* duplicate no extra event */
    CHECK(matter_retransmission_complete(f->a, f->request.id, MATTER_RETRANSMISSION_SENT) == MATTER_OK);
    CHECK(matter_retransmission_take(f->a, &f->result) == MATTER_OK && f->result.message.id == f->ids[1]);
    CHECK(f->result.outcome == MATTER_RETRANSMISSION_ACKNOWLEDGED);
    CHECK(matter_retransmission_take(f->a, &f->result) == MATTER_WOULD_BLOCK);
    for (unsigned i = 8; i-- > 2;) CHECK(matter_retransmission_cancel(f->a, f->ids[i]) == MATTER_OK);
    for (unsigned i = 2; i < 8; ++i) {
        CHECK(matter_retransmission_take(f->a, &f->result) == MATTER_OK && f->result.message.id == f->ids[i]);
        CHECK(f->result.attempts == 0 && f->result.outcome == MATTER_RETRANSMISSION_CANCELLED);
    }
    CHECK(matter_retransmission_add(f->a, &key, 7, f->bytes, 1, &id) == MATTER_OK && id > f->ids[7]);
    CHECK(matter_retransmission_add(f->b, &key, 7, f->bytes, 1, &f->ids[0]) == MATTER_OK);
    CHECK(matter_retransmission_cancel(f->a, id) == MATTER_OK);
    CHECK(matter_retransmission_drained(f->b, &key) == MATTER_PENDING);
    CHECK(matter_retransmission_next(f->b, 0, &f->message) == MATTER_OK);
    ok = true;
done: cleanup(f); return ok;
}

static bool limits_and_jitter(void) {
    bool ok = false;
    Fixture* f = create(5);
    uint64_t deadline = 99, id = 99;
    Matter_Retransmission_Parameters_T big = {UINT32_MAX, UINT32_MAX, true};
    /* ceil(300*1.1*(1 + 32768/(4*65535))) = 372. */
    CHECK(f && f->a && f->b);
    CHECK(matter_retransmission_new(0) == NULL && matter_retransmission_new(6) == NULL);
    CHECK(matter_retransmission_delete(NULL) == MATTER_OK);
    CHECK(matter_retransmission_add(NULL, &key, 0, f->bytes, 1, &id) == MATTER_INVALID_ARGUMENT && id == 99);
    CHECK(matter_retransmission_add(f->a, &key, 0, f->bytes, 0, &id) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_retransmission_add(f->a, &key, 0, f->bytes, 1233, &id) == MATTER_LIMIT_REACHED && id == 99);
    CHECK(matter_retransmission_deadline(f->a, &deadline) == MATTER_WOULD_BLOCK && deadline == 99);
    CHECK(matter_retransmission_add(f->a, &key, 0, f->bytes, 1232, &id) == MATTER_OK);
    CHECK(matter_retransmission_prepare(f->a, id, NULL, 0, 0, &f->request) == MATTER_INVALID_ARGUMENT && !f->request.id);
    CHECK(matter_retransmission_prepare(f->a, id, &active, 32768, 0, &f->request) == MATTER_OK);
    CHECK(f->request.deadline_ms == 372);
    CHECK(matter_retransmission_complete(f->a, f->request.id, (Matter_Retransmission_Tx_Result_T)9) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_retransmission_complete(f->a, f->request.id, MATTER_RETRANSMISSION_SENT) == MATTER_OK);
    uint64_t now = 372;
    for (unsigned n = 1; n < 5; ++n) {
        CHECK(matter_retransmission_prepare(f->a, id, &big, UINT16_MAX, now, &f->request) == MATTER_OK);
        now = f->request.deadline_ms;
        if (n == 4) CHECK(now - deadline == UINT64_C(24189255806)); /* UINT32_MAX * 1.1 * 4.096 * 1.25 */
        deadline = now;
        CHECK(matter_retransmission_complete(f->a, f->request.id, MATTER_RETRANSMISSION_SENT) == MATTER_OK);
    }
    CHECK(matter_retransmission_next(f->a, now, &f->message) == MATTER_WOULD_BLOCK);
    CHECK(matter_retransmission_next(f->a, now - 1, &f->message) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_retransmission_take(f->a, &f->result) == MATTER_OK);
    CHECK(matter_retransmission_add(f->b, &key, 0, f->bytes, 1, &id) == MATTER_OK);
    CHECK(matter_retransmission_prepare(f->b, id, &big, UINT16_MAX, UINT64_MAX - 1, &f->other) == MATTER_OK);
    CHECK(f->other.deadline_ms == UINT64_MAX);
    CHECK(matter_retransmission_complete(f->b, f->other.id, MATTER_RETRANSMISSION_SENT) == MATTER_OK);
    CHECK(matter_retransmission_prepare(f->b, id, &active, 0, UINT64_MAX - 1, &f->other) == MATTER_WOULD_BLOCK);
    CHECK(matter_retransmission_stop(f->b) == MATTER_PENDING);
    CHECK(matter_retransmission_add(f->b, &key, 1, f->bytes, 1, &id) == MATTER_INVALID_STATE);
    CHECK(matter_retransmission_cancel(f->b, id) == MATTER_OK);
    CHECK(matter_retransmission_take(f->b, &f->result) == MATTER_OK && f->result.outcome == MATTER_RETRANSMISSION_CANCELLED);
    ok = true;
done: cleanup(f); return ok;
}

/* Real RX executor -> new ledger through existing port hooks; no protocol I/O. */
typedef struct {
    Matter_T owner;
    Matter_Rx_T rx;
    Matter_Retransmission_T tx;
    Matter_Retransmission_Request_T request;
    Matter_Retransmission_Result_T result;
    uint8_t bytes[16];
    unsigned pins, dependencies, deliveries;
} Integration;
static Matter_Result_T retain(void* u, Matter_Exchange_Session_T s) { (void)s; ++((Integration*)u)->pins; return MATTER_OK; }
static void release(void* u, Matter_Exchange_Session_T s) { (void)s; Integration* f = u; if (!f->pins) abort(); --f->pins; }
static Matter_Result_T ack(void* u, const Matter_Exchange_Info_T* k, uint32_t c) {
    return matter_retransmission_ack(((Integration*)u)->tx, k, c);
}
static Matter_Result_T closed(void* u, const Matter_Exchange_Info_T* k) {
    return matter_retransmission_drained(((Integration*)u)->tx, k);
}
static void delivered(void* u, const Matter_Rx_Decision_T* d) { (void)d; ++((Integration*)u)->deliveries; }
static Matter_Result_T stop_dependencies(void* u) {
    Integration* f = u;
    if (f->pins || matter_retransmission_stop(f->tx) != MATTER_OK) abort();
    ++f->dependencies; return MATTER_OK;
}
static Matter_Result_T unused_send(void* u, uint64_t r, const Matter_Ack_Message_T* m) { (void)u; (void)r; (void)m; abort(); }
static void detach(void* u) { (void)u; }
static bool rx_integration(void) {
    bool ok = false;
    Integration* f = calloc(1, sizeof(*f));
    Matter_Exchange_Handle_T handle = 0;
    Matter_Exchange_Info_T info;
    uint64_t id = 0;
    static const uint8_t wire[] = {2, 0x10, 0x34, 0x12, 0, 0, 0, 0, 0, 0}; /* peer responder ACK counter 0 */
    CHECK(f);
    f->owner = matter_new(NULL); f->tx = matter_retransmission_new(5);
    Matter_Rx_Port_T port = {f, {f, unused_send, detach}, retain, release, ack, closed, delivered, stop_dependencies};
    f->rx = matter_rx_new(f->owner, 0x1234, &port);
    CHECK(f->owner && f->tx && f->rx);
    CHECK(matter_start(f->owner) == MATTER_OK && matter_rx_start(f->rx) == MATTER_OK);
    CHECK(matter_rx_initiate(f->rx, 1, &handle) == MATTER_OK && f->pins == 1);
    CHECK(matter_rx_get(f->rx, handle, &info) == MATTER_OK);
    CHECK(matter_retransmission_add(f->tx, &info, 0, f->bytes, sizeof(f->bytes), &id) == MATTER_OK);
    CHECK(matter_retransmission_prepare(f->tx, id, &active, 0, 0, &f->request) == MATTER_OK);
    CHECK(matter_rx_stop(f->rx) == MATTER_PENDING && matter_rx_process(f->rx, 0) == MATTER_PENDING);
    Matter_Rx_Input_T input = {1, 23, true, wire, sizeof(wire)};
    CHECK(matter_rx_receive(f->rx, &input, 1) == MATTER_OK && matter_rx_process(f->rx, 1) == MATTER_PENDING);
    CHECK(!f->deliveries && !f->dependencies && f->pins == 1);
    CHECK(matter_retransmission_take(f->tx, &f->result) == MATTER_WOULD_BLOCK);
    CHECK(matter_rx_get(f->rx, handle, &info) == MATTER_OK);
    CHECK(matter_retransmission_complete(f->tx, f->request.id, MATTER_RETRANSMISSION_SENT) == MATTER_OK);
    CHECK(matter_rx_process(f->rx, 2) == MATTER_PENDING && f->pins == 1);
    CHECK(matter_retransmission_take(f->tx, &f->result) == MATTER_OK && f->result.outcome == MATTER_RETRANSMISSION_ACKNOWLEDGED);
    CHECK(matter_rx_process(f->rx, 2) == MATTER_OK && !f->pins && f->dependencies == 1);
    ok = true;
done:
    if (f) {
        if (f->tx && id) matter_retransmission_cancel(f->tx, id);
        if (f->tx && f->request.id) matter_retransmission_complete(f->tx, f->request.id, MATTER_RETRANSMISSION_FATAL);
        if (f->tx) while (matter_retransmission_take(f->tx, &f->result) == MATTER_OK) {}
        if (f->rx) {
            matter_rx_stop(f->rx);
            if (matter_get_state(f->owner) == MATTER_STATE_RUNNING) matter_rx_process(f->rx, UINT64_MAX);
            if (matter_rx_delete(f->rx) != MATTER_OK) abort();
        }
        if (matter_retransmission_delete(f->tx) != MATTER_OK) abort();
        matter_stop(f->owner); if (matter_delete(f->owner) != MATTER_OK) abort(); free(f);
    }
    return ok;
}

#ifdef MATTER_TEST_ALLOC
static bool allocation(void) {
    bool ok = false;
    Fixture* f = create(5);
    CHECK(f && f->a && f->b && live == 2);
    printf("Retransmission table: %zu bytes\n", last_size);
    fail_next = true;
    CHECK(matter_retransmission_new(5) == NULL && live == 2);
    size_t baseline = calls;
    for (unsigned i = 0; i < 1000; ++i) {
        CHECK(matter_retransmission_add(f->a, &key, i, f->bytes, 1, &f->ids[0]) == MATTER_OK);
        CHECK(matter_retransmission_prepare(f->a, f->ids[0], &active, 0, i, &f->request) == MATTER_OK);
        CHECK(matter_retransmission_ack(f->a, &key, i) == MATTER_OK);
        CHECK(matter_retransmission_complete(f->a, f->request.id, MATTER_RETRANSMISSION_SENT) == MATTER_OK);
        CHECK(matter_retransmission_take(f->a, &f->result) == MATTER_OK);
    }
    CHECK(calls == baseline);
    ok = true;
done: fail_next = false; cleanup(f); return ok && !live;
}
#endif

int main(void) {
    unsigned passed = 0;
#define RUN(t) do { if (!(t)()) return 1; ++passed; } while (0)
    RUN(normative_backoff); RUN(inflight_ack_and_cancel); RUN(retry_errors_and_updates);
    RUN(capacity_and_reordering); RUN(limits_and_jitter); RUN(rx_integration);
#ifdef MATTER_TEST_ALLOC
    RUN(allocation);
    if (live) return 1;
#endif
    printf("PASS retransmission: %u groups\n", passed);
    return 0;
}

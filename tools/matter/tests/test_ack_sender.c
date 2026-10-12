#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "transport/matter_ack_sender.h"

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
    Matter_Ack_Table_T table;
    Matter_Ack_Sender_T sender, target;
    const Matter_Ack_Message_T* retained;
    Matter_Ack_Message_T snapshot;
    Matter_Ack_Request_T external;
    uint8_t bytes[10];
    uint64_t request, binding;
    Matter_Result_T submission;
    unsigned sends, detaches, probes, violations;
    bool probe;
} Fixture;

static void probe(Fixture* f) {
    if (!f->probe) return;
    ++f->probes;
    if (matter_ack_sender_process(f->sender, 0) != MATTER_BUSY) ++f->violations;
    if (matter_ack_sender_stop(f->sender) != MATTER_BUSY) ++f->violations;
    if (matter_ack_sender_delete(f->sender) != MATTER_BUSY) ++f->violations;
    if (matter_ack_sender_complete(f->sender, f->request, MATTER_OPERATION_SUCCEEDED) != MATTER_BUSY)
        ++f->violations;
}

static Matter_Result_T send_message(void* user, uint64_t request, const Matter_Ack_Message_T* message) {
    Fixture* f = user;
    ++f->sends;
    if (f->retained || !request || !message || !message->data || message->size != sizeof(f->bytes)) abort();
    f->request = request;
    f->snapshot = *message;
    memcpy(f->bytes, message->data, sizeof(f->bytes));
    probe(f);
    if (f->submission == MATTER_OK) f->retained = message;
    return f->submission;
}

static void detach(void* user) {
    Fixture* f = user;
    ++f->detaches;
    probe(f);
    if (f->retained) ++f->violations;
    f->target = NULL; /* Invalidate routing, including delayed duplicate events. */
}

static bool attach(Fixture* f) {
    Matter_Ack_Port_T port = {f, send_message, detach};
    f->sender = matter_ack_sender_new(f->table, &port);
    f->target = f->sender;
    ++f->binding;
    /* Sender must have copied the port, not borrowed its stack descriptor. */
    port = (Matter_Ack_Port_T){0};
    return f->sender != NULL;
}

static Fixture* create(void) {
    Fixture* f = calloc(1, sizeof(*f));
    if (!f) return NULL;
    f->table = matter_ack_new();
    if (!f->table || !attach(f)) {
        matter_ack_delete(f->table); free(f); return NULL;
    }
    return f;
}

static bool unchanged(Fixture* f) {
    return f->retained && f->retained->data == f->snapshot.data &&
        f->retained->size == sizeof(f->bytes) &&
        f->retained->exchange.session == f->snapshot.exchange.session &&
        f->retained->exchange.exchange_id == f->snapshot.exchange.exchange_id &&
        f->retained->exchange.initiator == f->snapshot.exchange.initiator &&
        memcmp(f->retained->data, f->bytes, sizeof(f->bytes)) == 0;
}

static bool deliver(Fixture* f, uint64_t binding, uint64_t request, Matter_Operation_Result_T result) {
    if (!f->target || binding != f->binding || request != f->request || !f->retained) return false;
    if (!unchanged(f)) abort();
    const Matter_Ack_Message_T* saved = f->retained;
    f->retained = NULL; /* Drop byte/descriptor references BEFORE terminal event. */
    if (matter_ack_sender_complete(f->target, request, result) != MATTER_OK) {
        f->retained = saved; return false;
    }
    return true;
}

static void cleanup(Fixture* f) {
    if (!f) return;
    f->probe = false;
    f->submission = MATTER_OK;
    if (f->external.id) matter_ack_complete(f->table, f->external.id, MATTER_OPERATION_FAILED);
    if (f->sender) {
        unsigned steps = 0;
        while (matter_ack_sender_stop(f->sender) == MATTER_PENDING) {
            if (++steps > 12) abort();
            if (f->retained) {
                if (!deliver(f, f->binding, f->request, MATTER_OPERATION_SUCCEEDED)) abort();
            } else if (matter_ack_sender_process(f->sender, UINT64_MAX) != MATTER_PENDING) abort();
        }
        if (matter_ack_sender_delete(f->sender) != MATTER_OK) abort();
    }
    if (matter_ack_delete(f->table) != MATTER_OK) abort();
    free(f);
}

/* Independent literal expected bytes, NOT decoded/re-encoded by our codec. */
static const uint8_t responder[] = {0x02, 0x10, 0x34, 0x12, 0, 0, 0x12, 0x34, 0x56, 0x78};
static const uint8_t initiator_zero[] = {0x03, 0x10, 0xff, 0xff, 0, 0, 0, 0, 0, 0};
static const uint8_t responder_max[] = {0x02, 0x10, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff};

static bool wire_and_lifetime(void) {
    bool ok = false;
    Fixture* f = create();
    Matter_Exchange_Info_T key = {17, 0x1234, false};
    CHECK(f);
    CHECK(matter_ack_record(f->table, &key, 0x78563412, 1000) == MATTER_OK);
    CHECK(matter_ack_sender_process(f->sender, 1199) == MATTER_WOULD_BLOCK && !f->sends);
    CHECK(matter_ack_sender_process(f->sender, 1198) == MATTER_INVALID_ARGUMENT && !f->sends);
    CHECK(matter_ack_sender_process(f->sender, 1200) == MATTER_PENDING && f->sends == 1);
    CHECK(unchanged(f) && memcmp(f->retained->data, responder, sizeof(responder)) == 0);
    CHECK(f->retained->exchange.session == 17 && !f->retained->exchange.initiator);
    CHECK(matter_ack_sender_delete(f->sender) == MATTER_INVALID_STATE);
    CHECK(matter_ack_close(f->table, &key) == MATTER_PENDING);
    CHECK(matter_ack_immediate(f->table, &(Matter_Exchange_Info_T){18, UINT16_MAX, true}, 0) == MATTER_OK);
    key = (Matter_Exchange_Info_T){99, 99, true}; /* no pointer to input retained */
    for (unsigned i = 0; i < 5; ++i)
        CHECK(matter_ack_sender_process(f->sender, 1200 + i) == MATTER_PENDING && f->sends == 1 && unchanged(f));
    CHECK(matter_ack_sender_complete(f->sender, f->request + 1, MATTER_OPERATION_SUCCEEDED) == MATTER_INVALID_STATE);
    CHECK(matter_ack_sender_complete(f->sender, f->request, (Matter_Operation_Result_T)99) == MATTER_INVALID_ARGUMENT);
    CHECK(unchanged(f));
    uint64_t old = f->request;
    CHECK(deliver(f, f->binding, old, MATTER_OPERATION_SUCCEEDED));
    CHECK(matter_ack_close(f->table, &(Matter_Exchange_Info_T){17, 0x1234, false}) == MATTER_OK);
    CHECK(matter_ack_sender_process(f->sender, 1205) == MATTER_PENDING && f->request > old);
    CHECK(memcmp(f->retained->data, initiator_zero, sizeof(initiator_zero)) == 0);
    CHECK(matter_ack_sender_complete(f->sender, old, MATTER_OPERATION_SUCCEEDED) == MATTER_INVALID_STATE);
    CHECK(deliver(f, f->binding, f->request, MATTER_OPERATION_SUCCEEDED));
    CHECK(matter_ack_immediate(f->table, &(Matter_Exchange_Info_T){18, 0, false}, UINT32_MAX) == MATTER_OK);
    CHECK(matter_ack_sender_process(f->sender, 1205) == MATTER_PENDING);
    CHECK(memcmp(f->retained->data, responder_max, sizeof(responder_max)) == 0);
    CHECK(deliver(f, f->binding, f->request, MATTER_OPERATION_SUCCEEDED));
    CHECK(matter_ack_sender_process(f->sender, 1205) == MATTER_WOULD_BLOCK && f->sends == 3);
    ok = true;
done: cleanup(f); return ok;
}

static bool rejection_and_retry(void) {
    bool ok = false;
    Fixture* f = create();
    Matter_Exchange_Info_T key = {1, 1, false};
    static const Matter_Result_T rejected[] = {
        MATTER_WOULD_BLOCK, MATTER_OFFLINE, MATTER_PORT_ERROR, MATTER_BUSY, MATTER_PENDING, (Matter_Result_T)99
    };
    CHECK(f);
    CHECK(matter_ack_record(f->table, &key, 1, 0) == MATTER_OK);
    CHECK(matter_ack_record(f->table, &key, 2, 50) == MATTER_WOULD_BLOCK);
    uint64_t previous = 0;
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
        f->submission = rejected[i];
        Matter_Result_T expected = i < 3 ? rejected[i] : MATTER_PORT_ERROR;
        CHECK(matter_ack_sender_process(f->sender, 50) == expected);
        CHECK(!f->retained && f->request > previous && f->sends == i + 1);
        CHECK(f->bytes[6] == 1); /* rejection did not silently replace the old counter */
        CHECK(matter_ack_sender_complete(f->sender, f->request, MATTER_OPERATION_SUCCEEDED) == MATTER_INVALID_STATE);
        CHECK(matter_ack_record(f->table, &key, 2, 50) == MATTER_WOULD_BLOCK);
        previous = f->request;
    }
    f->submission = MATTER_OK;
    CHECK(matter_ack_sender_process(f->sender, 50) == MATTER_PENDING && f->bytes[6] == 1);
    CHECK(deliver(f, f->binding, f->request, MATTER_OPERATION_FAILED));
    CHECK(matter_ack_sender_process(f->sender, 50) == MATTER_PENDING && f->bytes[6] == 1);
    CHECK(deliver(f, f->binding, f->request, MATTER_OPERATION_CANCELLED));
    CHECK(matter_ack_sender_process(f->sender, 300) == MATTER_PENDING && f->bytes[6] == 1);
    CHECK(deliver(f, f->binding, f->request, MATTER_OPERATION_SUCCEEDED));
    CHECK(matter_ack_record(f->table, &key, 2, 50) == MATTER_OK); /* retain original RX time */
    CHECK(matter_ack_sender_process(f->sender, 300) == MATTER_PENDING && f->bytes[6] == 2);
    CHECK(deliver(f, f->binding, f->request, MATTER_OPERATION_SUCCEEDED));
    CHECK(matter_ack_sender_process(f->sender, 500) == MATTER_WOULD_BLOCK);
    ok = true;
done: cleanup(f); return ok;
}

static bool stop_and_reentry(void) {
    bool ok = false;
    Fixture* f = create();
    Matter_Exchange_Info_T key = {1, 1, false}, other = {1, 2, false}, ephemeral = {2, 3, true};
    CHECK(f);
    f->probe = true;
    CHECK(matter_ack_record(f->table, &key, 1, 0) == MATTER_OK);
    CHECK(matter_ack_record(f->table, &other, 2, 0) == MATTER_OK);
    CHECK(matter_ack_immediate(f->table, &ephemeral, 3) == MATTER_OK);
    CHECK(matter_ack_sender_process(f->sender, 0) == MATTER_PENDING && f->bytes[6] == 3);
    CHECK(matter_ack_sender_stop(f->sender) == MATTER_PENDING);
    CHECK(matter_ack_record(f->table, &key, 4, 0) == MATTER_INVALID_STATE);
    CHECK(matter_ack_immediate(f->table, &key, 4) == MATTER_INVALID_STATE);
    CHECK(matter_ack_sender_delete(f->sender) == MATTER_INVALID_STATE && !f->detaches);
    CHECK(matter_ack_sender_process(f->sender, 0) == MATTER_PENDING && f->sends == 1 && unchanged(f));
    CHECK(deliver(f, f->binding, f->request, MATTER_OPERATION_CANCELLED));
    CHECK(matter_ack_sender_stop(f->sender) == MATTER_PENDING);
    f->submission = MATTER_OFFLINE;
    CHECK(matter_ack_sender_process(f->sender, 0) == MATTER_OFFLINE);
    CHECK(matter_ack_sender_stop(f->sender) == MATTER_PENDING && !f->detaches);
    f->submission = MATTER_OK;
    CHECK(matter_ack_sender_process(f->sender, 0) == MATTER_PENDING && f->bytes[6] == 3);
    CHECK(deliver(f, f->binding, f->request, MATTER_OPERATION_SUCCEEDED));
    for (unsigned i = 1; i <= 2; ++i) {
        CHECK(matter_ack_sender_stop(f->sender) == MATTER_PENDING);
        CHECK(matter_ack_sender_process(f->sender, 0) == MATTER_PENDING && f->bytes[6] == i);
        CHECK(matter_ack_sender_delete(f->sender) == MATTER_INVALID_STATE);
        CHECK(deliver(f, f->binding, f->request, MATTER_OPERATION_SUCCEEDED));
    }
    CHECK(matter_ack_sender_process(f->sender, 0) == MATTER_OK);
    CHECK(matter_ack_sender_stop(f->sender) == MATTER_OK && !f->detaches);
    CHECK(matter_ack_sender_delete(f->sender) == MATTER_OK);
    f->sender = NULL;
    CHECK(f->detaches == 1 && !f->target && f->probes == f->sends + 1 && !f->violations);
    CHECK(!deliver(f, f->binding, f->request, MATTER_OPERATION_SUCCEEDED));
    ok = true;
done: cleanup(f); return ok;
}

static bool external_piggyback(void) {
    bool ok = false;
    Fixture* f = create();
    Matter_Exchange_Info_T key = {1, 1, false};
    CHECK(f);
    CHECK(matter_ack_record(f->table, &key, 1, 0) == MATTER_OK);
    CHECK(matter_ack_piggyback(f->table, &key, &f->external) == MATTER_OK);
    CHECK(matter_ack_sender_process(f->sender, 200) == MATTER_WOULD_BLOCK && !f->sends);
    CHECK(matter_ack_sender_complete(f->sender, f->external.id, MATTER_OPERATION_SUCCEEDED) == MATTER_INVALID_STATE);
    CHECK(matter_ack_sender_stop(f->sender) == MATTER_PENDING);
    CHECK(matter_ack_sender_delete(f->sender) == MATTER_INVALID_STATE);
    CHECK(matter_ack_complete(f->table, f->external.id, MATTER_OPERATION_FAILED) == MATTER_OK);
    f->external.id = 0;
    CHECK(matter_ack_sender_process(f->sender, 200) == MATTER_PENDING);
    CHECK(deliver(f, f->binding, f->request, MATTER_OPERATION_SUCCEEDED));
    CHECK(matter_ack_sender_stop(f->sender) == MATTER_OK);
    ok = true;
done: cleanup(f); return ok;
}

static bool instances_and_binding(void) {
    bool ok = false;
    Fixture* f = create();
    Fixture* g = create();
    Matter_Exchange_Info_T key = {1, 1, false};
    CHECK(f && g);
    CHECK(matter_ack_immediate(f->table, &key, 1) == MATTER_OK);
    CHECK(matter_ack_immediate(g->table, &key, 2) == MATTER_OK);
    CHECK(matter_ack_sender_process(f->sender, 0) == MATTER_PENDING);
    CHECK(matter_ack_sender_process(g->sender, 0) == MATTER_PENDING);
    CHECK(f->request == g->request && f->bytes[6] == 1 && g->bytes[6] == 2);
    CHECK(f->retained->data != g->retained->data);
    uint64_t old_binding = f->binding, old_request = f->request;
    CHECK(matter_ack_sender_stop(f->sender) == MATTER_PENDING);
    CHECK(deliver(f, f->binding, f->request, MATTER_OPERATION_SUCCEEDED));
    CHECK(matter_ack_sender_stop(f->sender) == MATTER_OK);
    CHECK(matter_ack_sender_delete(f->sender) == MATTER_OK);
    f->sender = NULL;
    CHECK(matter_ack_delete(f->table) == MATTER_OK);
    f->table = matter_ack_new();
    CHECK(f->table && attach(f));
    CHECK(matter_ack_immediate(f->table, &key, 3) == MATTER_OK);
    CHECK(matter_ack_sender_process(f->sender, 0) == MATTER_PENDING);
    CHECK(f->request == old_request && f->binding != old_binding);
    CHECK(!deliver(f, old_binding, old_request, MATTER_OPERATION_SUCCEEDED));
    CHECK(unchanged(f) && unchanged(g));
    CHECK(deliver(f, f->binding, f->request, MATTER_OPERATION_SUCCEEDED));
    CHECK(deliver(g, g->binding, g->request, MATTER_OPERATION_FAILED));
    CHECK(matter_ack_sender_process(g->sender, 0) == MATTER_PENDING && g->bytes[6] == 2);
    CHECK(deliver(g, g->binding, g->request, MATTER_OPERATION_SUCCEEDED));
    ok = true;
done: cleanup(f); cleanup(g); return ok;
}

static bool arguments(void) {
    bool ok = false;
    Fixture* f = create();
    CHECK(f);
    Matter_Ack_Port_T port = {f, send_message, detach};
    CHECK(!matter_ack_sender_new(NULL, &port));
    CHECK(!matter_ack_sender_new(f->table, NULL));
    port.send = NULL;
    CHECK(!matter_ack_sender_new(f->table, &port));
    port.send = send_message; port.detach = NULL;
    CHECK(!matter_ack_sender_new(f->table, &port));
    CHECK(matter_ack_sender_delete(NULL) == MATTER_OK);
    CHECK(matter_ack_sender_stop(NULL) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_ack_sender_process(NULL, 0) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_ack_sender_complete(NULL, 1, MATTER_OPERATION_SUCCEEDED) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_ack_sender_complete(f->sender, 0, MATTER_OPERATION_SUCCEEDED) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_ack_sender_complete(f->sender, 1, (Matter_Operation_Result_T)99) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_ack_sender_complete(f->sender, 1, MATTER_OPERATION_SUCCEEDED) == MATTER_INVALID_STATE);
    CHECK(matter_ack_sender_delete(f->sender) == MATTER_INVALID_STATE);
    CHECK(!f->sends && !f->detaches);
    CHECK(matter_ack_sender_stop(f->sender) == MATTER_OK);
    CHECK(matter_ack_sender_process(f->sender, 0) == MATTER_OK && !f->sends);
    ok = true;
done: cleanup(f); return ok;
}

#ifdef MATTER_TEST_ALLOC
static bool allocation(void) {
    bool ok = false;
    Fixture* f = create();
    CHECK(f && live == 2);
    printf("ACK sender context: %zu bytes\n", last_size);
    Matter_Ack_Port_T port = {f, send_message, detach};
    fail_next = true;
    CHECK(!matter_ack_sender_new(f->table, &port) && live == 2 && !f->sends && !f->detaches);
    size_t before = allocations;
    Matter_Exchange_Info_T key = {1, 1, false};
    for (unsigned i = 0; i < 1000; ++i) {
        CHECK(matter_ack_immediate(f->table, &key, i) == MATTER_OK);
        CHECK(matter_ack_sender_process(f->sender, i) == MATTER_PENDING);
        CHECK(deliver(f, f->binding, f->request, MATTER_OPERATION_SUCCEEDED));
    }
    CHECK(allocations == before);
    ok = true;
done: cleanup(f); return ok && live == 0;
}
#endif

int main(void) {
    unsigned passed = 0;
#define RUN(t) do { if (!(t)()) return 1; ++passed; } while (0)
    RUN(wire_and_lifetime); RUN(rejection_and_retry); RUN(stop_and_reentry);
    RUN(external_piggyback); RUN(instances_and_binding); RUN(arguments);
#ifdef MATTER_TEST_ALLOC
    RUN(allocation);
    if (live) return 1;
#endif
    printf("PASS ACK sender: %u groups\n", passed);
    return 0;
}

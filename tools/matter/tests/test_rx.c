#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "transport/matter_rx.h"
#include "matter_udp.h"

#ifdef MATTER_TEST_ALLOC
static size_t live, calls, fail_at, context_size;
void* matter_test_calloc(size_t n, size_t size) {
    ++calls;
    if (calls == fail_at) return NULL;
    void* p = calloc(n, size);
    if (p) { ++live; if (n * size > context_size) context_size = n * size; }
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
    Matter_Udp_T udp;
    Matter_Rx_T rx;
    Matter_Rx_Port_T port;
    Matter_Rx_Input_T input;
    Matter_Rx_Decision_T delivered;
    Matter_Exchange_Info_T ack_key;
    const Matter_Ack_Message_T* retained;
    uint64_t request;
    uint8_t wire[MATTER_RX_MAX_PLAINTEXT + 1], sent[10];
    unsigned pins[4], sends, deliveries, acks, ack_calls, dependencies, detaches, deactivations, violations;
    uint32_t ack_counter;
    uint8_t payload;
    Matter_Result_T submission, retention, ack_result, tx_drain, dependency_result;
    bool started, probe, clear_tx_on_ack;
} Fixture;

static unsigned pins(Fixture* f) { return f->pins[1] + f->pins[2] + f->pins[3]; }

static void reentry(Fixture* f) {
    if (!f->probe) return;
    Matter_Exchange_Handle_T handle = 99;
    Matter_Exchange_Info_T info = {0};
    if (matter_rx_start(f->rx) != MATTER_BUSY || matter_rx_stop(f->rx) != MATTER_BUSY ||
        matter_rx_delete(f->rx) != MATTER_BUSY || matter_rx_process(f->rx, 0) != MATTER_BUSY ||
        matter_rx_receive(f->rx, &f->input, 0) != MATTER_BUSY ||
        matter_rx_complete(f->rx, 1, MATTER_OPERATION_SUCCEEDED) != MATTER_BUSY ||
        matter_rx_register(f->rx, 0, 1) != MATTER_BUSY || matter_rx_unregister(f->rx, 0, 1) != MATTER_BUSY ||
        matter_rx_initiate(f->rx, 1, &handle) != MATTER_BUSY || matter_rx_get(f->rx, 1, &info) != MATTER_BUSY ||
        matter_rx_close(f->rx, 1) != MATTER_BUSY ||
        matter_rx_retire_session(f->rx, 1) != MATTER_BUSY || handle != 99) ++f->violations;
}

static Matter_Result_T retain(void* user, Matter_Exchange_Session_T session) {
    Fixture* f = user;
    reentry(f);
    if (!session || session >= 4) abort();
    if (f->retention == MATTER_OK) ++f->pins[session];
    return f->retention;
}
static void release(void* user, Matter_Exchange_Session_T session) {
    Fixture* f = user;
    reentry(f);
    if (!session || session >= 4 || !f->pins[session]) abort();
    --f->pins[session];
    if (f->retained && !f->pins[f->retained->exchange.session]) ++f->violations;
}
static Matter_Result_T process_ack(void* user, const Matter_Exchange_Info_T* key, uint32_t counter) {
    Fixture* f = user;
    reentry(f);
    ++f->ack_calls;
    if (!f->pins[key->session]) ++f->violations;
    if (f->ack_result == MATTER_OK) {
        ++f->acks; f->ack_key = *key; f->ack_counter = counter;
        if (f->clear_tx_on_ack) f->tx_drain = MATTER_OK;
    }
    return f->ack_result;
}
static Matter_Result_T drained(void* user, const Matter_Exchange_Info_T* key) {
    Fixture* f = user;
    reentry(f);
    if (!f->pins[key->session] || !matter_udp_is_active(f->udp)) ++f->violations;
    return f->tx_drain;
}
static void deliver(void* user, const Matter_Rx_Decision_T* d) {
    Fixture* f = user;
    reentry(f);
    ++f->deliveries;
    if (!d->exchange || f->pins[d->session] < 2 || d->payload == f->wire + 6) ++f->violations;
    f->delivered = *d;
    f->delivered.payload = NULL;
    f->payload = d->payload_size ? d->payload[0] : 0;
}
static Matter_Result_T send_ack(void* user, uint64_t request, const Matter_Ack_Message_T* message) {
    Fixture* f = user;
    reentry(f);
    if (f->retained || !request || message->size != 10 || !f->pins[message->exchange.session] ||
        !matter_udp_is_active(f->udp) || f->deactivations || matter_get_state(f->owner) != MATTER_STATE_RUNNING)
        ++f->violations;
    ++f->sends;
    if (f->submission == MATTER_OK) {
        f->request = request; f->retained = message;
        memcpy(f->sent, message->data, sizeof(f->sent));
    }
    return f->submission;
}
static void detach_ack(void* user) {
    Fixture* f = user;
    reentry(f);
    if (f->retained || pins(f)) ++f->violations;
    ++f->detaches;
}
static Matter_Result_T activate(void* user, Matter_Operation_Id_T epoch) { (void)user; (void)epoch; return MATTER_OK; }
static void deactivate(void* user, Matter_Operation_Id_T epoch) {
    Fixture* f = user;
    (void)epoch;
    if (pins(f) || f->retained) ++f->violations;
    ++f->deactivations;
}
static Matter_Result_T unused_send(void* user, uint64_t request, const Matter_Udp_Datagram_T* datagram) {
    (void)user; (void)request; (void)datagram;
    abort(); /* Never send plaintext ACK as a UDP packet. */
}
static void unused_cancel(void* user, uint64_t request) { (void)user; (void)request; abort(); }
static void detach_udp(void* user) { (void)user; }
static Matter_Result_T dependencies(void* user) {
    Fixture* f = user;
    reentry(f);
    ++f->dependencies;
    if (pins(f) || f->retained || matter_get_state(f->owner) != MATTER_STATE_RUNNING) ++f->violations;
    if (f->dependency_result != MATTER_OK) return f->dependency_result;
    Matter_Result_T result = matter_udp_stop(f->udp);
    return result == MATTER_PENDING ? matter_udp_process(f->udp) : result;
}

static bool finish(Fixture* f, Matter_Operation_Result_T result) {
    if (!f->retained || memcmp(f->sent, f->retained->data, sizeof(f->sent))) return false;
    f->retained = NULL;
    return matter_rx_complete(f->rx, f->request, result) == MATTER_OK;
}

static void cleanup(Fixture* f) {
    if (!f) return;
    f->probe = false;
    f->retention = f->submission = f->ack_result = f->tx_drain = f->dependency_result = MATTER_OK;
    if (f->rx) {
        matter_rx_stop(f->rx);
        if (f->started) {
            unsigned steps = 0;
            for (;;) {
                if (++steps > 64) abort();
                if (f->retained && !finish(f, MATTER_OPERATION_SUCCEEDED)) abort();
                Matter_Result_T result = matter_rx_process(f->rx, UINT64_MAX);
                if (result == MATTER_OK) break;
                if (result != MATTER_PENDING) abort();
            }
        }
        if (matter_rx_delete(f->rx) != MATTER_OK) abort();
    }
    if (f->udp) {
        matter_udp_stop(f->udp);
        matter_udp_process(f->udp); matter_udp_process(f->udp);
        if (matter_udp_delete(f->udp) != MATTER_OK) abort();
    }
    matter_stop(f->owner);
    if (matter_delete(f->owner) != MATTER_OK || pins(f) || f->violations) abort();
    free(f);
}

static Fixture* create(bool start) {
    Fixture* f = calloc(1, sizeof(*f));
    if (!f) return NULL;
    f->owner = matter_new(NULL);
    Matter_Udp_Port_T udp = {f, activate, deactivate, unused_send, unused_cancel, detach_udp};
    f->udp = matter_udp_new(f->owner, &udp, NULL);
    f->port = (Matter_Rx_Port_T){f, {f, send_ack, detach_ack}, retain, release, process_ack, drained, deliver, dependencies};
    f->rx = matter_rx_new(f->owner, 0x1234, &f->port);
    if (!f->owner || !f->udp || !f->rx) { cleanup(f); return NULL; }
    if (matter_start(f->owner) != MATTER_OK || matter_udp_start(f->udp) != MATTER_OK ||
        matter_rx_register(f->rx, 0, 1) != MATTER_OK) abort();
    if (start) {
        if (matter_rx_start(f->rx) != MATTER_OK) abort();
        f->started = true;
    }
    f->probe = true;
    return f;
}

/* Independent literal bytes, not generated by the production writer. */
static void packet(Fixture* f, uint8_t flags, uint16_t protocol, uint32_t counter, bool duplicate) {
    memset(f->wire, 0, sizeof(f->wire));
    f->wire[0] = flags; f->wire[1] = 1; f->wire[2] = 0x34; f->wire[3] = 0x12;
    f->wire[4] = (uint8_t)protocol; f->wire[5] = (uint8_t)(protocol >> 8);
    size_t header = flags & 2 ? 10 : 6;
    f->wire[header] = 0xa5;
    f->input = (Matter_Rx_Input_T){1, counter, duplicate, f->wire, header + 1};
}

static bool owned_retry(void) {
    bool ok = false;
    Fixture* f = create(true);
    CHECK(f);
    packet(f, 5, 1, 1, false);
    CHECK(matter_rx_receive(f->rx, &f->input, 1000) == MATTER_OK && pins(f) == 1);
    memset(f->wire, 0xcc, sizeof(f->wire));
    CHECK(matter_rx_process(f->rx, 999) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_rx_process(f->rx, 1000) == MATTER_OK && f->deliveries == 1 && f->payload == 0xa5);
    Matter_Exchange_Handle_T handle = f->delivered.exchange;
    CHECK(pins(f) == 1 && !f->sends);
    packet(f, 7, 1, 2, false);
    CHECK(matter_rx_receive(f->rx, &f->input, 1010) == MATTER_OK);
    CHECK(matter_rx_process(f->rx, 1010) == MATTER_PENDING && f->deliveries == 1 && f->acks == 1);
    CHECK(f->sent[0] == 2 && f->sent[1] == 0x10 && f->sent[6] == 1 && pins(f) == 2);
    CHECK(matter_rx_receive(f->rx, &f->input, 1010) == MATTER_WOULD_BLOCK && pins(f) == 2);
    memset(f->wire, 0xdd, sizeof(f->wire));
    CHECK(matter_rx_process(f->rx, 1100) == MATTER_PENDING && f->acks == 1 && f->ack_calls == 1);
    CHECK(finish(f, MATTER_OPERATION_FAILED));
    f->submission = MATTER_OFFLINE;
    CHECK(matter_rx_process(f->rx, 1200) == MATTER_OFFLINE && f->deliveries == 1);
    f->submission = MATTER_OK;
    CHECK(matter_rx_process(f->rx, 1250) == MATTER_PENDING && f->sent[6] == 1);
    CHECK(finish(f, MATTER_OPERATION_SUCCEEDED));
    CHECK(matter_rx_process(f->rx, 1300) == MATTER_PENDING && f->deliveries == 2 && f->sent[6] == 2);
    /* Original 1010 + 200 has expired; retry at 1300 must NOT rearm to 1500. */
    CHECK(f->payload == 0xa5 && f->acks == 1 && f->delivered.exchange == handle && pins(f) == 1);
    CHECK(matter_rx_close(f->rx, handle) == MATTER_PENDING);
    CHECK(finish(f, MATTER_OPERATION_SUCCEEDED));
    CHECK(matter_rx_complete(f->rx, f->request, MATTER_OPERATION_SUCCEEDED) == MATTER_INVALID_STATE);
    CHECK(matter_rx_process(f->rx, 1300) == MATTER_OK && pins(f) == 0);
    CHECK(!f->violations);
    ok = true;
done: cleanup(f); return ok;
}

static bool ephemeral_roles(void) {
    bool ok = false;
    Fixture* f = create(true);
    CHECK(f);
    for (unsigned role = 0; role < 2; ++role) {
        packet(f, (uint8_t)(6 | role), 3, 0, true); /* unsupported, duplicate, A/R */
        CHECK(matter_rx_receive(f->rx, &f->input, role) == MATTER_OK);
        f->submission = MATTER_WOULD_BLOCK;
        CHECK(matter_rx_process(f->rx, role) == MATTER_PENDING && pins(f) == 1);
        CHECK(!f->deliveries && f->acks == role + 1 && f->ack_counter == 0);
        CHECK(f->ack_key.initiator == !role && f->ack_key.exchange_id == 0x1234);
        f->submission = MATTER_OK;
        CHECK(matter_rx_process(f->rx, role) == MATTER_PENDING);
        CHECK(f->sent[0] == (role ? 2 : 3) && f->retained->exchange.initiator == !role);
        CHECK(f->sent[2] == 0x34 && f->sent[3] == 0x12 && !f->sent[4] && !f->sent[5] && !f->sent[6]);
        CHECK(finish(f, MATTER_OPERATION_CANCELLED));
        CHECK(matter_rx_process(f->rx, role) == MATTER_PENDING && pins(f) == 1);
        CHECK(finish(f, MATTER_OPERATION_SUCCEEDED));
        CHECK(matter_rx_process(f->rx, role) == MATTER_OK && pins(f) == 0);
    }
    CHECK(!f->violations);
    ok = true;
done: cleanup(f); return ok;
}

static bool ephemeral_contention(void) {
    bool ok = false;
    Fixture* f = create(true);
    CHECK(f);
    packet(f, 5, 1, 1, true); /* registered duplicate still creates only ephemeral */
    CHECK(matter_rx_receive(f->rx, &f->input, 0) == MATTER_OK);
    CHECK(matter_rx_process(f->rx, 0) == MATTER_PENDING && pins(f) == 1 && !f->deliveries);
    packet(f, 7, 1, 2, false); /* normal responder on the same key must wait */
    CHECK(matter_rx_receive(f->rx, &f->input, 1) == MATTER_OK);
    CHECK(matter_rx_process(f->rx, 1) == MATTER_PENDING && pins(f) == 2 && f->acks == 1 && !f->deliveries);
    CHECK(finish(f, MATTER_OPERATION_SUCCEEDED));
    CHECK(matter_rx_process(f->rx, 2) == MATTER_PENDING && pins(f) == 1 && !f->deliveries);
    CHECK(matter_rx_process(f->rx, 2) == MATTER_OK && pins(f) == 1 && f->deliveries == 1 && f->acks == 1);
    CHECK(matter_rx_process(f->rx, 200) == MATTER_OK && !f->retained);
    CHECK(matter_rx_process(f->rx, 201) == MATTER_PENDING && f->sent[6] == 2);
    CHECK(finish(f, MATTER_OPERATION_SUCCEEDED));
    CHECK(matter_rx_close(f->rx, f->delivered.exchange) == MATTER_OK && !pins(f));
    packet(f, 4, 3, 3, false); /* unsupported nonduplicate, opposite role */
    CHECK(matter_rx_receive(f->rx, &f->input, 201) == MATTER_OK && matter_rx_process(f->rx, 201) == MATTER_PENDING);
    packet(f, 5, 3, 4, false); f->input.session = 2;
    CHECK(matter_rx_receive(f->rx, &f->input, 201) == MATTER_OK);
    CHECK(matter_rx_process(f->rx, 201) == MATTER_PENDING && f->pins[1] == 1 && f->pins[2] == 1);
    CHECK(matter_rx_stop(f->rx) == MATTER_PENDING && !f->dependencies);
    CHECK(finish(f, MATTER_OPERATION_SUCCEEDED));
    CHECK(matter_rx_process(f->rx, 201) == MATTER_PENDING && !f->pins[1] && f->pins[2] == 1);
    CHECK(matter_rx_process(f->rx, 201) == MATTER_PENDING && f->retained->exchange.session == 2);
    CHECK(f->retained->exchange.initiator == false && f->sent[6] == 4 && !f->dependencies);
    CHECK(finish(f, MATTER_OPERATION_SUCCEEDED));
    CHECK(matter_rx_process(f->rx, 201) == MATTER_PENDING && f->dependencies == 1 && !pins(f));
    CHECK(matter_rx_process(f->rx, 201) == MATTER_OK && f->deliveries == 1 && !f->violations);
    ok = true;
done: cleanup(f); return ok;
}

static bool closing_control(void) {
    bool ok = false;
    Fixture* f = create(true);
    Matter_Exchange_Info_T info;
    CHECK(f);
    packet(f, 5, 1, 10, false);
    CHECK(matter_rx_receive(f->rx, &f->input, 0) == MATTER_OK && matter_rx_process(f->rx, 0) == MATTER_OK);
    Matter_Exchange_Handle_T handle = f->delivered.exchange;
    f->tx_drain = MATTER_PENDING;
    CHECK(matter_rx_stop(f->rx) == MATTER_PENDING && matter_rx_delete(f->rx) == MATTER_INVALID_STATE);
    CHECK(matter_rx_process(f->rx, 0) == MATTER_PENDING && f->retained && !f->dependencies);
    CHECK(matter_rx_get(f->rx, handle, &info) == MATTER_OK && matter_udp_is_active(f->udp));
    CHECK(finish(f, MATTER_OPERATION_SUCCEEDED));
    CHECK(matter_rx_process(f->rx, 1) == MATTER_PENDING && !f->dependencies && pins(f) == 1);
    packet(f, 7, 1, 11, false);
    f->clear_tx_on_ack = true;
    CHECK(matter_rx_receive(f->rx, &f->input, 1) == MATTER_OK);
    CHECK(matter_rx_process(f->rx, 1) == MATTER_PENDING && f->acks == 1 && f->deliveries == 1);
    CHECK(f->retained && f->sent[6] == 11 && !f->dependencies);
    CHECK(finish(f, MATTER_OPERATION_SUCCEEDED));
    f->dependency_result = MATTER_OFFLINE;
    CHECK(matter_rx_process(f->rx, 2) == MATTER_PORT_ERROR && f->dependencies == 1);
    CHECK(pins(f) == 0 && !f->deactivations && matter_udp_is_active(f->udp));
    CHECK(matter_rx_receive(f->rx, &f->input, 2) == MATTER_INVALID_STATE);
    CHECK(matter_rx_start(f->rx) == MATTER_INVALID_STATE && matter_rx_delete(f->rx) == MATTER_INVALID_STATE);
    f->dependency_result = MATTER_OK;
    CHECK(matter_rx_process(f->rx, 2) == MATTER_PENDING && f->deactivations == 1);
    CHECK(matter_rx_process(f->rx, 2) == MATTER_OK && !matter_udp_is_active(f->udp));
    CHECK(matter_rx_stop(f->rx) == MATTER_OK && matter_get_state(f->owner) == MATTER_STATE_RUNNING);
    CHECK(matter_stop(f->owner) == MATTER_OK && !f->violations);
    ok = true;
done: cleanup(f); return ok;
}

static bool deferred_close_and_registry(void) {
    bool ok = false;
    Fixture* f = create(true);
    Matter_Exchange_Handle_T handle = 0;
    Matter_Exchange_Info_T info;
    CHECK(f && matter_rx_initiate(f->rx, 1, &handle) == MATTER_OK);
    packet(f, 4, 1, 3, false); /* peer responder */
    CHECK(matter_rx_receive(f->rx, &f->input, 0) == MATTER_OK && pins(f) == 2);
    CHECK(matter_rx_close(f->rx, handle) == MATTER_PENDING); /* queued RX holds metadata */
    CHECK(matter_rx_get(f->rx, handle, &info) == MATTER_OK && info.initiator);
    CHECK(matter_rx_process(f->rx, 0) == MATTER_PENDING && !f->deliveries && f->sent[0] == 3);
    CHECK(finish(f, MATTER_OPERATION_SUCCEEDED));
    CHECK(matter_rx_process(f->rx, 0) == MATTER_OK && !pins(f));
    CHECK(matter_rx_get(f->rx, handle, &info) == MATTER_INVALID_STATE);
    packet(f, 7, 1, 4, false);
    f->ack_result = MATTER_WOULD_BLOCK;
    CHECK(matter_rx_receive(f->rx, &f->input, 0) == MATTER_OK && matter_rx_process(f->rx, 0) == MATTER_PENDING);
    CHECK(!f->acks && pins(f) == 1);
    CHECK(matter_rx_unregister(f->rx, 0, 1) == MATTER_OK);
    f->ack_result = MATTER_OK;
    CHECK(matter_rx_process(f->rx, 0) == MATTER_PENDING && !f->deliveries && f->acks == 1);
    CHECK(f->retained && f->sent[0] == 2 && f->sent[6] == 4);
    CHECK(finish(f, MATTER_OPERATION_SUCCEEDED));
    CHECK(matter_rx_process(f->rx, 0) == MATTER_OK && pins(f) == 0 && !f->violations);
    ok = true;
done: cleanup(f); return ok;
}

static bool boundaries_and_errors(void) {
    bool ok = false;
    Fixture* f = create(false);
    Matter_Exchange_Handle_T handle = 99;
    CHECK(f && matter_rx_process(f->rx, 0) == MATTER_INVALID_STATE);
    CHECK(matter_rx_delete(NULL) == MATTER_OK && matter_rx_process(NULL, 0) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_rx_new(f->owner, 0, NULL) == NULL);
    Matter_Rx_Port_T bad = f->port; bad.process_ack = NULL;
    CHECK(matter_rx_new(f->owner, 0, &bad) == NULL && !f->detaches);
    CHECK(matter_rx_start(f->rx) == MATTER_OK); f->started = true;
    CHECK(matter_rx_start(f->rx) == MATTER_OK);
    CHECK(matter_rx_initiate(f->rx, 0, &handle) == MATTER_INVALID_ARGUMENT && handle == 99);
    packet(f, 1, 1, 1, false);
    f->input.size = 5;
    CHECK(matter_rx_receive(f->rx, &f->input, 0) == MATTER_INVALID_ARGUMENT && !pins(f));
    f->input.size = sizeof(f->wire);
    CHECK(matter_rx_receive(f->rx, &f->input, 0) == MATTER_LIMIT_REACHED && !pins(f));
    f->input.size = MATTER_RX_MAX_PLAINTEXT;
    f->retention = MATTER_OFFLINE;
    CHECK(matter_rx_receive(f->rx, &f->input, 0) == MATTER_OFFLINE && !pins(f));
    f->retention = MATTER_OK;
    CHECK(matter_rx_receive(f->rx, &f->input, 0) == MATTER_OK);
    f->retention = MATTER_PENDING; /* invalid pin result, preserve queued input */
    CHECK(matter_rx_process(f->rx, 0) == MATTER_PORT_ERROR && pins(f) == 1 && !f->deliveries);
    f->retention = MATTER_OK;
    CHECK(matter_rx_process(f->rx, 0) == MATTER_OK && f->deliveries == 1);
    CHECK(f->delivered.payload_size == MATTER_RX_MAX_PLAINTEXT - 6);
    handle = f->delivered.exchange;
    f->tx_drain = MATTER_INVALID_ARGUMENT;
    CHECK(matter_rx_close(f->rx, handle) == MATTER_PORT_ERROR && pins(f) == 1);
    f->tx_drain = MATTER_OK;
    CHECK(matter_rx_process(f->rx, 1) == MATTER_OK && !pins(f));
    CHECK(matter_rx_process(f->rx, 0) == MATTER_INVALID_ARGUMENT);
    packet(f, 3, 0, 2, false); f->wire[1] = 0x10; f->input.size = 10;
    f->ack_result = MATTER_PENDING;
    CHECK(matter_rx_receive(f->rx, &f->input, 1) == MATTER_OK && matter_rx_process(f->rx, 1) == MATTER_PORT_ERROR);
    f->ack_result = MATTER_OK;
    CHECK(matter_rx_process(f->rx, 1) == MATTER_OK && f->acks == 1 && f->deliveries == 1 && !pins(f));
    /* Caller retries a packet rejected while the owned slot was full. Its
     * reception time predates process; retain it instead of extending timeout. */
    packet(f, 1, 3, 3, false);
    CHECK(matter_rx_receive(f->rx, &f->input, 2) == MATTER_OK);
    packet(f, 5, 1, 4, false);
    CHECK(matter_rx_receive(f->rx, &f->input, 3) == MATTER_WOULD_BLOCK);
    CHECK(matter_rx_process(f->rx, 100) == MATTER_OK);
    CHECK(matter_rx_receive(f->rx, &f->input, 3) == MATTER_OK);
    CHECK(matter_rx_process(f->rx, 100) == MATTER_OK && f->deliveries == 2);
    CHECK(matter_rx_process(f->rx, 202) == MATTER_OK && !f->retained);
    CHECK(matter_rx_process(f->rx, 203) == MATTER_PENDING && f->sent[6] == 4);
    CHECK(finish(f, MATTER_OPERATION_SUCCEEDED));
    CHECK(!f->violations);
    ok = true;
done: cleanup(f); return ok;
}

static bool terminal_session(void) {
    bool ok = false;
    Fixture* f = create(true); CHECK(f);
    CHECK(matter_rx_retire_session(f->rx, 0) == MATTER_INVALID_ARGUMENT);
    for (unsigned mode = 0; mode < 3; ++mode) {
        /* Normal ACK, immediate duplicate ACK (ephemeral), unsent ACK. */
        packet(f, 5, 1, 10 + mode, mode == 1);
        CHECK(matter_rx_receive(f->rx, &f->input, 1000 * mode) == MATTER_OK);
        Matter_Result_T r = matter_rx_process(f->rx, 1000 * mode + (mode == 2 ? 0 : 200));
        CHECK(r == (mode == 2 ? MATTER_OK : MATTER_PENDING));
        CHECK((f->retained != NULL) == (mode != 2));
        uint64_t stale = f->request;
        /* A second session retains its own pending ACK on the same executor. */
        packet(f, 5, 1, 20 + mode, false); f->input.session = 2;
        CHECK(matter_rx_receive(f->rx, &f->input, 1000 * mode + 200) == MATTER_OK);
        r = matter_rx_process(f->rx, 1000 * mode + 200);
        CHECK(r == MATTER_OK || r == MATTER_PENDING);
        /* A queued packet for the retiring session must never be delivered. */
        packet(f, 5, 1, 30 + mode, false);
        CHECK(matter_rx_receive(f->rx, &f->input, 1000 * mode + 200) == MATTER_OK);
        unsigned deliveries = f->deliveries, sends = f->sends;
        CHECK(matter_rx_retire_session(f->rx, 1) == MATTER_PENDING);
        CHECK(f->pins[1] && f->pins[2] && !f->dependencies && matter_udp_is_active(f->udp));
        CHECK(finish(f, mode == 1 ? MATTER_OPERATION_CANCELLED : MATTER_OPERATION_FAILED));
        CHECK(matter_rx_retire_session(f->rx, 1) == MATTER_OK && !f->pins[1]);
        CHECK(matter_rx_complete(f->rx, stale, MATTER_OPERATION_SUCCEEDED) == MATTER_INVALID_STATE);
        CHECK(matter_rx_process(f->rx, 1000 * mode + 400) == MATTER_PENDING);
        CHECK(f->retained->exchange.session == 2 && f->deliveries == deliveries && f->sends == sends + 1);
        CHECK(finish(f, MATTER_OPERATION_SUCCEEDED));
        CHECK(matter_rx_retire_session(f->rx, 2) == MATTER_OK && !pins(f) && !f->violations);
    }
    /* Pure queued admission can be dropped without sending anything. */
    packet(f, 5, 1, 99, false);
    CHECK(matter_rx_receive(f->rx, &f->input, 3000) == MATTER_OK);
    CHECK(matter_rx_retire_session(f->rx, 1) == MATTER_OK && !pins(f));
    CHECK(!f->dependencies && matter_udp_is_active(f->udp));
    ok = true;
done: cleanup(f); return ok;
}

static bool isolation_and_capacity(void) {
    bool ok = false;
    Fixture* f = create(true);
    Fixture* g = create(true);
    Matter_Exchange_Handle_T handle = 0, first = 0;
    CHECK(f && g);
    for (unsigned i = 0; i < MATTER_EXCHANGE_CAPACITY; ++i) {
        CHECK(matter_rx_initiate(f->rx, 1 + i / 5, &handle) == MATTER_OK);
        if (!i) first = handle;
    }
    CHECK(pins(f) == MATTER_EXCHANGE_CAPACITY);
    CHECK(matter_rx_initiate(f->rx, 3, &handle) == MATTER_LIMIT_REACHED && pins(f) == MATTER_EXCHANGE_CAPACITY);
    packet(f, 1, 1, 1, false);
    CHECK(matter_rx_receive(f->rx, &f->input, 0) == MATTER_OK);
    CHECK(matter_rx_process(f->rx, 0) == MATTER_LIMIT_REACHED && !f->deliveries);
    CHECK(matter_rx_close(f->rx, first) == MATTER_OK);
    CHECK(matter_rx_process(f->rx, 0) == MATTER_OK && f->deliveries == 1);
    packet(g, 4, 3, 99, true);
    CHECK(matter_rx_receive(g->rx, &g->input, 0) == MATTER_OK && matter_rx_process(g->rx, 0) == MATTER_PENDING);
    CHECK(matter_rx_stop(f->rx) == MATTER_PENDING);
    CHECK(matter_rx_process(f->rx, 0) == MATTER_PENDING && !pins(f) && pins(g) == 1);
    CHECK(matter_rx_process(f->rx, 0) == MATTER_OK && g->retained && !g->dependencies);
    CHECK(finish(g, MATTER_OPERATION_SUCCEEDED));
    CHECK(matter_rx_process(g->rx, 0) == MATTER_OK && !pins(g));
    CHECK(!f->violations && !g->violations);
    ok = true;
done: cleanup(f); cleanup(g); return ok;
}

#ifdef MATTER_TEST_ALLOC
static bool allocation(void) {
    bool ok = false;
    Fixture* f = create(false);
    CHECK(f && live == 7); /* owner, UDP, executor and four owned modules */
    size_t baseline = live;
    /* A successful never-started instance detaches once and cannot restart after stop. */
    Matter_Rx_T unused = matter_rx_new(f->owner, 0, &f->port);
    CHECK(unused);
    f->probe = false; /* This binding is not f->rx. */
    CHECK(matter_rx_stop(unused) == MATTER_OK && matter_rx_start(unused) == MATTER_INVALID_STATE);
    CHECK(matter_rx_delete(unused) == MATTER_OK && live == baseline && f->detaches == 1);
    f->detaches = 0; f->probe = true;
    for (unsigned i = 1; i <= 5; ++i) {
        fail_at = calls + i;
        CHECK(matter_rx_new(f->owner, 0, &f->port) == NULL && live == baseline && !f->detaches);
        fail_at = 0;
    }
    CHECK(matter_rx_start(f->rx) == MATTER_OK); f->started = true;
    size_t before = calls;
    for (unsigned i = 0; i < 1000; ++i) {
        packet(f, 5, 1, i, false);
        CHECK(matter_rx_receive(f->rx, &f->input, i) == MATTER_OK && matter_rx_process(f->rx, i) == MATTER_OK);
        CHECK(matter_rx_close(f->rx, f->delivered.exchange) == MATTER_PENDING);
        CHECK(matter_rx_process(f->rx, i) == MATTER_PENDING);
        CHECK(finish(f, MATTER_OPERATION_SUCCEEDED));
        CHECK(matter_rx_process(f->rx, i) == MATTER_OK && !pins(f));
    }
    CHECK(calls == before && !f->violations);
    printf("RX context: %zu bytes; five allocations, no per-message allocation\n", context_size);
    ok = true;
done: fail_at = 0; cleanup(f); return ok && !live;
}
#endif

int main(void) {
    unsigned passed = 0;
#define RUN(t) do { if (!(t)()) return 1; ++passed; } while (0)
    RUN(owned_retry); RUN(ephemeral_roles); RUN(ephemeral_contention); RUN(closing_control); RUN(deferred_close_and_registry);
    RUN(boundaries_and_errors); RUN(isolation_and_capacity); RUN(terminal_session);
#ifdef MATTER_TEST_ALLOC
    RUN(allocation);
    if (live) return 1;
#endif
    printf("PASS RX executor: %u groups\n", passed);
    return 0;
}

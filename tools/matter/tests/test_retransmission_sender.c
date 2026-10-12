#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "transport/matter_retransmission_sender.h"
#include "transport/matter_ack_sender.h"

#ifdef MATTER_TEST_ALLOC
static size_t live, calls, fail_at, sender_size;
void* matter_test_calloc(size_t n, size_t size) {
    ++calls;
    if (calls == fail_at) return NULL;
    void* p = calloc(n, size);
    if (p) { ++live; if (!sender_size) sender_size = n * size; }
    return p;
}
void matter_test_free(void* p) { if (p) { if (!live) abort(); --live; } free(p); }
#endif

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #c); goto done; } } while (0)
static const Matter_Exchange_Info_T key = {1, 0x1234, true};

typedef struct {
    Matter_Retransmission_Sender_T sender, target;
    Matter_Ack_Table_T ack;
    Matter_Ack_Sender_T ack_sender;
    Matter_Retransmission_Port_T port;
    const Matter_Retransmission_Request_T* retained;
    const Matter_Ack_Message_T* retained_ack;
    Matter_Retransmission_Request_T snapshot;
    Matter_Retransmission_Result_T result;
    Matter_Retransmission_Parameters_T parameters;
    uint8_t bytes[1233], copy[1233];
    uint64_t ids[8], binding, ack_request, wire_route, route;
    unsigned pins, retains, releases, sends, notifications, cancels, detaches, violations, occupied;
    unsigned ready_calls, parameter_calls, random_calls, discovery_calls, discoveries;
    uint8_t next_attempt;
    uint16_t sample;
    Matter_Result_T retain_result, ready_result, parameter_result, random_result, discovery_result;
    Matter_Retransmission_Submission_T submission;
    bool probe, ack_owed;
} Fixture;

static void reentry(Fixture* f) {
    if (!f->probe) return;
    uint64_t id = 999, deadline = 999;
    if (matter_retransmission_sender_add(f->sender, &key, 0, f->bytes, 1, &id) != MATTER_BUSY ||
        matter_retransmission_sender_process(f->sender, 0) != MATTER_BUSY ||
        matter_retransmission_sender_complete(f->sender, 1, MATTER_RETRANSMISSION_SENT) != MATTER_BUSY ||
        matter_retransmission_sender_stop(f->sender) != MATTER_BUSY ||
        matter_retransmission_sender_delete(f->sender) != MATTER_BUSY ||
        matter_retransmission_sender_ack(f->sender, &key, 0) != MATTER_BUSY ||
        matter_retransmission_sender_drained(f->sender, &key) != MATTER_BUSY ||
        matter_retransmission_sender_deadline(f->sender, &deadline) != MATTER_BUSY ||
        matter_retransmission_sender_cancel(f->sender, 1) != MATTER_BUSY ||
        matter_retransmission_sender_cancel_session(f->sender, 1) != MATTER_BUSY || id != 999 || deadline != 999)
        ++f->violations;
}
static Matter_Result_T retain(void* user, const Matter_Exchange_Info_T* k, const uint8_t* data, size_t size) {
    Fixture* f = user; reentry(f);
    if (!k->session || data != f->bytes || !size) ++f->violations;
    ++f->retains;
    if (f->retain_result == MATTER_OK) ++f->pins;
    return f->retain_result;
}
static void release(void* user, const Matter_Exchange_Info_T* k, const uint8_t* data, size_t size) {
    Fixture* f = user; reentry(f);
    if (!f->pins || !k->session || data != f->bytes || !size) abort();
    --f->pins; ++f->releases;
    if (f->retained && !f->pins) ++f->violations;
}
static Matter_Result_T ready(void* user) {
    Fixture* f = user; reentry(f); ++f->ready_calls;
    if (f->occupied || f->ack_owed) return MATTER_WOULD_BLOCK;
    return f->ready_result;
}
static Matter_Result_T parameters(void* user, const Matter_Retransmission_Message_T* m,
    uint8_t attempt, Matter_Retransmission_Parameters_T* p) {
    Fixture* f = user; reentry(f); ++f->parameter_calls;
    if (!f->pins || m->data != f->bytes) ++f->violations;
    *p = f->parameters; /* Writes on error must be ignored. */
    f->next_attempt = attempt;
    return f->parameter_result;
}
static Matter_Result_T random_sample(void* user, uint16_t* sample) {
    Fixture* f = user; reentry(f); ++f->random_calls; *sample = f->sample;
    return f->random_result;
}
static Matter_Result_T rediscover(void* user, const Matter_Retransmission_Message_T* m) {
    Fixture* f = user; reentry(f); ++f->discovery_calls;
    if (!f->pins || m->data != f->bytes) ++f->violations;
    if (f->discovery_result == MATTER_OK) ++f->discoveries;
    /* Resolver owns independent work; no sender/message pointer retained. */
    return f->discovery_result;
}
static Matter_Retransmission_Submission_T send_message(void* user, const Matter_Retransmission_Request_T* request) {
    Fixture* f = user; reentry(f); ++f->sends;
    if (!f->pins || f->occupied || f->retained || request->message.data != f->bytes) abort();
    f->snapshot = *request;
    memcpy(f->copy, request->message.data, request->message.size);
    if (f->submission == MATTER_RETRANSMISSION_SUBMITTED) {
        f->retained = request; f->occupied = 1; f->wire_route = f->route;
    }
    return f->submission;
}
static void cancel(void* user, uint64_t request) {
    Fixture* f = user; reentry(f); ++f->cancels;
    if (!f->retained || request != f->retained->id) ++f->violations;
}
static void finished(void* user, const Matter_Retransmission_Result_T* result) {
    Fixture* f = user; reentry(f);
    if (!f->pins || (f->retained && result->message.id == f->retained->message.id)) ++f->violations;
    f->result = *result;
    f->result.message.data = NULL; /* No borrowed pointers escape callback. */
    ++f->notifications;
}
static void detach(void* user) {
    Fixture* f = user; reentry(f);
    if (f->retained || f->pins) ++f->violations;
    ++f->detaches; f->target = NULL;
}
static Matter_Result_T send_ack(void* user, uint64_t request, const Matter_Ack_Message_T* m) {
    Fixture* f = user;
    if (f->occupied) return MATTER_WOULD_BLOCK;
    f->retained_ack = m; f->ack_request = request; f->occupied = 2;
    return MATTER_OK;
}
static void detach_ack(void* user) { Fixture* f = user; if (f->retained_ack) abort(); }

static bool unchanged(Fixture* f) {
    return f->retained && f->retained->id == f->snapshot.id &&
        f->retained->message.id == f->snapshot.message.id &&
        f->retained->message.data == f->bytes && f->retained->message.size == f->snapshot.message.size &&
        f->retained->message.counter == f->snapshot.message.counter &&
        f->retained->deadline_ms == f->snapshot.deadline_ms &&
        !memcmp(f->copy, f->retained->message.data, f->retained->message.size);
}
static bool finish(Fixture* f, uint64_t binding, Matter_Retransmission_Tx_Result_T result) {
    if (!f->target || binding != f->binding || !f->retained) return false;
    if (!unchanged(f)) abort();
    uint64_t id = f->retained->id;
    f->retained = NULL; f->occupied = 0;
    return matter_retransmission_sender_complete(f->target, id, result) == MATTER_OK;
}
static bool finish_ack(Fixture* f) {
    if (!f->retained_ack) return false;
    f->retained_ack = NULL; f->occupied = 0; f->ack_owed = false;
    return matter_ack_sender_complete(f->ack_sender, f->ack_request, MATTER_OPERATION_SUCCEEDED) == MATTER_OK;
}
static Matter_Result_T step(Fixture* f, uint64_t now) { return matter_retransmission_sender_process(f->sender, now); }
static Matter_Result_T add(Fixture* f, uint32_t counter, uint64_t* id) {
    return matter_retransmission_sender_add(f->sender, &key, counter, f->bytes, 1232, id);
}

static void cleanup(Fixture* f) {
    if (!f) return;
    f->probe = false; f->ack_owed = false;
    if (f->retained_ack && !finish_ack(f)) abort();
    f->retain_result = f->ready_result = f->parameter_result = f->random_result = f->discovery_result = MATTER_OK;
    f->submission = MATTER_RETRANSMISSION_REJECTED_FATAL;
    if (f->sender) {
        unsigned steps = 0;
        while (matter_retransmission_sender_stop(f->sender) == MATTER_PENDING) {
            if (++steps > 32) abort();
            if (f->retained && !finish(f, f->binding, MATTER_RETRANSMISSION_FATAL)) abort();
            Matter_Result_T result = step(f, UINT64_MAX);
            if (result != MATTER_OK && result != MATTER_PENDING && result != MATTER_PORT_ERROR) abort();
        }
        if (matter_retransmission_sender_delete(f->sender) != MATTER_OK) abort();
    }
    if (f->ack_sender) {
        while (matter_ack_sender_stop(f->ack_sender) == MATTER_PENDING) {
            if (matter_ack_sender_process(f->ack_sender, UINT64_MAX) != MATTER_PENDING || !finish_ack(f)) abort();
        }
        if (matter_ack_sender_delete(f->ack_sender) != MATTER_OK) abort();
    }
    if (matter_ack_delete(f->ack) != MATTER_OK || f->pins || f->violations) abort();
    free(f);
}
static bool attach(Fixture* f, uint8_t maximum) {
    Matter_Retransmission_Port_T port = f->port;
    f->sender = matter_retransmission_sender_new(maximum, &port);
    f->target = f->sender; ++f->binding;
    port = (Matter_Retransmission_Port_T){0}; /* copied descriptor */
    return f->sender != NULL;
}
static Fixture* create(uint8_t maximum) {
    Fixture* f = calloc(1, sizeof(*f));
    if (!f) return NULL;
    f->port = (Matter_Retransmission_Port_T){f, retain, release, ready, parameters, random_sample, rediscover,
        send_message, cancel, finished, detach};
    f->parameters = (Matter_Retransmission_Parameters_T){500, 300, true};
    f->route = 1;
    memset(f->bytes, 0xa5, sizeof(f->bytes));
    if (!attach(f, maximum)) { cleanup(f); return NULL; }
    f->ack = matter_ack_new();
    Matter_Ack_Port_T ack_port = {f, send_ack, detach_ack};
    f->ack_sender = matter_ack_sender_new(f->ack, &ack_port);
    if (!f->ack || !f->ack_sender) { cleanup(f); return NULL; }
    f->probe = true;
    return f;
}

static bool ownership_and_ack(void) {
    bool ok = false;
    Fixture* f = create(5);
    uint64_t rejected = 999;
    CHECK(f && add(f, 0, &f->ids[0]) == MATTER_OK && f->pins == 1 && !f->sends);
    CHECK(add(f, 1, &rejected) == MATTER_BUSY && rejected == 999 && f->pins == 1 && f->releases == 1);
    CHECK(step(f, 0) == MATTER_PENDING && unchanged(f) && f->snapshot.attempt == 1);
    CHECK(matter_retransmission_sender_ack(f->sender, &key, 0) == MATTER_OK && !f->notifications);
    CHECK(matter_retransmission_sender_cancel(f->sender, f->ids[0]) == MATTER_PENDING && f->cancels == 1);
    CHECK(matter_retransmission_sender_cancel(f->sender, f->ids[0]) == MATTER_PENDING && f->cancels == 1);
    f->route = 9; /* An accepted TX still holds route 1 and unchanged bytes. */
    CHECK(step(f, 1000) == MATTER_PENDING && unchanged(f) && f->wire_route == 1 && f->pins == 1);
    CHECK(matter_retransmission_sender_drained(f->sender, &key) == MATTER_PENDING);
    CHECK(matter_retransmission_sender_stop(f->sender) == MATTER_PENDING);
    CHECK(matter_retransmission_sender_delete(f->sender) == MATTER_INVALID_STATE);
    CHECK(matter_retransmission_sender_complete(f->sender, f->snapshot.id + 1, MATTER_RETRANSMISSION_SENT) == MATTER_INVALID_STATE);
    CHECK(matter_retransmission_sender_complete(f->sender, f->snapshot.id, (Matter_Retransmission_Tx_Result_T)9) == MATTER_INVALID_ARGUMENT);
    CHECK(unchanged(f) && finish(f, f->binding, MATTER_RETRANSMISSION_FATAL));
    CHECK(!f->notifications && f->pins == 1); /* complete never releases inline */
    CHECK(step(f, 1000) == MATTER_OK && f->notifications == 1 && !f->pins);
    CHECK(f->result.outcome == MATTER_RETRANSMISSION_ACKNOWLEDGED && f->result.attempts == 1);
    CHECK(matter_retransmission_sender_drained(f->sender, &key) == MATTER_OK && !f->violations);
    ok = true;
done: cleanup(f); return ok;
}

static bool preflight_and_discovery(void) {
    bool ok = false;
    Fixture* f = create(5);
    uint64_t deadline = 999, id = 999;
    CHECK(f);
    f->retain_result = MATTER_OFFLINE;
    CHECK(add(f, 1, &id) == MATTER_OFFLINE && !f->pins && id == 999);
    f->retain_result = MATTER_OK;
    CHECK(add(f, 1, &id) == MATTER_OK);
    f->ready_result = MATTER_WOULD_BLOCK;
    CHECK(step(f, 0) == MATTER_WOULD_BLOCK && !f->parameter_calls && !f->sends);
    f->ready_result = MATTER_OK; f->parameter_result = MATTER_OFFLINE;
    CHECK(step(f, 0) == MATTER_OFFLINE && !f->random_calls && !f->sends);
    f->parameter_result = MATTER_OK; f->random_result = MATTER_PENDING; /* invalid -> PORT_ERROR */
    CHECK(step(f, 0) == MATTER_PORT_ERROR && !f->sends && !f->discoveries);
    f->random_result = MATTER_PORT_ERROR;
    CHECK(step(f, 5) == MATTER_PORT_ERROR && !f->sends);
    f->random_result = MATTER_OK; f->submission = MATTER_RETRANSMISSION_REJECTED_RETRYABLE;
    CHECK(step(f, 10) == MATTER_WOULD_BLOCK && f->snapshot.attempt == 1 && !f->retained && f->pins == 1);
    CHECK(matter_retransmission_sender_deadline(f->sender, &deadline) == MATTER_OK && deadline == 340);
    CHECK(step(f, 339) == MATTER_WOULD_BLOCK && f->sends == 1 && !f->discovery_calls);
    f->discovery_result = MATTER_OFFLINE;
    CHECK(step(f, 340) == MATTER_OFFLINE && f->discovery_calls == 1 && !f->discoveries && f->sends == 1);
    f->discovery_result = MATTER_OK; f->random_result = MATTER_PORT_ERROR;
    CHECK(step(f, 340) == MATTER_PORT_ERROR && f->discoveries == 1 && f->sends == 1);
    f->parameter_result = MATTER_WOULD_BLOCK;
    CHECK(step(f, 341) == MATTER_WOULD_BLOCK && f->discoveries == 1 && f->discovery_calls == 2);
    /* Resolver result arrives independently; next snapshot uses its new data. */
    f->route = 2; f->parameters.active_interval_ms = 600;
    f->parameter_result = f->random_result = MATTER_OK; f->sample = UINT16_MAX;
    f->submission = MATTER_RETRANSMISSION_SUBMITTED;
    CHECK(step(f, 350) == MATTER_PENDING && f->snapshot.attempt == 2 && f->wire_route == 2);
    CHECK(f->snapshot.deadline_ms == 1175 && f->snapshot.message.counter == 1 && unchanged(f));
    CHECK(finish(f, f->binding, MATTER_RETRANSMISSION_RETRYABLE));
    f->route = 3; f->parameters.active_interval_ms = 300;
    CHECK(step(f, 1175) == MATTER_PENDING && f->snapshot.attempt == 3 && f->snapshot.deadline_ms == 1835);
    CHECK(f->wire_route == 3 && f->discoveries == 1 && f->discovery_calls == 2);
    CHECK(finish(f, f->binding, MATTER_RETRANSMISSION_FATAL));
    CHECK(step(f, 1175) == MATTER_WOULD_BLOCK && !f->pins && f->notifications == 1);
    CHECK(f->result.outcome == MATTER_RETRANSMISSION_FAILED && f->result.attempts == 3 && !f->violations);
    ok = true;
done: cleanup(f); return ok;
}

static bool late_result_timeout_and_cancel(void) {
    bool ok = false;
    Fixture* f = create(2);
    CHECK(f && add(f, 1, &f->ids[0]) == MATTER_OK);
    CHECK(matter_retransmission_sender_cancel(f->sender, f->ids[0]) == MATTER_OK && !f->cancels);
    CHECK(step(f, 0) == MATTER_WOULD_BLOCK && f->notifications == 1 && !f->pins);
    CHECK(f->result.outcome == MATTER_RETRANSMISSION_CANCELLED && !f->result.attempts);
    CHECK(add(f, 2, &f->ids[0]) == MATTER_OK && step(f, 0) == MATTER_PENDING);
    CHECK(step(f, 1000) == MATTER_PENDING && f->sends == 1 && !f->discoveries);
    CHECK(finish(f, f->binding, MATTER_RETRANSMISSION_RETRYABLE));
    CHECK(step(f, 1000) == MATTER_PENDING && f->snapshot.attempt == 2 && f->snapshot.deadline_ms == 1330);
    CHECK(matter_retransmission_sender_stop(f->sender) == MATTER_PENDING && !f->cancels);
    CHECK(step(f, 1400) == MATTER_PENDING && f->pins == 1 && f->notifications == 1);
    CHECK(finish(f, f->binding, MATTER_RETRANSMISSION_SENT));
    CHECK(step(f, 1400) == MATTER_OK && f->notifications == 2 && !f->pins);
    CHECK(f->result.outcome == MATTER_RETRANSMISSION_TIMEOUT && f->result.attempts == 2 && !f->violations);
    ok = true;
done: cleanup(f); return ok;
}

static bool shared_ack_port(void) {
    bool ok = false;
    Fixture* f = create(5);
    CHECK(f && add(f, 0, &f->ids[0]) == MATTER_OK);
    CHECK(matter_ack_immediate(f->ack, &key, 9) == MATTER_OK);
    f->ack_owed = true;
    CHECK(step(f, 0) == MATTER_WOULD_BLOCK && !f->sends && !f->random_calls);
    CHECK(matter_ack_sender_process(f->ack_sender, 0) == MATTER_PENDING && f->occupied == 2);
    CHECK(step(f, 10) == MATTER_WOULD_BLOCK && !f->sends);
    CHECK(finish_ack(f));
    CHECK(step(f, 10) == MATTER_PENDING && f->snapshot.attempt == 1 && f->occupied == 1);
    CHECK(matter_ack_immediate(f->ack, &key, 10) == MATTER_OK);
    CHECK(matter_ack_sender_process(f->ack_sender, 10) == MATTER_WOULD_BLOCK && unchanged(f));
    CHECK(finish(f, f->binding, MATTER_RETRANSMISSION_SENT));
    CHECK(matter_ack_sender_process(f->ack_sender, 10) == MATTER_PENDING && f->retained_ack->data[6] == 10);
    CHECK(matter_retransmission_sender_ack(f->sender, &key, 0) == MATTER_OK);
    CHECK(step(f, 10) == MATTER_WOULD_BLOCK && !f->pins && f->notifications == 1);
    CHECK(finish_ack(f) && !f->violations);
    ok = true;
done: cleanup(f); return ok;
}

static bool capacity_isolation_and_binding(void) {
    bool ok = false;
    Fixture* f = create(5);
    Fixture* g = create(5);
    uint64_t id = 999;
    CHECK(f && g);
    for (unsigned i = 0; i < 8; ++i) {
        Matter_Exchange_Info_T k = {1, (uint16_t)i, true};
        CHECK(matter_retransmission_sender_add(f->sender, &k, i, f->bytes, 1, &f->ids[i]) == MATTER_OK);
    }
    CHECK(add(f, 9, &id) == MATTER_LIMIT_REACHED && id == 999 && f->pins == 8);
    CHECK(add(g, 1, &g->ids[0]) == MATTER_OK && step(g, 0) == MATTER_PENDING);
    CHECK(step(f, 0) == MATTER_PENDING);
    for (unsigned i = 1; i < 8; ++i) CHECK(matter_retransmission_sender_cancel(f->sender, f->ids[i]) == MATTER_OK);
    CHECK(step(f, 0) == MATTER_PENDING && f->notifications == 7 && f->pins == 1 && g->pins == 1);
    CHECK(matter_retransmission_sender_cancel(f->sender, f->ids[0]) == MATTER_PENDING);
    CHECK(matter_retransmission_sender_ack(f->sender, &f->snapshot.message.exchange, 0) == MATTER_OK);
    CHECK(finish(f, f->binding, MATTER_RETRANSMISSION_SENT));
    CHECK(step(f, 0) == MATTER_WOULD_BLOCK && f->result.outcome == MATTER_RETRANSMISSION_CANCELLED && !f->pins);
    CHECK(matter_retransmission_sender_stop(f->sender) == MATTER_OK);
    uint64_t old_binding = f->binding;
    CHECK(matter_retransmission_sender_delete(f->sender) == MATTER_OK && !f->target);
    f->sender = NULL;
    CHECK(attach(f, 5) && add(f, 44, &id) == MATTER_OK && step(f, 0) == MATTER_PENDING);
    CHECK(f->snapshot.id == 1 && !finish(f, old_binding, MATTER_RETRANSMISSION_SENT) && unchanged(f));
    CHECK(finish(f, f->binding, MATTER_RETRANSMISSION_FATAL));
    CHECK(step(f, 0) == MATTER_WOULD_BLOCK && !f->pins && g->retained);
    CHECK(matter_retransmission_sender_ack(g->sender, &key, 1) == MATTER_OK);
    CHECK(finish(g, g->binding, MATTER_RETRANSMISSION_SENT) && step(g, 0) == MATTER_WOULD_BLOCK && !g->pins);
    CHECK(!f->violations && !g->violations);
    ok = true;
done: cleanup(f); cleanup(g); return ok;
}

static bool terminal_session(void) {
    bool ok = false;
    Fixture* f = create(3); CHECK(f);
    Matter_Exchange_Info_T other = {2, 0x1234, true};
    Matter_Exchange_Info_T queued = {1, 0x1235, true};
    CHECK(matter_retransmission_sender_cancel_session(f->sender, 0) == MATTER_INVALID_ARGUMENT);
    CHECK(add(f, 1, &f->ids[0]) == MATTER_OK && step(f, 0) == MATTER_PENDING);
    uint64_t stale = f->retained->id;
    CHECK(matter_retransmission_sender_add(f->sender, &other, 1, f->bytes, 1232, &f->ids[1]) == MATTER_OK);
    CHECK(matter_retransmission_sender_add(f->sender, &queued, 2, f->bytes, 1232, &f->ids[2]) == MATTER_OK);
    CHECK(matter_retransmission_sender_cancel_session(f->sender, 1) == MATTER_PENDING && f->cancels == 1);
    CHECK(matter_retransmission_sender_cancel_session(f->sender, 1) == MATTER_PENDING && f->cancels == 1);
    CHECK(step(f, 1) == MATTER_PENDING && f->notifications == 1 && f->pins == 2 && unchanged(f));
    CHECK(f->result.outcome == MATTER_RETRANSMISSION_CANCELLED && !f->result.attempts);
    CHECK(finish(f, f->binding, MATTER_RETRANSMISSION_RETRYABLE));
    CHECK(step(f, 2) == MATTER_PENDING && f->notifications == 2 && f->pins == 1);
    CHECK(f->retained->message.exchange.session == 2 && f->result.outcome == MATTER_RETRANSMISSION_CANCELLED);
    CHECK(matter_retransmission_sender_cancel_session(f->sender, 1) == MATTER_OK && f->cancels == 1);
    CHECK(matter_retransmission_sender_complete(f->sender, stale, MATTER_RETRANSMISSION_SENT) == MATTER_INVALID_STATE);
    CHECK(matter_retransmission_sender_ack(f->sender, &other, 1) == MATTER_OK);
    CHECK(matter_retransmission_sender_cancel_session(f->sender, 2) == MATTER_PENDING && f->cancels == 2);
    CHECK(finish(f, f->binding, MATTER_RETRANSMISSION_FATAL));
    CHECK(step(f, 3) == MATTER_WOULD_BLOCK && !f->pins && f->notifications == 3);
    CHECK(f->result.outcome == MATTER_RETRANSMISSION_ACKNOWLEDGED && !f->violations);
    ok = true;
done: cleanup(f); return ok;
}

static bool errors_and_stop(void) {
    bool ok = false;
    Fixture* f = create(1);
    uint64_t id = 999;
    CHECK(f && matter_retransmission_sender_delete(NULL) == MATTER_OK);
    CHECK(matter_retransmission_sender_new(0, &f->port) == NULL);
    Matter_Retransmission_Port_T invalid = f->port; invalid.random = NULL;
    CHECK(matter_retransmission_sender_new(1, &invalid) == NULL && !f->detaches);
    CHECK(matter_retransmission_sender_add(f->sender, &key, 0, f->bytes, 1233, &id) == MATTER_LIMIT_REACHED && id == 999);
    CHECK(!f->retains);
    CHECK(matter_retransmission_sender_cancel(f->sender, 999) == MATTER_INVALID_STATE);
    CHECK(add(f, 0, &id) == MATTER_OK);
    f->submission = (Matter_Retransmission_Submission_T)99;
    CHECK(step(f, 1) == MATTER_PORT_ERROR && f->notifications == 1 && !f->pins);
    CHECK(f->result.outcome == MATTER_RETRANSMISSION_FAILED && f->result.attempts == 1);
    CHECK(step(f, 0) == MATTER_INVALID_ARGUMENT);
    CHECK(add(f, 1, &id) == MATTER_OK);
    f->submission = MATTER_RETRANSMISSION_REJECTED_RETRYABLE;
    CHECK(step(f, 2) == MATTER_WOULD_BLOCK && f->pins == 1);
    CHECK(matter_retransmission_sender_stop(f->sender) == MATTER_PENDING);
    CHECK(add(f, 2, &id) == MATTER_INVALID_STATE && f->pins == 1);
    CHECK(step(f, 331) == MATTER_PENDING && f->notifications == 1);
    CHECK(step(f, 332) == MATTER_OK && f->notifications == 2 && !f->pins);
    CHECK(f->result.outcome == MATTER_RETRANSMISSION_TIMEOUT && !f->discoveries && !f->violations);
    ok = true;
done: cleanup(f); return ok;
}

#ifdef MATTER_TEST_ALLOC
static bool allocation(void) {
    bool ok = false;
    Fixture* f = create(5);
    CHECK(f && live == 4);
    for (unsigned i = 1; i <= 2; ++i) {
        fail_at = calls + i;
        CHECK(matter_retransmission_sender_new(5, &f->port) == NULL && live == 4 && !f->detaches && !f->retains);
        fail_at = 0;
    }
    size_t baseline = calls;
    for (unsigned i = 0; i < 1000; ++i) {
        CHECK(add(f, i, &f->ids[0]) == MATTER_OK && step(f, i) == MATTER_PENDING);
        CHECK(matter_retransmission_sender_ack(f->sender, &key, i) == MATTER_OK);
        CHECK(finish(f, f->binding, MATTER_RETRANSMISSION_SENT));
        CHECK(step(f, i) == MATTER_WOULD_BLOCK && !f->pins);
    }
    CHECK(calls == baseline && f->notifications == 1000 && f->releases == 1000 && !f->violations);
    printf("Retransmission sender context: %zu bytes (+ ledger 552 bytes)\n", sender_size);
    ok = true;
done: fail_at = 0; cleanup(f); return ok && !live;
}
#endif

int main(void) {
    unsigned passed = 0;
#define RUN(t) do { if (!(t)()) return 1; ++passed; } while (0)
    RUN(ownership_and_ack); RUN(preflight_and_discovery); RUN(late_result_timeout_and_cancel);
    RUN(shared_ack_port); RUN(capacity_isolation_and_binding); RUN(errors_and_stop); RUN(terminal_session);
#ifdef MATTER_TEST_ALLOC
    RUN(allocation);
    if (live) return 1;
#endif
    printf("PASS retransmission sender: %u groups\n", passed);
    return 0;
}

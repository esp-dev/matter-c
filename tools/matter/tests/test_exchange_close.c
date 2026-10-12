#include <stdio.h>
#include <stdlib.h>
#include "transport/matter_ack_sender.h"
#include "transport/matter_rx_policy.h"

#ifdef MATTER_TEST_ALLOC
static size_t live, allocations;
void* matter_test_calloc(size_t count, size_t size) {
    void* p = calloc(count, size);
    if (p) { ++live; ++allocations; }
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
    Matter_Ack_Table_T ack;
    Matter_Ack_Sender_T sender;
    Matter_Rx_Policy_T policy;
    Matter_Exchange_Handle_T handles[MATTER_EXCHANGE_CAPACITY];
    Matter_Exchange_Info_T infos[MATTER_EXCHANGE_CAPACITY];
    Matter_Result_T barriers[MATTER_EXCHANGE_CAPACITY];
    unsigned calls[MATTER_EXCHANGE_CAPACITY];
    Matter_Rx_Decision_T decision;
    const Matter_Ack_Message_T* retained;
    uint64_t request;
    Matter_Result_T submission;
    unsigned sends, decisions, violations, probes, stopped;
    bool use_ack, probe;
} Fixture;

static bool same(const Matter_Exchange_Info_T* a, const Matter_Exchange_Info_T* b) {
    return a->session == b->session && a->exchange_id == b->exchange_id && a->initiator == b->initiator;
}

static void reentry(Fixture* f) {
    if (!f->probe) return;
    ++f->probes;
    Matter_Exchange_Handle_T handle = 999;
    Matter_Exchange_Info_T info = {99, 99, true};
    bool closing = false;
    if (matter_exchange_check(f->table) != MATTER_BUSY) ++f->violations;
    if (matter_exchange_set_close_port(f->table, NULL) != MATTER_BUSY) ++f->violations;
    if (matter_exchange_delete(f->table) != MATTER_BUSY) ++f->violations;
    if (matter_exchange_start(f->table) != MATTER_BUSY) ++f->violations;
    if (matter_exchange_stop(f->table) != MATTER_BUSY) ++f->violations;
    if (matter_exchange_process(f->table) != MATTER_BUSY) ++f->violations;
    if (matter_exchange_initiate(f->table, 1, &handle) != MATTER_BUSY) ++f->violations;
    if (matter_exchange_accept(f->table, 1, 1, &handle) != MATTER_BUSY) ++f->violations;
    if (matter_exchange_match(f->table, 1, 1, true, &handle) != MATTER_BUSY) ++f->violations;
    if (matter_exchange_get(f->table, 1, &info) != MATTER_BUSY) ++f->violations;
    if (matter_exchange_is_closing(f->table, 1, &closing) != MATTER_BUSY) ++f->violations;
    if (matter_exchange_release(f->table, 1) != MATTER_BUSY) ++f->violations;
    if (matter_exchange_release_session(f->table, 1) != MATTER_BUSY) ++f->violations;
    if (handle != 999 || info.session != 99 || info.exchange_id != 99 || !info.initiator || closing)
        ++f->violations;
}

static Matter_Result_T prepare(void* user, Matter_Exchange_Handle_T handle, const Matter_Exchange_Info_T* info) {
    Fixture* f = user;
    reentry(f);
    for (size_t i = 0; i < MATTER_EXCHANGE_CAPACITY; ++i) {
        if (f->handles[i] != handle) continue;
        ++f->calls[i];
        if (!same(info, &f->infos[i])) ++f->violations;
        return f->use_ack ? matter_ack_close(f->ack, info) : f->barriers[i];
    }
    ++f->violations;
    return MATTER_PORT_ERROR;
}

static void changed(void* user, Matter_State_T state) {
    Fixture* f = user;
    if (state == MATTER_STATE_STOPPED) { ++f->stopped; reentry(f); }
}
static void decided(void* user, const Matter_Rx_Decision_T* decision) {
    Fixture* f = user;
    ++f->decisions;
    f->decision = *decision; /* Tests use static wire data; no retained RX buffer. */
}
static Matter_Result_T send_message(void* user, uint64_t request, const Matter_Ack_Message_T* message) {
    Fixture* f = user;
    if (f->retained || !request || !message || message->size != 10) abort();
    ++f->sends;
    f->request = request;
    if (f->submission == MATTER_OK) f->retained = message;
    return f->submission;
}
static void detach(void* user) {
    Fixture* f = user;
    if (f->retained) abort();
}
static bool finish(Fixture* f, Matter_Operation_Result_T result) {
    if (!f->retained) return false;
    f->retained = NULL;
    return matter_ack_sender_complete(f->sender, f->request, result) == MATTER_OK;
}

static void cleanup(Fixture* f) {
    if (!f) return;
    f->probe = false; f->use_ack = true; f->submission = MATTER_OK;
    if (f->sender) {
        unsigned steps = 0;
        while (matter_ack_sender_stop(f->sender) == MATTER_PENDING) {
            if (++steps > 2 * (MATTER_ACK_CAPACITY + 1)) abort();
            if (f->retained) { if (!finish(f, MATTER_OPERATION_SUCCEEDED)) abort(); }
            else if (matter_ack_sender_process(f->sender, UINT64_MAX) != MATTER_PENDING) abort();
        }
        if (matter_ack_sender_delete(f->sender) != MATTER_OK) abort();
    }
    matter_rx_policy_delete(f->policy);
    matter_exchange_stop(f->table);
    matter_exchange_process(f->table);
    if (matter_exchange_delete(f->table) != MATTER_OK) abort();
    if (matter_ack_delete(f->ack) != MATTER_OK) abort();
    matter_stop(f->owner);
    if (matter_delete(f->owner) != MATTER_OK) abort();
    free(f);
}

static Fixture* create(void) {
    Fixture* f = calloc(1, sizeof(*f));
    if (!f) return NULL;
    f->use_ack = true;
    Matter_Port_T owner_port = {f, changed};
    f->owner = matter_new(&owner_port);
    f->table = matter_exchange_new(f->owner, 0x1234);
    f->ack = matter_ack_new();
    Matter_Ack_Port_T ack_port = {f, send_message, detach};
    f->sender = matter_ack_sender_new(f->ack, &ack_port);
    Matter_Rx_Listener_T listener = {f, decided};
    f->policy = matter_rx_policy_new(f->table, &listener);
    if (!f->owner || !f->table || !f->ack || !f->sender || !f->policy) { cleanup(f); return NULL; }
    Matter_Exchange_Close_Port_T port = {f, prepare};
    if (matter_exchange_set_close_port(f->table, &port) != MATTER_OK || matter_start(f->owner) != MATTER_OK ||
        matter_exchange_start(f->table) != MATTER_OK || matter_rx_policy_register(f->policy, 0, 1) != MATTER_OK) abort();
    port = (Matter_Exchange_Close_Port_T){0}; /* callback descriptor must be copied */
    return f;
}

static bool open_entry(Fixture* f, size_t index, uint64_t session, uint16_t wire, bool initiator) {
    Matter_Result_T result = initiator ? matter_exchange_initiate(f->table, session, &f->handles[index]) :
        matter_exchange_accept(f->table, session, wire, &f->handles[index]);
    return result == MATTER_OK && matter_exchange_get(f->table, f->handles[index], &f->infos[index]) == MATTER_OK;
}

static const uint8_t rx[] = {0x07, 1, 0x34, 0x12, 1, 0, 0, 0, 0, 0}; /* I,R,A, IM, ack counter 0 */
static const struct {
    uint8_t wire[10];
    size_t size;
    bool process_ack;
    Matter_Rx_Ack_T ack;
} closing_rx[] = {
    {{0x01, 1, 0x34, 0x12, 1, 0}, 6, false, MATTER_RX_ACK_NONE},
    {{0x03, 1, 0x34, 0x12, 1, 0, 0, 0, 0, 0}, 10, true, MATTER_RX_ACK_NONE},
    {{0x05, 1, 0x34, 0x12, 1, 0}, 6, false, MATTER_RX_ACK_IMMEDIATE},
    {{0x07, 1, 0x34, 0x12, 1, 0, 0, 0, 0, 0}, 10, true, MATTER_RX_ACK_IMMEDIATE}
};

static bool ack_and_policy(void) {
    bool ok = false, closing = false;
    Fixture* f = create();
    Matter_Exchange_Handle_T matched = 999;
    Matter_Exchange_Info_T info;
    Matter_Rx_Input_T input = {1, 77, false, rx, sizeof(rx)};
    CHECK(f && open_entry(f, 0, 1, 0x1234, false));
    f->probe = true;
    CHECK(matter_exchange_is_closing(f->table, f->handles[0], &closing) == MATTER_OK && !closing);
    CHECK(matter_rx_policy_receive(f->policy, &input) == MATTER_OK && f->decision.action == MATTER_RX_EXISTING);
    CHECK(matter_ack_record(f->ack, &f->infos[0], 0x11223344, 0) == MATTER_OK);
    CHECK(matter_exchange_release(f->table, f->handles[0]) == MATTER_PENDING);
    CHECK(matter_exchange_is_closing(f->table, f->handles[0], &closing) == MATTER_OK && closing);
    CHECK(matter_exchange_match(f->table, 1, 0x1234, true, &matched) == MATTER_OK && matched == f->handles[0]);
    CHECK(matter_exchange_accept(f->table, 1, 0x1234, &matched) == MATTER_BUSY);
    CHECK(matter_rx_policy_receive(f->policy, &input) == MATTER_OK);
    CHECK(f->decision.action == MATTER_RX_DROP && f->decision.exchange == f->handles[0]);
    CHECK(f->decision.process_ack && f->decision.header.acknowledged_message_counter == 0);
    CHECK(f->decision.ack == MATTER_RX_ACK_IMMEDIATE); /* retain control obligations while closing */
    for (size_t i = 0; i < sizeof(closing_rx) / sizeof(closing_rx[0]); ++i) {
        for (unsigned duplicate = 0; duplicate < 2; ++duplicate) {
            input.data = closing_rx[i].wire; input.size = closing_rx[i].size; input.duplicate = duplicate != 0;
            CHECK(matter_rx_policy_receive(f->policy, &input) == MATTER_OK);
            CHECK(f->decision.action == MATTER_RX_DROP && f->decision.exchange == f->handles[0]);
            CHECK(f->decision.process_ack == closing_rx[i].process_ack && f->decision.ack == closing_rx[i].ack);
        }
    }
    input = (Matter_Rx_Input_T){1, 77, false, rx, sizeof(rx)};
    f->submission = MATTER_WOULD_BLOCK;
    CHECK(matter_ack_sender_process(f->sender, 0) == MATTER_WOULD_BLOCK);
    CHECK(matter_exchange_release(f->table, f->handles[0]) == MATTER_PENDING);
    f->submission = MATTER_OK;
    CHECK(matter_ack_sender_process(f->sender, 0) == MATTER_PENDING && f->retained->data[6] == 0x44);
    CHECK(matter_exchange_release(f->table, f->handles[0]) == MATTER_PENDING);
    CHECK(matter_exchange_get(f->table, f->handles[0], &info) == MATTER_OK && same(&info, &f->infos[0]));
    CHECK(finish(f, MATTER_OPERATION_FAILED));
    CHECK(matter_exchange_release(f->table, f->handles[0]) == MATTER_PENDING);
    CHECK(matter_ack_sender_process(f->sender, 0) == MATTER_PENDING);
    CHECK(finish(f, MATTER_OPERATION_SUCCEEDED));
    CHECK(matter_exchange_get(f->table, f->handles[0], &info) == MATTER_OK); /* explicit release still owed */
    CHECK(matter_exchange_release(f->table, f->handles[0]) == MATTER_OK);
    CHECK(matter_exchange_get(f->table, f->handles[0], &info) == MATTER_INVALID_STATE);
    CHECK(matter_rx_policy_receive(f->policy, &input) == MATTER_OK && f->decision.action == MATTER_RX_NEW_RESPONDER);
    CHECK(f->calls[0] == 5 && f->probes == 5 && !f->violations);
    ok = true;
done: cleanup(f); return ok;
}

static bool batch_errors(void) {
    bool ok = false, closing = false;
    Fixture* f = create();
    Matter_Exchange_Info_T info;
    CHECK(f && open_entry(f, 0, 10, 1, false) && open_entry(f, 1, 20, 1, false) && open_entry(f, 2, 10, 0, true));
    f->use_ack = false;
    f->barriers[0] = MATTER_PENDING; f->barriers[2] = MATTER_OFFLINE; /* invalid callback outcome */
    CHECK(matter_exchange_release_session(f->table, 10) == MATTER_PORT_ERROR);
    CHECK(f->calls[0] == 1 && f->calls[1] == 0 && f->calls[2] == 1);
    for (size_t i = 0; i < 3; ++i) {
        CHECK(matter_exchange_get(f->table, f->handles[i], &info) == MATTER_OK && same(&info, &f->infos[i]));
        CHECK(matter_exchange_is_closing(f->table, f->handles[i], &closing) == MATTER_OK && closing == (i != 1));
    }
    f->barriers[0] = MATTER_OK; f->barriers[2] = MATTER_PENDING;
    CHECK(matter_exchange_release_session(f->table, 10) == MATTER_PENDING);
    CHECK(matter_exchange_get(f->table, f->handles[0], &info) == MATTER_OK);
    f->barriers[2] = MATTER_OK;
    CHECK(matter_exchange_release_session(f->table, 10) == MATTER_OK);
    CHECK(f->calls[0] == 3 && f->calls[2] == 3 && !f->calls[1]);
    CHECK(matter_exchange_get(f->table, f->handles[0], &info) == MATTER_INVALID_STATE);
    CHECK(matter_exchange_get(f->table, f->handles[2], &info) == MATTER_INVALID_STATE);
    CHECK(matter_exchange_get(f->table, f->handles[1], &info) == MATTER_OK);
    CHECK(matter_exchange_release_session(f->table, 10) == MATTER_OK && f->calls[0] == 3);
    CHECK(!f->violations);
    ok = true;
done: cleanup(f); return ok;
}

static bool shutdown(void) {
    bool ok = false;
    Fixture* f = NULL;
    for (unsigned owner_stop = 0; owner_stop < 2; ++owner_stop) {
        f = create();
        CHECK(f && open_entry(f, 0, 1, 1, false) && open_entry(f, 1, 1, 2, false));
        f->probe = true;
        CHECK(matter_ack_record(f->ack, &f->infos[0], 11, 0) == MATTER_OK);
        CHECK(matter_ack_record(f->ack, &f->infos[1], 12, 0) == MATTER_OK);
        CHECK((owner_stop ? matter_stop(f->owner) : matter_exchange_stop(f->table)) == MATTER_PENDING);
        CHECK(matter_exchange_process(f->table) == MATTER_PENDING && f->calls[0] == 1 && f->calls[1] == 1);
        CHECK(matter_exchange_check(f->table) == MATTER_INVALID_STATE);
        CHECK(matter_exchange_delete(f->table) == MATTER_INVALID_STATE && matter_delete(f->owner) == MATTER_INVALID_STATE);
        CHECK(matter_exchange_set_close_port(f->table, NULL) == MATTER_INVALID_STATE);
        CHECK(matter_ack_sender_process(f->sender, 0) == MATTER_PENDING);
        CHECK(matter_exchange_process(f->table) == MATTER_PENDING && f->calls[0] == 2 && f->calls[1] == 2);
        CHECK(finish(f, MATTER_OPERATION_FAILED));
        CHECK(matter_exchange_process(f->table) == MATTER_PENDING);
        f->submission = MATTER_OFFLINE;
        CHECK(matter_ack_sender_process(f->sender, 0) == MATTER_OFFLINE);
        CHECK(matter_exchange_process(f->table) == MATTER_PENDING);
        f->submission = MATTER_OK;
        CHECK(matter_ack_sender_process(f->sender, 0) == MATTER_PENDING && f->retained->data[6] == 11);
        CHECK(finish(f, MATTER_OPERATION_SUCCEEDED));
        CHECK(matter_exchange_process(f->table) == MATTER_PENDING); /* no partial metadata removal */
        CHECK(matter_ack_sender_process(f->sender, 0) == MATTER_PENDING && f->retained->data[6] == 12);
        CHECK(finish(f, MATTER_OPERATION_SUCCEEDED));
        CHECK(matter_exchange_process(f->table) == MATTER_OK && f->calls[0] == 6 && f->calls[1] == 6);
        CHECK(matter_get_state(f->owner) == (owner_stop ? MATTER_STATE_STOPPED : MATTER_STATE_RUNNING));
        CHECK(f->stopped == owner_stop && !f->violations);
        CHECK(matter_start(f->owner) == MATTER_OK && matter_exchange_start(f->table) == MATTER_OK);
        Matter_Exchange_Handle_T old = f->handles[0];
        CHECK(open_entry(f, 0, 1, 1, false) && f->handles[0] > old);
        CHECK(matter_exchange_release(f->table, old) == MATTER_INVALID_STATE);
        CHECK(matter_exchange_release(f->table, f->handles[0]) == MATTER_OK && f->calls[0] == 7); /* port survives restart */
        CHECK(!f->violations);
        cleanup(f); f = NULL;
    }
    ok = true;
done: cleanup(f); return ok;
}

static bool configuration(void) {
    bool ok = false, closing = true;
    Fixture* f = create();
    Matter_Exchange_Close_Port_T invalid = {0};
    CHECK(f);
    CHECK(matter_exchange_set_close_port(NULL, NULL) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_exchange_is_closing(NULL, 1, &closing) == MATTER_INVALID_ARGUMENT && closing);
    CHECK(matter_exchange_is_closing(f->table, 0, &closing) == MATTER_INVALID_ARGUMENT && closing);
    CHECK(matter_exchange_is_closing(f->table, 1, NULL) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_exchange_is_closing(f->table, 1, &closing) == MATTER_INVALID_STATE && closing);
    CHECK(matter_exchange_set_close_port(f->table, NULL) == MATTER_INVALID_STATE);
    CHECK(matter_exchange_stop(f->table) == MATTER_PENDING && matter_exchange_process(f->table) == MATTER_OK);
    CHECK(matter_exchange_set_close_port(f->table, &invalid) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_exchange_is_closing(f->table, 1, &closing) == MATTER_INVALID_STATE && closing);
    CHECK(matter_exchange_start(f->table) == MATTER_OK && open_entry(f, 0, 1, 1, false));
    f->use_ack = false; f->barriers[0] = MATTER_PORT_ERROR;
    CHECK(matter_exchange_release(f->table, f->handles[0]) == MATTER_PORT_ERROR && f->calls[0] == 1);
    CHECK(matter_exchange_is_closing(f->table, f->handles[0], &closing) == MATTER_OK && closing);
    CHECK(matter_exchange_stop(f->table) == MATTER_PENDING);
    CHECK(matter_exchange_process(f->table) == MATTER_PORT_ERROR);
    CHECK(matter_exchange_delete(f->table) == MATTER_INVALID_STATE);
    f->barriers[0] = MATTER_OK;
    CHECK(matter_exchange_process(f->table) == MATTER_OK);
    CHECK(matter_exchange_set_close_port(f->table, NULL) == MATTER_OK);
    CHECK(matter_exchange_start(f->table) == MATTER_OK && open_entry(f, 0, 1, 1, false));
    CHECK(matter_exchange_is_closing(f->table, f->handles[0], &closing) == MATTER_OK && !closing);
    CHECK(matter_exchange_release(f->table, f->handles[0]) == MATTER_OK && f->calls[0] == 3); /* disabled */
    ok = true;
done: cleanup(f); return ok;
}

static bool isolation(void) {
    bool ok = false;
    Fixture* f = create();
    Fixture* g = create();
    CHECK(f && g && open_entry(f, 0, 1, 1, true) && open_entry(g, 0, 1, 1, true));
    CHECK(f->handles[0] == g->handles[0] && same(&f->infos[0], &g->infos[0]));
    CHECK(matter_ack_record(f->ack, &f->infos[0], 1, 0) == MATTER_OK);
    CHECK(matter_ack_record(g->ack, &g->infos[0], 2, 0) == MATTER_OK);
    CHECK(matter_exchange_release(f->table, f->handles[0]) == MATTER_PENDING && !g->calls[0]);
    CHECK(matter_exchange_release(g->table, g->handles[0]) == MATTER_PENDING);
    CHECK(matter_ack_sender_process(f->sender, 0) == MATTER_PENDING && f->retained->data[0] == 3);
    CHECK(matter_ack_sender_process(g->sender, 0) == MATTER_PENDING && g->retained->data[6] == 2);
    CHECK(finish(f, MATTER_OPERATION_SUCCEEDED));
    CHECK(matter_exchange_release(f->table, f->handles[0]) == MATTER_OK);
    CHECK(matter_exchange_release(g->table, g->handles[0]) == MATTER_PENDING);
    CHECK(finish(g, MATTER_OPERATION_CANCELLED));
    CHECK(matter_exchange_release(g->table, g->handles[0]) == MATTER_PENDING);
    CHECK(matter_ack_sender_process(g->sender, 0) == MATTER_PENDING);
    CHECK(finish(g, MATTER_OPERATION_SUCCEEDED));
    CHECK(matter_exchange_release(g->table, g->handles[0]) == MATTER_OK);
    CHECK(!f->violations && !g->violations);
    ok = true;
done: cleanup(f); cleanup(g); return ok;
}

#ifdef MATTER_TEST_ALLOC
static bool allocation(void) {
    bool ok = false;
    Fixture* f = create();
    CHECK(f && live == 5);
    size_t baseline = allocations;
    for (unsigned i = 0; i < 1000; ++i) {
        CHECK(open_entry(f, 0, 1, 0, true));
        CHECK(matter_ack_record(f->ack, &f->infos[0], i, i) == MATTER_OK);
        CHECK(matter_exchange_release(f->table, f->handles[0]) == MATTER_PENDING);
        CHECK(matter_ack_sender_process(f->sender, i) == MATTER_PENDING);
        CHECK(finish(f, MATTER_OPERATION_SUCCEEDED));
        CHECK(matter_exchange_release(f->table, f->handles[0]) == MATTER_OK);
    }
    CHECK(allocations == baseline && !f->violations);
    ok = true;
done: cleanup(f); return ok && live == 0;
}
#endif

int main(void) {
    unsigned passed = 0;
#define RUN(t) do { if (!(t)()) return 1; ++passed; } while (0)
    RUN(ack_and_policy); RUN(batch_errors); RUN(shutdown); RUN(configuration); RUN(isolation);
#ifdef MATTER_TEST_ALLOC
    RUN(allocation);
    if (live) return 1;
#endif
    printf("PASS exchange close: %u groups\n", passed);
    return 0;
}

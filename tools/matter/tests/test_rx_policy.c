#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "transport/matter_rx_policy.h"

#ifdef MATTER_TEST_ALLOC
static size_t live, calls, last_size;
static bool fail_next;
void* matter_test_calloc(size_t n, size_t size) {
    if (fail_next) { fail_next = false; return NULL; }
    void* p = calloc(n, size);
    if (p) { ++live; ++calls; last_size = n * size; }
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
    Matter_Rx_Policy_T policy;
    Matter_Rx_Input_T input;
    Matter_Rx_Decision_T decision;
    uint8_t wire[32], copy[32];
    const uint8_t* expected_payload;
    unsigned events, violations;
} Fixture;

static void decided(void* user, const Matter_Rx_Decision_T* d) {
    Fixture* f = user;
    ++f->events;
    if (d->payload != f->expected_payload || d->payload_size > sizeof(f->copy)) ++f->violations;
    if (d->payload_size <= sizeof(f->copy)) memcpy(f->copy, d->payload, d->payload_size);
    f->decision = *d;
    f->decision.payload = NULL; /* Never retain the borrowed pointer. */
    if (matter_rx_policy_receive(f->policy, &f->input) != MATTER_BUSY) ++f->violations;
    if (matter_rx_policy_register(f->policy, 0, 0) != MATTER_BUSY) ++f->violations;
    if (matter_rx_policy_unregister(f->policy, 0, 0) != MATTER_BUSY) ++f->violations;
    if (matter_rx_policy_delete(f->policy) != MATTER_BUSY) ++f->violations;
    if (matter_exchange_check(f->table) != MATTER_OK) ++f->violations;
}
static bool create(Fixture* f) {
    f->owner = matter_new(NULL);
    if (!f->owner) return false;
    f->table = matter_exchange_new(f->owner, 0x1234);
    if (!f->table) return false;
    Matter_Rx_Listener_T listener = {f, decided};
    f->policy = matter_rx_policy_new(f->table, &listener);
    listener = (Matter_Rx_Listener_T){0}; /* Descriptor was copied. */
    return f->policy && matter_start(f->owner) == MATTER_OK && matter_exchange_start(f->table) == MATTER_OK;
}
static void cleanup(Fixture* f) {
    if (matter_rx_policy_delete(f->policy) != MATTER_OK) abort();
    matter_exchange_stop(f->table);
    matter_exchange_process(f->table);
    if (matter_exchange_delete(f->table) != MATTER_OK) abort();
    matter_stop(f->owner);
    if (matter_delete(f->owner) != MATTER_OK) abort();
}
/* Literal byte construction, no production writer: exchange=0x1234, ack=0. */
static void packet(Fixture* f, uint8_t flags, uint16_t vendor, uint16_t protocol) {
    memset(f->wire, 0, sizeof(f->wire));
    f->wire[0] = flags; f->wire[1] = 1; f->wire[2] = 0x34; f->wire[3] = 0x12;
    size_t n = 4;
    if (flags & MATTER_PROTOCOL_VENDOR) { f->wire[n++] = (uint8_t)vendor; f->wire[n++] = (uint8_t)(vendor >> 8); }
    f->wire[n++] = (uint8_t)protocol; f->wire[n++] = (uint8_t)(protocol >> 8);
    if (flags & MATTER_PROTOCOL_ACK) n += 4;
    if (flags & MATTER_PROTOCOL_EXTENSIONS) { f->wire[n++] = 1; f->wire[n++] = 0; f->wire[n++] = 0xef; }
    f->expected_payload = f->wire + n;
    f->wire[n++] = 0xa5;
    f->input = (Matter_Rx_Input_T){10, 0xabcdef01, false, f->wire, n};
}

static bool matrix(void) {
    /* Core truth table, rows: known protocol + 2*existing + 4*duplicate;
     * columns: incoming I=0, I=1. ACK rows apply only when R=1. */
    static const Matter_Rx_Action_T actions[8][2] = {
        {MATTER_RX_DROP, MATTER_RX_DROP},
        {MATTER_RX_DROP, MATTER_RX_NEW_RESPONDER},
        {MATTER_RX_DROP, MATTER_RX_DROP},
        {MATTER_RX_EXISTING, MATTER_RX_EXISTING},
        {MATTER_RX_DROP, MATTER_RX_DROP},
        {MATTER_RX_DROP, MATTER_RX_DROP},
        {MATTER_RX_DROP, MATTER_RX_DROP},
        {MATTER_RX_DROP, MATTER_RX_DROP}
    };
    static const Matter_Rx_Ack_T acks[8][2] = {
        {MATTER_RX_ACK_IMMEDIATE, MATTER_RX_ACK_IMMEDIATE},
        {MATTER_RX_ACK_IMMEDIATE, MATTER_RX_ACK_PENDING},
        {MATTER_RX_ACK_PENDING, MATTER_RX_ACK_PENDING},
        {MATTER_RX_ACK_PENDING, MATTER_RX_ACK_PENDING},
        {MATTER_RX_ACK_IMMEDIATE, MATTER_RX_ACK_IMMEDIATE},
        {MATTER_RX_ACK_IMMEDIATE, MATTER_RX_ACK_IMMEDIATE},
        {MATTER_RX_ACK_IMMEDIATE, MATTER_RX_ACK_IMMEDIATE},
        {MATTER_RX_ACK_IMMEDIATE, MATTER_RX_ACK_IMMEDIATE}
    };
    bool ok = false;
    Fixture* f = calloc(1, sizeof(*f));
    if (!f) return false;
    Matter_Exchange_Handle_T init, responder;
    CHECK(create(f));
    CHECK(matter_rx_policy_register(f->policy, 0, 1) == MATTER_OK);
    CHECK(matter_exchange_initiate(f->table, 10, &init) == MATTER_OK);
    CHECK(matter_exchange_accept(f->table, 10, 0x1234, &responder) == MATTER_OK);
    for (unsigned flags = 0; flags < 256; ++flags) {
        for (unsigned conditions = 0; conditions < 8; ++conditions) {
            bool registered = (conditions & 1) != 0, existing = (conditions & 2) != 0;
            bool duplicate = (conditions & 4) != 0, incoming_i = (flags & 1) != 0;
            packet(f, (uint8_t)flags, 0, registered ? 1 : 2);
            f->input.session = existing ? 10 : 20;
            f->input.duplicate = duplicate;
            unsigned before = f->events;
            CHECK(matter_rx_policy_receive(f->policy, &f->input) == MATTER_OK && f->events == before + 1);
            Matter_Rx_Ack_T ack = flags & MATTER_PROTOCOL_RELIABLE ? acks[conditions][incoming_i] : MATTER_RX_ACK_NONE;
            CHECK(f->decision.action == actions[conditions][incoming_i] && f->decision.ack == ack);
            CHECK(f->decision.process_ack == ((flags & MATTER_PROTOCOL_ACK) != 0));
            CHECK(f->decision.header.acknowledged_message_counter == 0 && !f->decision.standalone_ack);
            CHECK(f->decision.exchange == (existing ? (incoming_i ? responder : init) : 0));
            CHECK(f->decision.header.exchange_flags == flags && f->decision.payload_size == 1 && f->copy[0] == 0xa5);
            CHECK(f->decision.message_counter == 0xabcdef01 && f->decision.session == f->input.session);
        }
    }
    /* Decisions neither create entries nor advance outgoing exchange IDs. */
    Matter_Exchange_Handle_T h = 999;
    CHECK(matter_exchange_match(f->table, 20, 0x1234, true, &h) == MATTER_INVALID_STATE && h == 999);
    CHECK(matter_exchange_initiate(f->table, 20, &h) == MATTER_OK);
    Matter_Exchange_Info_T info;
    CHECK(matter_exchange_get(f->table, h, &info) == MATTER_OK && info.exchange_id == 0x1235);
    CHECK(!f->violations);
    ok = true;
done:
    cleanup(f); free(f); return ok;
}

static bool registry(void) {
    bool ok = false;
    Fixture* f = calloc(1, sizeof(*f));
    if (!f) return false;
    CHECK(create(f));
    CHECK(matter_rx_policy_register(f->policy, 0, 5) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_rx_policy_register(f->policy, 0, UINT16_MAX) == MATTER_INVALID_ARGUMENT);
    for (uint16_t i = 0; i < 5; ++i) CHECK(matter_rx_policy_register(f->policy, 0, i) == MATTER_OK);
    CHECK(matter_rx_policy_register(f->policy, 0, 1) == MATTER_BUSY);
    CHECK(matter_rx_policy_register(f->policy, 0xfff1, 1) == MATTER_OK);
    CHECK(matter_rx_policy_register(f->policy, 0xfff2, 1) == MATTER_OK);
    CHECK(matter_rx_policy_register(f->policy, 0xfff1, UINT16_MAX) == MATTER_OK);
    CHECK(matter_rx_policy_register(f->policy, 0xfff1, 2) == MATTER_LIMIT_REACHED);
    CHECK(matter_rx_policy_unregister(f->policy, 0, 1) == MATTER_OK);
    CHECK(matter_rx_policy_unregister(f->policy, 0, 1) == MATTER_INVALID_STATE);
    packet(f, MATTER_PROTOCOL_INITIATOR, 0, 1);
    CHECK(matter_rx_policy_receive(f->policy, &f->input) == MATTER_OK && f->decision.action == MATTER_RX_DROP);
    packet(f, MATTER_PROTOCOL_INITIATOR | MATTER_PROTOCOL_VENDOR, 0xfff1, 1);
    CHECK(matter_rx_policy_receive(f->policy, &f->input) == MATTER_OK && f->decision.action == MATTER_RX_NEW_RESPONDER);
    packet(f, MATTER_PROTOCOL_INITIATOR | MATTER_PROTOCOL_VENDOR, 0xfff3, 1);
    CHECK(matter_rx_policy_receive(f->policy, &f->input) == MATTER_OK && f->decision.action == MATTER_RX_DROP);
    CHECK(matter_rx_policy_register(f->policy, 0, 1) == MATTER_OK);
    CHECK(!f->violations);
    ok = true;
done:
    cleanup(f); free(f); return ok;
}

static bool syntax_ack(void) {
    bool ok = false;
    Fixture* f = calloc(1, sizeof(*f));
    if (!f) return false;
    CHECK(create(f));
    CHECK(matter_rx_policy_register(f->policy, 0, 0) == MATTER_OK);
    packet(f, MATTER_PROTOCOL_ACK, 0, 0);
    f->wire[1] = 0x10;
    --f->input.size; /* Valid standalone ACK has no payload. */
    CHECK(matter_rx_policy_receive(f->policy, &f->input) == MATTER_OK);
    CHECK(f->decision.action == MATTER_RX_DROP && f->decision.standalone_ack && f->decision.process_ack);
    CHECK(f->decision.payload_size == 0 && f->decision.ack == MATTER_RX_ACK_NONE);
    f->wire[6] = 0x12; f->wire[7] = 0x34; f->wire[8] = 0x56; f->wire[9] = 0x78;
    CHECK(matter_rx_policy_receive(f->policy, &f->input) == MATTER_OK);
    CHECK(f->decision.header.acknowledged_message_counter == 0x78563412 && f->decision.process_ack);
    unsigned before = f->events;
    ++f->input.size;
    CHECK(matter_rx_policy_receive(f->policy, &f->input) == MATTER_INVALID_ARGUMENT && f->events == before);
    packet(f, 0, 0, 0); f->wire[1] = 0x10; --f->input.size;
    CHECK(matter_rx_policy_receive(f->policy, &f->input) == MATTER_INVALID_ARGUMENT && f->events == before);
    /* Vendor-specific opcode 0x10 is not the standard standalone ACK. */
    CHECK(matter_rx_policy_register(f->policy, 0xfff1, 0) == MATTER_OK);
    packet(f, MATTER_PROTOCOL_VENDOR | MATTER_PROTOCOL_INITIATOR, 0xfff1, 0); f->wire[1] = 0x10;
    CHECK(matter_rx_policy_receive(f->policy, &f->input) == MATTER_OK && !f->decision.standalone_ack);
    CHECK(f->decision.action == MATTER_RX_NEW_RESPONDER);
    packet(f, MATTER_PROTOCOL_VENDOR | MATTER_PROTOCOL_ACK | MATTER_PROTOCOL_EXTENSIONS, 0, 0);
    size_t full = f->input.size;
    before = f->events;
    for (size_t n = 0; n < full - 1; ++n) {
        f->input.size = n;
        CHECK(matter_rx_policy_receive(f->policy, &f->input) == MATTER_INVALID_ARGUMENT && f->events == before);
    }
    f->input.size = full;
    CHECK(matter_rx_policy_receive(f->policy, &f->input) == MATTER_OK);
    CHECK(f->decision.payload_size == 1 && f->copy[0] == 0xa5);
    CHECK(!f->violations);
    ok = true;
done:
    cleanup(f); free(f); return ok;
}

static bool lifetime(void) {
    bool ok = false;
    Fixture* f = calloc(2, sizeof(*f));
    if (!f) return false;
    CHECK(create(&f[0]) && create(&f[1]));
    CHECK(matter_rx_policy_register(f[0].policy, 0, 1) == MATTER_OK);
    for (size_t i = 0; i < 2; ++i) packet(&f[i], MATTER_PROTOCOL_INITIATOR, 0, 1);
    CHECK(matter_rx_policy_receive(f[0].policy, &f[0].input) == MATTER_OK && f[0].decision.action == MATTER_RX_NEW_RESPONDER);
    CHECK(matter_rx_policy_receive(f[1].policy, &f[1].input) == MATTER_OK && f[1].decision.action == MATTER_RX_DROP);
    CHECK(matter_exchange_stop(f[0].table) == MATTER_PENDING);
    CHECK(matter_get_state(f[0].owner) == MATTER_STATE_RUNNING);
    CHECK(matter_rx_policy_receive(f[0].policy, &f[0].input) == MATTER_INVALID_STATE && f[0].events == 1);
    CHECK(matter_exchange_process(f[0].table) == MATTER_OK);
    CHECK(matter_rx_policy_receive(f[0].policy, &f[0].input) == MATTER_INVALID_STATE);
    CHECK(matter_exchange_start(f[0].table) == MATTER_OK);
    CHECK(matter_rx_policy_receive(f[0].policy, &f[0].input) == MATTER_OK && f[0].decision.action == MATTER_RX_NEW_RESPONDER);
    CHECK(matter_stop(f[0].owner) == MATTER_PENDING);
    CHECK(matter_rx_policy_receive(f[0].policy, &f[0].input) == MATTER_INVALID_STATE);
    CHECK(matter_rx_policy_receive(f[1].policy, &f[1].input) == MATTER_OK);
    CHECK(matter_exchange_process(f[0].table) == MATTER_OK);
    CHECK(matter_start(f[0].owner) == MATTER_OK && matter_exchange_start(f[0].table) == MATTER_OK);
    CHECK(matter_rx_policy_receive(f[0].policy, &f[0].input) == MATTER_OK && f[0].decision.action == MATTER_RX_NEW_RESPONDER);
    CHECK(!f[0].violations && !f[1].violations);
    ok = true;
done:
    cleanup(&f[0]); cleanup(&f[1]); free(f); return ok;
}

static bool invalid(void) {
    bool ok = false;
    Fixture* f = calloc(1, sizeof(*f));
    if (!f) return false;
    CHECK(create(f));
    Matter_Rx_Listener_T listener = {f, decided}, empty = {0};
    CHECK(!matter_rx_policy_new(NULL, &listener));
    CHECK(!matter_rx_policy_new(f->table, NULL));
    CHECK(!matter_rx_policy_new(f->table, &empty));
    CHECK(matter_rx_policy_delete(NULL) == MATTER_OK);
    CHECK(matter_rx_policy_register(NULL, 0, 1) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_rx_policy_unregister(NULL, 0, 1) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_rx_policy_receive(NULL, NULL) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_rx_policy_receive(f->policy, NULL) == MATTER_INVALID_ARGUMENT);
    packet(f, 0, 0, 1); f->input.session = 0;
    CHECK(matter_rx_policy_receive(f->policy, &f->input) == MATTER_INVALID_ARGUMENT);
    f->input.session = 1; f->input.data = NULL;
    CHECK(matter_rx_policy_receive(f->policy, &f->input) == MATTER_INVALID_ARGUMENT);
    CHECK(!f->events);
    ok = true;
done:
    cleanup(f); free(f); return ok;
}

#ifdef MATTER_TEST_ALLOC
static bool allocation(void) {
    bool ok = false;
    Fixture* f = calloc(1, sizeof(*f));
    if (!f) return false;
    CHECK(create(f));
    Matter_Rx_Listener_T listener = {f, decided};
    size_t before = live;
    fail_next = true;
    CHECK(!matter_rx_policy_new(f->table, &listener) && live == before && !fail_next);
    printf("RX policy allocation: %zu bytes\n", last_size);
    before = calls;
    fail_next = true;
    CHECK(matter_rx_policy_register(f->policy, 0, 1) == MATTER_OK);
    packet(f, MATTER_PROTOCOL_INITIATOR | MATTER_PROTOCOL_RELIABLE, 0, 1);
    for (unsigned i = 0; i < 100; ++i) CHECK(matter_rx_policy_receive(f->policy, &f->input) == MATTER_OK);
    CHECK(fail_next && calls == before && !f->violations);
    ok = true;
done:
    fail_next = false;
    cleanup(f); free(f); return ok && live == 0;
}
#endif

int main(void) {
    const struct { const char* name; bool (*run)(void); } tests[] = {
        {"2048 policy cases and no exchange mutation", matrix},
        {"registry capacity, namespaces and removal", registry},
        {"standalone ACK, truncation and payload lifetime", syntax_ack},
        {"table readiness, stop/restart and isolation", lifetime},
        {"invalid inputs and callbacks", invalid},
#ifdef MATTER_TEST_ALLOC
        {"OOM and no per-message allocation", allocation},
#endif
    };
    for (size_t i = 0; i < sizeof(tests)/sizeof(tests[0]); ++i) {
        if (!tests[i].run()) return 1;
        printf("PASS rx policy: %s\n", tests[i].name);
    }
#ifdef MATTER_TEST_ALLOC
    if (live) return 1;
#endif
    return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "transport/matter_unsecured_prepare.h"
#include "ports/matter_udp_port.h"

#ifdef MATTER_TEST_ALLOC
static size_t calls, live;
void* matter_test_calloc(size_t n, size_t size) {
    ++calls; void* p = calloc(n, size); if (p) ++live; return p;
}
void matter_test_free(void* p) { if (p) { if (!live) abort(); --live; } free(p); }
#endif
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #c); return false; } } while (0)
#define REQUIRE(c) do { if (!(c)) abort(); } while (0)
typedef struct {
    Matter_Unsecured_T sessions;
    Matter_Counter_T counter;
    Matter_Exchange_Session_T initiator, responder;
    uint8_t bytes[MATTER_UDP_MAX_PAYLOAD + 1], before[MATTER_UDP_MAX_PAYLOAD + 1];
} Fixture;
static Matter_Result_T random_node(void* u, uint64_t* out) {
    (void)u; *out = UINT64_C(0x123456789abcdef0); return MATTER_OK;
}
static Matter_Result_T random_counter(void* u, uint32_t* out) {
    (void)u; *out = 0; return MATTER_OK;
}
static const Matter_Protocol_Header_T data_header = {
    .exchange_flags = MATTER_PROTOCOL_INITIATOR | MATTER_PROTOCOL_RELIABLE,
    .opcode = 0x20, .exchange_id = 0x1234, .protocol_id = 0
};
static const uint8_t data[] = {
    4,0,0,0, 1,0,0,0, 0xf0,0xde,0xbc,0x9a,0x78,0x56,0x34,0x12,
    5,0x20,0x34,0x12,0,0, 0xaa
};
static const uint8_t ack[] = {
    1,0,0,0, 2,0,0,0, 0xf0,0xde,0xbc,0x9a,0x78,0x56,0x34,0x22,
    2,0x10,0x34,0x12,0,0, 0x78,0x56,0x34,0x12
};
static const uint8_t vendor[] = {
    4,0,0,0, 3,0,0,0, 0xf0,0xde,0xbc,0x9a,0x78,0x56,0x34,0x12,
    0x12,0x55,0x34,0x12,0x34,0x12,0x78,0x56,0x44,0x33,0x22,0x11
};
static bool vectors(Fixture* f) {
    Matter_Unsecured_Prepared_T out;
    uint8_t payload = 0xaa;
    CHECK(matter_unsecured_prepare(f->sessions, f->initiator, &f->counter, &data_header, &payload, 1,
        f->bytes, sizeof(f->bytes), &out) == MATTER_OK);
    CHECK(out.counter == 1 && out.size == sizeof(data) && !memcmp(f->bytes, data, sizeof(data)));
    CHECK(matter_unsecured_prepare_encoded(f->sessions, f->responder, &f->counter, ack + 16, sizeof(ack) - 16,
        f->bytes, sizeof(f->bytes), &out) == MATTER_OK);
    CHECK(out.counter == 2 && out.size == sizeof(ack) && !memcmp(f->bytes, ack, sizeof(ack)));
    /* Session initiator, exchange responder: these roles must stay independent. */
    Matter_Protocol_Header_T h = {.exchange_flags = MATTER_PROTOCOL_VENDOR | MATTER_PROTOCOL_ACK,
        .opcode = 0x55, .exchange_id = 0x1234, .vendor_id = 0x1234, .protocol_id = 0x5678,
        .acknowledged_message_counter = 0x11223344};
    CHECK(matter_unsecured_prepare(f->sessions, f->initiator, &f->counter, &h, NULL, 0,
        f->bytes, sizeof(f->bytes), &out) == MATTER_OK);
    CHECK(out.counter == 3 && out.size == sizeof(vendor) && !memcmp(f->bytes, vendor, sizeof(vendor)));
    /* An application discarding this packet cannot recycle its number. */
    CHECK(matter_unsecured_prepare(f->sessions, f->initiator, &f->counter, &h, NULL, 0,
        f->bytes, sizeof(f->bytes), &out) == MATTER_OK && out.counter == 4);
    return true;
}
static bool unchanged(Fixture* f, const Matter_Unsecured_Prepared_T* out, uint32_t next) {
    return f->counter.next == next && out->counter == 99 && out->size == 99 &&
        !memcmp(f->bytes, f->before, sizeof(f->bytes));
}
static bool preflight(Fixture* f) {
    Matter_Unsecured_Prepared_T out = {99, 99};
    uint32_t next = f->counter.next;
    memset(f->bytes, 0xcc, sizeof(f->bytes)); memcpy(f->before, f->bytes, sizeof(f->bytes));
    for (size_t n = 0; n < sizeof(data); ++n) {
        CHECK(matter_unsecured_prepare(f->sessions, f->initiator, &f->counter, &data_header, data + 22, 1,
            f->bytes, n, &out) == MATTER_LIMIT_REACHED && unchanged(f, &out, next));
    }
    for (size_t n = 0; n < 10; ++n) {
        CHECK(matter_unsecured_prepare_encoded(f->sessions, f->responder, &f->counter, ack + 16, n,
            f->bytes, sizeof(f->bytes), &out) == MATTER_INVALID_ARGUMENT && unchanged(f, &out, next));
    }
    Matter_Protocol_Header_T invalid = data_header;
    invalid.exchange_flags |= MATTER_PROTOCOL_EXTENSIONS;
    CHECK(matter_unsecured_prepare(f->sessions, f->initiator, &f->counter, &invalid, NULL, 0,
        f->bytes, sizeof(f->bytes), &out) == MATTER_INVALID_ARGUMENT && unchanged(f, &out, next));
    static const uint8_t reserved[] = {0x80,0,0,0,0,0};
    CHECK(matter_unsecured_prepare_encoded(f->sessions, f->initiator, &f->counter, reserved, sizeof(reserved),
        f->bytes, sizeof(f->bytes), &out) == MATTER_INVALID_ARGUMENT && unchanged(f, &out, next));
    CHECK(matter_unsecured_prepare(f->sessions, f->initiator, &f->counter, &data_header, NULL, 1,
        f->bytes, sizeof(f->bytes), &out) == MATTER_INVALID_ARGUMENT && unchanged(f, &out, next));
    CHECK(matter_unsecured_prepare(f->sessions, f->initiator, &f->counter, &data_header, f->bytes, SIZE_MAX,
        f->bytes, sizeof(f->bytes), &out) == MATTER_LIMIT_REACHED && unchanged(f, &out, next));
    CHECK(matter_unsecured_prepare(f->sessions, 99, &f->counter, &data_header, NULL, 0,
        f->bytes, sizeof(f->bytes), &out) == MATTER_INVALID_STATE && unchanged(f, &out, next));
    CHECK(matter_unsecured_unpin(f->sessions, f->initiator) == MATTER_OK);
    CHECK(matter_unsecured_prepare(f->sessions, f->initiator, &f->counter, &data_header, NULL, 0,
        f->bytes, sizeof(f->bytes), &out) == MATTER_INVALID_STATE && unchanged(f, &out, next));
    REQUIRE(matter_unsecured_pin(f->sessions, f->initiator) == MATTER_OK);
    /* Test-only counter faults; production callers never edit initialized state. */
    f->counter.busy = true;
    CHECK(matter_unsecured_prepare(f->sessions, f->initiator, &f->counter, &data_header, NULL, 0,
        f->bytes, sizeof(f->bytes), &out) == MATTER_BUSY && unchanged(f, &out, next));
    f->counter.busy = false; f->counter.initialized = false;
    CHECK(matter_unsecured_prepare(f->sessions, f->initiator, &f->counter, &data_header, NULL, 0,
        f->bytes, sizeof(f->bytes), &out) == MATTER_INVALID_STATE && unchanged(f, &out, next));
    f->counter.initialized = true; f->counter.mode = MATTER_COUNTER_SECURE_UNICAST;
    CHECK(matter_unsecured_prepare(f->sessions, f->initiator, &f->counter, &data_header, NULL, 0,
        f->bytes, sizeof(f->bytes), &out) == MATTER_INVALID_STATE && unchanged(f, &out, next));
    f->counter.mode = MATTER_COUNTER_UNSECURED;
    return true;
}
static bool overlap_and_limits(Fixture* f) {
    Matter_Unsecured_Prepared_T out;
    /* Encoded protocol at start, final location, and beyond final location. */
    static const size_t offsets[] = {0,16,32};
    for (unsigned i = 0; i < 3; ++i) {
        memset(f->bytes, 0xcc, sizeof(f->bytes));
        memcpy(f->bytes + offsets[i], ack + 16, sizeof(ack) - 16);
        memcpy(f->before, f->bytes, sizeof(f->bytes));
        CHECK(matter_unsecured_prepare_encoded(f->sessions, f->responder, &f->counter,
            f->bytes + offsets[i], sizeof(ack) - 16, f->bytes, sizeof(ack), &out) == MATTER_OK);
        CHECK(out.size == sizeof(ack) && !memcmp(f->bytes + 16, ack + 16, sizeof(ack) - 16));
        CHECK(!memcmp(f->bytes + sizeof(ack), f->before + sizeof(ack), sizeof(f->bytes) - sizeof(ack)));
    }
    /* Maximum payload in-place, and one byte too large. All large storage heap-owned. */
    memset(f->bytes, 0x5a, sizeof(f->bytes));
    CHECK(matter_unsecured_prepare(f->sessions, f->initiator, &f->counter, &data_header,
        f->bytes, MATTER_UDP_MAX_PAYLOAD - 22, f->bytes, MATTER_UDP_MAX_PAYLOAD, &out) == MATTER_OK);
    CHECK(out.size == MATTER_UDP_MAX_PAYLOAD && f->bytes[MATTER_UDP_MAX_PAYLOAD] == 0x5a);
    for (size_t i = 22; i < out.size; ++i) CHECK(f->bytes[i] == 0x5a);
    uint32_t next = f->counter.next; out = (Matter_Unsecured_Prepared_T){99,99};
    memcpy(f->before, f->bytes, sizeof(f->bytes));
    CHECK(matter_unsecured_prepare(f->sessions, f->initiator, &f->counter, &data_header,
        f->bytes, MATTER_UDP_MAX_PAYLOAD - 21, f->bytes, sizeof(f->bytes), &out) == MATTER_LIMIT_REACHED);
    CHECK(unchanged(f, &out, next));
    f->counter.next = UINT32_MAX; /* Fast-forward only in test. */
    CHECK(matter_unsecured_prepare_encoded(f->sessions, f->responder, &f->counter, ack + 16, sizeof(ack) - 16,
        f->bytes, sizeof(f->bytes), &out) == MATTER_OK && out.counter == UINT32_MAX);
    CHECK(matter_unsecured_prepare(f->sessions, f->initiator, &f->counter, &data_header, NULL, 0,
        f->bytes, sizeof(f->bytes), &out) == MATTER_OK && out.counter == 0 && f->counter.next == 1);
    CHECK(matter_unsecured_unpin(f->sessions, f->responder) == MATTER_OK);
    CHECK(matter_unsecured_remove(f->sessions, f->responder) == MATTER_OK);
    Matter_Exchange_Session_T stale = f->responder; f->responder = 0;
    out = (Matter_Unsecured_Prepared_T){99,99}; memcpy(f->before, f->bytes, sizeof(f->bytes));
    CHECK(matter_unsecured_prepare_encoded(f->sessions, stale, &f->counter, ack + 16, sizeof(ack) - 16,
        f->bytes, sizeof(f->bytes), &out) == MATTER_INVALID_STATE && unchanged(f, &out, 1));
    return true;
}
int main(void) {
    Fixture* f = calloc(1, sizeof(*f));
    if (!f) return 1;
    f->sessions = matter_unsecured_new(1, 10);
    if (!f->sessions) { free(f); return 1; }
    REQUIRE(matter_counter_init(&f->counter, MATTER_COUNTER_UNSECURED, random_counter, NULL) == MATTER_OK);
    REQUIRE(matter_unsecured_initiate(f->sessions, random_node, NULL, &f->initiator) == MATTER_OK);
    Matter_Message_Header_T h = {.message_flags = MATTER_MESSAGE_SOURCE_PRESENT,
        .source_node_id = UINT64_C(0x223456789abcdef0)};
    REQUIRE(matter_unsecured_resolve(f->sessions, &h, true, &f->responder) == MATTER_OK);
    REQUIRE(matter_unsecured_pin(f->sessions, f->initiator) == MATTER_OK);
    REQUIRE(matter_unsecured_pin(f->sessions, f->responder) == MATTER_OK);
    bool ok = vectors(f) && preflight(f) && overlap_and_limits(f);
    for (Matter_Exchange_Session_T s = 1; s <= 2; ++s) {
        Matter_Unsecured_Info_T info;
        if (matter_unsecured_get(f->sessions, s, &info) == MATTER_OK) {
            if (info.pins) REQUIRE(matter_unsecured_unpin(f->sessions, s) == MATTER_OK);
            REQUIRE(matter_unsecured_remove(f->sessions, s) == MATTER_OK);
        }
    }
    REQUIRE(matter_unsecured_delete(f->sessions) == MATTER_OK); free(f);
#ifdef MATTER_TEST_ALLOC
    REQUIRE(calls == 1 && live == 0); /* Only table construction, no per-message allocation. */
#endif
    if (ok) puts("PASS unsecured preparation: 3 groups");
    return ok ? 0 : 1;
}

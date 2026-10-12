#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "transport/matter_unsecured_rx.h"

#ifdef MATTER_TEST_ALLOC
static size_t live, calls, fail_at, last_size;
void* matter_test_calloc(size_t n, size_t size) {
    if (++calls == fail_at) return NULL;
    void* p = calloc(n, size);
    if (p) { ++live; last_size = n * size; }
    return p;
}
void matter_test_free(void* p) { if (p) { if (!live) abort(); --live; } free(p); }
#endif
#define REQUIRE(c) do { if (!(c)) { fprintf(stderr, "fixture:%d: %s\n", __LINE__, #c); abort(); } } while (0)
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #c); goto done; } } while (0)
typedef struct {
    Matter_T owner;
    Matter_Rx_T rx;
    Matter_Unsecured_T sessions;
    Matter_Unsecured_Rx_T ingress;
    Matter_Udp_Datagram_T datagram;
    Matter_Udp_Path_T accepted_path;
    Matter_Exchange_Session_T session, looked_up;
    const Matter_Ack_Message_T* ack;
    uint64_t ack_request;
    Matter_Result_T policy_result, retain_result;
    unsigned admitted, accepted, deliveries, acks, pins, detached;
    bool create, omit_create, any_payload, duplicate, started, in_receive;
    uint8_t payload;
    uint8_t bytes[MATTER_UDP_MAX_PAYLOAD + 1];
} Fixture;
static const uint8_t data[] = {4,0,0,0,7,0,0,0,1,0,0,0,0,0,0,0,5,1,0x34,0x12,4,0,0xa1};
static const uint8_t ack[] = {4,0,0,0,8,0,0,0,1,0,0,0,0,0,0,0,3,0x10,0x34,0x12,0,0,7,0,0,0};
static void probe(Fixture* f) {
    REQUIRE(matter_unsecured_rx_receive(f->ingress, &f->datagram, 0) == MATTER_BUSY);
    REQUIRE(matter_unsecured_rx_close(f->ingress) == MATTER_BUSY);
    REQUIRE(matter_unsecured_rx_stop(f->ingress) == MATTER_BUSY);
    REQUIRE(matter_unsecured_rx_delete(f->ingress) == MATTER_BUSY);
}
static Matter_Result_T admit(void* u, const Matter_Unsecured_Rx_Message_T* m, bool* create) {
    Fixture* f = u; probe(f); ++f->admitted; f->looked_up = m->session;
    REQUIRE(m->datagram == &f->datagram && m->payload >= f->bytes && m->payload <= f->bytes + f->datagram.size);
    if (f->policy_result != MATTER_OK) return f->policy_result;
    bool payload = m->protocol.protocol_id == 4 && m->protocol.opcode == 1 &&
        (f->any_payload || m->payload_size == 1);
    bool control = !m->protocol.protocol_id && m->protocol.opcode == 0x10 &&
        (m->protocol.exchange_flags & MATTER_PROTOCOL_ACK) &&
        !(m->protocol.exchange_flags & MATTER_PROTOCOL_RELIABLE) && !m->payload_size;
    if (m->protocol.vendor_id || (!payload && !control)) return MATTER_INVALID_ARGUMENT;
    if (!f->omit_create) *create = f->create && payload;
    return MATTER_OK; /* Test policy only, deliberately not commissioning. */
}
static void accepted(void* u, const Matter_Unsecured_Rx_Message_T* m, bool duplicate) {
    Fixture* f = u; probe(f);
    Matter_Unsecured_Info_T info;
    REQUIRE(m->session && matter_unsecured_get(f->sessions, m->session, &info) == MATTER_OK && info.pins >= 2);
    REQUIRE(matter_unsecured_remove(f->sessions, m->session) == MATTER_BUSY);
    bool committed = false;
    REQUIRE(matter_unsecured_classify(f->sessions, m->session, m->message.message_counter, &committed) == MATTER_OK && committed);
    f->session = m->session; f->duplicate = duplicate; f->accepted_path = m->datagram->path; ++f->accepted;
}
static void detach(void* u) { Fixture* f = u; probe(f); ++f->detached; }
static Matter_Result_T retain(void* u, Matter_Exchange_Session_T session) {
    Fixture* f = u;
    if (f->in_receive) probe(f);
    if (f->retain_result != MATTER_OK) return f->retain_result;
    Matter_Result_T result = matter_unsecured_pin(f->sessions, session);
    if (result == MATTER_OK) ++f->pins;
    return result;
}
static void release(void* u, Matter_Exchange_Session_T session) {
    Fixture* f = u; REQUIRE(f->pins && matter_unsecured_unpin(f->sessions, session) == MATTER_OK); --f->pins;
}
static Matter_Result_T process_ack(void* u, const Matter_Exchange_Info_T* key, uint32_t counter) {
    Fixture* f = u; (void)key; REQUIRE(counter == 7); ++f->acks; return MATTER_OK;
}
static Matter_Result_T drained(void* u, const Matter_Exchange_Info_T* key) { (void)u; (void)key; return MATTER_OK; }
static void deliver(void* u, const Matter_Rx_Decision_T* d) {
    Fixture* f = u; REQUIRE(d->payload != f->bytes + 22);
    f->payload = d->payload_size ? d->payload[0] : 0; ++f->deliveries;
}
static Matter_Result_T send_ack(void* u, uint64_t id, const Matter_Ack_Message_T* m) {
    Fixture* f = u; REQUIRE(!f->ack && f->pins); f->ack = m; f->ack_request = id; return MATTER_OK;
}
static void detach_ack(void* u) { Fixture* f = u; REQUIRE(!f->ack && !f->pins); }
static Matter_Result_T dependencies(void* u) { REQUIRE(!((Fixture*)u)->pins); return MATTER_OK; }
static void finish_ack(Fixture* f) {
    if (f->ack) { f->ack = NULL; REQUIRE(matter_rx_complete(f->rx, f->ack_request, MATTER_OPERATION_SUCCEEDED) == MATTER_OK); }
}
static bool process(Fixture* f, uint64_t now) {
    Matter_Result_T r = matter_rx_process(f->rx, now); return r == MATTER_OK || r == MATTER_PENDING;
}
static Matter_Result_T receive(Fixture* f) {
    f->in_receive = true;
    Matter_Result_T result = matter_unsecured_rx_receive(f->ingress, &f->datagram, 0);
    f->in_receive = false; return result;
}
static unsigned pins(Fixture* f, Matter_Exchange_Session_T token) {
    Matter_Unsecured_Info_T info;
    REQUIRE(matter_unsecured_get(f->sessions, token, &info) == MATTER_OK); return info.pins;
}
static bool seen(Fixture* f, uint32_t counter) {
    bool duplicate;
    REQUIRE(matter_unsecured_pin(f->sessions, f->session) == MATTER_OK);
    REQUIRE(matter_unsecured_classify(f->sessions, f->session, counter, &duplicate) == MATTER_OK);
    REQUIRE(matter_unsecured_unpin(f->sessions, f->session) == MATTER_OK); return duplicate;
}
static void cleanup(Fixture* f) {
    if (!f) return;
    if (f->ingress) {
        REQUIRE(matter_unsecured_rx_stop(f->ingress) == MATTER_OK);
        REQUIRE(matter_unsecured_rx_delete(f->ingress) == MATTER_OK);
        f->ingress = NULL; REQUIRE(f->detached == 1);
    }
    f->retain_result = MATTER_OK;
    if (f->rx) {
        matter_rx_stop(f->rx);
        if (f->started) {
            Matter_Result_T r = MATTER_PENDING;
            for (unsigned i = 0; i < 32 && r != MATTER_OK; ++i) {
                finish_ack(f); r = matter_rx_process(f->rx, UINT64_MAX);
                REQUIRE(r == MATTER_OK || r == MATTER_PENDING);
            }
            REQUIRE(r == MATTER_OK);
        }
        REQUIRE(matter_rx_delete(f->rx) == MATTER_OK);
    }
    if (f->sessions) for (unsigned id = 1; id <= 1000; ++id) {
        Matter_Unsecured_Info_T info;
        if (matter_unsecured_get(f->sessions, id, &info) == MATTER_OK) {
            REQUIRE(!info.pins); REQUIRE(matter_unsecured_remove(f->sessions, id) == MATTER_OK);
        }
    }
    REQUIRE(matter_unsecured_delete(f->sessions) == MATTER_OK);
    if (f->owner) REQUIRE(matter_stop(f->owner) == MATTER_OK);
    REQUIRE(matter_delete(f->owner) == MATTER_OK && !f->pins);
    free(f);
}
static Fixture* create(bool start) {
    Fixture* f = calloc(1, sizeof(*f)); if (!f) return NULL;
    f->create = true;
    memcpy(f->bytes, data, sizeof(data)); f->datagram.data = f->bytes; f->datagram.size = sizeof(data);
    f->datagram.path.local.address[15] = f->datagram.path.peer.address[15] = 1;
    f->datagram.path.local.port = 5540; f->datagram.path.peer.port = 5541; f->datagram.path.interface_id = 7;
    f->owner = matter_new(NULL); if (!f->owner) goto fail;
    f->sessions = matter_unsecured_new(1, 1000); if (!f->sessions) goto fail;
    Matter_Rx_Port_T rx = {f, {f, send_ack, detach_ack}, retain, release, process_ack, drained, deliver, dependencies};
    f->rx = matter_rx_new(f->owner, 0x1234, &rx); if (!f->rx) goto fail;
    Matter_Unsecured_Rx_Port_T port = {f, admit, accepted, detach};
    f->ingress = matter_unsecured_rx_new(f->rx, f->sessions, &port); if (!f->ingress) goto fail;
    memset(&port, 0, sizeof(port)); /* Copied port, no constructor callbacks. */
    REQUIRE(!f->admitted && !f->accepted && !f->detached);
    REQUIRE(matter_start(f->owner) == MATTER_OK && matter_rx_register(f->rx, 0, 4) == MATTER_OK);
    if (start) { REQUIRE(matter_rx_start(f->rx) == MATTER_OK); f->started = true; }
    return f;
fail: cleanup(f); return NULL;
}
static bool copying_commit_and_backpressure(void) {
    bool ok = false;
    Fixture* f = create(true); CHECK(f);
    CHECK(receive(f) == MATTER_OK && f->session == 1 && !f->looked_up && !f->duplicate && !f->deliveries);
    CHECK(pins(f, 1) == 1 && seen(f, 7)); /* Only queued RX's independent pin remains. */
    f->bytes[4] = 8; f->bytes[22] = 0xb2; f->datagram.path.peer.port = 6000;
    CHECK(receive(f) == MATTER_WOULD_BLOCK && !seen(f, 8) && f->accepted == 1 && f->accepted_path.peer.port == 5541);
    CHECK(process(f, 0) && f->deliveries == 1 && f->payload == 0xa1);
    CHECK(receive(f) == MATTER_OK && !f->duplicate && seen(f, 8) && f->accepted_path.peer.port == 6000);
    CHECK(process(f, 0) && f->ack && f->deliveries == 1); /* Old ACK must drain before next delivery. */
    finish_ack(f); CHECK(process(f, 1) && f->deliveries == 2 && f->payload == 0xb2);
    CHECK(receive(f) == MATTER_OK && f->duplicate && process(f, 1) && f->deliveries == 2);
    finish_ack(f);
    CHECK(pins(f, 1) == 1);
    f->retain_result = MATTER_OFFLINE; f->bytes[4] = 9;
    CHECK(receive(f) == MATTER_OFFLINE && !seen(f, 9) && pins(f, 1) == 1 && f->accepted == 3);
    ok = true;
done: cleanup(f); return ok;
}
static bool admission_and_rollback(void) {
    bool ok = false;
    Fixture* f = create(true); Matter_Unsecured_Info_T info; CHECK(f);
    const Matter_Result_T errors[] = {MATTER_INVALID_ARGUMENT, MATTER_INVALID_STATE, MATTER_WOULD_BLOCK, MATTER_OFFLINE,
        MATTER_PORT_ERROR, MATTER_PENDING, MATTER_BUSY};
    for (size_t i = 0; i < sizeof(errors)/sizeof(*errors); ++i) {
        f->policy_result = errors[i];
        CHECK(receive(f) == (i < 5 ? errors[i] : MATTER_PORT_ERROR) && !f->accepted);
        CHECK(matter_unsecured_get(f->sessions, 1, &info) == MATTER_INVALID_STATE);
    }
    f->policy_result = MATTER_OK; f->omit_create = true;
    CHECK(receive(f) == MATTER_INVALID_STATE); f->omit_create = false;
    f->bytes[20] = 5; CHECK(receive(f) == MATTER_INVALID_ARGUMENT); f->bytes[20] = 4;
    f->bytes[0] = 1; CHECK(receive(f) == MATTER_INVALID_STATE); f->bytes[0] = 4;
    f->retain_result = MATTER_OFFLINE;
    CHECK(receive(f) == MATTER_OFFLINE && !f->pins && !f->accepted);
    CHECK(matter_unsecured_get(f->sessions, 1, &info) == MATTER_INVALID_STATE);
    f->retain_result = MATTER_OK;
    CHECK(receive(f) == MATTER_OK && f->session == 2); /* Rollback removed slot, did not recycle token. */
    f->bytes[8] = 2; /* Unknown source while RX slot occupied must also roll back. */
    CHECK(receive(f) == MATTER_WOULD_BLOCK && f->accepted == 1);
    CHECK(matter_unsecured_get(f->sessions, 3, &info) == MATTER_INVALID_STATE);
    ok = true;
done: cleanup(f); return ok;
}
static bool syntax_and_limits(void) {
    bool ok = false;
    Fixture* f = create(true); CHECK(f);
    for (size_t size = 0; size < sizeof(data); ++size) {
        f->datagram.size = size; CHECK(receive(f) == MATTER_INVALID_ARGUMENT && !f->accepted);
    }
    f->datagram.size = sizeof(data);
    const unsigned offsets[] = {0,0,0,1,3,3,8};
    const uint8_t values[] = {0x14,0x07,0x00,1,0x80,0x40,0};
    for (size_t i = 0; i < sizeof(values); ++i) {
        memcpy(f->bytes, data, sizeof(data)); f->bytes[offsets[i]] = values[i];
        unsigned before = f->admitted;
        CHECK(receive(f) == MATTER_INVALID_ARGUMENT && f->admitted == before);
    }
    memcpy(f->bytes, data, sizeof(data));
    f->datagram.path.local.address[0] = 0xff; CHECK(receive(f) == MATTER_INVALID_ARGUMENT);
    f->datagram.path.local.address[0] = 0; f->datagram.path.peer.address[15] = 0;
    CHECK(receive(f) == MATTER_INVALID_ARGUMENT);
    f->datagram.path.peer.address[15] = 1; f->datagram.path.local.port = 0;
    CHECK(receive(f) == MATTER_INVALID_ARGUMENT); f->datagram.path.local.port = 5540;
    f->datagram.size = sizeof(f->bytes); CHECK(receive(f) == MATTER_LIMIT_REACHED);
    f->datagram.size = MATTER_UDP_MAX_PAYLOAD; f->any_payload = true;
    CHECK(receive(f) == MATTER_OK && process(f, 0) && f->deliveries == 1);
    ok = true;
done: cleanup(f); return ok;
}
static bool extensions_and_lifecycle(void) {
    bool ok = false;
    Fixture* f = create(true); Fixture* other = create(false); CHECK(f && other);
    /* Ignored reserved bits, one-byte MX and SX; lengths and payload are literals. */
    static const uint8_t extended[] = {0x0c,0,0,0x3c,7,0,0,0,1,0,0,0,0,0,0,0,1,0,0xaa,
        0x2d,1,0x34,0x12,4,0,1,0,0xbb,0xa1};
    memcpy(f->bytes, extended, sizeof(extended)); f->datagram.size = sizeof(extended);
    CHECK(receive(f) == MATTER_OK && process(f, 0) && f->payload == 0xa1);
    CHECK(receive(other) == MATTER_INVALID_STATE && !other->accepted); /* RX not started; context rollback. */
    REQUIRE(matter_rx_start(other->rx) == MATTER_OK); other->started = true;
    CHECK(receive(other) == MATTER_OK && other->session == 2 && !other->duplicate);
    CHECK(matter_unsecured_rx_delete(f->ingress) == MATTER_INVALID_STATE);
    CHECK(matter_unsecured_rx_close(f->ingress) == MATTER_OK && matter_unsecured_rx_close(f->ingress) == MATTER_OK);
    memcpy(f->bytes, data, sizeof(data)); f->datagram.size = sizeof(data); f->bytes[8] = 2;
    CHECK(receive(f) == MATTER_INVALID_STATE && f->accepted == 1);
    CHECK(matter_rx_stop(f->rx) == MATTER_PENDING);
    memcpy(f->bytes, ack, sizeof(ack)); f->datagram.size = sizeof(ack);
    CHECK(receive(f) == MATTER_OK && f->looked_up == 1 && process(f, 1) && f->acks == 1 && f->deliveries == 1);
    CHECK(matter_unsecured_rx_stop(f->ingress) == MATTER_OK && matter_unsecured_rx_stop(f->ingress) == MATTER_OK);
    CHECK(receive(f) == MATTER_INVALID_STATE && f->accepted == 2);
    CHECK(matter_unsecured_rx_receive(NULL, &f->datagram, 0) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_unsecured_rx_receive(other->ingress, NULL, 0) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_unsecured_rx_close(NULL) == MATTER_INVALID_ARGUMENT && matter_unsecured_rx_stop(NULL) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_unsecured_rx_delete(NULL) == MATTER_OK);
    CHECK(!matter_unsecured_rx_new(NULL, f->sessions, NULL));
    ok = true;
done: cleanup(f); cleanup(other); return ok;
}
#ifdef MATTER_TEST_ALLOC
static bool allocation_failures(void) {
    bool ok = false;
    Fixture* f = NULL;
    for (unsigned i = 1; i <= 8; ++i) {
        fail_at = calls + i; f = create(true); CHECK(!f && !live); fail_at = 0;
    }
    f = create(true); CHECK(f && live == 8);
    printf("Unsecured RX adapter: %zu bytes, one allocation\n", last_size);
    size_t before = calls;
    for (unsigned i = 0; i < 100; ++i) {
        f->bytes[4] = (uint8_t)(7 + i);
        CHECK(receive(f) == MATTER_OK && process(f, i));
        finish_ack(f); CHECK(process(f, i)); finish_ack(f);
    }
    CHECK(calls == before && f->deliveries == 100);
    ok = true;
done: fail_at = 0; cleanup(f); return ok && !live;
}
#endif
int main(void) {
    unsigned count = 0;
#define RUN(t) do { if (!(t)()) return 1; ++count; } while (0)
    RUN(copying_commit_and_backpressure); RUN(admission_and_rollback); RUN(syntax_and_limits); RUN(extensions_and_lifecycle);
#ifdef MATTER_TEST_ALLOC
    RUN(allocation_failures); REQUIRE(!live);
#endif
    printf("PASS unsecured RX: %u groups\n", count); return 0;
}

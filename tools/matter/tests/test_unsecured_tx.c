#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "transport/matter_unsecured_tx.h"

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
    Matter_Udp_T udp;
    Matter_Unsecured_T sessions;
    Matter_Unsecured_Tx_T tx, target;
    Matter_Exchange_Session_T session;
    Matter_Udp_Path_T path;
    Matter_Operation_Id_T epoch;
    const Matter_Udp_Datagram_T* retained;
    uint64_t request;
    uint8_t bytes[MATTER_UDP_MAX_PAYLOAD + 1];
    Matter_Result_T route_result, send_result;
    unsigned routes, sends, events, detaches, cancels, violations;
    bool external, omit_path;
} Fixture;
static const uint8_t packet[] = {4,0,0,0,7,0,0,0,1,0,0,0,0,0,0,0,5,1,0x34,0x12,4,0,0xa1};
static unsigned pins(Fixture* f) {
    Matter_Unsecured_Info_T info;
    REQUIRE(matter_unsecured_get(f->sessions, f->session, &info) == MATTER_OK);
    return info.pins;
}
static void probe(Fixture* f) {
    uint64_t id = 99;
    Matter_Unsecured_Tx_Result_T out = {.request = 88};
    if (matter_unsecured_tx_send(f->tx, f->session, f->bytes, sizeof(packet), &id) != MATTER_BUSY || id != 99 ||
        matter_unsecured_tx_close(f->tx) != MATTER_BUSY || matter_unsecured_tx_delete(f->tx) != MATTER_BUSY ||
        matter_unsecured_tx_complete(f->tx, 1, MATTER_OPERATION_SUCCEEDED) != MATTER_BUSY ||
        matter_unsecured_tx_take(f->tx, &out) != MATTER_BUSY || out.request != 88) ++f->violations;
}
static Matter_Result_T route(void* u, Matter_Exchange_Session_T session, Matter_Udp_Path_T* path) {
    Fixture* f = u; ++f->routes;
    REQUIRE(session == f->session && pins(f)); probe(f);
    REQUIRE(matter_unsecured_remove(f->sessions, session) == MATTER_BUSY);
    if (!f->omit_path) *path = f->path;
    return f->route_result;
}
static void detached(void* u) {
    Fixture* f = u; ++f->detaches; probe(f); f->target = NULL;
}
static Matter_Result_T activate(void* u, Matter_Operation_Id_T epoch) { ((Fixture*)u)->epoch = epoch; return MATTER_OK; }
static void deactivate(void* u, Matter_Operation_Id_T epoch) { REQUIRE(((Fixture*)u)->epoch == epoch); }
static Matter_Result_T send_udp(void* u, uint64_t id, const Matter_Udp_Datagram_T* d) {
    Fixture* f = u; ++f->sends;
    if (!f->external) probe(f);
    if (f->send_result != MATTER_OK) return f->send_result;
    REQUIRE(!f->retained); f->retained = d; f->request = id; return MATTER_OK;
}
static void cancel_udp(void* u, uint64_t id) { Fixture* f = u; REQUIRE(f->retained && id == f->request); ++f->cancels; }
static void detach_udp(void* u) { REQUIRE(!((Fixture*)u)->retained); }
static void sent(void* u, uint64_t id, Matter_Operation_Result_T result) {
    Fixture* f = u; ++f->events;
    REQUIRE(!f->retained);
    if (!f->external) {
        REQUIRE(f->target && matter_unsecured_tx_complete(f->target, id, result) == MATTER_OK);
        REQUIRE(pins(f)); /* Listener must not take/free; application does that later. */
    }
}
static Matter_Result_T random_node(void* u, uint64_t* out) { (void)u; *out = 1; return MATTER_OK; }
static bool create(Fixture* f) {
    memcpy(f->bytes, packet, sizeof(packet));
    f->path.local.port = 5540; f->path.peer.port = 5541; f->path.peer.address[15] = 1; f->path.interface_id = 7;
    f->owner = matter_new(NULL); if (!f->owner) return false;
    f->sessions = matter_unsecured_new(10, 20); if (!f->sessions) return false;
    Matter_Udp_Port_T port = {f, activate, deactivate, send_udp, cancel_udp, detach_udp};
    Matter_Udp_Listener_T listener = {f, NULL, sent};
    f->udp = matter_udp_new(f->owner, &port, &listener); if (!f->udp) return false;
    Matter_Unsecured_Tx_Port_T tx_port = {f, route, detached};
    f->tx = matter_unsecured_tx_new(f->udp, f->sessions, &tx_port); if (!f->tx) return false;
    f->target = f->tx;
    memset(&tx_port, 0, sizeof(tx_port)); /* Constructor must copy configuration. */
    return matter_unsecured_initiate(f->sessions, random_node, NULL, &f->session) == MATTER_OK &&
        matter_start(f->owner) == MATTER_OK && matter_udp_start(f->udp) == MATTER_OK;
}
static void complete(Fixture* f, Matter_Operation_Result_T outcome) {
    REQUIRE(f->retained); f->retained = NULL;
    REQUIRE(matter_udp_complete(f->udp, f->request, outcome) == MATTER_OK);
}
static void cleanup(Fixture* f) {
    if (!f) return;
    if (f->retained) complete(f, MATTER_OPERATION_CANCELLED);
    if (f->tx) {
        Matter_Unsecured_Tx_Result_T out;
        Matter_Result_T r = matter_unsecured_tx_take(f->tx, &out);
        REQUIRE(r == MATTER_OK || r == MATTER_INVALID_STATE);
        REQUIRE(matter_unsecured_tx_close(f->tx) == MATTER_OK);
        REQUIRE(matter_unsecured_tx_delete(f->tx) == MATTER_OK); f->tx = NULL;
    }
    if (f->udp) {
        matter_udp_stop(f->udp);
        for (unsigned i = 0; i < 4 && matter_udp_is_active(f->udp); ++i) matter_udp_process(f->udp);
        REQUIRE(matter_udp_delete(f->udp) == MATTER_OK);
    }
    if (f->session) REQUIRE(matter_unsecured_remove(f->sessions, f->session) == MATTER_OK);
    REQUIRE(matter_unsecured_delete(f->sessions) == MATTER_OK);
    if (f->owner) REQUIRE(matter_stop(f->owner) == MATTER_OK);
    REQUIRE(matter_delete(f->owner) == MATTER_OK);
    REQUIRE(!f->violations);
}
static bool ownership_and_snapshot(void) {
    bool ok = false;
    Fixture* f = calloc(1, sizeof(*f)); if (!f) return false;
    uint64_t id = 99, rejected = 88;
    Matter_Unsecured_Tx_Result_T out = {.request = 77};
    CHECK(create(f));
    CHECK(matter_unsecured_tx_delete(f->tx) == MATTER_INVALID_STATE);
    CHECK(matter_unsecured_tx_send(f->tx, f->session, f->bytes, sizeof(packet), &id) == MATTER_PENDING);
    CHECK(pins(f) == 1 && !f->events && f->retained->data == f->bytes && !memcmp(f->retained->data, packet, sizeof(packet)));
    CHECK(matter_unsecured_tx_take(f->tx, &out) == MATTER_PENDING && out.request == 77);
    CHECK(matter_unsecured_tx_send(f->tx, f->session, f->bytes, sizeof(packet), &rejected) == MATTER_BUSY && rejected == 88);
    f->path.peer.port = 6000; f->path.interface_id = 9;
    CHECK(f->retained->path.peer.port == 5541 && f->retained->path.interface_id == 7);
    CHECK(matter_unsecured_tx_complete(f->tx, id + 1, MATTER_OPERATION_FAILED) == MATTER_INVALID_STATE);
    CHECK(matter_unsecured_tx_complete(f->tx, id, (Matter_Operation_Result_T)9) == MATTER_INVALID_ARGUMENT);
    complete(f, MATTER_OPERATION_SUCCEEDED);
    CHECK(f->events == 1 && pins(f) == 1 && matter_unsecured_remove(f->sessions, f->session) == MATTER_BUSY);
    CHECK(matter_unsecured_tx_complete(f->tx, id, MATTER_OPERATION_FAILED) == MATTER_INVALID_STATE);
    CHECK(matter_unsecured_tx_send(f->tx, f->session, f->bytes, sizeof(packet), &rejected) == MATTER_BUSY);
    CHECK(matter_unsecured_tx_take(f->tx, &out) == MATTER_OK && out.request == id && out.session == f->session &&
        out.data == f->bytes && out.size == sizeof(packet) && out.outcome == MATTER_OPERATION_SUCCEEDED && !pins(f));
    CHECK(matter_unsecured_tx_take(f->tx, &out) == MATTER_INVALID_STATE);
    CHECK(matter_unsecured_tx_send(f->tx, f->session, f->bytes, sizeof(packet), &rejected) == MATTER_PENDING && rejected > id);
    CHECK(f->retained->path.peer.port == 6000 && f->retained->path.interface_id == 9 && !memcmp(f->bytes, packet, sizeof(packet)));
    CHECK(matter_unsecured_tx_complete(f->tx, id, MATTER_OPERATION_SUCCEEDED) == MATTER_INVALID_STATE);
    complete(f, MATTER_OPERATION_FAILED);
    CHECK(matter_unsecured_tx_take(f->tx, &out) == MATTER_OK && out.outcome == MATTER_OPERATION_FAILED);
    ok = true;
done: cleanup(f); free(f); return ok;
}
static bool rejection_and_validation(void) {
    bool ok = false;
    Fixture* f = calloc(1, sizeof(*f)); if (!f) return false;
    uint64_t id = 99;
    Matter_Unsecured_Tx_Result_T out = {.request = 88};
    CHECK(create(f));
    static const Matter_Result_T errors[] = {MATTER_WOULD_BLOCK, MATTER_OFFLINE, MATTER_PORT_ERROR, MATTER_PENDING};
    for (unsigned i = 0; i < 4; ++i) {
        f->route_result = errors[i];
        CHECK(matter_unsecured_tx_send(f->tx, f->session, f->bytes, sizeof(packet), &id) == (i == 3 ? MATTER_PORT_ERROR : errors[i]));
        CHECK(id == 99 && !pins(f) && !f->sends && !f->events);
    }
    f->route_result = MATTER_OK; f->omit_path = true;
    CHECK(matter_unsecured_tx_send(f->tx, f->session, f->bytes, sizeof(packet), &id) == MATTER_PORT_ERROR && !pins(f));
    f->omit_path = false; f->path.peer.address[0] = 0xff;
    CHECK(matter_unsecured_tx_send(f->tx, f->session, f->bytes, sizeof(packet), &id) == MATTER_PORT_ERROR);
    f->path.peer.address[0] = 0;
    for (unsigned i = 0; i < 4; ++i) {
        f->send_result = errors[i];
        CHECK(matter_unsecured_tx_send(f->tx, f->session, f->bytes, sizeof(packet), &id) == (i == 3 ? MATTER_PORT_ERROR : errors[i]));
        CHECK(id == 99 && !pins(f) && !f->retained && !f->events);
    }
    f->send_result = MATTER_OK;
    unsigned routes = f->routes;
    CHECK(matter_unsecured_tx_send(f->tx, f->session, f->bytes, MATTER_UDP_MAX_PAYLOAD + 1, &id) == MATTER_LIMIT_REACHED);
    CHECK(matter_unsecured_tx_send(f->tx, f->session, NULL, sizeof(packet), &id) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_unsecured_tx_send(f->tx, 0, f->bytes, sizeof(packet), &id) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_unsecured_tx_send(f->tx, f->session + 1, f->bytes, sizeof(packet), &id) == MATTER_INVALID_STATE);
    CHECK(matter_unsecured_tx_send(f->tx, f->session, f->bytes, sizeof(packet), NULL) == MATTER_INVALID_ARGUMENT);
    for (size_t i = 0; i <= 16; ++i)
        CHECK(matter_unsecured_tx_send(f->tx, f->session, f->bytes, i, &id) == MATTER_INVALID_ARGUMENT);
    static const unsigned offsets[] = {0,1,3,8};
    static const uint8_t values[] = {1,1,1,2};
    for (unsigned i = 0; i < 4; ++i) {
        f->bytes[offsets[i]] = values[i];
        CHECK(matter_unsecured_tx_send(f->tx, f->session, f->bytes, sizeof(packet), &id) == MATTER_INVALID_ARGUMENT);
        memcpy(f->bytes, packet, sizeof(packet));
    }
    CHECK(f->routes == routes && id == 99 && !pins(f));
    CHECK(matter_unsecured_tx_take(f->tx, &out) == MATTER_INVALID_STATE && out.request == 88);
    CHECK(matter_unsecured_tx_take(f->tx, NULL) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_unsecured_tx_complete(f->tx, 0, MATTER_OPERATION_SUCCEEDED) == MATTER_INVALID_ARGUMENT);
    /* Shared UDP is occupied by another routed producer; adapter rejection unpins. */
    f->external = true;
    Matter_Udp_Datagram_T direct = {f->path, f->bytes, sizeof(packet)};
    CHECK(matter_udp_send(f->udp, &direct, &id) == MATTER_PENDING);
    id = 99;
    CHECK(matter_unsecured_tx_send(f->tx, f->session, f->bytes, sizeof(packet), &id) == MATTER_BUSY && id == 99 && !pins(f));
    complete(f, MATTER_OPERATION_SUCCEEDED); f->external = false;
    CHECK(matter_unsecured_tx_send(f->tx, f->session, f->bytes, MATTER_UDP_MAX_PAYLOAD, &id) == MATTER_PENDING);
    CHECK(f->retained->size == MATTER_UDP_MAX_PAYLOAD);
    complete(f, MATTER_OPERATION_CANCELLED);
    CHECK(matter_unsecured_tx_take(f->tx, &out) == MATTER_OK && out.outcome == MATTER_OPERATION_CANCELLED);
    CHECK(matter_udp_stop(f->udp) == MATTER_PENDING);
    CHECK(matter_unsecured_tx_send(f->tx, f->session, f->bytes, sizeof(packet), &id) == MATTER_INVALID_STATE && !pins(f));
    ok = true;
done: cleanup(f); free(f); return ok;
}
static bool close_isolation_and_rebinding(void) {
    bool ok = false;
    Fixture* f = calloc(2, sizeof(*f)); if (!f) return false;
    uint64_t a, b, rejected = 99;
    Matter_Unsecured_Tx_Result_T out;
    CHECK(create(&f[0]) && create(&f[1]));
    CHECK(matter_unsecured_tx_send(f[0].tx, f[0].session, f[0].bytes, sizeof(packet), &a) == MATTER_PENDING);
    CHECK(matter_unsecured_tx_send(f[1].tx, f[1].session, f[1].bytes, sizeof(packet), &b) == MATTER_PENDING && a == b);
    CHECK(matter_unsecured_tx_close(f[0].tx) == MATTER_PENDING && !f[0].cancels && matter_udp_is_active(f[0].udp));
    CHECK(matter_unsecured_tx_delete(f[0].tx) == MATTER_INVALID_STATE);
    CHECK(matter_unsecured_tx_send(f[0].tx, f[0].session, f[0].bytes, sizeof(packet), &rejected) == MATTER_INVALID_STATE && rejected == 99);
    complete(&f[1], MATTER_OPERATION_SUCCEEDED);
    CHECK(matter_unsecured_tx_take(f[1].tx, &out) == MATTER_OK && !pins(&f[1]) && pins(&f[0]) == 1);
    /* Explicit service shutdown is separate from adapter close; cancellation
     * still owes a terminal event. Simulate a successful send racing cancel. */
    CHECK(matter_udp_stop(f[0].udp) == MATTER_PENDING);
    CHECK(matter_udp_process(f[0].udp) == MATTER_PENDING && matter_udp_process(f[0].udp) == MATTER_PENDING);
    CHECK(f[0].cancels == 1 && matter_unsecured_tx_close(f[0].tx) == MATTER_PENDING);
    complete(&f[0], MATTER_OPERATION_SUCCEEDED);
    CHECK(matter_unsecured_tx_close(f[0].tx) == MATTER_PENDING && pins(&f[0]) == 1);
    CHECK(matter_unsecured_tx_take(f[0].tx, &out) == MATTER_OK && out.outcome == MATTER_OPERATION_SUCCEEDED);
    CHECK(matter_unsecured_tx_close(f[0].tx) == MATTER_OK);
    CHECK(matter_unsecured_tx_delete(f[0].tx) == MATTER_OK && f[0].detaches == 1 && !f[0].target); f[0].tx = NULL;
    CHECK(matter_udp_process(f[0].udp) == MATTER_OK && matter_udp_start(f[0].udp) == MATTER_OK);
    Matter_Unsecured_Tx_Port_T port = {&f[0], route, detached};
    f[0].tx = matter_unsecured_tx_new(f[0].udp, f[0].sessions, &port); f[0].target = f[0].tx;
    CHECK(f[0].tx && matter_unsecured_tx_complete(f[0].tx, a, MATTER_OPERATION_SUCCEEDED) == MATTER_INVALID_STATE);
    CHECK(matter_unsecured_tx_send(f[0].tx, f[0].session, f[0].bytes, sizeof(packet), &rejected) == MATTER_PENDING && rejected > a);
    CHECK(matter_unsecured_tx_complete(f[0].tx, a, MATTER_OPERATION_FAILED) == MATTER_INVALID_STATE);
    complete(&f[0], MATTER_OPERATION_FAILED);
    CHECK(matter_unsecured_tx_take(f[0].tx, &out) == MATTER_OK && out.outcome == MATTER_OPERATION_FAILED);
    ok = true;
done: cleanup(&f[0]); cleanup(&f[1]); free(f); return ok;
}
#ifdef MATTER_TEST_ALLOC
static bool allocation_failures(void) {
    bool ok = false;
    Fixture* f = calloc(1, sizeof(*f)); if (!f) return false;
    for (unsigned i = 1; i <= 4; ++i) {
        fail_at = calls + i;
        CHECK(!create(f)); cleanup(f); memset(f, 0, sizeof(*f)); CHECK(!live);
    }
    fail_at = 0;
    CHECK(create(f) && live == 4);
    printf("Unsecured TX adapter: %zu bytes, one allocation\n", last_size);
    size_t before = calls;
    for (unsigned i = 0; i < 100; ++i) {
        uint64_t id;
        Matter_Unsecured_Tx_Result_T out;
        CHECK(matter_unsecured_tx_send(f->tx, f->session, f->bytes, sizeof(packet), &id) == MATTER_PENDING);
        complete(f, MATTER_OPERATION_SUCCEEDED);
        CHECK(matter_unsecured_tx_take(f->tx, &out) == MATTER_OK);
    }
    CHECK(calls == before && !pins(f)); ok = true;
done: fail_at = 0; cleanup(f); free(f); return ok && !live;
}
#endif
int main(void) {
    unsigned passed = 0;
#define RUN(t) do { if (!(t)()) return 1; ++passed; } while (0)
    RUN(ownership_and_snapshot); RUN(rejection_and_validation); RUN(close_isolation_and_rebinding);
#ifdef MATTER_TEST_ALLOC
    RUN(allocation_failures); REQUIRE(!live);
#endif
    printf("PASS unsecured TX: %u groups\n", passed); return 0;
}

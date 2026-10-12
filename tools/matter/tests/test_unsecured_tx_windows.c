#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "matter_udp_windows.h"
#include "transport/matter_unsecured_tx.h"

#ifdef MATTER_TEST_ALLOC
static size_t live, calls;
void* matter_test_calloc(size_t n, size_t size) {
    void* p = calloc(n, size); if (p) { ++live; ++calls; } return p;
}
void matter_test_free(void* p) { if (p) { if (!live) abort(); --live; } free(p); }
#endif
#define REQUIRE(c) do { if (!(c)) { fprintf(stderr, "fixture:%d: %s\n", __LINE__, #c); abort(); } } while (0)
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #c); goto done; } } while (0)
typedef struct {
    Matter_T owner;
    Matter_Udp_Windows_T host;
    Matter_Udp_T udp;
    Matter_Unsecured_T sessions;
    Matter_Unsecured_Tx_T tx, target;
    Matter_Exchange_Session_T session;
    Matter_Udp_Address_T local;
    Matter_Udp_Path_T path, received_path;
    uint8_t bytes[64], received[64];
    size_t size;
    unsigned rx, completed, detached;
} Endpoint;
static void receive(void* u, const Matter_Udp_Datagram_T* d) {
    Endpoint* e = u; REQUIRE(d->size <= sizeof(e->received));
    memcpy(e->received, d->data, d->size); e->size = d->size; e->received_path = d->path; ++e->rx;
}
static void sent(void* u, uint64_t id, Matter_Operation_Result_T result) {
    Endpoint* e = u;
    REQUIRE(e->target && matter_unsecured_tx_complete(e->target, id, result) == MATTER_OK);
    ++e->completed; /* No take/send from this UDP/host callback. */
}
static Matter_Result_T route(void* u, Matter_Exchange_Session_T session, Matter_Udp_Path_T* path) {
    Endpoint* e = u; REQUIRE(session == e->session); *path = e->path; return MATTER_OK;
}
static void detach(void* u) { Endpoint* e = u; e->target = NULL; ++e->detached; }
static bool create(Endpoint* e) {
    e->owner = matter_new(NULL); if (!e->owner) return false;
    e->sessions = matter_unsecured_new(10, 20); if (!e->sessions) return false;
    Matter_Udp_Address_T local = {{0}, 0}; local.address[15] = 1;
    Matter_Udp_Listener_T listener = {e, receive, sent};
    e->host = matter_udp_windows_new(e->owner, &local, 0, &listener); if (!e->host) return false;
    e->udp = matter_udp_windows_module(e->host);
    Matter_Unsecured_Tx_Port_T port = {e, route, detach};
    e->tx = matter_unsecured_tx_new(e->udp, e->sessions, &port); if (!e->tx) return false;
    e->target = e->tx;
    return matter_start(e->owner) == MATTER_OK && matter_udp_start(e->udp) == MATTER_OK &&
        matter_udp_windows_local(e->host, &e->local) == MATTER_OK;
}
static Matter_Result_T wait_event(Endpoint* e) {
    ULONGLONG end = GetTickCount64() + 2000;
    do {
        Matter_Result_T r = matter_udp_windows_poll(e->host);
        if (r != MATTER_WOULD_BLOCK) return r;
        Sleep(1); /* Test only; adapter and host never block. */
    } while (GetTickCount64() < end);
    return MATTER_WOULD_BLOCK;
}
static void cleanup(Endpoint* e) {
    if (e->tx) {
        matter_unsecured_tx_close(e->tx);
        matter_udp_windows_poll(e->host);
        Matter_Unsecured_Tx_Result_T out;
        Matter_Result_T r = matter_unsecured_tx_take(e->tx, &out);
        REQUIRE(r == MATTER_OK || r == MATTER_INVALID_STATE);
        REQUIRE(matter_unsecured_tx_close(e->tx) == MATTER_OK);
        REQUIRE(matter_unsecured_tx_delete(e->tx) == MATTER_OK);
    }
    if (e->udp) {
        matter_udp_stop(e->udp);
        for (unsigned i = 0; i < 5 && matter_udp_is_active(e->udp); ++i) {
            matter_udp_process(e->udp); matter_udp_windows_poll(e->host);
        }
    }
    REQUIRE(matter_udp_windows_delete(e->host) == MATTER_OK);
    if (e->session) REQUIRE(matter_unsecured_remove(e->sessions, e->session) == MATTER_OK);
    REQUIRE(matter_unsecured_delete(e->sessions) == MATTER_OK);
    if (e->owner) REQUIRE(matter_stop(e->owner) == MATTER_OK);
    REQUIRE(matter_delete(e->owner) == MATTER_OK);
}
static Matter_Result_T random_node(void* u, uint64_t* out) { (void)u; *out = 1; return MATTER_OK; }
int main(void) {
    bool ok = false;
    Endpoint* e = calloc(2, sizeof(*e)); if (!e) return 1;
    static const uint8_t data[] = {4,0,0,0,7,0,0,0,1,0,0,0,0,0,0,0,5,1,0x34,0x12,4,0,0xa1};
    static const uint8_t ack[] = {1,0,0,0,100,0,0,0,1,0,0,0,0,0,0,0,2,0x10,0x34,0x12,0,0,7,0,0,0};
    uint64_t a_id, b_id;
    Matter_Unsecured_Tx_Result_T out;
    Matter_Unsecured_Info_T info;
    Matter_Message_Header_T header;
    size_t used;
    CHECK(create(&e[0]) && create(&e[1]));
    CHECK(matter_unsecured_initiate(e[0].sessions, random_node, NULL, &e[0].session) == MATTER_OK);
    e[0].path.local = e[0].local; e[0].path.peer = e[1].local;
    memcpy(e[0].bytes, data, sizeof(data));
#ifdef MATTER_TEST_ALLOC
    size_t before = calls;
#endif
    CHECK(matter_unsecured_tx_send(e[0].tx, e[0].session, e[0].bytes, sizeof(data), &a_id) == MATTER_PENDING);
    CHECK(!e[0].completed && matter_unsecured_tx_take(e[0].tx, &out) == MATTER_PENDING);
    CHECK(matter_unsecured_tx_close(e[0].tx) == MATTER_PENDING && matter_udp_is_active(e[0].udp));
    CHECK(wait_event(&e[0]) == MATTER_OK && e[0].completed == 1);
    CHECK(matter_unsecured_get(e[0].sessions, e[0].session, &info) == MATTER_OK && info.pins == 1);
    CHECK(matter_unsecured_tx_close(e[0].tx) == MATTER_PENDING);
    CHECK(matter_unsecured_tx_take(e[0].tx, &out) == MATTER_OK && out.request == a_id && out.outcome == MATTER_OPERATION_SUCCEEDED);
    CHECK(matter_unsecured_tx_close(e[0].tx) == MATTER_OK && matter_udp_is_active(e[0].udp));
    CHECK(wait_event(&e[1]) == MATTER_OK && e[1].rx == 1 && e[1].size == sizeof(data));
    CHECK(!memcmp(e[1].received, data, sizeof(data)) && e[1].received_path.peer.port == e[0].local.port);
    CHECK(matter_message_header_read(e[1].received, e[1].size, &header, &used) == MATTER_MESSAGE_OK);
    CHECK(matter_unsecured_resolve(e[1].sessions, &header, true, &e[1].session) == MATTER_OK);
    CHECK(matter_unsecured_get(e[1].sessions, e[1].session, &info) == MATTER_OK && !info.initiator);
    e[1].path = e[1].received_path; memcpy(e[1].bytes, ack, sizeof(ack));
    CHECK(matter_unsecured_tx_send(e[1].tx, e[1].session, e[1].bytes, sizeof(ack), &b_id) == MATTER_PENDING);
    CHECK(wait_event(&e[1]) == MATTER_OK && e[1].completed == 1);
    CHECK(matter_unsecured_tx_take(e[1].tx, &out) == MATTER_OK && out.request == b_id && out.outcome == MATTER_OPERATION_SUCCEEDED);
    CHECK(wait_event(&e[0]) == MATTER_OK && e[0].rx == 1 && e[0].size == sizeof(ack));
    CHECK(!memcmp(e[0].received, ack, sizeof(ack)) && !memcmp(e[0].bytes, data, sizeof(data)));
#ifdef MATTER_TEST_ALLOC
    CHECK(calls == before);
#endif
    ok = true;
done:
    cleanup(&e[0]); cleanup(&e[1]); free(e);
#ifdef MATTER_TEST_ALLOC
    REQUIRE(!live);
#endif
    if (!ok) return 1;
    puts("PASS unsecured TX Windows: real IPv6 data/ACK, deferred result, pin/drain and isolation"); return 0;
}

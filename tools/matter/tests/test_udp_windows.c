#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
typedef int SOCKET;
typedef struct sockaddr SOCKADDR;
typedef struct sockaddr_in6 SOCKADDR_IN6;
#define INVALID_SOCKET (-1)
#define closesocket close
#endif
#include "matter_host_platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "matter_udp_windows.h"

#ifdef MATTER_TEST_ALLOC
static size_t live, countdown;
void* matter_test_calloc(size_t count, size_t size) {
    if (countdown && !--countdown) return NULL;
    void* p = calloc(count, size);
    if (p) ++live;
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
    Matter_Udp_Windows_T host;
    Matter_Udp_T udp;
    Matter_Udp_Address_T local;
    Matter_Udp_Path_T path;
    uint8_t bytes[MATTER_UDP_MAX_PAYLOAD + 64], received[MATTER_UDP_MAX_PAYLOAD];
    size_t size;
    uint64_t request;
    unsigned rx, tx, violations;
    Matter_Operation_Result_T terminal;
} Endpoint;

static void probe(Endpoint* e) {
    if (matter_udp_windows_poll(e->host) != MATTER_BUSY) ++e->violations;
    if (matter_udp_windows_delete(e->host) != MATTER_BUSY) ++e->violations;
}
static void received(void* user, const Matter_Udp_Datagram_T* datagram) {
    Endpoint* e = user;
    ++e->rx;
    e->path = datagram->path;
    e->size = datagram->size;
    memcpy(e->received, datagram->data, datagram->size);
    probe(e);
}
static void sent(void* user, uint64_t request, Matter_Operation_Result_T result) {
    Endpoint* e = user;
    ++e->tx;
    e->request = request;
    e->terminal = result;
    probe(e);
}
static bool create(Endpoint* e, const Matter_Udp_Address_T* address) {
    e->owner = matter_new(NULL);
    if (!e->owner) return false;
    Matter_Udp_Listener_T listener = {e, received, sent};
    e->host = matter_udp_windows_new(e->owner, address, 0, &listener);
    if (!e->host) return false;
    e->udp = matter_udp_windows_module(e->host);
    if (matter_start(e->owner) != MATTER_OK) return false;
    return true;
}
static bool start(Endpoint* e) {
    return matter_udp_start(e->udp) == MATTER_OK &&
        matter_udp_windows_local(e->host, &e->local) == MATTER_OK;
}
static bool cleanup(Endpoint* e) {
    if (e->udp) {
        matter_udp_stop(e->udp);
        for (unsigned i = 0; i < 5 && matter_udp_is_active(e->udp); ++i) {
            matter_udp_process(e->udp);
            matter_udp_windows_poll(e->host);
        }
    }
    if (matter_udp_windows_delete(e->host) != MATTER_OK) return false;
    matter_stop(e->owner);
    if (matter_delete(e->owner) != MATTER_OK) return false;
    return true;
}
static Matter_Udp_Address_T loopback(uint16_t port) {
    Matter_Udp_Address_T address = {{0}, port};
    address.address[15] = 1;
    return address;
}
static Matter_Result_T wait_event(Endpoint* e) {
    uint64_t deadline = matter_host_now() + 2000;
    Matter_Result_T result;
    do {
        result = matter_udp_windows_poll(e->host);
        if (result != MATTER_WOULD_BLOCK) return result;
        matter_host_sleep(1); /* Only the test waits; backend has no sleep/event loop. */
    } while (matter_host_now() < deadline);
    return MATTER_WOULD_BLOCK;
}
static Matter_Result_T send_to(Endpoint* from, Endpoint* to, size_t size, uint64_t* id) {
    Matter_Udp_Datagram_T datagram = {0};
    datagram.path.local = from->local;
    datagram.path.peer = loopback(to->local.port);
    datagram.data = from->bytes;
    datagram.size = size;
    return matter_udp_send(from->udp, &datagram, id);
}
/* Independent socket injects bytes rejected by the Matter send-side validator. */
static bool raw_send(Endpoint* to, size_t size) {
    SOCKET s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return false;
#ifdef _WIN32
    u_long nonblocking = 1;
    if(ioctlsocket(s,FIONBIO,&nonblocking)) { closesocket(s); return false; }
#endif
    SOCKADDR_IN6 peer = {0};
    peer.sin6_family = AF_INET6;
    peer.sin6_port = htons(to->local.port);
    peer.sin6_addr.s6_addr[15] = 1;
    bool ok = sendto(s, (const char*)to->bytes, (int)size, 0, (SOCKADDR*)&peer, sizeof(peer)) == (int)size;
    closesocket(s);
    return ok;
}

static bool exchange(void) {
    bool ok = false;
    Endpoint* e = calloc(2, sizeof(*e));
    if (!e) return false;
    Matter_Udp_Address_T address = loopback(0), any = {{0},0};
    uint64_t id = 0;
    CHECK(create(&e[0], &address) && create(&e[1], &any));
    CHECK(start(&e[0]) && start(&e[1]));
    CHECK(e[0].local.port && e[1].local.port && e[0].local.port != e[1].local.port);
    CHECK(matter_udp_windows_poll(e[1].host) == MATTER_WOULD_BLOCK);
    memset(e[0].bytes, 0xa5, MATTER_UDP_MAX_PAYLOAD);
    CHECK(send_to(&e[0], &e[1], MATTER_UDP_MAX_PAYLOAD, &id) == MATTER_PENDING);
    CHECK(!e[0].tx && !e[1].rx);
    CHECK(matter_udp_windows_poll(e[0].host) == MATTER_OK);
    CHECK(e[0].tx == 1 && e[0].request == id && e[0].terminal == MATTER_OPERATION_SUCCEEDED);
    CHECK(wait_event(&e[1]) == MATTER_OK);
    CHECK(e[1].rx == 1 && e[1].size == MATTER_UDP_MAX_PAYLOAD);
    CHECK(!memcmp(e[1].received, e[0].bytes, MATTER_UDP_MAX_PAYLOAD));
    CHECK(!memcmp(e[1].path.local.address, address.address, 16));
    CHECK(!memcmp(e[1].path.peer.address, address.address, 16));
    CHECK(e[1].path.interface_id && e[1].path.peer.port == e[0].local.port);
    CHECK(e[1].path.local.port == e[1].local.port);
    /* Reply using exactly the received destination + interface, even though
     * receiver bound ::. No guessing the destination from getsockname(). */
    Matter_Udp_Datagram_T reply = {e[1].path, e[1].bytes, 1};
    e[1].bytes[0] = 0x42;
    CHECK(matter_udp_send(e[1].udp, &reply, &id) == MATTER_PENDING);
    CHECK(matter_udp_windows_poll(e[1].host) == MATTER_OK);
    CHECK(wait_event(&e[0]) == MATTER_OK && e[0].received[0] == 0x42);
    CHECK(!e[0].violations && !e[1].violations);
    ok = true;
done:
    ok = cleanup(&e[0]) && ok;
    ok = cleanup(&e[1]) && ok;
    free(e);
    return ok;
}

static bool lifecycle(void) {
    bool ok = false;
    Endpoint* e = calloc(2, sizeof(*e));
    if (!e) return false;
    Matter_Udp_Address_T address = loopback(0);
    uint64_t id = 0;
    CHECK(create(&e[0], &address) && create(&e[1], &address));
    CHECK(start(&e[0]) && start(&e[1]));
    CHECK(matter_udp_windows_delete(e[0].host) == MATTER_INVALID_STATE);
    CHECK(send_to(&e[0], &e[1], 1, &id) == MATTER_PENDING);
    CHECK(matter_stop(e[0].owner) == MATTER_PENDING);
    CHECK(matter_udp_process(e[0].udp) == MATTER_PENDING); /* RX close */
    CHECK(matter_udp_process(e[0].udp) == MATTER_PENDING); /* TX cancel */
    CHECK(!e[0].tx);
    CHECK(matter_udp_windows_poll(e[0].host) == MATTER_OK);
    CHECK(e[0].tx == 1 && e[0].terminal == MATTER_OPERATION_SUCCEEDED);
    CHECK(matter_udp_process(e[0].udp) == MATTER_OK);
    CHECK(matter_get_state(e[0].owner) == MATTER_STATE_STOPPED);
    CHECK(wait_event(&e[1]) == MATTER_OK); /* Closing A does not shut down B. */
    CHECK(matter_start(e[0].owner) == MATTER_OK && start(&e[0]));
    CHECK(raw_send(&e[0], 1)); /* Leave an old packet unread in the kernel. */
    CHECK(matter_udp_stop(e[0].udp) == MATTER_PENDING);
    CHECK(matter_udp_process(e[0].udp) == MATTER_PENDING);
    CHECK(matter_udp_process(e[0].udp) == MATTER_OK);
    CHECK(start(&e[0]));
    CHECK(matter_udp_windows_poll(e[0].host) == MATTER_WOULD_BLOCK && !e[0].rx);
    CHECK(send_to(&e[1], &e[0], 1, &id) == MATTER_PENDING);
    CHECK(matter_udp_windows_poll(e[1].host) == MATTER_OK);
    CHECK(wait_event(&e[0]) == MATTER_OK && e[0].rx == 1);
    CHECK(matter_udp_stop(e[0].udp) == MATTER_PENDING);
    CHECK(matter_udp_process(e[0].udp) == MATTER_PENDING);
    CHECK(matter_udp_process(e[0].udp) == MATTER_OK);
    CHECK(matter_udp_windows_delete(e[0].host) == MATTER_OK);
    e[0].host = NULL; e[0].udp = NULL;
    Matter_Udp_Listener_T listener = {&e[0], received, sent};
    e[0].host = matter_udp_windows_new(e[0].owner, &address, 0, &listener);
    CHECK(e[0].host);
    e[0].udp = matter_udp_windows_module(e[0].host);
    CHECK(start(&e[0]));
    CHECK(matter_udp_windows_poll(e[0].host) == MATTER_WOULD_BLOCK);
    CHECK(send_to(&e[0], &e[1], 1, &id) == MATTER_PENDING);
    CHECK(matter_udp_windows_poll(e[0].host) == MATTER_OK);
    CHECK(wait_event(&e[1]) == MATTER_OK && e[1].rx == 2);
    CHECK(!e[0].violations && !e[1].violations);
    ok = true;
done:
    ok = cleanup(&e[0]) && ok;
    ok = cleanup(&e[1]) && ok;
    free(e);
    return ok;
}

static bool errors(void) {
    bool ok = false;
    Endpoint* e = calloc(2, sizeof(*e));
    if (!e) return false;
    Matter_Udp_Address_T address = loopback(0), output = loopback(99);
    uint64_t id = 999;
    CHECK(create(&e[0], &address));
    CHECK(matter_udp_windows_local(e[0].host, &output) == MATTER_INVALID_STATE && output.port == 99);
    CHECK(start(&e[0]));
    CHECK(create(&e[1], &e[0].local));
    CHECK(matter_udp_start(e[1].udp) == MATTER_PORT_ERROR); /* Exclusive bind */
    CHECK(!matter_udp_is_active(e[1].udp));
    CHECK(raw_send(&e[0], MATTER_UDP_MAX_PAYLOAD + 1));
#ifdef _WIN32
    CHECK(wait_event(&e[0]) == MATTER_LIMIT_REACHED && !e[0].rx);
#else
    CHECK(wait_event(&e[0]) == MATTER_WOULD_BLOCK && !e[0].rx); /* Kernel MTU filter. */
#endif
    CHECK(raw_send(&e[0], 0));
    CHECK(wait_event(&e[0]) == MATTER_INVALID_ARGUMENT && !e[0].rx);
    CHECK(raw_send(&e[0], 1));
    CHECK(wait_event(&e[0]) == MATTER_OK && e[0].rx == 1);
    CHECK(send_to(&e[0], &e[0], MATTER_UDP_MAX_PAYLOAD+1, &id) == MATTER_LIMIT_REACHED && id == 999);
    Matter_Udp_Datagram_T packet = {{e[0].local, e[0].local, 0}, e[0].bytes, 1};
    packet.path.local.port ^= 1;
    if (!packet.path.local.port) packet.path.local.port = 2;
    CHECK(matter_udp_send(e[0].udp, &packet, &id) == MATTER_PORT_ERROR && id == 999);
    packet.path.local = e[0].local;
    memset(packet.path.peer.address, 0, 16);
    packet.path.peer.address[0] = 0xfe; packet.path.peer.address[1] = 0x80;
    CHECK(matter_udp_send(e[0].udp, &packet, &id) == MATTER_PORT_ERROR && id == 999);
    CHECK(matter_udp_windows_poll(e[0].host) == MATTER_WOULD_BLOCK && !e[0].tx);
    CHECK(matter_udp_stop(e[0].udp) == MATTER_PENDING);
    CHECK(matter_udp_process(e[0].udp) == MATTER_PENDING);
    CHECK(matter_udp_process(e[0].udp) == MATTER_OK);
    CHECK(start(&e[1])); /* Failed activate released socket and operation lease. */
    ok = true;
done:
    ok = cleanup(&e[0]) && ok;
    ok = cleanup(&e[1]) && ok;
    free(e);
    return ok;
}

#ifdef MATTER_TEST_ALLOC
static bool allocation(void) {
    Matter_T owner = matter_new(NULL);
    if (!owner) return false;
    Matter_Udp_Address_T address = loopback(0);
    bool ok = true;
    for (size_t failure = 1; failure <= 2; ++failure) {
        size_t before = live;
        countdown = failure; /* Host context, then nested module allocation. */
        Matter_Udp_Windows_T host = matter_udp_windows_new(owner, &address, 0, NULL);
        countdown = 0;
        if (host || live != before) ok = false;
        matter_udp_windows_delete(host);
    }
    matter_delete(owner);
    return ok && live == 0;
}
#endif

int main(void) {
    if (!exchange() || !lifecycle() || !errors()) return 1;
    puts("PASS UDP host: real IPv6 payload/pktinfo/reply, lifecycle/isolation, errors/truncation");
#ifdef MATTER_TEST_ALLOC
    if (live || !allocation()) return 1;
    puts("PASS UDP host: allocation failures and balanced allocations");
#endif
    return 0;
}

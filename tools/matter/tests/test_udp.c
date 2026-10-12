#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "matter_udp.h"

#ifdef MATTER_TEST_ALLOC
#include "alloc.h"
static size_t live;
static bool fail_next;
void* matter_test_calloc(size_t count, size_t size) {
    if (fail_next) { fail_next = false; return NULL; }
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
    fprintf(stderr,"%s:%d %s: %s\n",__FILE__,__LINE__,__func__,#c); goto done; } } while (0)

/* All packet-sized test buffers live on heap, as must backend buffers on MCU. */
typedef struct {
    Matter_T owner;
    Matter_Udp_T udp, target;
    Matter_Result_T activate_result, send_result;
    Matter_Operation_Id_T epoch;
    uint64_t binding, request;
    const Matter_Udp_Datagram_T* retained;
    Matter_Udp_Datagram_T datagram;
    Matter_Udp_Path_T received_path;
    uint8_t bytes[MATTER_UDP_MAX_PAYLOAD+1], received_bytes[MATTER_UDP_MAX_PAYLOAD];
    size_t received_size;
    unsigned activates, deactivates, sends, cancels, detaches, sent, received, violations;
    Matter_Operation_Result_T terminal;
    bool receiving;
} Fixture;

static void probe(Fixture* f) {
    uint64_t id = 999;
    if (matter_udp_start(f->udp) != MATTER_BUSY) ++f->violations;
    if (matter_udp_stop(f->udp) != MATTER_BUSY) ++f->violations;
    if (matter_udp_process(f->udp) != MATTER_BUSY) ++f->violations;
    if (matter_udp_delete(f->udp) != MATTER_BUSY) ++f->violations;
    if (matter_udp_send(f->udp,&f->datagram,&id) != MATTER_BUSY || id != 999) ++f->violations;
    if (matter_udp_complete(f->udp,1,MATTER_OPERATION_SUCCEEDED) != MATTER_BUSY) ++f->violations;
    if (matter_udp_receive(f->udp,f->epoch,&f->datagram,false) != MATTER_BUSY) ++f->violations;
    (void)matter_udp_is_active(f->udp);
}
static Matter_Result_T activate(void* user, Matter_Operation_Id_T epoch) {
    Fixture* f = user;
    ++f->activates; probe(f);
    if (f->receiving || f->retained) ++f->violations;
    if (f->activate_result == MATTER_OK) { f->epoch = epoch; f->receiving = true; }
    return f->activate_result;
}
static void deactivate(void* user, Matter_Operation_Id_T epoch) {
    Fixture* f = user;
    ++f->deactivates; probe(f);
    if (!f->receiving || epoch != f->epoch) ++f->violations;
    f->receiving = false; /* Queued RX routes for epoch are now invalid. */
}
static Matter_Result_T send_packet(void* user, uint64_t request, const Matter_Udp_Datagram_T* datagram) {
    Fixture* f = user;
    ++f->sends; probe(f);
    if (!f->receiving || f->retained) ++f->violations;
    if (f->send_result == MATTER_OK) { f->request = request; f->retained = datagram; }
    return f->send_result;
}
static void cancel(void* user, uint64_t request) {
    Fixture* f = user;
    ++f->cancels; probe(f);
    if (request != f->request || !f->retained || f->receiving) ++f->violations;
}
static void detach(void* user) {
    Fixture* f = user;
    ++f->detaches; probe(f);
    if (f->retained || f->receiving) ++f->violations;
    f->target = NULL;
}
static void received(void* user, const Matter_Udp_Datagram_T* datagram) {
    Fixture* f = user;
    ++f->received; probe(f);
    f->received_path = datagram->path;
    f->received_size = datagram->size;
    memcpy(f->received_bytes,datagram->data,datagram->size);
}
static void sent(void* user, uint64_t request, Matter_Operation_Result_T result) {
    Fixture* f = user;
    ++f->sent; probe(f);
    if (f->retained || request != f->request) ++f->violations;
    f->terminal = result;
}
static Matter_Udp_Port_T port_for(Fixture* f) {
    return (Matter_Udp_Port_T){f,activate,deactivate,send_packet,cancel,detach};
}
static bool attach(Fixture* f, bool listener) {
    Matter_Udp_Port_T port = port_for(f);
    Matter_Udp_Listener_T events = {f,received,sent};
    f->udp = matter_udp_new(f->owner,&port,listener ? &events : NULL);
    f->target = f->udp;
    ++f->binding;
    return f->udp != NULL;
}
static Fixture* fixture_new(void) {
    Fixture* f = calloc(1,sizeof(*f));
    if (!f) return NULL;
    f->owner = matter_new(NULL);
    if (!f->owner) { free(f); return NULL; }
    f->datagram = (Matter_Udp_Datagram_T){.data=f->bytes,.size=1};
    f->datagram.path.local.port = 5540; f->datagram.path.peer.port = 12345;
    f->datagram.path.local.address[0] = 0xfd; f->datagram.path.local.address[15] = 1;
    f->datagram.path.peer.address[0] = 0xfe; f->datagram.path.peer.address[1] = 0x80;
    f->datagram.path.peer.address[15] = 2; f->datagram.path.interface_id = 7;
    f->bytes[0] = 0xa5;
    if (!attach(f,true)) { matter_delete(f->owner); free(f); return NULL; }
    return f;
}
static bool deliver(Fixture* f, uint64_t binding, uint64_t request, Matter_Operation_Result_T result) {
    if (!f->target || binding != f->binding || !f->retained || request != f->request) return false;
    const Matter_Udp_Datagram_T* saved = f->retained;
    f->retained = NULL; /* No byte/descriptor access after terminal delivery. */
    if (matter_udp_complete(f->target,request,result) != MATTER_OK) { f->retained = saved; return false; }
    return true;
}
static void fixture_delete(Fixture* f) {
    if (!f) return;
    if (f->udp) {
        matter_udp_stop(f->udp);
        matter_udp_process(f->udp);
        if (f->retained) {
            matter_udp_process(f->udp);
            if (!deliver(f,f->binding,f->request,MATTER_OPERATION_CANCELLED)) abort();
        }
        if (matter_udp_process(f->udp) != MATTER_OK) abort();
        if (matter_udp_delete(f->udp) != MATTER_OK) abort();
    }
    matter_stop(f->owner);
    if (matter_delete(f->owner) != MATTER_OK) abort();
    free(f);
}
static bool start(Fixture* f) {
    return matter_start(f->owner) == MATTER_OK && matter_udp_start(f->udp) == MATTER_OK;
}

static bool test_lifecycle_and_activation(void) {
    bool passed = false;
    Fixture* f = fixture_new();
    CHECK(f);
    CHECK(matter_udp_new(NULL,NULL,NULL) == NULL && matter_udp_delete(NULL) == MATTER_OK);
    CHECK(matter_udp_start(NULL) == MATTER_INVALID_ARGUMENT && !matter_udp_is_active(NULL));
    CHECK(matter_udp_stop(NULL) == MATTER_INVALID_ARGUMENT && matter_udp_process(NULL) == MATTER_INVALID_ARGUMENT);
    Matter_Udp_Port_T port = port_for(f); port.send = NULL;
    CHECK(!matter_udp_new(f->owner,&port,NULL));
    CHECK(matter_udp_start(f->udp) == MATTER_INVALID_STATE && f->activates == 0);
    CHECK(matter_udp_stop(f->udp) == MATTER_OK && matter_udp_process(f->udp) == MATTER_OK);
    CHECK(matter_start(f->owner) == MATTER_OK);
    const Matter_Result_T rejections[] = {MATTER_WOULD_BLOCK,MATTER_OFFLINE,MATTER_PORT_ERROR};
    for (unsigned repeat = 0; repeat < 3; ++repeat) for (size_t i = 0; i < 3; ++i) {
        f->activate_result = rejections[i];
        CHECK(matter_udp_start(f->udp) == rejections[i] && !matter_udp_is_active(f->udp));
        CHECK(!f->receiving && matter_stop(f->owner) == MATTER_OK); /* No leaked pool lease. */
        CHECK(matter_start(f->owner) == MATTER_OK);
    }
    f->activate_result = MATTER_OK;
    CHECK(matter_udp_start(f->udp) == MATTER_OK && matter_udp_is_active(f->udp));
    CHECK(matter_udp_start(f->udp) == MATTER_OK && f->activates == 10);
    CHECK(matter_udp_delete(f->udp) == MATTER_INVALID_STATE);
    CHECK(matter_stop(f->owner) == MATTER_PENDING && matter_delete(f->owner) == MATTER_INVALID_STATE);
    CHECK(matter_udp_start(f->udp) == MATTER_INVALID_STATE);
    CHECK(matter_udp_process(f->udp) == MATTER_PENDING && f->deactivates == 1);
    CHECK(matter_udp_process(f->udp) == MATTER_OK && matter_get_state(f->owner) == MATTER_STATE_STOPPED);
    CHECK(f->violations == 0);
    passed = true;
done: fixture_delete(f); return passed;
}

static bool test_send_rejections_and_ownership(void) {
    bool passed = false;
    Fixture* f = fixture_new();
    uint64_t id = 999;
    CHECK(f && start(f));
    const Matter_Result_T rejects[] = {MATTER_WOULD_BLOCK,MATTER_OFFLINE,MATTER_PORT_ERROR};
    for (size_t i = 0; i < 3; ++i) {
        f->send_result = rejects[i];
        CHECK(matter_udp_send(f->udp,&f->datagram,&id) == rejects[i] && id == 999);
        CHECK(!f->retained && f->sent == 0);
    }
    f->send_result = MATTER_OK;
    Matter_Udp_Datagram_T copy = f->datagram;
    CHECK(matter_udp_send(f->udp,&copy,&id) == MATTER_PENDING && id);
    copy.path.peer.port = 1; copy.data = NULL; copy.size = 0;
    CHECK(f->retained != &copy && f->retained->data == f->bytes && f->retained->data[0] == 0xa5);
    CHECK(f->retained->path.peer.port == 12345 && f->retained->path.interface_id == 7);
    uint64_t other = 888;
    CHECK(matter_udp_send(f->udp,&f->datagram,&other) == MATTER_BUSY && other == 888);
    CHECK(matter_udp_complete(f->udp,id+1,MATTER_OPERATION_SUCCEEDED) == MATTER_INVALID_STATE);
    CHECK(matter_udp_complete(f->udp,id,(Matter_Operation_Result_T)99) == MATTER_INVALID_ARGUMENT);
    CHECK(deliver(f,f->binding,id,MATTER_OPERATION_FAILED) && f->terminal == MATTER_OPERATION_FAILED);
    CHECK(matter_udp_complete(f->udp,id,MATTER_OPERATION_SUCCEEDED) == MATTER_INVALID_STATE);
    CHECK(matter_udp_send(f->udp,&f->datagram,&other) == MATTER_PENDING && other > id);
    CHECK(!deliver(f,f->binding,id,MATTER_OPERATION_SUCCEEDED));
    CHECK(deliver(f,f->binding,other,MATTER_OPERATION_SUCCEEDED) && f->sent == 2);
    CHECK(f->violations == 0);
    passed = true;
done: fixture_delete(f); return passed;
}

static bool test_receive_and_boundaries(void) {
    bool passed = false;
    Fixture* f = fixture_new();
    uint64_t id = 999;
    CHECK(f && start(f));
    CHECK(matter_udp_send(f->udp,NULL,&id) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_udp_send(f->udp,&f->datagram,NULL) == MATTER_INVALID_ARGUMENT);
    f->datagram.size = 0;
    CHECK(matter_udp_send(f->udp,&f->datagram,&id) == MATTER_INVALID_ARGUMENT);
    CHECK(matter_udp_receive(f->udp,f->epoch,&f->datagram,false) == MATTER_INVALID_ARGUMENT);
    f->datagram.size = MATTER_UDP_MAX_PAYLOAD+1;
    CHECK(matter_udp_send(f->udp,&f->datagram,&id) == MATTER_LIMIT_REACHED);
    CHECK(matter_udp_receive(f->udp,f->epoch,&f->datagram,false) == MATTER_LIMIT_REACHED);
    f->datagram.size = MATTER_UDP_MAX_PAYLOAD;
    f->datagram.path.peer.port = 0;
    CHECK(matter_udp_send(f->udp,&f->datagram,&id) == MATTER_INVALID_ARGUMENT);
    f->datagram.path.peer.port = 12345;
    CHECK(f->sends == 0 && id == 999 && f->received == 0);
    CHECK(matter_udp_receive(f->udp,f->epoch,&f->datagram,true) == MATTER_LIMIT_REACHED);
    CHECK(matter_udp_receive(f->udp,f->epoch+1,&f->datagram,false) == MATTER_INVALID_STATE);
    CHECK(matter_udp_receive(f->udp,f->epoch,&f->datagram,false) == MATTER_OK);
    CHECK(f->received == 1 && f->received_size == MATTER_UDP_MAX_PAYLOAD);
    CHECK(!memcmp(f->received_bytes,f->bytes,MATTER_UDP_MAX_PAYLOAD));
    CHECK(f->received_path.interface_id == 7 && f->received_path.peer.port == 12345);
    CHECK(!memcmp(f->received_path.peer.address,f->datagram.path.peer.address,16));
    CHECK(matter_udp_send(f->udp,&f->datagram,&id) == MATTER_PENDING);
    CHECK(deliver(f,f->binding,id,MATTER_OPERATION_SUCCEEDED));
    CHECK(matter_udp_stop(f->udp) == MATTER_PENDING);
    CHECK(matter_udp_receive(f->udp,f->epoch,&f->datagram,false) == MATTER_INVALID_STATE && f->received == 1);
    CHECK(f->violations == 0);
    passed = true;
done: fixture_delete(f); return passed;
}

static bool test_stop_drain_and_restart(void) {
    bool passed = false;
    Fixture* f = fixture_new();
    CHECK(f);
    for (unsigned result = 0; result < 3; ++result) {
        CHECK(start(f));
        uint64_t request = 0, epoch = f->epoch;
        CHECK(matter_udp_send(f->udp,&f->datagram,&request) == MATTER_PENDING);
        CHECK(matter_stop(f->owner) == MATTER_PENDING);
        CHECK(matter_udp_process(f->udp) == MATTER_PENDING && !f->receiving);
        CHECK(matter_udp_process(f->udp) == MATTER_PENDING && f->cancels == result+1);
        CHECK(matter_udp_process(f->udp) == MATTER_PENDING && f->cancels == result+1);
        CHECK(matter_udp_stop(f->udp) == MATTER_PENDING && matter_stop(f->owner) == MATTER_PENDING);
        CHECK(matter_udp_delete(f->udp) == MATTER_INVALID_STATE && matter_delete(f->owner) == MATTER_INVALID_STATE);
        CHECK(f->retained && f->retained->data[0] == 0xa5);
        CHECK(deliver(f,f->binding,request,(Matter_Operation_Result_T)result));
        CHECK(f->terminal == (Matter_Operation_Result_T)result && f->sent == result+1);
        CHECK(matter_get_state(f->owner) == MATTER_STATE_STOPPING);
        CHECK(matter_udp_process(f->udp) == MATTER_OK && matter_get_state(f->owner) == MATTER_STATE_STOPPED);
        CHECK(start(f) && f->epoch > epoch);
        CHECK(matter_udp_receive(f->udp,epoch,&f->datagram,false) == MATTER_INVALID_STATE);
        CHECK(matter_udp_complete(f->udp,request,MATTER_OPERATION_SUCCEEDED) == MATTER_INVALID_STATE);
        CHECK(matter_udp_stop(f->udp) == MATTER_PENDING);
        CHECK(matter_udp_process(f->udp) == MATTER_PENDING);
        CHECK(matter_udp_process(f->udp) == MATTER_OK); /* Module stop leaves owner running. */
        CHECK(matter_get_state(f->owner) == MATTER_STATE_RUNNING);
    }
    CHECK(f->violations == 0);
    passed = true;
done: fixture_delete(f); return passed;
}

static bool test_isolation_and_rebinding(void) {
    bool passed = false;
    Fixture* a = fixture_new(); Fixture* b = fixture_new();
    CHECK(a && b && start(a) && start(b));
    uint64_t ar = 0, br = 0, old_binding = a->binding;
    CHECK(matter_udp_send(a->udp,&a->datagram,&ar) == MATTER_PENDING);
    CHECK(matter_udp_send(b->udp,&b->datagram,&br) == MATTER_PENDING);
    CHECK(matter_stop(a->owner) == MATTER_PENDING && matter_get_state(b->owner) == MATTER_STATE_RUNNING);
    CHECK(matter_udp_process(a->udp) == MATTER_PENDING && matter_udp_process(a->udp) == MATTER_PENDING);
    CHECK(b->receiving && b->cancels == 0 && b->retained);
    CHECK(deliver(a,old_binding,ar,MATTER_OPERATION_CANCELLED));
    CHECK(matter_udp_process(a->udp) == MATTER_OK);
    CHECK(matter_udp_delete(a->udp) == MATTER_OK); a->udp = NULL;
    CHECK(!deliver(a,old_binding,ar,MATTER_OPERATION_SUCCEEDED));
    CHECK(attach(a,false) && start(a));
    CHECK(matter_udp_send(a->udp,&a->datagram,&ar) == MATTER_PENDING);
    CHECK(!deliver(a,old_binding,ar,MATTER_OPERATION_SUCCEEDED));
    CHECK(deliver(a,a->binding,ar,MATTER_OPERATION_SUCCEEDED));
    CHECK(matter_udp_receive(a->udp,a->epoch,&a->datagram,false) == MATTER_OK && a->received == 0);
    CHECK(deliver(b,b->binding,br,MATTER_OPERATION_SUCCEEDED));
    CHECK(a->violations == 0 && b->violations == 0);
    passed = true;
done: fixture_delete(a); fixture_delete(b); return passed;
}

#ifdef MATTER_TEST_ALLOC
static bool test_oom(void) {
    bool passed = false;
    Fixture* f = fixture_new();
    CHECK(f && live == 2);
    Matter_Udp_Port_T port = port_for(f);
    fail_next = true;
    CHECK(!matter_udp_new(f->owner,&port,NULL) && !fail_next && live == 2);
    CHECK(start(f));
    fail_next = true;
    uint64_t request;
    CHECK(matter_udp_send(f->udp,&f->datagram,&request) == MATTER_PENDING);
    CHECK(deliver(f,f->binding,request,MATTER_OPERATION_SUCCEEDED));
    CHECK(fail_next && live == 2);
    passed = true;
done: fail_next = false; fixture_delete(f); return passed;
}
#endif

int main(void) {
    static const struct { const char* name; bool (*run)(void); } tests[] = {
        {"lifecycle and activation rollback",test_lifecycle_and_activation},
        {"send rejection and borrowed buffers",test_send_rejections_and_ownership},
        {"receive metadata and size boundaries",test_receive_and_boundaries},
        {"stop drain, cancellation races and restart",test_stop_drain_and_restart},
        {"instance isolation and binding after delete",test_isolation_and_rebinding},
#ifdef MATTER_TEST_ALLOC
        {"OOM and no per-send allocation",test_oom},
#endif
    };
    unsigned failures = 0;
    for (size_t i = 0; i < sizeof(tests)/sizeof(tests[0]); ++i) {
        bool ok = tests[i].run();
#ifdef MATTER_TEST_ALLOC
        if (live) { fprintf(stderr,"Unreleased UDP allocations: %zu\n",live); ok = false; }
#endif
        printf("%s udp: %s\n",ok ? "PASS" : "FAIL",tests[i].name);
        if (!ok) ++failures;
    }
    return failures ? 1 : 0;
}

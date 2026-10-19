/* Drive the real host composition and mDNS lifecycle with a deferred backend.
 * No network or sleeps: close/reopen must work before withdrawal completes. */
#include "../host/matter_host_platform.h"
#include "../host/matter_mdns_windows.h"
#include "../host/matter_server.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"discovery:%d: %s\n",__LINE__,#x); abort(); } } while(0)
enum { WITHDRAW_MS=1000, POLL_MS=10 };
typedef struct { uint8_t mode; uint16_t discriminator; } Window;
static unsigned random_calls,bindings;
static bool entropy_failure;
static bool fake_random(void* p,size_t n) {
    if(entropy_failure) return false;
    memset(p,(int)++random_calls,n); return true;
}
static uint8_t window_mode(Matter_Server_T s,uint16_t* discriminator) {
    Window* w=(Window*)s; *discriminator=w->discriminator; return w->mode;
}
static const Matter_Fabric_View_T* no_fabrics(Matter_Server_T s) { (void)s; return NULL; }
static Matter_Mdns_Windows_T backend_new(Matter_T,const Matter_Mdns_Windows_Interface_T*,const Matter_Mdns_Record_T*);
static Matter_Mdns_T backend_module(Matter_Mdns_Windows_T);
static Matter_Result_T backend_poll(Matter_Mdns_Windows_T,uint64_t);
static Matter_Result_T backend_delete(Matter_Mdns_Windows_T);
#define matter_host_random fake_random
#define matter_server_commissioning_mode window_mode
#define matter_server_fabrics no_fabrics
#define matter_mdns_windows_new backend_new
#define matter_mdns_windows_module backend_module
#define matter_mdns_windows_poll backend_poll
#define matter_mdns_windows_delete backend_delete
#define main single_node_entry
#include "../host/matter_node.c"
#undef main

struct Matter_Mdns_Windows {
    Matter_Mdns_T module; uint64_t request,now,due; bool installed,publishing,cancelled;
};
static bool publish_record(void* u,uint64_t request,const Matter_Mdns_Record_T* r) {
    Matter_Mdns_Windows_T h=u; (void)r; CHECK(!h->request && !h->installed);
    h->request=request; h->publishing=true; h->due=h->now; return true;
}
static bool remove_record(void* u,uint64_t request) {
    Matter_Mdns_Windows_T h=u; CHECK(!h->request && h->installed);
    h->request=request; h->publishing=false; h->due=h->now+WITHDRAW_MS; return true;
}
static void cancel_record(void* u,uint64_t request) {
    Matter_Mdns_Windows_T h=u; CHECK(h->request==request); h->cancelled=true;
}
static void detach_record(void* u) {
    Matter_Mdns_Windows_T h=u; CHECK(!h->request && !h->installed);
}
static Matter_Mdns_Windows_T backend_new(Matter_T owner,const Matter_Mdns_Windows_Interface_T* iface,const Matter_Mdns_Record_T* record) {
    (void)iface; Matter_Mdns_Windows_T h=calloc(1,sizeof(*h)); CHECK(h);
    Matter_Mdns_Port_T p={h,publish_record,remove_record,cancel_record,detach_record};
    h->module=matter_mdns_new(owner,&p,record); CHECK(h->module);
    CHECK(!matter_mdns_backend(h->module,1,true)); ++bindings; return h;
}
static Matter_Mdns_T backend_module(Matter_Mdns_Windows_T h) { return h?h->module:NULL; }
static Matter_Result_T backend_poll(Matter_Mdns_Windows_T h,uint64_t now) {
    CHECK(h && now>=h->now); h->now=now;
    if(!h->request || now<h->due) return MATTER_WOULD_BLOCK;
    uint64_t request=h->request; h->request=0;
    Matter_Operation_Result_T result=h->cancelled?MATTER_OPERATION_CANCELLED:MATTER_OPERATION_SUCCEEDED;
    if(!h->cancelled) h->installed=h->publishing;
    h->cancelled=false; return matter_mdns_complete(h->module,request,result);
}
static Matter_Result_T backend_delete(Matter_Mdns_Windows_T h) {
    if(!h) return MATTER_OK;
    Matter_Result_T r=matter_mdns_delete(h->module); if(r) return r;
    CHECK(bindings); --bindings; free(h); return MATTER_OK;
}
static Node* create(Window* w) {
    Node* n=calloc(1,sizeof(*n)); CHECK(n);
    n->owner=matter_new(NULL); CHECK(n->owner && !matter_start(n->owner));
    n->server=(Matter_Server_T)w; n->port=5551; n->discriminator=w->discriminator;
    n->extended_duration_ms=UINT64_C(1000)*HOST_EXTENDED_DISCOVERY_SECONDS;
    n->iface.mac[0]=2; CHECK(fake_random(n->random,sizeof(n->random))); return n;
}
static void tick(Node* n,uint64_t now) {
    CHECK(advertisements(n,now,false));
    if(n->mdns) {
        CHECK(matter_mdns_process(backend_module(n->mdns))!=MATTER_PORT_ERROR);
        CHECK(backend_poll(n->mdns,now)!=MATTER_PORT_ERROR);
    }
}
static void destroy(Node* n,uint64_t now) {
    if(n->mdns) {
        CHECK(matter_mdns_stop(backend_module(n->mdns))==MATTER_PENDING);
        for(unsigned i=0;i<2*WITHDRAW_MS/POLL_MS;++i) {
            now+=POLL_MS; CHECK(matter_mdns_process(backend_module(n->mdns))!=MATTER_PORT_ERROR);
            CHECK(backend_poll(n->mdns,now)!=MATTER_PORT_ERROR);
        }
        CHECK(!backend_delete(n->mdns));
    }
    matter_discovery_delete(n->discovery);
    CHECK(!matter_stop(n->owner) && !matter_delete(n->owner)); free(n);
}
int main(void) {
    for(unsigned scenario=0;scenario<2;++scenario) {
        bool rapid=scenario==0;
        Window w={2,777},other={2,1234}; Node* n=create(&w); Node* peer=create(&other);
        for(uint64_t t=0;t<=100;t+=POLL_MS) { tick(n,t); tick(peer,t); }
        CHECK(matter_mdns_is_published(backend_module(n->mdns)));
        char initial[17],independent[17];
        strcpy(initial,matter_discovery_record(n->discovery)->instance);
        strcpy(independent,matter_discovery_record(peer->discovery)->instance);
        w.mode=0; tick(n,110); /* Withdrawal starts, but has not completed. */
        uint64_t reopen=rapid?120:1500;
        for(uint64_t t=120;t<=3000;t+=POLL_MS) {
            if(t==reopen) w.mode=2; /* Same discriminator and mode as before. */
            tick(n,t); tick(peer,t);
        }
        CHECK(matter_mdns_is_published(backend_module(n->mdns)));
        CHECK(strcmp(initial,matter_discovery_record(n->discovery)->instance));
        CHECK(!strcmp(independent,matter_discovery_record(peer->discovery)->instance));
        strcpy(initial,matter_discovery_record(n->discovery)->instance);
        unsigned calls=random_calls;
        for(uint64_t t=3010;t<=3200;t+=POLL_MS) tick(n,t);
        CHECK(random_calls==calls && !strcmp(initial,matter_discovery_record(n->discovery)->instance));
        destroy(n,3200); destroy(peer,3200); CHECK(!bindings);
    }
    Window w={2,777}; Node* n=create(&w); entropy_failure=true;
    CHECK(!advertisements(n,0,false) && !n->mdns && !n->discovery);
    entropy_failure=false; destroy(n,0); CHECK(!bindings);
    const uint64_t budgets[]={0,100,UINT64_MAX};
    for(unsigned i=0;i<sizeof(budgets)/sizeof(budgets[0]);++i) {
        Window closed={0,123}; Node* limited=create(&closed); limited->extended_duration_ms=budgets[i];
        for(uint64_t t=0;t<=1500;t+=POLL_MS) tick(limited,t);
        CHECK((limited->mdns!=NULL)==(budgets[i]==UINT64_MAX));
        closed.mode=2;
        for(uint64_t t=1510;t<=1600;t+=POLL_MS) tick(limited,t);
        CHECK(limited->mdns && matter_mdns_is_published(backend_module(limited->mdns)));
        closed.mode=0;
        for(uint64_t t=1610;t<=3000;t+=POLL_MS) tick(limited,t);
        CHECK((limited->mdns!=NULL)==(budgets[i]==UINT64_MAX));
        destroy(limited,3000); CHECK(!bindings);
    }
    puts("PASS host discovery: delayed and rapid reopen, fresh/stable instance names, independent peer, entropy failure, drained teardown");
    return 0;
}

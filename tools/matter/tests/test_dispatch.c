/* Inspect private routing/lifetime invariants; the independent JS controller
 * covers successful protocol traffic using its own encoders and crypto. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "alloc.h"
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"dispatch:%d: %s\n",__LINE__,#x); exit(1); } } while(0)
static size_t allocations; static bool fail_alloc;
void* matter_test_calloc(size_t n,size_t size) { if(fail_alloc) return NULL; void* p=calloc(n,size); if(p) ++allocations; return p; }
void matter_test_free(void* p) { if(p) { CHECK(allocations); --allocations; free(p); } }
#define calloc matter_test_calloc
#define free matter_test_free
#include "../host/matter_dispatch.c"
#undef calloc
#undef free
#include "matter_udp_windows.h"
#include "crypto/matter_crypto_mbedtls.h"
#include "session/matter_secure_internal.h"
static Matter_Result_T load_root(void* user,Matter_Root_Config_T* c) {
    (void)user; memset(c,0,sizeof(*c));
    c->vendor_name=(Matter_Root_Text_T){1,{'v'}}; c->product_name=(Matter_Root_Text_T){1,{'p'}};
    c->hardware_string=(Matter_Root_Text_T){1,{'h'}}; c->software_string=(Matter_Root_Text_T){1,{'s'}}; c->unique_id=(Matter_Root_Text_T){1,{'u'}};
    c->vendor_id=0xfff1; c->product_id=0x8001; c->configuration_version=1;
    c->capabilities=(Matter_Root_Capabilities_T){3,3,1,1,9,3}; c->settings.location[0]=c->settings.location[1]='X'; return MATTER_OK;
}
static uint8_t denied(void* u,Matter_Exchange_Session_T s,const Matter_Im_Path_T* p,Matter_Im_Privilege_T v) { (void)u;(void)s;(void)p;(void)v; return MATTER_IM_UNSUPPORTED_ACCESS; }
static Matter_Result_T store_root(void* u,const Matter_Root_Settings_T* s) { (void)u;(void)s; return MATTER_OK; }
static Matter_Result_T entropy(void* u,uint8_t* out,size_t size) { if(*(bool*)u) return MATTER_PORT_ERROR; memset(out,0x11,size); return MATTER_OK; }
static bool fabric_live(void* u,uint8_t index) { (void)index; return !*(bool*)u; }
static uint64_t rotated(void* u,uint8_t index,Matter_Exchange_Session_T* invoker) {
    (void)u; *invoker=100; return index==1?2:1;
}
static void diagnostic_counts(Matter_Dispatch_T d) {
    Matter_Dispatch_Load_T load=matter_dispatch_load(d,0); CHECK(!load.sent && !load.established && !load.current);
    d->connections[0]=(Connection){.token=100,.operational=true,.fabric_index=1};
    d->connections[1]=(Connection){.token=101,.operational=true,.fabric_index=2};
    d->connections[2]=(Connection){.token=102}; /* PASE has no accessing fabric. */
    for(unsigned i=0;i<3;++i) {
        Transaction* t=&d->transactions[i];
        *t=(Transaction){.owner=d,.handle=i+1,.key={100+i,1,false},.fabric_index=i<2?i+1:0,
            .subscription_id=i+1,.im_packet=true,.sub_response=true};
        CHECK(!matter_dispatch_load(d,1).current); /* Reservations are not subscriptions. */
        /* Only mark these established after all reservations have been made. */
    }
    for(unsigned i=0;i<3;++i) {
        Transaction* t=&d->transactions[i];
        count_sent(d,t,MATTER_OPERATION_FAILED); CHECK(!t->sub_established);
        count_sent(d,t,MATTER_OPERATION_SUCCEEDED); count_sent(d,t,MATTER_OPERATION_SUCCEEDED); /* MRP retry. */
    }
    load=matter_dispatch_load(d,1); CHECK(load.sent==3 && load.established==3 && load.current==3 && load.current_for_fabric==1);
    CHECK(matter_dispatch_load(d,2).current_for_fabric==1 && !matter_dispatch_load(d,0).current_for_fabric);
    d->transactions[0].closing=true; CHECK(matter_dispatch_load(d,1).current==2);
    unreserve(&d->transactions[1],2); CHECK(matter_dispatch_load(d,2).current==1 && matter_dispatch_load(d,2).established==3);
    d->connections[2].retiring=true; CHECK(!matter_dispatch_load(d,0).current);
    Transaction* t=&d->transactions[0];
    t->closing=false; t->im_counted=false; t->im_packet=false;
    count_sent(d,t,MATTER_OPERATION_SUCCEEDED); CHECK(d->im_sent==3); /* CASE/BDX/ACK. */
    d->im_sent=d->subscriptions_established=UINT32_MAX; t->im_packet=true; t->sub_established=false;
    count_sent(d,t,MATTER_OPERATION_SUCCEEDED); CHECK(d->im_sent==UINT32_MAX && d->subscriptions_established==UINT32_MAX);
    memset(d->connections,0,sizeof(d->connections)); memset(d->transactions,0,sizeof(d->transactions));
    d->im_sent=d->subscriptions_established=0;
    puts("PASS diagnostic load: local completion, retries/failures, reservations, fabric/PASE scope, cancellation and saturation");
}
static void rotation(Matter_Dispatch_T d) {
    d->config.credential_revision=rotated;
    for(unsigned outcome=0;outcome<3;++outcome) {
        d->connections[0]=(Connection){.token=100,.operational=true,.fabric_index=1,.credential_revision=1};
        d->connections[1]=(Connection){.token=101,.operational=true,.fabric_index=1,.credential_revision=1};
        d->connections[2]=(Connection){.token=102,.operational=true,.fabric_index=2,.credential_revision=1};
        d->connections[3]=(Connection){.token=103,.operational=true,.fabric_index=1,.credential_revision=2};
        Transaction* reply=&d->transactions[0];
        *reply=(Transaction){.owner=d,.handle=1,.key={100,1,false},.invoke=(Matter_Im_Invoke_T)d};
        d->transactions[1]=(Transaction){.handle=2,.key={100,2,false}};
        reconcile(d);
        CHECK(d->connections[0].rotating && !d->connections[0].retiring && !reply->closing);
        CHECK(d->transactions[1].closing && d->connections[1].retiring);
        CHECK(!d->connections[2].retiring && !d->connections[3].retiring);
        CHECK(!create_handler(d,&d->transactions[1],2)); /* No new work on retiring identity. */
        /* Local send acceptance/completion does not authorize retirement. */
        reply->sent=true; reconcile(d); CHECK(!d->connections[0].retiring);
        if(outcome<2) {
            Matter_Retransmission_Result_T result={.message={.exchange=reply->key},
                .outcome=outcome?MATTER_RETRANSMISSION_CANCELLED:MATTER_RETRANSMISSION_ACKNOWLEDGED};
            finished(d,&result);
        } else reply->closing=true; /* Reply construction/transport/handler failure. */
        reconcile(d); CHECK(d->connections[0].retiring && reply->closing);
        CHECK(!d->connections[2].retiring && !d->connections[3].retiring);
        memset(d->connections,0,sizeof(d->connections)); memset(d->transactions,0,sizeof(d->transactions));
    }
    d->config.credential_revision=NULL;
    puts("PASS rotation: old sessions/subscriptions scoped by epoch; invoking exchange through MRP delivery/error; new CASE/other fabric retained");
}
static bool removed(void* u,uint8_t index) { return index==2 || (!index && !*(bool*)u); }
static void removal(Matter_Dispatch_T d) {
    Matter_Dispatch_Config_T saved=d->config; bool reset=false;
    d->config.user=&reset; d->config.fabric_live=removed;
    for(unsigned mode=0;mode<6;++mode) {
        reset=mode>=3;
        Connection* c=&d->connections[0]; Transaction* reply=&d->transactions[0];
        *c=(Connection){.token=100,.operational=true,.fabric_index=1,.removal_reply=1,.removal_deadline=d->now+30000};
        d->connections[1]=(Connection){.token=101,.operational=true,.fabric_index=1};
        d->connections[2]=(Connection){.token=102,.operational=true,.fabric_index=2};
        *reply=(Transaction){.owner=d,.handle=1,.key={100,1,false}};
        d->transactions[1]=(Transaction){.handle=2,.key={100,2,false}};
        reconcile(d);
        CHECK(matter_dispatch_removal_pending(d) && !c->retiring && !reply->closing);
        CHECK(d->connections[1].retiring && d->transactions[1].closing);
        CHECK(d->connections[2].retiring==reset);
        CHECK(!matter_dispatch_session(d,100) && !create_handler(d,reply,2));
        reply->sent=true; reconcile(d); CHECK(!c->retiring); /* UDP success is not ACK. */
        /* Even data addressed to the original exchange cannot execute again. */
        d->decision=(Matter_Rx_Decision_T){.session=100,.header={.exchange_id=1,.exchange_flags=MATTER_PROTOCOL_INITIATOR},.exchange=1};
        dispatch(d); CHECK(!reply->closing);
        if(mode%3==0) {
            Matter_Retransmission_Result_T r={.message={.exchange=reply->key},.outcome=MATTER_RETRANSMISSION_ACKNOWLEDGED};
            finished(d,&r);
        } else if(mode%3==1) reply->closing=true; /* Encoding/send failure or explicit stop. */
        else c->removal_deadline=d->now; /* Missing ACK: finite wall-clock bound. */
        reconcile(d); CHECK(c->retiring && reply->closing && !matter_dispatch_removal_pending(d));
        CHECK(d->connections[2].retiring==reset);
        memset(d->connections,0,sizeof(d->connections)); memset(d->transactions,0,sizeof(d->transactions));
    }
    d->config=saved;
    puts("PASS RemoveFabric: reply-only exchange through ACK/error/deadline; no new IM authority; other fabric preserved; last-fabric drain");
}
static void udp_received(void* u,const Matter_Udp_Datagram_T* p) { matter_dispatch_received(*(Matter_Dispatch_T*)u,p); }
static void expiry_retirement(Matter_Dispatch_T d) {
    for(unsigned mode=0;mode<4;++mode) {
        Connection* c=&d->connections[0]; Transaction* t=&d->transactions[0];
        *c=(Connection){.token=100,.operational=true,.fabric_index=1};
        d->connections[1]=(Connection){.token=101,.operational=true,.fabric_index=1};
        d->connections[2]=(Connection){.token=102,.operational=true,.fabric_index=2};
        *t=(Transaction){.owner=d,.handle=1,.key={100,1,false},.expiry_reply=mode!=3};
        d->transactions[1]=(Transaction){.handle=2,.key={100,2,false}};
        CHECK(matter_dispatch_retire_fabric(d,1)==MATTER_PENDING);
        CHECK(d->connections[1].retiring && d->transactions[1].closing && !d->connections[2].retiring);
        if(mode==3) CHECK(c->retiring && t->closing && !c->removal_reply); /* Natural expiry/unrelated Invoke. */
        else {
            CHECK(!c->retiring && !t->closing && c->removal_reply==t->handle);
            uint64_t deadline=c->removal_deadline;
            CHECK(!matter_dispatch_session(d,100) && !create_handler(d,t,8));
            t->sent=true; d->sending=c; /* UDP submission alone is not completion. */
            CHECK(matter_dispatch_retire_fabric(d,1)==MATTER_PENDING && !c->retiring && c->removal_deadline==deadline);
            d->sending=NULL; /* Actual UDP completion; deliberately no peer ACK. */
            if(mode==1) t->closing=true;
            else if(mode==2) { t->sent=false; c->removal_deadline=d->now; }
            CHECK(matter_dispatch_retire_fabric(d,1)==MATTER_PENDING && c->retiring && t->closing);
        }
        memset(d->connections,0,sizeof(d->connections)); memset(d->transactions,0,sizeof(d->transactions));
    }
    /* PASE retirement uses the same bounded exemption, irrespective of fabric. */
    Connection* c=&d->connections[0]; Transaction* t=&d->transactions[0];
    *c=(Connection){.token=100};
    *t=(Transaction){.owner=d,.handle=1,.key={100,1,false},.expiry_reply=true};
    CHECK(matter_dispatch_retire(d,false)==MATTER_PENDING && !t->closing && !c->retiring && c->removal_reply==1);
    CHECK(!matter_dispatch_session(d,100) && !create_handler(d,t,8));
    t->sent=true; d->sending=c;
    CHECK(matter_dispatch_retire(d,false)==MATTER_PENDING && !c->retiring && !t->closing);
    d->sending=NULL;
    CHECK(matter_dispatch_retire(d,false)==MATTER_PENDING && c->retiring && t->closing && !t->notified);
    memset(c,0,sizeof(*c)); memset(t,0,sizeof(*t));
    puts("PASS fail-safe retirement: local UDP completion without peer ACK, error/deadline, PASE and pending CASE; other fabric preserved");
}
static void udp_sent(void* u,uint64_t id,Matter_Operation_Result_T r) { matter_dispatch_sent(*(Matter_Dispatch_T*)u,id,r); }
static Matter_Result_T take_keys(void* u,Matter_Pase_Keys_T* keys,Matter_Secure_Identity_T* identity) {
    unsigned i=*(unsigned*)u; memset(keys,0,sizeof(*keys));
    keys->local_session_id=(uint16_t)(10+i); keys->peer_session_id=(uint16_t)(20+i);
    keys->peer_intervals=(Matter_Pase_Intervals_T){500,300,4000};
    *identity=(Matter_Secure_Identity_T){.fabric_index=1,.local_node_id=1,.peer_node_id=2}; return MATTER_OK;
}
static Matter_Result_T cleanup_wait(void* u) { return *(bool*)u?MATTER_PENDING:MATTER_OK; }
static Matter_Result_T cleanup_regulatory(void* u,const Matter_Root_Settings_T* s,uint8_t c,bool* out) {
    (void)u; (void)s; (void)c; *out=true; return MATTER_OK;
}
static void subscription_cleanup(Matter_Dispatch_T d) {
    bool pending=true; Matter_Root_T saved=d->config.root;
    Matter_Root_Port_T rp={NULL,load_root,denied,store_root};
    Matter_Root_Commissioning_Config_T cfg={60,900,0,2,true,true,0};
    Matter_Root_Commissioning_Port_T cp={&pending,cleanup_wait,cleanup_wait,cleanup_regulatory,NULL};
    d->config.root=matter_root_new_commissioning(&rp,&cfg,&cp,d->now); CHECK(d->config.root);
    Matter_Crypto_Mbedtls_T crypto=matter_crypto_mbedtls_new(NULL); CHECK(crypto);
    Matter_Crypto_Port_T port; CHECK(matter_crypto_mbedtls_port(crypto,&port)==MATTER_OK); unsigned i=0;
    Connection* c=&d->connections[0]; c->token=100; c->operational=true; c->fabric_index=1;
    c->secure=matter_secure_from_case(&port,&i,take_keys,d->now); CHECK(c->secure);
    Transaction* t=&d->transactions[0]; t->owner=d; t->key=(Matter_Exchange_Info_T){100,1,false};
    CHECK(create_handler(d,t,3));
    const uint8_t empty[]={0x15,0x18};
    Matter_Rx_Decision_T rx={.action=MATTER_RX_EXISTING,.session=100,
        .header={.protocol_id=1,.opcode=3,.exchange_id=1,.exchange_flags=1},.payload=empty,.payload_size=sizeof(empty)};
    CHECK(matter_im_subscribe_receive(t->sub,&rx)==MATTER_OK);
    process_transaction(t); CHECK(matter_im_subscribe_state(t->sub)==MATTER_IM_SUB_WAITING && !t->closing);
    pending=false; CHECK(matter_root_process(d->config.root,d->now)==MATTER_OK);
    d->request=99; /* Do not transmit the deliberately malformed queued request. */
    process_transaction(t); CHECK(matter_im_subscribe_state(t->sub)==MATTER_IM_SUB_OUTPUT);
    d->request=0; t->closing=true; process_transaction(t); CHECK(!t->sub);
    CHECK(matter_secure_close(c->secure)==MATTER_OK && matter_secure_delete(c->secure)==MATTER_OK);
    memset(c,0,sizeof(*c)); CHECK(matter_crypto_mbedtls_delete(crypto)==MATTER_OK);
    CHECK(matter_root_delete(d->config.root)==MATTER_OK); d->config.root=saved;
    puts("PASS dispatcher CASE subscription pauses during fail-safe cleanup and resumes queued work afterward");
}
static void read_cleanup(Matter_Dispatch_T d) {
    bool pending=true; Matter_Root_T saved=d->config.root;
    Matter_Root_Port_T rp={NULL,load_root,denied,store_root};
    Matter_Root_Commissioning_Config_T cfg={60,900,0,2,true,true,0};
    Matter_Root_Commissioning_Port_T cp={&pending,cleanup_wait,cleanup_wait,cleanup_regulatory,NULL};
    d->config.root=matter_root_new_commissioning(&rp,&cfg,&cp,d->now); CHECK(d->config.root);
    Matter_Crypto_Mbedtls_T crypto=matter_crypto_mbedtls_new(NULL); CHECK(crypto);
    Matter_Crypto_Port_T port; CHECK(matter_crypto_mbedtls_port(crypto,&port)==MATTER_OK); unsigned i=0;
    Connection* c=&d->connections[0]; c->token=100; c->operational=true; c->fabric_index=1;
    c->secure=matter_secure_from_case(&port,&i,take_keys,d->now); CHECK(c->secure);
    Transaction* t=&d->transactions[0]; t->owner=d; t->key=(Matter_Exchange_Info_T){100,1,false};
    CHECK(create_handler(d,t,2));
    const uint8_t empty[]={0x15,0x18};
    Matter_Rx_Decision_T rx={.action=MATTER_RX_EXISTING,.session=100,
        .header={.protocol_id=1,.opcode=2,.exchange_id=1,.exchange_flags=1},.payload=empty,.payload_size=sizeof(empty)};
    CHECK(matter_im_read_receive(t->read,&rx)==MATTER_OK);
    process_transaction(t); CHECK(matter_im_read_state(t->read)==MATTER_IM_READ_WAITING && !t->closing);
    pending=false; CHECK(matter_root_process(d->config.root,d->now)==MATTER_OK);
    /* A real transport handle is unnecessary here: suppress packet submission
     * while verifying that the queued malformed request resumes processing. */
    d->request=99; process_transaction(t); d->request=0;
    CHECK(matter_im_read_state(t->read)==MATTER_IM_READ_OUTPUT);
    t->closing=true; process_transaction(t); CHECK(!t->read);
    CHECK(matter_secure_close(c->secure)==MATTER_OK && matter_secure_delete(c->secure)==MATTER_OK);
    memset(c,0,sizeof(*c)); CHECK(matter_crypto_mbedtls_delete(crypto)==MATTER_OK);
    CHECK(matter_root_delete(d->config.root)==MATTER_OK); d->config.root=saved;
    puts("PASS retained CASE Read queued during cleanup, resumed after rollback instead of UnsupportedAccess");
}
typedef struct {
    Matter_Resolver_Query_T query; Matter_Resolver_Answer_T answer;
    uint64_t next,id; unsigned starts,cancels; bool done,reject;
    Matter_Operation_Result_T result;
} Resolver;
static Matter_Result_T resolve_begin(void* u,const Matter_Resolver_Query_T* q,uint64_t* id) {
    Resolver* r=u; ++r->starts; if(r->reject) return MATTER_OFFLINE;
    CHECK(!r->id); r->query=*q; *id=r->id=++r->next; r->done=false; return MATTER_PENDING;
}
static Matter_Result_T resolve_end(void* u,uint64_t id,Matter_Operation_Result_T* result,Matter_Resolver_Answer_T* answer) {
    Resolver* r=u; if(id!=r->id || !id) return MATTER_INVALID_STATE;
    if(!r->done) return MATTER_PENDING;
    *result=r->result; *answer=r->answer; r->id=0; return MATTER_OK;
}
static void resolve_abort(void* u,uint64_t id) { Resolver* r=u; CHECK(id==r->id); ++r->cancels; }
static Matter_Result_T compressed(void* u,uint8_t fabric,uint8_t out[8]) { (void)u; memset(out,fabric,8); return MATTER_OK; }
static Matter_Result_T bdx_open(void* u) { (void)u; return MATTER_OK; }
static Matter_Result_T bdx_write(void* u,const uint8_t* d,size_t n) { (void)u; (void)d; (void)n; return MATTER_OK; }
static Matter_Result_T bdx_finish(void* u,uint64_t n) { (void)u; (void)n; return MATTER_OK; }
static void bdx_cancel(void* u) { ++*(unsigned*)u; }
static void outgoing_cancel_tests(Matter_Dispatch_T d,const Matter_Udp_Address_T* bind) {
    uint64_t saved_now=d->now; Matter_Dispatch_Config_T saved=d->config;
    Resolver resolver={0}; d->config.resolver=(Matter_Resolver_Port_T){&resolver,resolve_begin,resolve_end,resolve_abort};
    d->config.compressed_fabric=compressed; d->config.credential_revision=rotated;
    d->config.outbound=(Matter_Udp_Path_T){.local=*bind,.interface_id=1};
    const uint8_t fields[]={0x15,0x18}; Matter_Im_Command_Path_T path={1,0x29,0};
    for(unsigned mode=0;mode<4;++mode) {
        uint64_t id=0,other=0; uint8_t status; const uint8_t* data; size_t size;
        CHECK(matter_dispatch_invoke(d,1,42,&path,1,fields,sizeof(fields),&id)==MATTER_PENDING && id);
        CHECK(matter_dispatch_invoke(d,1,42,&path,1,fields,sizeof(fields),&other)==MATTER_BUSY && !other);
        CHECK(resolver.query.node_id==42 && resolver.query.interface_id==1 && resolver.query.compressed_fabric[0]==1);
        CHECK(matter_dispatch_invoke_take(d,id,&status,&data,&size)==MATTER_PENDING);
        if(mode==0) matter_dispatch_invoke_cancel(d,id);
        if(mode==1) d->now=d->outgoing.deadline;
        if(mode==2) --d->outgoing.revision; /* Credential rotation or index reuse. */
        if(mode==3) *(bool*)d->config.user=true; /* Removed/reset fabric. */
        unsigned before=resolver.cancels; outgoing_process(d); outgoing_process(d); CHECK(resolver.cancels==before+1);
        CHECK(matter_dispatch_invoke_take(d,id,&status,&data,&size)==MATTER_PENDING); /* Cancel is not completion. */
        resolver.done=true; resolver.result=MATTER_OPERATION_SUCCEEDED; outgoing_process(d);
        CHECK(matter_dispatch_invoke_take(d,id,&status,&data,&size)==MATTER_PORT_ERROR);
        CHECK(!outgoing_transactions(d) && !d->outgoing.resolve);
        CHECK(matter_dispatch_invoke_take(d,id,&status,&data,&size)==MATTER_INVALID_ARGUMENT);
        *(bool*)d->config.user=false;
    }
    unsigned cancelled=0; Matter_Bdx_Sink_T sink={&cancelled,bdx_open,bdx_write,bdx_finish,bdx_cancel};
    for(unsigned mode=0;mode<4;++mode) {
        uint64_t id,bytes; resolver.done=false;
        CHECK(matter_dispatch_bdx(d,1,42,(const uint8_t*)"ota/image",9,&sink,4096,&id)==MATTER_PENDING);
        if(mode==0) matter_dispatch_invoke_cancel(d,id);
        if(mode==1) d->now=d->outgoing.deadline;
        if(mode==2) --d->outgoing.revision;
        if(mode==3) *(bool*)d->config.user=true;
        outgoing_process(d); CHECK(matter_dispatch_bdx_take(d,id,&bytes)==MATTER_PENDING);
        resolver.done=true; resolver.result=MATTER_OPERATION_SUCCEEDED; outgoing_process(d);
        CHECK(matter_dispatch_bdx_take(d,id,&bytes)==MATTER_PORT_ERROR && !cancelled);
        *(bool*)d->config.user=false;
    }
    matter_bdx_delete(d->outgoing.bdx); d->outgoing.bdx=NULL;
    d->now=saved_now; d->config=saved;
    /* SuppressResponse=false: successful client result must not cancel its
     * reliable StatusResponse while the final MRP ACK is still outstanding. */
    const uint8_t busy[]={0x15,0x28,0,0x36,1,0x15,0x35,0,0x37,0,0x24,0,1,0x24,1,0x29,0x24,2,1,0x18,
        0x35,1,0x24,0,1,0x24,1,120,0x18,0x18,0x18,0x18,0x24,255,12,0x18};
    matter_im_client_delete(d->outgoing.client);
    d->outgoing.client=matter_im_client_new(&path,1,fields,sizeof(fields)); CHECK(d->outgoing.client);
    CHECK(matter_im_client_sent(d->outgoing.client)==MATTER_OK);
    CHECK(matter_im_client_receive(d->outgoing.client,9,busy,sizeof(busy))==MATTER_OK);
    CHECK(matter_im_client_sent(d->outgoing.client)==MATTER_OK);
    Transaction* t=&d->transactions[0]; *t=(Transaction){.owner=d,.handle=1,.outbound=true,.admission=CLIENT,.pending=true};
    process_transaction(t); CHECK(!t->closing && t->pending);
    t->pending=false; process_transaction(t); CHECK(t->closing); memset(t,0,sizeof(*t));
    for(unsigned failed=0;failed<4;++failed) {
        d->outgoing.failed=d->outgoing.cancelled=false; d->outgoing.fabric=1;
        d->config.credential_revision=rotated; Matter_Exchange_Session_T ignored;
        d->outgoing.revision=rotated(d->config.user,1,&ignored);
        *t=(Transaction){.owner=d,.handle=1,.outbound=true,.admission=CLIENT,.notified=true,.acknowledged=failed!=1};
        confirm(t); CHECK(d->outgoing.failed==(failed==1));
        if(failed==2) --d->outgoing.revision;
        if(failed==3) *(bool*)d->config.user=true;
        memset(t,0,sizeof(*t)); d->outgoing.id=++d->outgoing.serial;
        uint8_t status; const uint8_t* data; size_t size;
        CHECK(matter_dispatch_invoke_take(d,d->outgoing.id,&status,&data,&size)==(failed?MATTER_PORT_ERROR:MATTER_OK));
        *(bool*)d->config.user=false;
    }
    for(unsigned failed=0;failed<3;++failed) {
        d->outgoing.failed=false; d->outgoing.fabric=1;
        d->config.credential_revision=rotated; Matter_Exchange_Session_T ignored;
        d->outgoing.revision=rotated(d->config.user,1,&ignored);
        d->outgoing.bdx=matter_bdx_new((const uint8_t*)"a",1,1024,4096,&sink,d->now); CHECK(d->outgoing.bdx);
        const uint8_t accept[]={0x20,0,0,4},eof[]={0,0,0,0};
        CHECK(matter_bdx_sent(d->outgoing.bdx,d->now)==MATTER_OK);
        CHECK(matter_bdx_receive(d->outgoing.bdx,2,5,accept,4,d->now)==MATTER_OK);
        CHECK(matter_bdx_sent(d->outgoing.bdx,d->now)==MATTER_OK);
        CHECK(matter_bdx_receive(d->outgoing.bdx,2,0x12,eof,4,d->now)==MATTER_OK);
        CHECK(matter_bdx_sent(d->outgoing.bdx,d->now)==MATTER_OK);
        *t=(Transaction){.owner=d,.handle=1,.outbound=true,.admission=CLIENT,.pending=true};
        process_transaction(t); CHECK(!t->closing && t->pending);
        t->pending=false; t->notified=true; t->acknowledged=failed!=1; confirm(t);
        CHECK(d->outgoing.failed==(failed==1));
        if(failed==2) --d->outgoing.revision; /* Change after final ACK, before take. */
        memset(t,0,sizeof(*t)); d->outgoing.id=++d->outgoing.serial;
        uint64_t bytes; CHECK(matter_dispatch_bdx_take(d,d->outgoing.id,&bytes)==(failed?MATTER_PORT_ERROR:MATTER_OK));
        matter_bdx_delete(d->outgoing.bdx); d->outgoing.bdx=NULL;
    }
    CHECK(cancelled==2); d->outgoing.failed=false; d->config=saved;
    puts("PASS outbound BDX: fabric/revision/timeout/cancel drain; final EOF ACK retained; MRP failure discards staged sink");
    puts("PASS outbound Invoke: copied discovery identity, single admission, cancellation/timeout/rotation/removal, late resolver success drained");
}
typedef struct { const Matter_Udp_Datagram_T* borrowed; } Wire;
static Matter_Result_T wire_activate(void* u,Matter_Operation_Id_T id) { (void)u;(void)id; return MATTER_OK; }
static void wire_deactivate(void* u,Matter_Operation_Id_T id) { (void)u;(void)id; }
static Matter_Result_T wire_send(void* u,uint64_t id,const Matter_Udp_Datagram_T* p) { (void)id; ((Wire*)u)->borrowed=p; return MATTER_OK; }
static void wire_cancel(void* u,uint64_t id) { (void)u;(void)id; }
static void wire_detach(void* u) { (void)u; }
static void rediscovery(Matter_Dispatch_T d,Matter_T owner,const Matter_Udp_Path_T* original) {
    Connection* c=&d->connections[0]; Connection* other=&d->connections[3];
    Resolver r={.answer={.peer=original->peer,.idle_ms=700,.active_ms=400,.active_threshold_ms=5000}};
    r.answer.peer.port=10;
    d->config.resolver=(Matter_Resolver_Port_T){&r,resolve_begin,resolve_end,resolve_abort}; d->config.compressed_fabric=compressed;
    Matter_Retransmission_Message_T m={.exchange={.session=c->token}};
    Matter_Secure_Info_T before,after; Matter_Udp_Path_T path;
    CHECK(matter_secure_info(c->secure,&before)==MATTER_OK && before.pins==1);
    c->operational=false; CHECK(rediscover(d,&m)==MATTER_OK && !r.starts); c->operational=true;
    r.reject=true; CHECK(rediscover(d,&m)==MATTER_OK && !c->resolve_pin); r.reject=false;
    CHECK(rediscover(d,&m)==MATTER_OK && c->resolve_pin && r.starts==2);
    CHECK(r.query.node_id==c->peer_node && r.query.interface_id==original->interface_id);
    for(unsigned i=0;i<8;++i) CHECK(r.query.compressed_fabric[i]==1);
    CHECK(rediscover(d,&m)==MATTER_OK && r.starts==2); /* One job, even across exchanges. */
    CHECK(matter_secure_info(c->secure,&after)==MATTER_OK && after.pins==2);
    CHECK(available(d)!=c);
    /* The first retry can continue with the old immutable bytes/path while
     * resolution runs. A ready result must wait through UDP complete AND take. */
    Wire wire={0}; Matter_Udp_Port_T wp={&wire,wire_activate,wire_deactivate,wire_send,wire_cancel,wire_detach};
    Matter_Udp_T udp=matter_udp_new(owner,&wp,NULL); CHECK(udp && matter_udp_start(udp)==MATTER_OK);
    const uint8_t plain[]={1,2,1,0,1,0,0x15,0x18}; uint8_t packet[64],copy[64];
    Matter_Secure_Prepared_T prepared;
    CHECK(matter_secure_channel_prepare(c->channel,plain,sizeof(plain),10,packet,sizeof(packet),&prepared)==MATTER_OK);
    memcpy(copy,packet,prepared.size); uint64_t id;
    CHECK(matter_secure_channel_send(c->channel,udp,packet,prepared.size,&id)==MATTER_PENDING);
    r.done=true; r.result=MATTER_OPERATION_SUCCEEDED; resolve_process(d);
    CHECK(c->resolve_pin && c->resolve_ready && !c->resolve_id && wire.borrowed->path.peer.port==9);
    CHECK(!memcmp(wire.borrowed->data,copy,prepared.size)); wire.borrowed=NULL;
    CHECK(matter_udp_complete(udp,id,MATTER_OPERATION_SUCCEEDED)==MATTER_OK);
    CHECK(matter_secure_channel_complete(c->channel,id,MATTER_OPERATION_SUCCEEDED)==MATTER_OK);
    resolve_process(d); CHECK(c->resolve_pin && !c->resolved);
    Matter_Secure_Channel_Result_T result;
    CHECK(matter_secure_channel_take(c->channel,&result)==MATTER_OK);
    resolve_process(d); CHECK(!c->resolve_pin && c->resolved);
    CHECK(matter_secure_channel_path(c->channel,&path)==MATTER_OK && path.peer.port==10);
    CHECK(!memcmp(path.local.address,original->local.address,16) && path.local.port==original->local.port && path.interface_id==original->interface_id);
    CHECK(matter_secure_info(c->secure,&after)==MATTER_OK && after.pins==1 && after.local_session_id==before.local_session_id && after.last_received_ms==before.last_received_ms);
    CHECK(matter_secure_channel_send(c->channel,udp,packet,prepared.size,&id)==MATTER_PENDING);
    CHECK(wire.borrowed->path.peer.port==10 && !memcmp(wire.borrowed->data,copy,prepared.size)); wire.borrowed=NULL;
    CHECK(matter_udp_complete(udp,id,MATTER_OPERATION_SUCCEEDED)==MATTER_OK &&
        matter_secure_channel_complete(c->channel,id,MATTER_OPERATION_SUCCEEDED)==MATTER_OK && matter_secure_channel_take(c->channel,&result)==MATTER_OK);
    d->now=10; Matter_Retransmission_Parameters_T params;
    CHECK(parameters(d,&m,2,&params)==MATTER_OK && params.idle_interval_ms==700 && params.active_interval_ms==400);
    CHECK(matter_secure_channel_path(other->channel,&path)==MATTER_OK && path.peer.port==9);
    /* Invalid endpoint, terminal failure and late success after timeout preserve
     * the current route. Cancellation is one request, not permission to free. */
    r.answer.peer.port=0; CHECK(rediscover(d,&m)==MATTER_OK); r.done=true; resolve_process(d);
    CHECK(!c->resolve_pin && matter_secure_channel_path(c->channel,&path)==MATTER_OK && path.peer.port==10);
    r.answer.peer.port=11; CHECK(rediscover(d,&m)==MATTER_OK); r.done=true; r.result=MATTER_OPERATION_FAILED; resolve_process(d); CHECK(!c->resolve_pin);
    CHECK(rediscover(d,&m)==MATTER_OK); uint64_t old=r.id; d->now=c->resolve_deadline;
    resolve_process(d); resolve_process(d); CHECK(c->resolve_pin && r.cancels==1);
    r.done=true; r.result=MATTER_OPERATION_SUCCEEDED; resolve_process(d);
    CHECK(!c->resolve_pin && matter_secure_channel_path(c->channel,&path)==MATTER_OK && path.peer.port==10);
    Matter_Resolver_Answer_T ignored; Matter_Operation_Result_T outcome;
    CHECK(resolve_end(&r,old,&outcome,&ignored)==MATTER_INVALID_STATE);
    CHECK(rediscover(d,&m)==MATTER_OK && r.id>old);
    CHECK(matter_dispatch_retire_fabric(d,1)==MATTER_PENDING && !other->retiring);
    resolve_process(d); CHECK(c->resolve_pin && c->secure && r.cancels==2);
    r.done=true; resolve_process(d); CHECK(!c->resolve_pin && !other->retiring);
    m.exchange.session=other->token;
    CHECK(rediscover(d,&m)==MATTER_OK && r.query.compressed_fabric[0]==2);
    d->stopping=true; resolve_process(d); CHECK(other->resolve_pin && r.cancels==3);
    r.done=true; resolve_process(d); CHECK(!other->resolve_pin && !other->resolved);
    d->stopping=false;
    CHECK(matter_udp_stop(udp)==MATTER_PENDING);
    while(matter_udp_process(udp)==MATTER_PENDING) {}
    CHECK(matter_udp_delete(udp)==MATTER_OK);
    /* Restore unaffected fixture slots; retired sessions remain closed until
     * the normal owner drain below, never reused for a late result. */
    CHECK(matter_dispatch_retire(d,true)==MATTER_OK);
    d->config.resolver=(Matter_Resolver_Port_T){0}; d->config.compressed_fabric=NULL; d->now=0;
}
static void seed_connections(Matter_Dispatch_T d,const Matter_Crypto_Port_T* port,const Matter_Udp_Path_T* path) {
    for(unsigned i=0;i<CONNECTIONS;++i) {
        Connection* c=&d->connections[i];
        c->token=100+i; c->operational=i<CONNECTIONS-1; c->fabric_index=c->operational?(uint8_t)(1+i/3):0; c->peer_node=i==2?3:2;
        c->secure=matter_secure_from_case(port,&i,take_keys,1+i); CHECK(c->secure);
        c->channel=matter_secure_channel_new(c->secure,c->token,path); CHECK(c->channel);
    }
}
static void policy(Matter_Dispatch_T d,Matter_T owner,Matter_Udp_Windows_T udp,const Matter_Udp_Address_T* bind) {
    Matter_Crypto_Mbedtls_T crypto=matter_crypto_mbedtls_new(NULL); Matter_Crypto_Port_T port;
    CHECK(crypto && matter_crypto_mbedtls_port(crypto,&port)==MATTER_OK);
    Matter_Udp_Path_T path={.local=*bind,.peer=*bind}; path.peer.port=9;
    seed_connections(d,&port,&path);
    rediscovery(d,owner,&path);
    seed_connections(d,&port,&path);
    CHECK(available(d)==&d->connections[0]);
    /* Restrict this legacy four-session lifecycle scenario; full profile below. */
    for(unsigned i=4;i<CONNECTIONS;++i) { d->connections[i].reserved=true; d->connections[i].reserved_fabric=d->connections[i].fabric_index; }
    Transaction* t=&d->transactions[4]; t->owner=d;
    for(unsigned i=0;i<4;++i) {
        d->transactions[i].handle=i+1; d->transactions[i].key.session=100+i;
        d->transactions[i].sub=(Matter_Im_Subscribe_T)t; /* Registry-only sentinel, never dereferenced. */
    }
    CHECK(!available(d)); uint32_t id;
    CHECK(reserve(t,101,true,&id)==0 && !d->transactions[0].closing);
    CHECK(reserve(t,101,false,&id)==0 && d->transactions[0].closing && d->transactions[1].closing &&
        !d->transactions[2].closing && !d->transactions[3].closing);
    /* PASE token equality must not join an operational node or another PASE. */
    d->connections[1].operational=false; d->transactions[0].closing=d->transactions[1].closing=false;
    CHECK(reserve(t,101,false,&id)==0 && !d->transactions[0].closing && d->transactions[1].closing);
    d->connections[1].operational=true;
    memset(d->transactions,0,sizeof(d->transactions)); t=&d->transactions[4]; t->owner=d;
    CHECK(matter_secure_retain(d->connections[0].secure)==MATTER_OK);
    CHECK(available(d)==&d->connections[1]);
    d->sending=&d->connections[1]; CHECK(available(d)==&d->connections[2]); d->sending=NULL;
    CHECK(matter_secure_release(d->connections[0].secure)==MATTER_OK);
    d->now=10; d->request=123; CHECK(!reserve_for(t,1) && !t->slot); d->request=0;
    CHECK(!reserve_for(t,1) && t->slot==&d->connections[0] && t->slot->retiring && d->control && d->request);
    CHECK(t->slot->secure && t->slot->reserved); /* Borrowed CloseSession ciphertext cannot be freed early. */
    for(unsigned i=0;i<1000 && t->slot->token;++i) {
        Matter_Result_T r=matter_udp_windows_poll(udp); CHECK(r==MATTER_OK || r==MATTER_WOULD_BLOCK);
        CHECK(matter_dispatch_process(d,11+i)==MATTER_PENDING);
    }
    CHECK(!t->slot->token && t->slot->reserved && !d->request && reserve_for(t,1));
    /* Failed handoff uses the same reset after deleting its newly allocated
     * secure object. Another handshake must not steal the slot before dispose. */
    clear_connection(t->slot);
    CHECK(available(d)!=t->slot); dispose(t); CHECK(!d->connections[0].reserved);
    for(unsigned i=4;i<CONNECTIONS;++i) d->connections[i].reserved=false;
    CHECK(matter_dispatch_retire(d,true)==MATTER_OK);
    CHECK(matter_crypto_mbedtls_delete(crypto)==MATTER_OK);
    /* Restore the unit fixture clock; no live secure state remains. */
    d->now=0;
}
static void resources(Matter_Dispatch_T d,const Matter_Udp_Address_T* bind) {
    Matter_Crypto_Mbedtls_T crypto=matter_crypto_mbedtls_new(NULL); Matter_Crypto_Port_T port;
    CHECK(crypto && matter_crypto_mbedtls_port(crypto,&port)==MATTER_OK);
    Matter_Udp_Path_T path={.local=*bind,.peer=*bind}; path.peer.port=9;
    seed_connections(d,&port,&path);
    /* Non-contiguous fabric indexes must not be used as array positions. */
    const uint8_t indexes[]={1,7,42,128,254};
    for(unsigned i=0;i<CONNECTIONS-1;++i) d->connections[i].fabric_index=indexes[i/3];
    CHECK(!available_for(d,0)); /* Independent PASE budget. */
    for(unsigned f=0;f<MATTER_FABRIC_CAPACITY;++f) {
        CHECK(available_for(d,indexes[f])==&d->connections[f*3]);
        for(unsigned j=0;j<3;++j) CHECK(matter_secure_retain(d->connections[f*3+j].secure)==MATTER_OK);
        CHECK(!available_for(d,indexes[f])); /* Cannot evict another fabric. */
        for(unsigned j=0;j<3;++j) CHECK(matter_secure_release(d->connections[f*3+j].secure)==MATTER_OK);
    }
    /* Exercise the real RX and MRP pools above their former eight-entry limit.
     * All packets are cancelled before sending; cancellation must release every
     * per-message/session pin before exchanges and sessions can be deleted. */
    for(unsigned i=0;i<TRANSACTIONS;++i) {
        Transaction* t=&d->transactions[i]; t->owner=d;
        CHECK(matter_rx_initiate(d->rx,d->connections[i%CONNECTIONS].token,&t->handle)==MATTER_OK);
        CHECK(matter_rx_get(d->rx,t->handle,&t->key)==MATTER_OK);
        t->size=1; t->packet[0]=0;
        CHECK(matter_retransmission_sender_add(d->tx,&t->key,i+1,t->packet,t->size,&t->message)==MATTER_OK);
        t->pending=true;
    }
    for(unsigned i=0;i<TRANSACTIONS;++i) CHECK(matter_retransmission_sender_cancel(d->tx,d->transactions[i].message)==MATTER_OK);
    (void)matter_retransmission_sender_process(d->tx,50);
    for(unsigned i=0;i<TRANSACTIONS;++i) {
        Transaction* t=&d->transactions[i]; CHECK(!t->pending && t->notified && !t->acknowledged);
        (void)matter_rx_close(d->rx,t->handle);
    }
    for(unsigned step=0;step<4;++step) (void)matter_rx_process(d->rx,50);
    for(unsigned i=0;i<TRANSACTIONS;++i) {
        Matter_Exchange_Info_T ignored; CHECK(matter_rx_get(d->rx,d->transactions[i].handle,&ignored)!=MATTER_OK);
    }
    memset(d->transactions,0,sizeof(d->transactions));
    /* Fill every partition (including fabricless optional work). Other buckets
     * retain their guaranteed capacity while one fabric is at its limit. */
    unsigned used=0;
    for(unsigned f=0;f<=MATTER_FABRIC_CAPACITY;++f) {
        uint8_t index=f<MATTER_FABRIC_CAPACITY?indexes[f]:0;
        for(unsigned j=0;j<4;++j) {
            CHECK(admit_work(d,SUBSCRIBE,index)); Transaction* t=&d->transactions[used++];
            t->owner=d; t->handle=used; t->admission=SUBSCRIBE; t->fabric_index=index;
            if(j<3) t->subscription_id=used;
        }
        CHECK(!admit_work(d,SUBSCRIBE,index) && admit_work(d,READ,index));
        Transaction* t=&d->transactions[used++]; t->handle=used; t->admission=READ; t->fabric_index=index;
        CHECK(!admit_work(d,READ,index)); t->closing=true; CHECK(!admit_work(d,READ,index));
    }
    CHECK(used==30 && admit_work(d,INVOKE,1) && admit_work(d,WRITE,254));
    d->transactions[used].handle=used+1; d->transactions[used++].admission=TIMED;
    CHECK(!admit_work(d,INVOKE,1) && !admit_work(d,WRITE,254) && !admit_work(d,TIMED,7));
    d->transactions[30].admission=INVOKE; CHECK(admit_work(d,WRITE,254));
    d->transactions[used].handle=used+1; d->transactions[used++].admission=WRITE;
    for(unsigned j=0;j<2;++j) {
        CHECK(admit_work(d,HANDSHAKE,0)); d->transactions[used].handle=used+1; d->transactions[used++].admission=HANDSHAKE;
    }
    CHECK(!admit_work(d,HANDSHAKE,0));
    for(unsigned j=0;j<2;++j) {
        CHECK(admit_work(d,REJECT,0)); d->transactions[used].handle=used+1; d->transactions[used++].admission=REJECT;
    }
    CHECK(!admit_work(d,REJECT,0));
    for(unsigned f=0;f<=MATTER_FABRIC_CAPACITY;++f) {
        Transaction* t=&d->transactions[used++]; t->handle=used; t->admission=READ; t->draining=true;
        t->fabric_index=f<MATTER_FABRIC_CAPACITY?indexes[f]:0;
    }
    d->transactions[used].handle=used+1; d->transactions[used].draining=true; d->transactions[used++].admission=INVOKE;
    d->transactions[used].handle=used+1; d->transactions[used].draining=true; d->transactions[used++].admission=WRITE;
    for(unsigned i=0;i<MATTER_HOST_DELIVERY_BURST;++i) {
        Transaction* t=&d->transactions[used++]; t->handle=used; t->admission=INVOKE;
        t->draining=t->delivery_shared=true;
    }
    CHECK(used==TRANSACTIONS && !admit_work(d,READ,1) && !admit_work(d,INVOKE,7));
    d->transactions[30].admission=NONE;
    CHECK(admit_work(d,INVOKE,7)); /* Retained final response does not execute a command. */
    /* Subscription admission is fabric-scoped across different peer sessions;
     * failed fourth reserve preserves all existing subscriptions. Replacement
     * can retire only the requesting node, never another fabric/node. */
    for(unsigned i=0;i<4;++i) {
        Transaction* t=&d->transactions[i]; t->key.session=100+i%3;
        t->sub=(Matter_Im_Subscribe_T)d;
    }
    Transaction* replacement=&d->transactions[3]; uint32_t id=99;
    CHECK(reserve(replacement,100,true,&id)==MATTER_IM_RESOURCE_EXHAUSTED && id==99);
    CHECK(!d->transactions[0].closing && !d->transactions[1].closing && !d->transactions[2].closing);
    CHECK(reserve(replacement,100,false,&id)==MATTER_IM_SUCCESS);
    CHECK(d->transactions[0].closing && d->transactions[1].closing && !d->transactions[2].closing);
    CHECK(!d->transactions[5].closing && replacement->subscription_id==id);
    unreserve(replacement,id+1); CHECK(replacement->subscription_id==id);
    unreserve(replacement,id); CHECK(!replacement->subscription_id);
    memset(d->transactions,0,sizeof(d->transactions));
    CHECK(admit_work(d,READ,1) && admit_work(d,SUBSCRIBE,254) && admit_work(d,TIMED,7));
    CHECK(matter_dispatch_retire(d,true)==MATTER_OK);
    /* An uninstalled reservation counts against its fabric across clear/drain. */
    for(unsigned i=0;i<3;++i) {
        Transaction* t=&d->transactions[i]; t->owner=d;
        CHECK(reserve_for(t,254)); clear_connection(t->slot);
    }
    CHECK(!available_for(d,254) && available_for(d,7));
    for(unsigned i=0;i<3;++i) dispose(&d->transactions[i]);
    CHECK(available_for(d,254));
    CHECK(matter_crypto_mbedtls_delete(crypto)==MATTER_OK);
    printf("PASS resources: 5 fabrics x 3 CASE/subscriptions; partitions/drain; 52 RX/MRP; sizeof dispatcher=%zu connection=%zu transaction=%zu\n",
        sizeof(*d),sizeof(Connection),sizeof(Transaction));
}
/* Completed CASE: retained route/window may ACK a retransmitted final
 * StatusReport, but must never restart the handler or admit a fresh counter. */
static void late_handshake(Matter_Dispatch_T d,const Matter_Udp_Address_T* local) {
    Matter_Message_Header_T header={.message_flags=MATTER_MESSAGE_SOURCE_PRESENT,.source_node_id=123,.message_counter=100};
    Matter_Exchange_Session_T token; CHECK(matter_unsecured_resolve(d->unsecured,&header,true,&token)==MATTER_OK);
    Matter_Udp_Datagram_T packet={.path={.local=*local,.peer=*local,.interface_id=1}}; packet.path.peer.port=9;
    Route* route_slot=NULL; for(unsigned i=0;i<ROUTES;++i) if(!d->routes[i].token) { route_slot=&d->routes[i]; break; }
    CHECK(route_slot); *route_slot=(Route){.token=token,.path=packet.path};
    bool duplicate=false; CHECK(matter_unsecured_pin(d->unsecured,token)==MATTER_OK);
    CHECK(matter_unsecured_commit(d->unsecured,token,100,&duplicate)==MATTER_OK && !duplicate);
    CHECK(matter_unsecured_unpin(d->unsecured,token)==MATTER_OK);
    Matter_Unsecured_Rx_Message_T m={.session=token,.message=header,.datagram=&packet,.payload_size=8,
        .protocol={.opcode=0x40,.exchange_id=7,.exchange_flags=MATTER_PROTOCOL_INITIATOR|MATTER_PROTOCOL_RELIABLE}};
    bool create=true; CHECK(admit(d,&m,&create)==MATTER_OK && !create);
    ++m.message.message_counter; CHECK(admit(d,&m,&create)==MATTER_INVALID_STATE); --m.message.message_counter;
    ++packet.path.peer.port; CHECK(admit(d,&m,&create)==MATTER_INVALID_ARGUMENT); --packet.path.peer.port;
    m.protocol.opcode=0x55; CHECK(admit(d,&m,&create)==MATTER_INVALID_STATE); m.protocol.opcode=0x40;
    m.session=0; CHECK(admit(d,&m,&create)==MATTER_INVALID_STATE); m.session=token;
    /* No transaction allocation needed, including while the previous one drains. */
    d->transactions[0]=(Transaction){.handle=1,.key={token,7,false},.closing=true};
    CHECK(admit(d,&m,&create)==MATTER_OK && !create); memset(&d->transactions[0],0,sizeof(d->transactions[0]));
    uint8_t bytes[40]={0}; size_t n,h;
    CHECK(matter_message_header_write(&header,bytes,sizeof(bytes),&n)==MATTER_MESSAGE_OK);
    CHECK(matter_protocol_header_write(&m.protocol,bytes+n,sizeof(bytes)-n,&h)==MATTER_MESSAGE_OK);
    packet.data=bytes; packet.size=n+h+8;
    CHECK(matter_unsecured_rx_receive(d->ingress,&packet,d->now)==MATTER_OK);
    CHECK(matter_rx_process(d->rx,d->now)==MATTER_PENDING && !d->delivered);
    Matter_Message_Header_T ack_header; Matter_Protocol_Header_T ack_protocol;
    CHECK(matter_message_header_read(d->ack,sizeof(d->ack),&ack_header,&n)==MATTER_MESSAGE_OK);
    CHECK(matter_protocol_header_read(d->ack+n,sizeof(d->ack)-n,&ack_protocol,&h)==MATTER_MESSAGE_OK &&
        ack_protocol.opcode==0x10 && ack_protocol.exchange_id==7 && ack_protocol.acknowledged_message_counter==100);
    for(unsigned i=0;i<TRANSACTIONS;++i) CHECK(!d->transactions[i].handle);
    /* Normal owner completion/stop below drains the generated control ACK. */
    puts("PASS late CASE: duplicate final StatusReport control ACK; fresh counter, wrong route/opcode denied; no handler restart");
}
/* Malformed Sigma1 must fail before accessing credentials. Exercise the real
 * CASE engine, ingress, dispatcher and MRP, not just the engine's output API. */
static Matter_Result_T unused_case_load(void* u,unsigned slot,Matter_Case_Fabric_T* f) {
    (void)u; (void)slot; (void)f; CHECK(false); return MATTER_PORT_ERROR;
}
static Matter_Result_T unused_case_valid(void* u,uint8_t index,uint32_t revision) {
    (void)u; (void)index; (void)revision; CHECK(false); return MATTER_PORT_ERROR;
}
static Matter_Result_T unused_case_sign(void* u,uint8_t index,const uint8_t* p,size_t n,uint8_t sig[64]) {
    (void)u; (void)index; (void)p; (void)n; (void)sig; CHECK(false); return MATTER_PORT_ERROR;
}
static void case_failure(Matter_Dispatch_T* current,Matter_T owner,Matter_Udp_Windows_T udp,
    const Matter_Udp_Address_T* bind,Matter_Root_T root) {
    Matter_Crypto_Mbedtls_T crypto=matter_crypto_mbedtls_new(NULL); CHECK(crypto);
    Matter_Dispatch_Config_T cfg={.root=root,.fabrics={.capacity=1,.load=unused_case_load,
        .valid=unused_case_valid,.sign=unused_case_sign},.time={MATTER_CERT_TIME_SUPPLIED,{2026,10,9,0,0,0}}};
    CHECK(matter_crypto_mbedtls_port(crypto,&cfg.crypto)==MATTER_OK &&
        matter_crypto_mbedtls_credentials(crypto,&cfg.credentials)==MATTER_OK);
    for(unsigned mode=0;mode<3;++mode) {
        Matter_Dispatch_T d=*current=matter_dispatch_new(owner,matter_udp_windows_module(udp),&cfg); CHECK(d);
        const uint8_t sigma1[]={4,0,0,0,1,0,0,0,1,0,0,0,0,0,0,0,5,0x30,7,0,0,0,0x15,0x18};
        Matter_Udp_Datagram_T packet={.path={.local=*bind,.peer=*bind},.data=sigma1,.size=sizeof(sigma1)};
        packet.path.peer.port=9;
        matter_dispatch_received(d,&packet); CHECK(matter_dispatch_process(d,0)==MATTER_PENDING);
        Transaction* t=&d->transactions[0];
        CHECK(t->case_attempt && matter_case_state(t->case_attempt)==MATTER_CASE_FAILED);
        CHECK(t->pending && t->final && !t->closing && !t->slot);
        Matter_Message_Header_T mh; Matter_Protocol_Header_T ph; size_t n,h;
        CHECK(matter_message_header_read(t->packet,t->size,&mh,&n)==MATTER_MESSAGE_OK && !mh.session_id);
        CHECK(matter_protocol_header_read(t->packet+n,t->size-n,&ph,&h)==MATTER_MESSAGE_OK &&
            ph.opcode==0x40 && !ph.protocol_id && (ph.exchange_flags&MATTER_PROTOCOL_RELIABLE));
        const uint8_t expected[]={1,0,0,0,0,0,2,0};
        CHECK(t->size==n+h+sizeof(expected) && !memcmp(t->packet+n+h,expected,sizeof(expected)));
        uint8_t* saved=malloc(t->size); CHECK(saved); size_t size=t->size; memcpy(saved,t->packet,size);
        uint64_t now=0,first=0;
        for(unsigned i=0;i<100;++i) {
            Matter_Result_T r=matter_udp_windows_poll(udp); CHECK(r==MATTER_OK || r==MATTER_WOULD_BLOCK);
            CHECK(matter_dispatch_process(d,++now)==MATTER_PENDING);
            if(t->sent && !d->request) { first=d->producer; break; }
        }
        CHECK(first && t->pending && !t->closing);
        /* Additional handshake data cannot abort the queued failure report. */
        d->decision=(Matter_Rx_Decision_T){.session=t->key.session,.exchange=t->handle,
            .header={.exchange_id=t->key.exchange_id,.opcode=0x32,.exchange_flags=MATTER_PROTOCOL_INITIATOR},
            .payload=expected,.payload_size=sizeof(expected)};
        dispatch(d); CHECK(!t->closing);
        uint64_t deadline; CHECK(matter_retransmission_sender_deadline(d->tx,&deadline)==MATTER_OK);
        now=deadline;
        for(unsigned i=0;i<100 && d->producer==first;++i) {
            Matter_Result_T r=matter_udp_windows_poll(udp); CHECK(r==MATTER_OK || r==MATTER_WOULD_BLOCK);
            CHECK(matter_dispatch_process(d,++now)==MATTER_PENDING);
        }
        CHECK(d->request && d->producer!=first && t->pending && !t->closing &&
            t->size==size && !memcmp(t->packet,saved,size)); free(saved);
        for(unsigned i=0;i<CONNECTIONS;++i) CHECK(!d->connections[i].token && !d->connections[i].reserved);
        if(mode==0) CHECK(matter_retransmission_sender_ack(d->tx,&t->key,mh.message_counter)==MATTER_OK);
        if(mode==2) CHECK(matter_dispatch_stop(d)==MATTER_PENDING); /* TX still borrowed. */
        for(unsigned i=0;i<1000 && t->handle;++i) {
            Matter_Result_T r=matter_udp_windows_poll(udp); CHECK(r==MATTER_OK || r==MATTER_WOULD_BLOCK);
            r=matter_dispatch_process(d,++now); CHECK(r==MATTER_OK || r==MATTER_PENDING);
            if(mode==1 && !d->request && matter_retransmission_sender_deadline(d->tx,&deadline)==MATTER_OK && deadline>now)
                now=deadline; /* All retries exhausted without a peer ACK. */
        }
        CHECK(!t->handle);
        for(unsigned i=0;i<1000 && matter_dispatch_stop(d)!=MATTER_OK;++i) {
            Matter_Result_T r=matter_udp_windows_poll(udp); CHECK(r==MATTER_OK || r==MATTER_WOULD_BLOCK);
            r=matter_dispatch_process(d,++now); CHECK(r==MATTER_OK || r==MATTER_PENDING);
        }
        CHECK(matter_dispatch_delete(d)==MATTER_OK && !allocations); *current=NULL;
    }
    CHECK(matter_crypto_mbedtls_delete(crypto)==MATTER_OK);
    puts("PASS CASE rejection: StatusReport, immutable retry, no handshake restart/session, ACK/exhaustion/stop drain");
}
int main(void) {
    Matter_T owner=matter_new(NULL); CHECK(owner && matter_start(owner)==MATTER_OK);
    Matter_Root_Port_T rp={NULL,load_root,denied,store_root}; Matter_Root_T root=matter_root_new(&rp); CHECK(root);
    Matter_Dispatch_T d=NULL; bool fail_random=false,reset=false;
    Matter_Udp_Address_T bind={0}; bind.address[15]=1;
    Matter_Udp_Listener_T listener={&d,udp_received,udp_sent};
    Matter_Udp_Windows_T udp=matter_udp_windows_new(owner,&bind,0,&listener); CHECK(udp);
    CHECK(matter_udp_start(matter_udp_windows_module(udp))==MATTER_OK && matter_udp_windows_local(udp,&bind)==MATTER_OK);
    case_failure(&d,owner,udp,&bind,root);
    Matter_Dispatch_Config_T cfg={.root=root,.crypto={.user=&fail_random,.random=entropy},.user=&reset,.fabric_live=fabric_live};
    fail_alloc=true; CHECK(!matter_dispatch_new(owner,matter_udp_windows_module(udp),&cfg)); fail_alloc=false;
    fail_random=true; CHECK(!matter_dispatch_new(owner,matter_udp_windows_module(udp),&cfg)); fail_random=false;
    CHECK(!allocations && matter_get_state(owner)==MATTER_STATE_RUNNING);
    for(unsigned run=0;run<3;++run) {
        d=matter_dispatch_new(owner,matter_udp_windows_module(udp),&cfg); CHECK(d && allocations==1);
        CHECK(matter_dispatch_delete(d)==MATTER_BUSY && !matter_dispatch_session(d,1));
        /* Removal can happen after another transaction queued a retry in this
         * same owner iteration. No ciphertext or ACK may leave a retired identity. */
        d->connections[0]=(Connection){.token=2,.retiring=true,.operational=true,.fabric_index=1};
        d->connections[1]=(Connection){.token=3,.operational=true,.fabric_index=2};
        d->transactions[0].handle=1; d->transactions[0].key=(Matter_Exchange_Info_T){2,1,false};
        Matter_Retransmission_Request_T retry={.message={.exchange=d->transactions[0].key}};
        CHECK(send_message(d,&retry)==MATTER_RETRANSMISSION_REJECTED_FATAL && !d->request);
        Matter_Ack_Message_T ack={.exchange=d->transactions[0].key};
        CHECK(send_ack(d,1,&ack)==MATTER_PORT_ERROR && !d->request);
        CHECK(matter_dispatch_retire_fabric(d,1)==MATTER_PENDING && d->transactions[0].closing && !d->connections[1].retiring);
        d->connections[0].operational=false; reset=true; reconcile(d);
        CHECK(d->connections[0].retiring && d->connections[1].retiring); reset=false;
        memset(d->connections,0,sizeof(d->connections)); memset(d->transactions,0,sizeof(d->transactions)); d->ack_waiting=false;
        diagnostic_counts(d); rotation(d);
        removal(d);
        expiry_retirement(d);
        outgoing_cancel_tests(d,&bind);
        policy(d,owner,udp,&bind);
        resources(d,&bind);
        subscription_cleanup(d);
        read_cleanup(d);
        const uint8_t invalid_im[]={4,0,0,0,1,0,0,0,1,0,0,0,0,0,0,0,5,2,7,0,1,0,0x15,0x18};
        Matter_Udp_Datagram_T packet={.path={.local=bind,.peer=bind,.interface_id=1},.data=invalid_im,.size=sizeof(invalid_im)};
        packet.path.peer.port=9;
        matter_dispatch_received(d,&packet); CHECK(d->queued);
        packet.size=PACKET+1; matter_dispatch_received(d,&packet); CHECK(d->inbox_size==sizeof(invalid_im));
        CHECK(matter_dispatch_process(d,100)==MATTER_PENDING);
        for(unsigned i=0;i<ROUTES;++i) CHECK(!d->routes[i].token);
        for(unsigned n=0;n<sizeof(invalid_im);++n) { packet.size=n; matter_dispatch_received(d,&packet); CHECK(matter_dispatch_process(d,101+n)==MATTER_PENDING); }
        uint8_t request[sizeof(invalid_im)]; memcpy(request,invalid_im,sizeof(request)); request[17]=0x20; request[20]=0;
        /* No admission capacity: reply BUSY instead of completing a handshake
         * that cannot install a session. A pending control send must survive stop. */
        if(!run) for(unsigned i=0;i<CONNECTIONS;++i) d->connections[i].reserved=true;
        packet.data=request; packet.size=sizeof(request); matter_dispatch_received(d,&packet);
        CHECK(matter_dispatch_process(d,200)==MATTER_PENDING);
        if(!run) {
            for(unsigned i=0;i<100 && !d->control;++i) {
                Matter_Result_T r=matter_udp_windows_poll(udp); CHECK(r==MATTER_OK || r==MATTER_WOULD_BLOCK);
                CHECK(matter_dispatch_process(d,200)==MATTER_PENDING);
            }
            CHECK(d->control && d->control_transaction && d->control_transaction->pending);
            Transaction* busy=d->control_transaction; Matter_Message_Header_T mh; Matter_Protocol_Header_T ph; size_t n,h;
            CHECK(matter_message_header_read(busy->packet,sizeof(busy->packet),&mh,&n)==MATTER_MESSAGE_OK && !mh.session_id);
            CHECK(matter_protocol_header_read(busy->packet+n,sizeof(busy->packet)-n,&ph,&h)==MATTER_MESSAGE_OK &&
                !ph.protocol_id && ph.opcode==0x40 && ph.exchange_id==7 && ph.exchange_flags==MATTER_PROTOCOL_ACK);
            const uint8_t expected_busy[10]={8,0,0,0,0,0,4,0,0xf4,1};
            CHECK(!memcmp(busy->packet+n+h,expected_busy,sizeof(expected_busy)));
            for(unsigned i=0;i<CONNECTIONS;++i) d->connections[i].reserved=false;
        }
        /* Closed commissioning callback: never creates a secure grant. Pending
         * ACK and exchange still have to drain before releasing the route. */
        for(unsigned i=0;i<CONNECTIONS;++i) CHECK(!d->connections[i].token);
        matter_dispatch_sent(d,UINT64_MAX,MATTER_OPERATION_SUCCEEDED); CHECK(!d->completion);
        CHECK(matter_dispatch_process(d,199)==MATTER_INVALID_ARGUMENT);
        if(run==2) late_handshake(d,&bind);
        CHECK(matter_dispatch_stop(d)==MATTER_PENDING);
        bool stopped=false;
        for(unsigned i=0;i<1000;++i) {
            Matter_Result_T r=matter_udp_windows_poll(udp); CHECK(r==MATTER_OK || r==MATTER_WOULD_BLOCK);
            r=matter_dispatch_process(d,201+i); CHECK(r==MATTER_OK || r==MATTER_PENDING);
            if(matter_dispatch_stop(d)==MATTER_OK) { stopped=true; break; }
        }
        if(!stopped || d->request) fprintf(stderr,"stop run=%u stopped=%u internal=%u request=%llu completion=%u ack=%llu now=%llu\n",run,stopped,d->stopped,(unsigned long long)d->request,d->completion,(unsigned long long)d->ack_token,(unsigned long long)d->now);
        CHECK(stopped && matter_dispatch_delete(d)==MATTER_OK); d=NULL;
        CHECK(!allocations && matter_get_state(owner)==MATTER_STATE_RUNNING);
    }
    Matter_Result_T stopped=matter_udp_stop(matter_udp_windows_module(udp)); CHECK(stopped==MATTER_OK || stopped==MATTER_PENDING);
    CHECK(matter_udp_process(matter_udp_windows_module(udp))==MATTER_PENDING);
    CHECK(matter_udp_process(matter_udp_windows_module(udp))==MATTER_OK);
    CHECK(matter_udp_windows_delete(udp)==MATTER_OK && matter_root_delete(root)==MATTER_OK);
    CHECK(matter_stop(owner)==MATTER_OK && matter_delete(owner)==MATTER_OK);
    puts("PASS dispatcher: OOM/RNG, three lifetimes, scoped subscriptions, idle LRU/protected slots, CloseSession reservation/drain, ingress, stale completion, clock, ACK/stop");
    puts("PASS rediscovery: identity/coalescing, session pin, pending TX/take, same ciphertext/new route, TXT intervals, failure/timeout/late completion, fabric/stop isolation");
    return 0;
}

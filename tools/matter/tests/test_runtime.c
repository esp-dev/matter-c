/* Full composition through installed public APIs: no host adapter headers. */
#include "runtime/matter_runtime.h"
#include "runtime/matter_host_limits.h"
#include "clusters/matter_time_sync.h"
#include "crypto/matter_crypto_mbedtls.h"
#include "codec/matter_message_header.h"
#include "codec/matter_protocol_header.h"
#include "test_opcreds_vectors.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"runtime:%d: %s\n",__LINE__,#x); abort(); } } while(0)
#ifdef MATTER_TEST_ALLOC
static size_t calls,fail_at,live;
void* matter_test_calloc(size_t n,size_t z) { if(++calls==fail_at) return NULL; void* p=calloc(n,z); if(p) ++live; return p; }
void* matter_test_malloc(size_t z) { if(++calls==fail_at) return NULL; void* p=malloc(z); if(p) ++live; return p; }
void matter_test_free(void* p) { if(p) { CHECK(live); --live; } free(p); }
#endif
typedef struct {
    Matter_Runtime_Config_T config; Matter_Root_Config_T identity;
    Matter_Runtime_T runtime; Matter_Crypto_Mbedtls_T crypto;
    Matter_T owner; Matter_Udp_T udp; Matter_Events_T events;
    Matter_Wifi_Settings_T settings; Matter_Wifi_Id_T connected;
    uint8_t key[32],*blob; size_t blob_size;
    unsigned stores,pumps,clocks,logs; uint64_t event_high,epoch;
    bool accept_packets; uint64_t pending_packet;
    bool ack_pase_failures,pending_failure_ack; uint32_t failure_counter; uint16_t failure_exchange;
    bool fail_store,fail_clock,fail_initialize,fail_snapshot;
    bool fail_network,oversized_network,invalid_network,network_online;
    uint64_t wifi_token; bool cancelling,hold_cancel;
    Matter_Cluster_T time_sync; Matter_Time_Sync_Sample_T time_sample;
} Node;
static Matter_Result_T blob_read(void* u,uint8_t* out,size_t cap,size_t* size) {
    Node* n=u; if(!n->blob) return MATTER_OFFLINE;
    if(cap<n->blob_size) return MATTER_LIMIT_REACHED;
    memcpy(out,n->blob,n->blob_size); *size=n->blob_size; return MATTER_OK;
}
static Matter_Result_T blob_replace(void* u,const uint8_t* data,size_t size) {
    Node* n=u; if(n->fail_store) return MATTER_PORT_ERROR;
    uint8_t* copy=malloc(size); if(!copy) return MATTER_PORT_ERROR;
    memcpy(copy,data,size); free(n->blob); n->blob=copy; n->blob_size=size; ++n->stores; return MATTER_OK;
}
static Matter_Result_T wifi_load(void* u,Matter_Wifi_Settings_T* s,Matter_Wifi_Id_T* c) {
    Node* n=u; if(n->fail_snapshot) return MATTER_PORT_ERROR;
    *s=n->settings; *c=n->connected; return MATTER_OK;
}
static Matter_Result_T configure(void* u,const Matter_Wifi_Settings_T* s) { ((Node*)u)->settings=*s; return MATTER_OK; }
static Matter_Result_T wifi_start(void* u,uint64_t t,bool scan,const Matter_Wifi_Network_T* n) {
    (void)scan; (void)n; ((Node*)u)->wifi_token=t; return MATTER_PENDING;
}
static Matter_Result_T wifi_cancel(void* u,uint64_t t) {
    Node* n=u; CHECK(n->wifi_token==t); n->cancelling=true;
    if(n->hold_cancel) return MATTER_PENDING;
    n->wifi_token=0; n->cancelling=false; return MATTER_OK;
}
static Matter_Result_T wifi_restore(void* u,const Matter_Wifi_Settings_T* s,const Matter_Wifi_Id_T* c) {
    Node* n=u; n->settings=*s; n->connected=*c; return MATTER_OK;
}
static Matter_Result_T initialize(void* u,const Matter_Wifi_Settings_T* s,const Matter_Wifi_Id_T* c) {
    if(((Node*)u)->fail_initialize) return MATTER_PORT_ERROR;
    return wifi_restore(u,s,c);
}
static Matter_Result_T pump(void* u,Matter_Wifi_T w,uint64_t now) {
    Node* n=u; ++n->pumps;
    if(n->cancelling) n->hold_cancel=false; /* Simulated deferred hardware drain. */
    return matter_wifi_process(w,now);
}
static Matter_Result_T observe(void* u,Matter_Wifi_Ap_T* ap,bool* online) {
    (void)u; memset(ap,0,sizeof(*ap)); *online=false; return MATTER_OK;
}
static Matter_Result_T network_snapshot(void* u,Matter_Diagnostics_Interface_T* out,size_t capacity,size_t* count) {
    Node* n=u; if(n->fail_network) return MATTER_PORT_ERROR;
    *count=n->oversized_network?capacity+1:1; if(!capacity) return MATTER_LIMIT_REACHED;
    out[0]=n->config.iface; out[0].type=n->invalid_network?5:2;
    out[0].operational=n->network_online; out[0].hardware[2]=2;
    out[0].ipv6_count=1; out[0].ipv6[0][0]=0xfe; out[0].ipv6[0][1]=0x80; out[0].ipv6[0][15]=7;
    return MATTER_OK;
}
static Matter_Result_T utc(void* u,Matter_Cert_Time_T* t) {
    Node* n=u; ++n->clocks; if(n->fail_clock) return MATTER_OFFLINE;
    *t=(Matter_Cert_Time_T){2026,10,12,12,0,0}; return MATTER_OK;
}
static Matter_Result_T timestamp(void* u,uint32_t* t) { (void)u; *t=845000000; return MATTER_OK; }
static void log_line(void* u,const char* text) { CHECK(text); ++((Node*)u)->logs; }
static Matter_Result_T regulatory(void* u,const Matter_Root_Settings_T* s,uint8_t c,bool* ok) {
    (void)u; (void)s; (void)c; *ok=true; return MATTER_OK;
}
static Matter_Result_T event_load(void* u,uint64_t* v) { return matter_store_host_event_load(matter_runtime_store(((Node*)u)->runtime),v); }
static Matter_Result_T event_store(void* u,uint64_t v) { return matter_store_host_event_store(matter_runtime_store(((Node*)u)->runtime),v); }
static Matter_Result_T activate(void* u,Matter_Operation_Id_T epoch) { ((Node*)u)->epoch=epoch; return MATTER_OK; }
static void deactivate(void* u,Matter_Operation_Id_T epoch) { Node* n=u; CHECK(n->epoch==epoch); n->epoch=0; }
static Matter_Result_T send_packet(void* u,uint64_t id,const Matter_Udp_Datagram_T* d) {
    Node* n=u; if(!n->accept_packets) return MATTER_OFFLINE;
    if(n->ack_pase_failures) {
        Matter_Message_Header_T mh; Matter_Protocol_Header_T ph; size_t m,h;
        CHECK(matter_message_header_read(d->data,d->size,&mh,&m)==MATTER_MESSAGE_OK && !mh.session_id);
        CHECK(matter_protocol_header_read(d->data+m,d->size-m,&ph,&h)==MATTER_MESSAGE_OK);
        if(!ph.protocol_id && ph.opcode==0x40 && (ph.exchange_flags&MATTER_PROTOCOL_RELIABLE)) {
            const uint8_t failure[]={1,0,0,0,0,0,2,0};
            CHECK(d->size==m+h+sizeof(failure) && !memcmp(d->data+m+h,failure,sizeof(failure)));
            n->failure_counter=mh.message_counter; n->failure_exchange=ph.exchange_id; n->pending_failure_ack=true;
        }
    }
    CHECK(!n->pending_packet); n->pending_packet=id; return MATTER_OK;
}
static void cancel_packet(void* u,uint64_t id) { (void)u; (void)id; CHECK(false); }
static void detach(void* u) { CHECK(!((Node*)u)->epoch); }
static void received(void* u,const Matter_Udp_Datagram_T* d) { matter_runtime_received(((Node*)u)->runtime,d); }
static void sent(void* u,uint64_t id,Matter_Operation_Result_T r) { matter_runtime_sent(((Node*)u)->runtime,id,r); }
static Node* node_new(unsigned id) {
    Node* n=calloc(1,sizeof(*n)); CHECK(n); n->key[31]=3; n->settings.enabled=true;
    n->crypto=matter_crypto_mbedtls_new(NULL); CHECK(n->crypto);
    Matter_Runtime_Config_T* c=&n->config;
    CHECK(matter_crypto_mbedtls_port(n->crypto,&c->crypto)==MATTER_OK);
    CHECK(matter_crypto_mbedtls_credentials(n->crypto,&c->credentials)==MATTER_OK);
    c->identity=&n->identity; c->user=n; c->utc=utc; c->timestamp=timestamp; c->log=log_line; c->regulatory=regulatory;
    c->storage=(Matter_Store_Blob_Port_T){n,blob_read,blob_replace};
    c->wifi.control=(Matter_Wifi_Port_T){n,wifi_load,configure,wifi_start,wifi_cancel,wifi_restore};
    c->wifi.initialize=initialize; c->wifi.process=pump; c->wifi.observe=observe;
    c->wifi_config=(Matter_Wifi_Config_T){4,10,20,1,1,1};
    c->iface=(Matter_Diagnostics_Interface_T){.name="application",.name_size=11,.type=1,.reachable4=-1,.reachable6=-1};
    c->boot_reason=1; c->reboot=true;
    c->attestation.identity=(Matter_Opcreds_Config_T){.dac={oc_dac,sizeof(oc_dac)},.pai={oc_pai,sizeof(oc_pai)},.certification_declaration={oc_cd,sizeof(oc_cd)}};
    c->attestation.trusted_paa=(Matter_Der_T){oc_paa,sizeof(oc_paa)}; c->attestation.dac_private=n->key;
    Matter_Root_Config_T* i=&n->identity;
    i->vendor_name=(Matter_Root_Text_T){1,{'v'}}; i->product_name=(Matter_Root_Text_T){1,{'p'}};
    i->hardware_string=(Matter_Root_Text_T){1,{'h'}}; i->software_string=(Matter_Root_Text_T){1,{'s'}};
    i->unique_id=(Matter_Root_Text_T){1,{(uint8_t)('A'+id)}}; i->vendor_id=0xfff1; i->product_id=0x8000;
    i->software_version=1; i->hardware_version=1; i->configuration_version=1;
    i->capabilities=(Matter_Root_Capabilities_T)MATTER_HOST_CAPABILITIES;
    i->settings.location[0]=i->settings.location[1]='X';
    return n;
}
static void run(Node* n,uint64_t now) { Matter_Result_T r=matter_runtime_process(n->runtime,now); CHECK(r==MATTER_OK || r==MATTER_PENDING); }
static void start_node(Node* n) {
    n->runtime=matter_runtime_new(&n->config,20202021,0); CHECK(n->runtime);
    n->owner=matter_new(NULL); CHECK(n->owner && matter_start(n->owner)==MATTER_OK);
    Matter_Udp_Port_T port={n,activate,deactivate,send_packet,cancel_packet,detach};
    Matter_Udp_Listener_T listener={n,received,sent};
    n->udp=matter_udp_new(n->owner,&port,&listener); CHECK(n->udp && matter_udp_start(n->udp)==MATTER_OK);
    Matter_Events_Port_T events={n,event_load,event_store}; n->events=matter_events_new(&events); CHECK(n->events);
    CHECK(matter_runtime_start(n->runtime,n->owner,n->udp,n->events)==MATTER_OK);
}
static Matter_Result_T time_sample(void* u,uint64_t now,Matter_Time_Sync_Sample_T* out) {
    (void)now; *out=((Node*)u)->time_sample; return MATTER_OK;
}
static Matter_Result_T time_set(void* u,uint64_t utc,uint8_t granularity,uint64_t now) {
    (void)now; ((Node*)u)->time_sample=(Matter_Time_Sync_Sample_T){utc,granularity,granularity?MATTER_TIME_SOURCE_ADMIN:0}; return MATTER_OK;
}
static void time_sync(void* u) { (void)u; }
static void check_snapshot(Node* n,bool valid,uint64_t posix) {
    uint8_t bytes[22]; const uint8_t empty[]={0x15,0x18}; Matter_Tlv_Writer_T w;
    Matter_Diagnostics_T diag=matter_root_cluster(matter_runtime_root(n->runtime),MATTER_DIAGNOSTICS_GENERAL);
    CHECK(matter_tlv_writer_init(&w,bytes,sizeof(bytes),1)==MATTER_TLV_OK);
    CHECK(!matter_diagnostics_invoke(diag,MATTER_DIAGNOSTICS_GENERAL,1,empty,sizeof(empty),&w).status);
    Matter_Tlv_Reader_T r; Matter_Tlv_Element_T e;
    CHECK(matter_tlv_init(&r,bytes,w.size,1)==MATTER_TLV_OK);
    CHECK(matter_tlv_next(&r,&e)==MATTER_TLV_OK && e.type==MATTER_TLV_STRUCTURE);
    CHECK(matter_tlv_next(&r,&e)==MATTER_TLV_OK && e.tag.number==0 && e.type==MATTER_TLV_UNSIGNED && e.unsigned_value==19);
    CHECK(matter_tlv_next(&r,&e)==MATTER_TLV_OK && e.tag.number==1);
    CHECK(e.type==(valid?MATTER_TLV_UNSIGNED:MATTER_TLV_NULL) && (!valid || e.unsigned_value==posix));
}
static void diagnostic_time(Node* a,Node* b) {
    /* No TS means null, even though the certificate UTC callback is available. */
    check_snapshot(a,false,0);
    Matter_Time_Sync_Port_T p={a,time_sample,time_set,time_sync};
    a->time_sync=matter_time_sync_new(&p,a->events,1,19); CHECK(a->time_sync);
    CHECK(matter_root_attach_cluster(matter_runtime_root(a->runtime),a->time_sync)==MATTER_OK);
    CHECK(matter_cluster_process(a->time_sync,19)==MATTER_OK); check_snapshot(a,false,0);
    const uint64_t samples[]={0,UINT64_C(845000000123456),UINT64_MAX};
    for(unsigned i=0;i<sizeof(samples)/sizeof(samples[0]);++i) {
        CHECK(time_set(a,samples[i],MATTER_TIME_MICROSECONDS,19)==MATTER_OK);
        CHECK(matter_cluster_process(a->time_sync,19)==MATTER_OK);
        check_snapshot(a,true,samples[i]/1000+UINT64_C(946684800000));
    }
    CHECK(!matter_root_cluster(matter_runtime_root(b->runtime),MATTER_TIME_SYNC_CLUSTER));
    CHECK(time_set(a,0,0,19)==MATTER_OK && matter_cluster_process(a->time_sync,19)==MATTER_OK);
    check_snapshot(a,false,0);
    puts("PASS runtime TimeSnapshot: absent/unsynchronized UTC, Matter-to-POSIX conversion, maximum value and clock isolation");
}
static void diagnostic_network(Node* a,Node* b) {
    Matter_Cluster_T diag=matter_root_cluster(matter_runtime_root(a->runtime),MATTER_DIAGNOSTICS_GENERAL);
    Matter_Im_Value_T value; Matter_Cluster_Request_T request={0};
    for(unsigned attempt=0;attempt<5;++attempt) {
        a->fail_network=attempt==1; a->oversized_network=attempt==2; a->invalid_network=attempt==3;
        a->network_online=attempt==4;
        run(a,19);
        uint8_t result=matter_cluster_read(diag,0,&request,&value);
        if(attempt>0 && attempt<4) { CHECK(result==MATTER_IM_FAILURE); continue; }
        CHECK(result==MATTER_IM_SUCCESS && value.type==MATTER_TLV_ARRAY);
        Matter_Tlv_Reader_T reader; Matter_Tlv_Element_T e; unsigned seen=0;
        CHECK(matter_tlv_init(&reader,value.data,value.size,4)==MATTER_TLV_OK);
        while(matter_tlv_next(&reader,&e)==MATTER_TLV_OK) {
            if(e.type==MATTER_TLV_BOOL && e.tag.control==1 && e.tag.number==1) {
                CHECK(e.unsigned_value==a->network_online); ++seen;
            }
            if(e.type==MATTER_TLV_BYTES && e.tag.control==1 && e.tag.number==4) {
                CHECK(e.size==8 && e.data[2]==2); ++seen;
            }
        }
        CHECK(seen==2);
    }
    /* Default radio-derived composition on B remains independent and valid. */
    diag=matter_root_cluster(matter_runtime_root(b->runtime),MATTER_DIAGNOSTICS_GENERAL);
    CHECK(matter_cluster_read(diag,0,&request,&value)==MATTER_IM_SUCCESS);
    puts("PASS runtime network callback: live state, padded MAC, failure/oversize/malformed rejection, recovery and default isolation");
}
static void close_runtime(Node* n,uint64_t now) {
    CHECK(matter_runtime_delete(n->runtime)==MATTER_BUSY);
    Matter_Result_T result=matter_runtime_stop(n->runtime,now);
    for(unsigned i=0;result==MATTER_PENDING && i<100;++i) {
        run(n,now); result=matter_runtime_stop(n->runtime,now);
    }
    CHECK(result==MATTER_OK);
    CHECK(matter_runtime_start(n->runtime,n->owner,n->udp,n->events)==MATTER_INVALID_STATE);
    CHECK(matter_runtime_delete(n->runtime)==MATTER_OK); n->runtime=NULL;
    if(n->time_sync) { CHECK(matter_cluster_delete(n->time_sync)==MATTER_OK); n->time_sync=NULL; }
    if(n->events) { CHECK(matter_events_delete(n->events)==MATTER_OK); n->events=NULL; }
    if(n->owner) {
        CHECK(matter_stop(n->owner)==MATTER_PENDING);
        while(matter_get_state(n->owner)==MATTER_STATE_STOPPING) (void)matter_udp_process(n->udp);
        CHECK(matter_udp_delete(n->udp)==MATTER_OK); n->udp=NULL;
        CHECK(matter_delete(n->owner)==MATTER_OK); n->owner=NULL;
    }
}
static void free_node(Node* n) { CHECK(!n->runtime && !n->owner); free(n->blob); CHECK(matter_crypto_mbedtls_delete(n->crypto)==MATTER_OK); memset(n,0,sizeof(*n)); free(n); }
static void commissioning_failures(void) {
    Node* a=node_new(0); Node* b=node_new(1); start_node(a); start_node(b); a->accept_packets=true; a->ack_pase_failures=true;
    uint64_t now=0; uint32_t peer_counter=100; uint8_t bytes[40],ack[40]; size_t n,h;
    Matter_Udp_Datagram_T packet={.path={.local={.address={0xfe,0x80},.port=5541},
        .peer={.address={0xfe,0x80},.port=6000},.interface_id=1},.data=bytes};
    packet.path.local.address[15]=1; packet.path.peer.address[15]=2;
    for(unsigned attempt=0;attempt<21;++attempt) {
        Matter_Message_Header_T mh={.message_flags=MATTER_MESSAGE_SOURCE_PRESENT,.source_node_id=123,.message_counter=++peer_counter};
        Matter_Protocol_Header_T ph={.opcode=0x20,.exchange_id=(uint16_t)(1+attempt),
            .exchange_flags=MATTER_PROTOCOL_INITIATOR|MATTER_PROTOCOL_RELIABLE};
        CHECK(matter_message_header_write(&mh,bytes,sizeof(bytes),&n)==MATTER_MESSAGE_OK);
        CHECK(matter_protocol_header_write(&ph,bytes+n,sizeof(bytes)-n,&h)==MATTER_MESSAGE_OK);
        bytes[n+h]=0x15; bytes[n+h+1]=0x18; packet.size=n+h+2; /* Invalid PBKDFParamRequest. */
        for(unsigned repeat=0;repeat<(attempt==0?25u:1u);++repeat) {
            matter_runtime_received(a->runtime,&packet);
            /* Let ACK/exchange cleanup finish before starting a new attempt;
             * admission BUSY is not a failed admitted PASE handshake. */
            for(unsigned tick=0;tick<5;++tick) {
                if(a->pending_packet) {
                    uint64_t id=a->pending_packet; a->pending_packet=0;
                    CHECK(matter_udp_complete(a->udp,id,MATTER_OPERATION_SUCCEEDED)==MATTER_OK);
                }
                (void)matter_udp_process(a->udp); now+=1000; run(a,now);
                if(a->pending_failure_ack) {
                    a->pending_failure_ack=false;
                    Matter_Message_Header_T ah={.message_flags=MATTER_MESSAGE_SOURCE_PRESENT,.source_node_id=123,.message_counter=++peer_counter};
                    Matter_Protocol_Header_T ap={.opcode=0x10,.exchange_id=a->failure_exchange,
                        .exchange_flags=MATTER_PROTOCOL_INITIATOR|MATTER_PROTOCOL_ACK,.acknowledged_message_counter=a->failure_counter};
                    size_t an,apn;
                    CHECK(matter_message_header_write(&ah,ack,sizeof(ack),&an)==MATTER_MESSAGE_OK);
                    CHECK(matter_protocol_header_write(&ap,ack+an,sizeof(ack)-an,&apn)==MATTER_MESSAGE_OK);
                    Matter_Udp_Datagram_T reply={.path=packet.path,.data=ack,.size=an+apn};
                    matter_runtime_received(a->runtime,&reply); run(a,now);
                }
            }
            if(matter_runtime_commissionable(a->runtime)!=(attempt<19))
                fprintf(stderr,"commissioning attempt=%u duplicate=%u open=%u\n",attempt+1,repeat,matter_runtime_commissionable(a->runtime));
            CHECK(matter_runtime_commissionable(a->runtime)==(attempt<19));
            CHECK(matter_runtime_commissionable(b->runtime));
        }
    }
    close_runtime(a,now); close_runtime(b,now); free_node(a); free_node(b);
    puts("PASS initial commissioning window: 20 failed PASE attempts, duplicate filtering, closed admission and independent runtime");
}
int main(void) {
    Node* a=node_new(0); Node* b=node_new(1);
    CHECK(matter_runtime_ota_request_query(NULL)==MATTER_INVALID_ARGUMENT);
    CHECK(!matter_runtime_ota_reboot_ready(NULL));
    a->config.network=(Matter_Diagnostics_Network_Port_T){a,network_snapshot};
    CHECK(!matter_runtime_new(NULL,20202021,0)); CHECK(!matter_runtime_new(&a->config,11111111,0));
    a->fail_clock=true; CHECK(!matter_runtime_new(&a->config,20202021,0)); a->fail_clock=false;
    a->fail_initialize=true; CHECK(!matter_runtime_new(&a->config,20202021,0)); a->fail_initialize=false;
    a->fail_snapshot=true; CHECK(!matter_runtime_new(&a->config,20202021,0)); a->fail_snapshot=false;
    a->fail_network=true; CHECK(!matter_runtime_new(&a->config,20202021,0)); a->fail_network=false;
#ifdef MATTER_TEST_ALLOC
    CHECK(!live); calls=0;
    a->runtime=matter_runtime_new(&a->config,20202021,0); CHECK(a->runtime);
    size_t count=calls; close_runtime(a,0); CHECK(!live);
    for(size_t failure=1;failure<=count;++failure) {
        calls=0; fail_at=failure;
        a->runtime=matter_runtime_new(&a->config,20202021,0);
        fail_at=0;
        if(a->runtime) close_runtime(a,0);
        CHECK(!live);
    }
#endif
    start_node(a); start_node(b);
    CHECK(!matter_runtime_ota_reboot_ready(a->runtime) && !matter_runtime_ota_reboot_ready(b->runtime));
    CHECK(matter_runtime_ota_request_query(a->runtime)==MATTER_INVALID_STATE);
    CHECK(matter_runtime_ota_request_query(b->runtime)==MATTER_INVALID_STATE);
    CHECK(matter_runtime_root(a->runtime)!=matter_runtime_root(b->runtime));
    Matter_Root_T ra=matter_runtime_root(a->runtime),rb=matter_runtime_root(b->runtime);
    Matter_Root_Endpoint_Config_T endpoint={.endpoint=7,.device_type=0x100,.revision=1};
    CHECK(matter_root_add_endpoint(ra,&endpoint)==MATTER_OK);
    CHECK(matter_root_has_device_type(ra,7,0x100) && !matter_root_has_device_type(rb,7,0x100));
    CHECK(matter_root_has_device_type(ra,0,0x16) && !matter_root_has_device_type(ra,1,0x510));
    /* Both runtimes expose Requestor even without an application OTA sink. */
    CHECK(matter_root_has_device_type(ra,0,0x12) && matter_root_has_device_type(rb,0,0x12));
    CHECK(matter_runtime_fabrics(a->runtime)!=matter_runtime_fabrics(b->runtime));
    CHECK(matter_runtime_set_certificate_validity(a->runtime,true)==MATTER_INVALID_STATE);
    CHECK(matter_runtime_commissionable(a->runtime) && matter_runtime_commissionable(b->runtime));
    for(uint64_t now=1;now<20;++now) { run(a,now); run(b,now*2); }
    CHECK(a->pumps==19 && b->pumps==19);
    diagnostic_time(a,b);
    diagnostic_network(a,b);
    Matter_Store_Host_T sa=matter_runtime_store(a->runtime),sb=matter_runtime_store(b->runtime);
    uint64_t ha,hb; CHECK(matter_store_host_event_load(sa,&ha)==MATTER_OK && matter_store_host_event_load(sb,&hb)==MATTER_OK);
    CHECK(matter_store_host_event_store(sa,ha+100)==MATTER_OK);
    CHECK(matter_store_host_event_load(sb,&b->event_high)==MATTER_OK && b->event_high==hb);
    a->fail_store=true; unsigned writes=a->stores;
    CHECK(matter_store_host_event_store(sa,ha+200)==MATTER_PORT_ERROR && a->stores==writes);
    CHECK(matter_store_host_event_load(sa,&a->event_high)==MATTER_OK && a->event_high==ha+100);
    CHECK(matter_store_host_event_store(sb,hb+300)==MATTER_OK); a->fail_store=false;
    /* Cancellation stays pending until the application's radio pump runs. */
    uint8_t* response=calloc(1,600); CHECK(response);
    Matter_Tlv_Writer_T writer; CHECK(matter_tlv_writer_init(&writer,response,600,4)==MATTER_TLV_OK);
    Matter_Wifi_Reply_T reply; uint64_t token; const uint8_t scan[]={0x15,0x18};
    Matter_Wifi_T wifi=matter_root_cluster(ra,0x31);
    CHECK(matter_wifi_invoke(wifi,0,true,scan,sizeof(scan),&writer,&reply,&token)==MATTER_PENDING);
    CHECK(token && a->wifi_token); a->hold_cancel=true;
    CHECK(matter_runtime_stop(a->runtime,20)==MATTER_PENDING);
    CHECK(matter_runtime_delete(a->runtime)==MATTER_BUSY);
    close_runtime(a,20); free(response); run(b,50);
    CHECK(b->pumps==20 && matter_runtime_commissionable(b->runtime));
    /* Recreate A from its own blob while B retains live dispatcher/events. */
    start_node(a); run(a,1); run(b,60);
    CHECK(matter_store_host_event_load(matter_runtime_store(a->runtime),&a->event_high)==MATTER_OK && a->event_high>ha+100);
    CHECK(matter_store_host_event_load(sb,&b->event_high)==MATTER_OK && b->event_high==hb+300);
    close_runtime(a,2); close_runtime(b,61); free_node(a); free_node(b);
    commissioning_failures();
#ifdef MATTER_TEST_ALLOC
    CHECK(!live);
#endif
    puts("PASS two full runtimes: independent ports, clocks, dispatchers, atomic blobs, events, stop/delete/recreate and failure cleanup");
    return 0;
}

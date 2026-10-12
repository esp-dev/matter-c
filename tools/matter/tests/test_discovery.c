/* Exercise the private adapter parser/timer without introducing public test APIs. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "alloc.h"
#define CHECK(c) do { if(!(c)) { fprintf(stderr,"discovery:%d: %s\n",__LINE__,#c); exit(1); } } while(0)
#ifdef MATTER_TEST_ALLOC
#define calloc matter_test_calloc
#define free matter_test_free
#endif
#ifdef _WIN32
#include <winsock2.h>
#endif
#include "../host/matter_host_platform.h"
static unsigned rng_fault,rng_calls;
static bool discovery_random(void* p,size_t n) {
    if(rng_fault) { ++rng_calls; if(rng_fault==1) return false; memset(p,255,n); return true; }
    return matter_host_random(p,n);
}
#define matter_host_random discovery_random
#include "../host/matter_mdns_windows.c"
#undef matter_host_random
#ifdef MATTER_TEST_ALLOC
#undef calloc
#undef free
#endif
#include "matter_discovery.h"
static size_t calls,fail_at,live;
static void* pointers[64];
void* matter_test_calloc(size_t count,size_t size) {
    if(++calls==fail_at) return NULL;
    void* p=calloc(count,size); CHECK(p);
    size_t i; for(i=0;i<64 && pointers[i];++i) {}
    CHECK(i<64); pointers[i]=p; ++live; return p;
}
void matter_test_free(void* p) {
    if(!p) return;
    size_t i; for(i=0;i<64 && pointers[i]!=p;++i) {}
    CHECK(i<64); pointers[i]=NULL; CHECK(live); --live; free(p);
}
static const uint8_t mac[]={0xb7,0x5a,0xfb,0x45,0x8e,0xcd},random_id[]={0xdd,0x20,0x0c,0x20,0xd2,0x5a,0xe5,0xf7};
static void builders(void) {
    CHECK(!matter_discovery_commissionable(mac,random_id,4096,0,5540));
    CHECK(!matter_discovery_commissionable(mac,random_id,0,4,5540));
    CHECK(!matter_discovery_commissionable(mac,random_id,0,1,0));
    CHECK(!matter_discovery_operational(mac,random_id,0,5540));
    CHECK(!matter_discovery_operational(mac,random_id,UINT64_MAX,5540));
    for(unsigned mode=0;mode<4;++mode) {
        Matter_Discovery_T d=matter_discovery_commissionable(mac,random_id,840,(uint8_t)mode,11111); CHECK(d);
        const Matter_Mdns_Record_T* r=matter_discovery_record(d);
        CHECK(!strcmp(r->instance,"DD200C20D25AE5F7") && !strcmp(r->hostname,"B75AFB458ECD") && r->port==11111);
        CHECK(!strcmp(r->service,"_matterc") && !strcmp(r->protocol,"_udp"));
        CHECK(!strcmp(r->subtypes[0],"_L840") && !strcmp(r->subtypes[1],"_S3") && r->subtype_count==(mode?3:2));
        CHECK(!strcmp(r->txt[0].key,"D") && !strcmp(r->txt[0].value,"840") && r->txt[1].value[0]==(char)('0'+mode));
        matter_discovery_delete(d);
    }
    Matter_Discovery_T d=matter_discovery_operational(mac,random_id,UINT64_C(0x1122334455667788),5540); CHECK(d);
    const Matter_Mdns_Record_T* r=matter_discovery_record(d);
    CHECK(!strcmp(r->instance,"DD200C20D25AE5F7-1122334455667788") && !strcmp(r->subtypes[0],"_IDD200C20D25AE5F7"));
    CHECK(!strcmp(r->service,"_matter") && !strcmp(r->protocol,"_tcp")); matter_discovery_delete(d);
#ifdef MATTER_TEST_ALLOC
    fail_at=calls+1; CHECK(!matter_discovery_commissionable(mac,random_id,1,0,1)); fail_at=0; CHECK(!live);
#endif
}
static void codec(void) {
    Matter_Mdns_Windows_T h=calloc(1,sizeof(*h)),other=calloc(1,sizeof(*other)); CHECK(h && other);
    h->iface.ipv6[0]=0xfe; h->iface.ipv6[1]=0x80; h->iface.ipv6[15]=1; other->iface=h->iface;
    Matter_Discovery_T d=matter_discovery_commissionable(mac,random_id,840,1,11111); CHECK(d);
    Matter_Mdns_Record_T record=*matter_discovery_record(d); CHECK(prepare(h,&record));
    size_t size=packet(h,true,false); CHECK(size>12 && get16(h->tx+4)==2 && get16(h->tx+8)==3);
    memcpy(h->rx,h->tx,size);
    for(size_t i=0;i<size;++i) { h->respond=false; CHECK(!parse(h,i) && !h->respond && !h->conflict); }
    CHECK(parse(h,size) && h->respond && !h->conflict);
    record.port=11112; CHECK(prepare(other,&record)); size=packet(other,true,false); memcpy(h->rx,other->tx,size);
    h->request=1; h->publishing=true; h->phase=1;
    CHECK(parse(h,size) && h->probe_lost && !h->conflict); h->probe_lost=false;
    /* Goodbyes and known answers must not be treated as ownership conflicts. */
    size=packet(other,false,true); memcpy(h->rx,other->tx,size); h->conflict=false; CHECK(parse(h,size) && !h->conflict);
    size=packet(other,false,false); memcpy(h->rx,other->tx,size); set16(h->rx+2,0); h->conflict=false; CHECK(parse(h,size) && !h->conflict);
    memset(h->rx,0,32); set16(h->rx+4,1); h->rx[12]=0xc0; h->rx[13]=12; CHECK(!parse(h,18));
    h->rx[13]=255; CHECK(!parse(h,18)); h->rx[12]=64; CHECK(!parse(h,18));
    set16(h->rx+4,65535); CHECK(!parse(h,18));
    /* TXT limit/duplicates and absent pointers rejected before publication. */
    record=*matter_discovery_record(d); record.protocol=NULL; CHECK(!prepare(h,&record));
    record=*matter_discovery_record(d); record.subtype_count=5; CHECK(!prepare(h,&record));
    Matter_Mdns_Txt_T txt[2]={{"D","1"},{"d","2"}}; record=*matter_discovery_record(d); record.txt=txt; CHECK(!prepare(h,&record));
    memset(h->target,'x',255); h->target[255]=0; txt[0].value=h->target; record.txt_count=1; CHECK(!prepare(h,&record));
    matter_discovery_delete(d); free(h); free(other);
}
static void lifecycle(void) {
    Matter_T owner=matter_new(NULL); CHECK(owner && matter_start(owner)==MATTER_OK);
    Matter_Discovery_T d=matter_discovery_commissionable(mac,random_id,1,0,5540); CHECK(d);
    Matter_Mdns_Windows_T h=calloc(1,sizeof(*h)); CHECK(h); h->sockets[0]=h->sockets[1]=INVALID_SOCKET; h->iface.ipv6[0]=0xfe; h->iface.ipv6[1]=0x80;
    Matter_Mdns_Port_T p={h,publish,remove_record,cancel,detach};
    h->module=matter_mdns_new(owner,&p,matter_discovery_record(d)); CHECK(h->module);
    CHECK(matter_mdns_backend(h->module,1,true)==MATTER_OK && matter_mdns_start(h->module)==MATTER_OK);
    CHECK(matter_mdns_process(h->module)==MATTER_PENDING && h->request);
    CHECK(matter_mdns_delete(h->module)==MATTER_INVALID_STATE);
    CHECK(matter_stop(owner)==MATTER_PENDING && matter_mdns_process(h->module)==MATTER_PENDING);
    CHECK(matter_mdns_windows_poll(h,0)==MATTER_OK && !h->request); /* cancel before publish */
    CHECK(matter_mdns_process(h->module)==MATTER_OK && matter_get_state(owner)==MATTER_STATE_STOPPED);
    CHECK(matter_mdns_delete(h->module)==MATTER_OK && !h->module); CHECK(matter_delete(owner)==MATTER_OK);
    matter_discovery_delete(d); free(h);
#ifdef MATTER_TEST_ALLOC
    Matter_Mdns_Windows_Interface_T iface={.index=1,.ipv6={0xfe,0x80}};
    owner=matter_new(NULL); CHECK(owner); fail_at=calls+1;
    CHECK(!matter_mdns_windows_new(owner,&iface,NULL)); fail_at=0;
    CHECK(matter_delete(owner)==MATTER_OK && !live);
#endif
}
static void resolver(void) {
    Matter_Resolver_Windows_T r=calloc(1,sizeof(*r)); CHECK(r);
    r->io=calloc(1,sizeof(*r->io)); CHECK(r->io);
    r->io->iface.index=13; r->io->sockets[0]=r->io->sockets[1]=INVALID_SOCKET;
    Matter_Resolver_Query_T q={.node_id=UINT64_C(0x1122334455667788),.interface_id=13}; memcpy(q.compressed_fabric,random_id,8);
    uint64_t id=99; CHECK(resolve_start(r,&q,&id)==MATTER_PENDING && id==1);
    Resolve_Job* j=job(r,id); CHECK(!strcmp(j->instance,"DD200C20D25AE5F7-1122334455667788._matter._tcp.local."));
    Matter_Operation_Result_T outcome=MATTER_OPERATION_CANCELLED; Matter_Resolver_Answer_T answer={.peer.port=123};
    CHECK(resolve_take(r,id,&outcome,&answer)==MATTER_PENDING && answer.peer.port==123 && outcome==MATTER_OPERATION_CANCELLED);
    CHECK(matter_resolver_windows_delete(r)==MATTER_BUSY);
    Matter_Mdns_Windows_T publisher=calloc(1,sizeof(*publisher)); CHECK(publisher);
    publisher->iface.ipv6[0]=0xfe; publisher->iface.ipv6[1]=0x80; publisher->iface.ipv6[15]=1;
    Matter_Discovery_T d=matter_discovery_operational(mac,random_id,q.node_id,11111); CHECK(d);
    Matter_Mdns_Record_T record=*matter_discovery_record(d); CHECK(prepare(publisher,&record));
    mdns_record_t swap=publisher->records[1]; publisher->records[1]=publisher->records[2]; publisher->records[2]=swap;
    size_t n=packet(publisher,false,false); memcpy(r->io->rx,publisher->tx,n);
    for(size_t i=0;i<n;++i) CHECK(!resolve_packet(r,i) && !j->has_address && !j->target[0] && !j->srv_expires);
    r->io->now=1;
    CHECK(resolve_packet(r,n) && j->has_address && j->answer.peer.port==11111 && j->answer.peer.address[15]==1);
    CHECK(j->answer.idle_ms==500 && j->answer.active_ms==300 && j->answer.active_threshold_ms==4000);
    CHECK(matter_resolver_windows_poll(r,1)==MATTER_OK && resolve_take(r,id,&outcome,&answer)==MATTER_OK && outcome==MATTER_OPERATION_SUCCEEDED);
    CHECK(resolve_take(r,id,&outcome,&answer)==MATTER_INVALID_STATE);
    /* Each new job needs fresh RRs; no cached answer can outlive its identity. */
    CHECK(resolve_start(r,&q,&id)==MATTER_PENDING && id==2); j=job(r,id);
    q.node_id++; uint64_t other; CHECK(resolve_start(r,&q,&other)==MATTER_PENDING);
    CHECK(resolve_packet(r,n) && j->has_address && !job(r,other)->has_address);
    n=packet(publisher,false,true); memcpy(r->io->rx,publisher->tx,n);
    CHECK(resolve_packet(r,n) && !j->has_address && !j->srv_expires && !j->txt_expires);
    n=packet(publisher,false,false); memcpy(r->io->rx,publisher->tx,n);
    CHECK(resolve_packet(r,n) && j->has_address);
    j->scheduled=false; j->deadline=200000; j->due=200000;
    job(r,other)->scheduled=false; job(r,other)->deadline=200000; job(r,other)->due=200000;
    CHECK(matter_resolver_windows_poll(r,120002)==MATTER_OK && !j->done); /* TTL, not job deadline. */
    record.port=22222; publisher->iface.ipv6[15]=2; CHECK(prepare(publisher,&record));
    n=packet(publisher,false,false); memcpy(r->io->rx,publisher->tx,n); CHECK(resolve_packet(r,n));
    CHECK(matter_resolver_windows_poll(r,120002)==MATTER_OK && resolve_take(r,id,&outcome,&answer)==MATTER_OK);
    CHECK(outcome==MATTER_OPERATION_SUCCEEDED && answer.peer.port==22222 && answer.peer.address[15]==2);
    /* Invalid TXT values use their respective defaults; valid zero accepted. */
    const uint8_t txt[]={6,'S','I','I','=','0','1',11,'S','A','I','=','3','6','0','0','0','0','1',9,'S','A','T','=','6','5','5','3','6'};
    CHECK(txt_valid(txt,sizeof(txt))); resolve_txt(job(r,other),txt,sizeof(txt));
    CHECK(job(r,other)->answer.idle_ms==500 && job(r,other)->answer.active_ms==300 && job(r,other)->answer.active_threshold_ms==4000);
    const uint8_t zero[]={5,'S','A','I','=','0'}; resolve_txt(job(r,other),zero,sizeof(zero)); CHECK(!job(r,other)->answer.active_ms);
    CHECK(!txt_valid(zero,sizeof(zero)-1));
    uint8_t invalid[16]={0}; CHECK(!ipv6_unicast(invalid)); invalid[0]=0xff; CHECK(!ipv6_unicast(invalid));
    invalid[0]=0; invalid[10]=invalid[11]=0xff; invalid[15]=1; CHECK(!ipv6_unicast(invalid));
    resolve_cancel(r,other); CHECK(resolve_take(r,other,&outcome,&answer)==MATTER_OK && outcome==MATTER_OPERATION_CANCELLED);
    for(unsigned i=0;i<4;++i) CHECK(resolve_start(r,&q,&id)==MATTER_PENDING);
    uint64_t unchanged=id; CHECK(resolve_start(r,&q,&id)==MATTER_LIMIT_REACHED && id==unchanged);
    for(unsigned i=0;i<4;++i) { uint64_t current=r->jobs[i].id; resolve_cancel(r,current); CHECK(resolve_take(r,current,&outcome,&answer)==MATTER_OK); }
    CHECK(resolve_start(r,&q,&id)==MATTER_PENDING); j=job(r,id); j->scheduled=false; j->deadline=r->io->now;
    CHECK(matter_resolver_windows_poll(r,r->io->now)==MATTER_OK && resolve_take(r,id,&outcome,&answer)==MATTER_OK && outcome==MATTER_OPERATION_FAILED);
    q.interface_id++; CHECK(resolve_start(r,&q,&id)==MATTER_OFFLINE); q.interface_id--;
    r->next=UINT64_MAX; CHECK(resolve_start(r,&q,&id)==MATTER_LIMIT_REACHED);
    matter_discovery_delete(d); free(publisher); free(r->io); free(r);
#ifdef MATTER_TEST_ALLOC
    Matter_Mdns_Windows_Interface_T iface={.index=13};
    for(unsigned i=1;i<=2;++i) { fail_at=calls+i; CHECK(!matter_resolver_windows_new(&iface)); fail_at=0; CHECK(!live); }
#endif
}
#include "test_mdns_ingress.h"
#include "test_mdns_known_answers.h"
#include "test_mdns_nsec.h"
#include "test_mdns_probe.h"
#include "test_mdns_addresses.h"
int main(void) {
    builders(); codec(); lifecycle(); resolver(); ingress_tests(); known_answer_tests(); nsec_tests(); probe_tests(); address_tests(); CHECK(!live);
    puts("PASS discovery: literal Matter names/subtypes, bounds/OOM, malformed DNS/prefixes/compression, conflict/known-answer/goodbye and cancel/drain");
    puts("PASS resolver: exact identity, fresh SRV/TXT/AAAA, malformed prefixes, TTL/goodbye, route change, TXT defaults, capacity/OOM, cancel/take/stale/timeout");
    puts("PASS ingress/replies: TTL64, interface/source/destination, QU/QM, legacy ID/questions/TTL/no-flush, capacity and cancellation");
    puts("PASS known answers/TC: TTL59/60, RR identity, compression, sections, partial/additional suppression, continuation delay, source isolation, capacity and cleanup");
    puts("PASS NSEC: owned names/types, bitmaps/wire, QU/legacy, known TTL, TC, unsupported RDATA, source isolation and cleanup");
    puts("PASS probes: canonical set order, unsigned data, stale/authoritative packets, 250ms defense, defer/reprobe/failure and cancel lifecycle");
    puts("PASS addresses/duplicates: multiple A/AAAA, bounds, wire/NSEC, probe sets, TTL119/120, partial/additional/family isolation and QU");
    return 0;
}

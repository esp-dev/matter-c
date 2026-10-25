#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "clusters/matter_fabric.h"
#include "matter_compat.h"
#define CHECK(c) do { if(!(c)) { fprintf(stderr,"Fabric encoding:%d: %s\n",__LINE__,#c); abort(); } } while(0)
#ifdef MATTER_TEST_ALLOC
static void before_free(void*,size_t);
static void after_alloc(void*,size_t);
#define MATTER_TEST_ALLOC_BEFORE_FREE before_free
#define MATTER_TEST_ALLOC_AFTER_ALLOC after_alloc
#include "test_alloc_bytes.h"
static unsigned wiped;
static void before_free(void* p,size_t n) {
    for(size_t i=0;i<n;++i) CHECK(!((uint8_t*)p)[i]);
    ++wiped;
}
#endif
typedef struct {
    Matter_Fabric_View_T view; Matter_Fabric_T model;
    Matter_Tlv_Writer_T writer; Matter_Tlv_Reader_T reader; Matter_Tlv_Element_T e;
    uint8_t saved[4096],request[64],challenge[16],signature[64]; size_t saved_size,request_size;
    const uint8_t* held; unsigned views,signs,reentries; bool guard,sign_fail;
} Fixture;
static void reentry(Fixture* f) {
    if(!f || !f->model || !f->guard) return;
    ++f->reentries; Matter_Im_Value_T v; uint8_t status,index;
    CHECK(matter_fabric_read_index(f->model,0,1,false,&v)==MATTER_IM_FAILURE);
    CHECK(matter_fabric_read(f->model,3,1,false,&v)==MATTER_IM_FAILURE);
    CHECK(matter_fabric_delete(f->model)==MATTER_BUSY && matter_fabric_rollback(f->model)==MATTER_BUSY);
    CHECK(matter_fabric_execute(f->model,1,11,0,NULL,0,&status,&index).status==MATTER_IM_FAILURE);
    CHECK(matter_fabric_manage(f->model,1,10,NULL,0,&status,&index).status==MATTER_IM_FAILURE);
    CHECK(matter_fabric_update(f->model,1,1,1,NULL,0,&status,&index).status==MATTER_IM_FAILURE);
    CHECK(matter_fabric_vid(f->model,1,13,f->request,f->request_size,f->challenge,&index,f->signature)==MATTER_IM_FAILURE);
}
#ifdef MATTER_TEST_ALLOC
static Fixture* allocating;
static void after_alloc(void* p,size_t n) { (void)p; (void)n; reentry(allocating); }
#endif
static const Matter_Fabric_View_T* view(void* u) { Fixture* f=u; ++f->views; reentry(f); return &f->view; }
static uint8_t root(void* u,Matter_Cert_Tlv_T c) { (void)u; (void)c; abort(); return 1; }
static Matter_Result_T install(void* u,Matter_Exchange_Session_T s,uint64_t c,const Matter_Fabric_Add_T* a,uint8_t* st,uint8_t* i) {
    (void)u; (void)s; (void)c; (void)a; (void)st; (void)i; abort(); return MATTER_INVALID_STATE;
}
static Matter_Result_T rollback(void* u) { (void)u; return MATTER_OK; }
static Matter_Result_T sign(void* u,uint8_t target,const uint8_t* p,size_t n,uint8_t signature[64]) {
    Fixture* f=u; const Matter_Fabric_Record_T* r=&f->view.records[target-1]; ++f->signs; reentry(f);
#ifdef MATTER_TEST_ALLOC
    CHECK(matter_test_allocation_size(p)==n);
#endif
    CHECK(n==126u+r->vvs_size && p[0]==1 && p[49]==target && p[50]==1);
    for(unsigned i=0;i<32;++i) CHECK(p[1+i]==0x5a);
    CHECK(!memcmp(p+33,f->challenge,16) && !memcmp(p+51,r->root_public,65));
    for(unsigned i=0;i<8;++i) CHECK(p[116+i]==(uint8_t)(r->fabric_id>>(56-8*i)));
    CHECK(p[124]==(uint8_t)(r->vendor>>8) && p[125]==(uint8_t)r->vendor && !memcmp(p+126,r->vvs,r->vvs_size));
    CHECK(f->held && !memcmp(f->held,f->saved,f->saved_size));
    /* Next backend callback may invalidate all certificate/metadata spans. */
    memset(&f->view,0,sizeof(f->view)); memset(signature,0x77,64);
    return f->sign_fail?MATTER_INVALID_STATE:MATTER_OK;
}
static Fixture* create(void) {
    Fixture* f=calloc(1,sizeof(*f)); CHECK(f);
    Matter_Fabric_Port_T p={.user=f,.view=view,.root=root,.install=install,.rollback=rollback,.sign=sign};
    f->model=matter_fabric_new(&p); CHECK(f->model); return f;
}
static void populate(Fixture* f) {
    memset(&f->view,0,sizeof(f->view)); f->view.count=5; f->view.revision=17;
    f->view.pase_session=91; f->view.pase_index=2;
    for(unsigned i=0;i<5;++i) {
        Matter_Fabric_Record_T* r=&f->view.records[i]; r->index=(uint8_t)(i+1); r->vendor=0xfff1;
        r->fabric_id=UINT64_C(0xfedcba9876543210)+i; r->node_id=UINT64_C(0x1122334455667788)+i;
        r->noc_size=400; r->root_size=400; r->label_size=32;
        memset(r->noc,0x10+i,400); memset(r->root,0x20+i,400); memset(r->root_public,0x30+i,65);
        memset(r->label,'a'+i,32);
        if(i%2) { r->icac_size=400; memset(r->icac,0x40+i,400); r->vvs_size=85; memset(r->vvs,0x50+i,85); }
    }
}
static void destroy(Fixture* f) { CHECK(!matter_fabric_delete(f->model)); free(f); }
static Matter_Im_Value_T read_value(Fixture* f,uint32_t attr,uint8_t accessing,bool filtered) {
    Matter_Im_Value_T out; unsigned calls_before=f->views;
    f->guard=true;
#ifdef MATTER_TEST_ALLOC
    allocating=f;
#endif
    CHECK(!matter_fabric_read_index(f->model,attr,accessing,filtered,&out));
#ifdef MATTER_TEST_ALLOC
    allocating=NULL;
    if(out.data) CHECK(matter_test_allocation_size(out.data)==out.size && out.size<=4096);
#endif
    f->guard=false; CHECK(f->views==calls_before+1); return out;
}
static void lists(Fixture* f) {
    for(unsigned attr=0;attr<=4;++attr) for(unsigned filtered=0;filtered<2;++filtered) for(unsigned index=0;index<=5;++index) {
        Matter_Im_Value_T out=read_value(f,attr,(uint8_t)index,filtered!=0);
        if(attr==2 || attr==3) { CHECK(!out.data && out.unsigned_value==5); continue; }
        CHECK(out.type==MATTER_TLV_ARRAY && out.size<=4096 && !matter_tlv_init(&f->reader,out.data,out.size,3));
        CHECK(!matter_tlv_next(&f->reader,&f->e) && f->e.type==MATTER_TLV_ARRAY); unsigned seen=0;
        for(unsigned i=0;i<5;++i) {
            if(attr!=4 && filtered && index!=i+1) continue;
            const Matter_Fabric_Record_T* r=&f->view.records[i]; ++seen;
            CHECK(!matter_tlv_next(&f->reader,&f->e));
            if(attr==4) { CHECK(f->e.type==MATTER_TLV_BYTES && f->e.size==400 && !memcmp(f->e.data,r->root,400)); continue; }
            CHECK(f->e.type==MATTER_TLV_STRUCTURE && !f->e.tag.control);
            CHECK(!matter_tlv_next(&f->reader,&f->e) && f->e.tag.number==1 && f->e.type==MATTER_TLV_BYTES);
            CHECK(f->e.size==(attr?65u:400u) && !memcmp(f->e.data,attr?r->root_public:r->noc,f->e.size));
            CHECK(!matter_tlv_next(&f->reader,&f->e) && f->e.tag.number==2);
            if(!attr) {
                CHECK(f->e.type==(r->icac_size?MATTER_TLV_BYTES:MATTER_TLV_NULL));
                if(r->icac_size) CHECK(f->e.size==400 && !memcmp(f->e.data,r->icac,400));
            } else {
                CHECK(f->e.unsigned_value==r->vendor);
                CHECK(!matter_tlv_next(&f->reader,&f->e) && f->e.tag.number==3 && f->e.unsigned_value==r->fabric_id);
                CHECK(!matter_tlv_next(&f->reader,&f->e) && f->e.tag.number==4 && f->e.unsigned_value==r->node_id);
                CHECK(!matter_tlv_next(&f->reader,&f->e) && f->e.tag.number==5 && f->e.type==MATTER_TLV_UTF8 && f->e.size==32 && !memcmp(f->e.data,r->label,32));
                if(r->vvs_size) CHECK(!matter_tlv_next(&f->reader,&f->e) && f->e.tag.number==6 && f->e.size==85 && !memcmp(f->e.data,r->vvs,85));
            }
            CHECK(!matter_tlv_next(&f->reader,&f->e) && f->e.tag.number==254 && f->e.unsigned_value==r->index);
            CHECK(!matter_tlv_next(&f->reader,&f->e) && f->e.type==MATTER_TLV_END);
        }
        CHECK(seen==(attr==4 || !filtered?5u:index?1u:0u));
        CHECK(!matter_tlv_next(&f->reader,&f->e) && f->e.type==MATTER_TLV_END && matter_tlv_next(&f->reader,&f->e)==MATTER_TLV_DONE);
    }
    f->view.root_ready=true; f->view.root_size=400; memset(f->view.root,0x66,400);
    Matter_Im_Value_T out=read_value(f,4,0,true); CHECK(out.size==2420); /* Six 400-byte roots, including pending. */
    memcpy(f->view.root,f->view.records[0].root,400);
    out=read_value(f,4,0,true); CHECK(out.size==(MATTER_CSA_COMPAT_PENDING_ROOT?2420u:2017u)); /* Optional extra pending entry. */
    memcpy(f->view.records[1].root,f->view.records[0].root,400);
    out=read_value(f,4,0,true); CHECK(out.size==(MATTER_CSA_COMPAT_PENDING_ROOT?2420u:2017u)); /* Installed duplicate stays visible. */
    f->view.added=true;
    out=read_value(f,4,0,true); CHECK(out.size==2017); /* Pending root consumed by AddNOC. */
    f->view.added=false;
}
static void signing(Fixture* f) {
    for(unsigned mode=0;mode<4;++mode) {
        populate(f); f->sign_fail=(mode%2)!=0; uint8_t target=0; Matter_Im_Value_T out=read_value(f,0,1,false);
        memcpy(f->saved,out.data,out.size); f->saved_size=out.size; f->held=out.data;
        CHECK(matter_fabric_read_index(f->model,6,1,false,&out)==MATTER_IM_UNSUPPORTED_ATTRIBUTE);
        CHECK(matter_fabric_revision(f->model)==17 && matter_fabric_index(f->model,91)==2 && !matter_fabric_added(f->model));
        CHECK(!matter_fabric_rollback(f->model) && !memcmp(f->held,f->saved,f->saved_size));
        /* Literal SignVID request, both the 126- and 211-byte message cases. */
        static const uint8_t prefix[]={0x15,0x24,0,1,0x30,1,32};
        memcpy(f->request,prefix,sizeof(prefix)); f->request[3]=(uint8_t)(mode<2?1:2);
        memset(f->request+sizeof(prefix),0x5a,32); f->request[39]=0x18; f->request_size=40;
        memset(f->signature,0xa5,64); f->guard=true;
#ifdef MATTER_TEST_ALLOC
        allocating=f; size_t before=live_bytes;
#endif
        CHECK(matter_fabric_vid(f->model,1,13,f->request,40,f->challenge,&target,f->signature)==(f->sign_fail?MATTER_IM_FAILURE:0));
#ifdef MATTER_TEST_ALLOC
        allocating=NULL; CHECK(live_bytes==before);
#endif
        f->guard=false;
        for(unsigned i=0;i<64;++i) CHECK(f->signature[i]==(f->sign_fail?0:0x77));
        CHECK(!memcmp(f->held,f->saved,f->saved_size));
        /* Backend was invalidated by sign; provider copy stays independent. */
        out=read_value(f,5,2,false); CHECK(!out.data && out.unsigned_value==2);
    }
}
static void bounds(Fixture* f) {
    populate(f);
    for(unsigned i=0;i<5;++i) { f->view.records[i].icac_size=400; memset(f->view.records[i].icac,0x66,400); }
    f->view.records[0].vvsc_size=26; memset(f->view.records[0].vvsc,0x77,400);
    Matter_Im_Value_T out=read_value(f,0,0,false); CHECK(out.size==4096);
    f->view.records[0].vvsc_size=27; memset(&out,0xa5,sizeof(out));
    CHECK(matter_fabric_read_index(f->model,0,0,false,&out)==MATTER_IM_FAILURE && !out.data && !out.size);
    out=read_value(f,0,1,true); CHECK(out.size<4096); /* Filter before applying the limit. */
}
#ifdef MATTER_TEST_ALLOC
static void oom(Fixture* f) {
    populate(f); Matter_Fabric_View_T* saved=malloc(sizeof(*saved)); CHECK(saved); memcpy(saved,&f->view,sizeof(*saved));
    for(unsigned attr=0;attr<=4;++attr) {
        if(attr==2 || attr==3) continue;
        Matter_Im_Value_T out=read_value(f,attr,1,false); CHECK(out.data);
        fail_at=calls+1; memset(&out,0xa5,sizeof(out));
        CHECK(matter_fabric_read_index(f->model,attr,1,false,&out)==MATTER_IM_RESOURCE_EXHAUSTED && !out.data && !out.size);
        fail_at=0; CHECK(!memcmp(saved,&f->view,sizeof(*saved))); read_value(f,attr,1,false);
    }
    /* Sign OOM must not invoke the backend or invalidate a borrowed read. */
    Matter_Im_Value_T out=read_value(f,0,1,false); memcpy(f->saved,out.data,out.size); f->saved_size=out.size; f->held=out.data;
    for(unsigned index=1;index<=2;++index) {
        unsigned signs=f->signs; uint8_t target; f->request[3]=(uint8_t)index;
        memset(f->signature,0xa5,64); fail_at=calls+1;
        CHECK(matter_fabric_vid(f->model,1,13,f->request,40,f->challenge,&target,f->signature)==MATTER_IM_RESOURCE_EXHAUSTED);
        fail_at=0; CHECK(f->signs==signs && !memcmp(saved,&f->view,sizeof(*saved)) && !memcmp(f->held,f->saved,f->saved_size));
        for(unsigned i=0;i<64;++i) CHECK(!f->signature[i]);
    }
    free(saved);
}
#endif
int main(void) {
#ifdef MATTER_TEST_ALLOC
    Fixture* empty=calloc(1,sizeof(*empty)); CHECK(empty);
    Matter_Fabric_Port_T p={.user=empty,.view=view,.root=root,.install=install,.rollback=rollback};
    fail_at=calls+1; CHECK(!matter_fabric_new(&p)); fail_at=0; free(empty);
#endif
    Fixture* f=create(); populate(f); lists(f); signing(f); bounds(f);
    f->guard=true; Matter_Im_Value_T direct;
    CHECK(!matter_fabric_read(f->model,5,91,true,&direct) && direct.unsigned_value==2); f->guard=false;
#ifdef MATTER_TEST_ALLOC
    oom(f); CHECK(live==2 && live_bytes<4096); /* Model plus one exact-sized value. */
#endif
    Fixture* second=create(); populate(second); Matter_Im_Value_T out=read_value(second,4,0,false);
    memcpy(second->saved,out.data,out.size); second->saved_size=out.size;
    read_value(f,3,0,false); CHECK(!memcmp(second->saved,out.data,out.size));
    CHECK(f->reentries && f->signs==4); destroy(f); destroy(second);
#ifdef MATTER_TEST_ALLOC
    CHECK(!live && !live_bytes && wiped); printf("PASS exact Fabric allocation, OOM, secure wipe: peak=%zu max=%zu wipes=%u\n",peak_bytes,max_request,wiped);
#endif
    puts("PASS Fabric certificates/filter/order/roots, TLV boundary, VID lifetime, reentry and independent owners"); return 0;
}

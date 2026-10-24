#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "clusters/matter_diagnostics.h"
#include "model/matter_im_subscribe.h"
#define CHECK(c) do { if(!(c)) { fprintf(stderr,"Diagnostics reports:%d: %s\n",__LINE__,#c); abort(); } } while(0)
#ifdef MATTER_TEST_ALLOC
#include "test_alloc_bytes.h"
#endif
/* Provider output, expected bytes, parsers and held packets all live on heap. */
typedef struct {
    Matter_Diagnostics_Snapshot_T backend;
    Matter_Diagnostics_T model;
    Matter_Im_Read_T read; Matter_Im_Subscribe_T sub;
    Matter_Tlv_Reader_T reader; Matter_Tlv_Element_T element;
    Matter_Rx_Decision_T rx;
    uint8_t expected[4096],held[384]; size_t starts[8],sizes[8];
    unsigned seen[2],replaces[2],adds[2],reads,releases;
    bool fail_encoded; uint64_t clock;
} Reports;
static const uint8_t read_request[]={0x15,0x36,0,0x17,0x24,2,0,0x24,3,0x33,0x24,4,0,0x18,0x18,0x29,3,0x24,255,13,0x18};
static const uint8_t sub_request[]={0x15,0x29,0,0x24,1,2,0x24,2,5,0x36,3,0x17,0x24,2,0,0x24,3,0x33,0x24,4,0,0x18,0x18,0x29,7,0x24,255,13,0x18};
static const uint8_t success[]={0x15,0x24,0,0,0x24,255,13,0x18};
static Matter_Result_T snapshot(void* u,Matter_Diagnostics_Snapshot_T* out) { *out=((Reports*)u)->backend; return MATTER_OK; }
static Matter_Result_T reset(void* u) { (void)u; return MATTER_OK; }
static Matter_Im_Status_T allow(void* u,Matter_Exchange_Session_T session,const Matter_Im_Path_T* path,Matter_Im_Privilege_T privilege) {
    (void)u; CHECK(session==1 && !path->endpoint && path->cluster==0x33 && !path->attribute && privilege==MATTER_IM_VIEW); return 0;
}
static Matter_Im_Status_T describe(void* u,const Matter_Im_Path_T* path,Matter_Im_Attribute_T* access) {
    (void)u; CHECK(!path->attribute); *access=(Matter_Im_Attribute_T){MATTER_IM_VIEW,false}; return 0;
}
static Matter_Im_Status_T read_value(void* u,const Matter_Im_Path_T* path,bool filtered,Matter_Im_Value_T* value) {
    Reports* f=u; CHECK(filtered); ++f->reads;
#ifdef MATTER_TEST_ALLOC
    if(f->fail_encoded) fail_at=calls+1;
#endif
    uint8_t result=matter_diagnostics_read(f->model,path->cluster,path->attribute,1,value);
#ifdef MATTER_TEST_ALLOC
    fail_at=0;
    CHECK(result==(f->fail_encoded?MATTER_IM_RESOURCE_EXHAUSTED:0));
#endif
    return (Matter_Im_Status_T)result;
}
static uint8_t reserve(void* u,Matter_Exchange_Session_T session,bool keep,uint32_t* id) {
    (void)u; CHECK(session==1 && keep); *id=42; return 0;
}
static void release(void* u,uint32_t id) { Reports* f=u; CHECK(id==42 && !f->releases++); }
static void receive(Reports* f,unsigned which,uint8_t opcode,const uint8_t* data,size_t size) {
    f->rx=(Matter_Rx_Decision_T){.action=MATTER_RX_EXISTING,.session=1,
        .header={.protocol_id=1,.opcode=opcode,.exchange_id=(uint16_t)(12+which),.exchange_flags=1},.payload=data,.payload_size=size};
    CHECK(!(which?matter_im_subscribe_receive(f->sub,&f->rx):matter_im_read_receive(f->read,&f->rx)));
}
static void process(Reports* f,unsigned which) {
    CHECK((which?matter_im_subscribe_process(f->sub,++f->clock):matter_im_read_process(f->read,++f->clock))==MATTER_PENDING);
}
static Matter_Im_Read_Message_T output(Reports* f,unsigned which) {
    Matter_Im_Read_Message_T out; process(f,which);
    CHECK(!(which?matter_im_subscribe_output(f->sub,&out):matter_im_read_output(f->read,&out))); return out;
}
static Reports* create(void) {
    Reports* f=calloc(1,sizeof(*f)); CHECK(f); f->backend.general.interface_count=8;
    for(unsigned i=0;i<8;++i) {
        Matter_Diagnostics_Interface_T* a=&f->backend.general.interfaces[i];
        a->name_size=32; memset(a->name,'a'+i,32); a->type=1; a->reachable4=a->reachable6=-1;
        a->ipv4_count=4; a->ipv6_count=8;
        for(unsigned j=0;j<8;++j) { a->ipv6[j][0]=0xfe; a->ipv6[j][1]=0x80; a->ipv6[j][15]=(uint8_t)(8*i+j+1); }
    }
    Matter_Diagnostics_Port_T port={f,snapshot,reset}; f->model=matter_diagnostics_new(&port,7,9); CHECK(f->model);
    Matter_Im_Value_T v; CHECK(!matter_diagnostics_read(f->model,0x33,0,1,&v) && v.size>1500 && v.size<=sizeof(f->expected));
    memcpy(f->expected,v.data,v.size); CHECK(!matter_tlv_init(&f->reader,f->expected,v.size,4));
    CHECK(!matter_tlv_next(&f->reader,&f->element) && f->element.type==MATTER_TLV_ARRAY);
    for(unsigned i=0;i<8;++i) {
        CHECK(!matter_tlv_next(&f->reader,&f->element) && f->element.type==MATTER_TLV_STRUCTURE);
        f->starts[i]=f->element.offset; CHECK(!matter_tlv_skip_container(&f->reader)); f->sizes[i]=f->reader.offset-f->starts[i];
    }
    CHECK(!matter_diagnostics_read(f->model,0x33,1,1,&v));
    Matter_Im_Read_Port_T p={f,allow,describe,read_value,NULL,NULL};
    Matter_Im_Read_Config_T c={{1,12,false},30000,sizeof(f->held),true}; f->read=matter_im_read_new(&p,&c,0); CHECK(f->read);
    Matter_Im_Subscribe_Port_T sp={p,reserve,release}; c.exchange.exchange_id=13;
    f->sub=matter_im_subscribe_new(&sp,&c,0); CHECK(f->sub); return f;
}
static void destroy(Reports* f) {
    CHECK(!matter_im_read_delete(f->read) && !matter_im_subscribe_delete(f->sub) && !matter_diagnostics_delete(f->model)); free(f);
#ifdef MATTER_TEST_ALLOC
    CHECK(!live && !live_bytes);
#endif
}
static void change_provider(Reports* f) {
    ++f->backend.general.system_ms;
    for(unsigned i=0;i<8;++i) { f->backend.general.interfaces[i].name[0]=(uint8_t)('z'-i); ++f->backend.general.interfaces[i].ipv6[0][15]; }
    CHECK(!matter_diagnostics_refresh(f->model)); Matter_Im_Value_T v;
    CHECK(!matter_diagnostics_read(f->model,0x33,0,1,&v));
    CHECK(!matter_diagnostics_read(f->model,0x36,0,1,&v)); /* Free encoding through the sibling. */
}
static bool report(Reports* f,unsigned which,Matter_Im_Read_Message_T out) {
    CHECK(out.opcode==5 && out.size<=sizeof(f->held)); memcpy(f->held,out.data,out.size);
    change_provider(f); CHECK(!memcmp(f->held,out.data,out.size));
    CHECK(!matter_tlv_init(&f->reader,out.data,out.size,8)); unsigned depth=0; bool more=false,append=false; Matter_Tlv_Result_T r;
    while((r=matter_tlv_next(&f->reader,&f->element))==MATTER_TLV_OK) {
        Matter_Tlv_Element_T* e=&f->element;
        if(e->type==MATTER_TLV_END) { CHECK(depth); --depth; continue; }
        if(depth==1 && e->tag.number==3) more=e->unsigned_value!=0;
        if(depth==4 && e->tag.number==0) CHECK(e->type==MATTER_TLV_UNSIGNED && e->unsigned_value==7);
        if(depth==4 && e->tag.number==1) append=false;
        if(depth==5 && e->tag.number==5) { CHECK(e->type==MATTER_TLV_NULL); append=true; }
        if(depth==4 && e->tag.number==2 && e->type==MATTER_TLV_ARRAY) { CHECK(!append && !f->replaces[which]++); }
        if(e->type==MATTER_TLV_STRUCTURE && ((depth==5 && !e->tag.control) || (depth==4 && e->tag.control==1 && e->tag.number==2))) {
            unsigned n=f->seen[which]++; CHECK(n<8 && f->replaces[which]==1); size_t start=e->offset,header=depth==4?2:1;
            if(depth==4) { CHECK(append); ++f->adds[which]; }
            CHECK(!matter_tlv_skip_container(&f->reader) && f->reader.offset-start==f->sizes[n]+header-1);
            CHECK(!memcmp(out.data+start+header,f->expected+f->starts[n]+1,f->sizes[n]-1)); continue;
        }
        if(e->type==MATTER_TLV_STRUCTURE || e->type==MATTER_TLV_ARRAY || e->type==MATTER_TLV_LIST) ++depth;
    }
    CHECK(r==MATTER_TLV_DONE && !depth); return more;
}
static void ack(Reports* f,unsigned which,bool more,bool im_first) {
    CHECK(!(which?matter_im_subscribe_sent_at(f->sub,f->clock):matter_im_read_sent(f->read)));
    if((which || more) && im_first) { receive(f,which,1,success,sizeof(success)); process(f,which); }
    CHECK(!(which?matter_im_subscribe_confirm(f->sub,f->clock):matter_im_read_confirm(f->read,f->clock)));
    if((which || more) && !im_first) receive(f,which,1,success,sizeof(success));
}
static void stable(unsigned order) {
    Reports* f=create(); receive(f,0,2,read_request,sizeof(read_request)); receive(f,1,3,sub_request,sizeof(sub_request));
    Matter_Im_Read_Message_T first=output(f,0),second=output(f,1); CHECK(f->reads==2);
    for(unsigned which=0;which<2;++which) {
        Matter_Im_Read_Message_T out=which?second:first; unsigned chunks=0; bool more;
        do { more=report(f,which,out); ack(f,which,more,(++chunks+order)%2!=0); if(more) out=output(f,which); } while(more);
        CHECK(chunks>1 && f->seen[which]==8 && f->replaces[which]==1 && f->adds[which] && f->reads==2);
    }
    CHECK(matter_im_read_state(f->read)==MATTER_IM_READ_COMPLETE);
    Matter_Im_Read_Message_T response=output(f,1); CHECK(response.opcode==4);
    CHECK(!matter_im_subscribe_sent_at(f->sub,f->clock) && !matter_im_subscribe_confirm(f->sub,f->clock));
    CHECK(matter_im_subscribe_state(f->sub)==MATTER_IM_SUB_IDLE); destroy(f);
}
#ifdef MATTER_TEST_ALLOC
static void oom(void) {
    Reports* f=create(); f->fail_encoded=true;
    receive(f,0,2,read_request,sizeof(read_request)); receive(f,1,3,sub_request,sizeof(sub_request));
    Matter_Im_Read_Message_T r=output(f,0),s=output(f,1);
    /* Preserve the existing IM provider-error policy: Read path Failure;
     * a failed sole priming path leaves Subscribe with no active path. */
    CHECK(r.opcode==5 && s.opcode==1 && s.data[3]==MATTER_IM_INVALID_ACTION);
    CHECK(!matter_tlv_init(&f->reader,r.data,r.size,8)); unsigned errors=0;
    while(matter_tlv_next(&f->reader,&f->element)==MATTER_TLV_OK)
        if(f->element.type==MATTER_TLV_UNSIGNED && f->element.tag.number==0 && f->element.unsigned_value==MATTER_IM_FAILURE) ++errors;
    CHECK(errors==1 && f->reads==2); destroy(f);
}
#endif
int main(void) {
    stable(0); stable(1);
#ifdef MATTER_TEST_ALLOC
    oom();
#endif
    puts("PASS Diagnostics reports: two concurrent Read/Subscribe snapshots, max8-interface ARRAY, repeated refresh/free/reencode before ACK, immutable bytes/version, both IM/MRP orders and provider OOM cleanup"); return 0;
}

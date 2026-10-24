#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "clusters/matter_acl.h"
#include "model/matter_im_subscribe.h"
#include "test_acl_wire.h"
#define CHECK(c) do { if(!(c)) { fprintf(stderr,"ACL reports:%d: %s\n",__LINE__,#c); abort(); } } while(0)
#ifdef MATTER_TEST_ALLOC
#include "test_alloc_bytes.h"
#endif
typedef struct Reports Reports;
typedef struct { Reports* owner; unsigned which; } Binding;
/* All large views, expected values, request scratch and parsers are heap-owned. */
struct Reports {
    Matter_Acl_View_T backend; Matter_Acl_T model; Binding bindings[2]; AclWire wire;
    Matter_Im_Read_T read; Matter_Im_Subscribe_T sub;
    Matter_Tlv_Reader_T reader; Matter_Tlv_Element_T element; Matter_Rx_Decision_T rx;
    uint8_t expected[2][4096],held[256]; size_t starts[2][20],sizes[2][20];
    unsigned seen[2],replaces[2],adds[2],reads[2],releases,changes;
    bool fail_encoded; uint64_t clock;
};
static const uint8_t read_request[]={0x15,0x36,0,0x17,0x24,2,0,0x24,3,0x1f,0x24,4,0,0x18,0x18,0x28,3,0x24,255,13,0x18};
static const uint8_t sub_request[]={0x15,0x29,0,0x24,1,2,0x24,2,5,0x36,3,0x17,0x24,2,0,0x24,3,0x1f,0x24,4,0,0x18,0x18,0x29,7,0x24,255,13,0x18};
static const uint8_t success[]={0x15,0x24,0,0,0x24,255,13,0x18};
static const Matter_Acl_View_T* view(void* u) { return &((Reports*)u)->backend; }
static uint8_t store(void* u,uint8_t index,const Matter_Acl_Entry_T* entries,size_t count) {
    Reports* f=u; CHECK(index && index<=5 && count<=4);
    Matter_Acl_Fabric_T* a=&f->backend.fabrics[index-1];
    memset(a->entries,0,sizeof(a->entries)); memcpy(a->entries,entries,count*sizeof(*entries));
    a->count=(uint8_t)count; ++f->backend.version; return 0;
}
static Matter_Im_Status_T allow(void* u,Matter_Exchange_Session_T session,const Matter_Im_Path_T* path,Matter_Im_Privilege_T privilege) {
    Binding* b=u; CHECK(session==b->which+1 && !path->endpoint && path->cluster==0x1f && !path->attribute &&
        (privilege==MATTER_IM_VIEW || privilege==MATTER_IM_ADMINISTER));
    return matter_acl_authorize(b->owner->model,(uint8_t)session,101,NULL,0,path,privilege,NULL)?0:MATTER_IM_UNSUPPORTED_ACCESS;
}
static Matter_Im_Status_T describe(void* u,const Matter_Im_Path_T* path,Matter_Im_Attribute_T* access) {
    Binding* b=u; return matter_cluster_describe(b->owner->model,path->attribute,access);
}
static Matter_Im_Status_T read_value(void* u,const Matter_Im_Path_T* path,bool filtered,Matter_Im_Value_T* value) {
    Binding* b=u; Reports* f=b->owner; CHECK(filtered==(b->which==1)); ++f->reads[b->which];
#ifdef MATTER_TEST_ALLOC
    if(f->fail_encoded) fail_at=calls+1;
#endif
    uint8_t result=matter_acl_read(f->model,path->attribute,(uint8_t)(b->which+1),filtered,value);
#ifdef MATTER_TEST_ALLOC
    fail_at=0; CHECK(result==(f->fail_encoded?MATTER_IM_RESOURCE_EXHAUSTED:0));
#endif
    return (Matter_Im_Status_T)result;
}
static uint8_t reserve(void* u,Matter_Exchange_Session_T session,bool keep,uint32_t* id) {
    Binding* b=u; CHECK(b->which==1 && session==2 && keep); *id=42; return 0;
}
static void release(void* u,uint32_t id) { Binding* b=u; CHECK(id==42 && !b->owner->releases++); }
static Matter_Result_T fabric_index(void* u,Matter_Exchange_Session_T session,uint8_t* index) {
    Binding* b=u; CHECK(session==b->which+1); *index=(uint8_t)session; return MATTER_OK;
}
static void receive(Reports* f,unsigned which,uint8_t opcode,const uint8_t* data,size_t size) {
    f->rx=(Matter_Rx_Decision_T){.action=MATTER_RX_EXISTING,.session=which+1,
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
static void capture(Reports* f,unsigned which) {
    Matter_Im_Value_T v; CHECK(!matter_acl_read(f->model,0,(uint8_t)(which+1),which==1,&v) && v.size<=4096);
    memcpy(f->expected[which],v.data,v.size); CHECK(!matter_tlv_init(&f->reader,f->expected[which],v.size,4));
    CHECK(!matter_tlv_next(&f->reader,&f->element) && f->element.type==MATTER_TLV_ARRAY);
    for(unsigned i=0;i<(which?4u:20u);++i) {
        CHECK(!matter_tlv_next(&f->reader,&f->element) && f->element.type==MATTER_TLV_STRUCTURE);
        f->starts[which][i]=f->element.offset; CHECK(!matter_tlv_skip_container(&f->reader));
        f->sizes[which][i]=f->reader.offset-f->starts[which][i];
        if(!which && i>=4) { /* Foreign fields must be omitted, even at maximum counts. */
            const uint8_t shell[]={0x15,0x24,254,(uint8_t)(i/4+1),0x18};
            CHECK(f->sizes[which][i]==sizeof(shell) && !memcmp(f->expected[which]+f->starts[which][i],shell,sizeof(shell)));
        }
    }
    CHECK(!matter_tlv_next(&f->reader,&f->element) && f->element.type==MATTER_TLV_END);
    CHECK(!matter_acl_read(f->model,2,0,true,&v));
}
static Reports* create(void) {
    Reports* f=calloc(1,sizeof(*f)); CHECK(f); f->backend.version=17;
    for(unsigned i=0;i<5;++i) {
        Matter_Acl_Fabric_T* fabric=&f->backend.fabrics[i]; fabric->index=(uint8_t)(i+1); fabric->count=4;
        for(unsigned j=0;j<4;++j) {
            Matter_Acl_Entry_T* a=&fabric->entries[j]; a->privilege=5; a->auth_mode=2; a->subject_count=4; a->target_count=3; a->subjects[0]=101;
            for(unsigned k=1;k<4;++k) a->subjects[k]=UINT64_C(0xffffffef00000001)+i*16+j*4+k;
            for(unsigned k=0;k<3;++k) a->targets[k]=(Matter_Acl_Target_T){.present=3,.cluster=k?0xfff4fc00u+k:0x1f,.endpoint=k?0xfffe:0};
        }
    }
    Matter_Acl_Port_T port={f,view,store}; f->model=matter_acl_new(&port); CHECK(f->model);
    for(unsigned which=0;which<2;++which) {
        capture(f,which); f->bindings[which]=(Binding){f,which};
        Matter_Im_Read_Port_T p={&f->bindings[which],allow,describe,read_value,NULL,NULL};
        Matter_Im_Read_Config_T c={{which+1,(uint16_t)(12+which),false},30000,sizeof(f->held),false};
        Matter_Im_Read_Fabric_Port_T resolver={fabric_index};
        if(which) { Matter_Im_Subscribe_Port_T sp={p,reserve,release}; f->sub=matter_im_subscribe_new_case(&sp,&resolver,&c,0); CHECK(f->sub); }
        else { f->read=matter_im_read_new_case(&p,&resolver,&c,0); CHECK(f->read); }
    }
    return f;
}
static void destroy(Reports* f) {
    CHECK(!matter_im_read_delete(f->read) && !matter_im_subscribe_delete(f->sub) && !matter_acl_delete(f->model)); free(f);
#ifdef MATTER_TEST_ALLOC
    CHECK(!live && !live_bytes);
#endif
}
static void change_provider(Reports* f) {
    aw_list(&f->wire,(++f->changes%2)!=0);
    CHECK(!matter_acl_write(f->model,1,MATTER_IM_LIST_REPLACE,f->wire.data,f->wire.size));
    Matter_Im_Value_T v; CHECK(!matter_acl_read(f->model,0,1,true,&v));
    CHECK(!matter_acl_write(f->model,1,MATTER_IM_LIST_REPLACE,v.data,v.size)); /* Read-to-write alias. */
    CHECK(!matter_acl_read(f->model,2,0,true,&v)); /* End the provider borrow. */
}
static bool report(Reports* f,unsigned which,Matter_Im_Read_Message_T out) {
    CHECK(out.opcode==5 && out.size<=sizeof(f->held)); memcpy(f->held,out.data,out.size);
    change_provider(f); CHECK(!memcmp(f->held,out.data,out.size));
    CHECK(!matter_tlv_init(&f->reader,out.data,out.size,8)); unsigned depth=0; bool more=false,append=false; Matter_Tlv_Result_T r;
    while((r=matter_tlv_next(&f->reader,&f->element))==MATTER_TLV_OK) {
        Matter_Tlv_Element_T* e=&f->element;
        if(e->type==MATTER_TLV_END) { CHECK(depth); --depth; continue; }
        if(depth==1 && e->tag.number==3) more=e->unsigned_value!=0;
        if(depth==4 && e->tag.number==0) CHECK(e->type==MATTER_TLV_UNSIGNED && e->unsigned_value==17);
        if(depth==4 && e->tag.number==1) append=false;
        if(depth==5 && e->tag.number==5) { CHECK(e->type==MATTER_TLV_NULL); append=true; }
        if(depth==4 && e->tag.number==2 && e->type==MATTER_TLV_ARRAY) { CHECK(!append && !f->replaces[which]++); }
        if(e->type==MATTER_TLV_STRUCTURE && ((depth==5 && !e->tag.control) || (depth==4 && e->tag.control==1 && e->tag.number==2))) {
            unsigned n=f->seen[which]++; CHECK(n<(which?4u:20u) && f->replaces[which]==1);
            size_t start=e->offset,header=depth==4?2:1;
            if(depth==4) { CHECK(append); ++f->adds[which]; }
            CHECK(!matter_tlv_skip_container(&f->reader) && f->reader.offset-start==f->sizes[which][n]+header-1);
            CHECK(!memcmp(out.data+start+header,f->expected[which]+f->starts[which][n]+1,f->sizes[which][n]-1)); continue;
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
    Matter_Im_Read_Message_T first=output(f,0),second=output(f,1); CHECK(f->reads[0]==1 && f->reads[1]==1);
    for(unsigned which=0;which<2;++which) {
        Matter_Im_Read_Message_T out=which?second:first; unsigned chunks=0; bool more;
        do { more=report(f,which,out); ack(f,which,more,(++chunks+order)%2!=0); if(more) out=output(f,which); } while(more);
        CHECK(chunks>1 && f->seen[which]==(which?4u:20u) && f->replaces[which]==1 && f->adds[which] && f->reads[which]==1);
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
    CHECK(r.opcode==5 && s.opcode==1 && s.data[3]==MATTER_IM_INVALID_ACTION);
    CHECK(!matter_tlv_init(&f->reader,r.data,r.size,8)); unsigned errors=0;
    while(matter_tlv_next(&f->reader,&f->element)==MATTER_TLV_OK)
        if(f->element.type==MATTER_TLV_UNSIGNED && f->element.tag.number==0 && f->element.unsigned_value==MATTER_IM_FAILURE) ++errors;
    CHECK(errors==1 && f->reads[0]==1 && f->reads[1]==1 && f->backend.version==17); destroy(f);
}
#endif
int main(void) {
    stable(0); stable(1);
#ifdef MATTER_TEST_ALLOC
    oom();
#endif
    puts("PASS ACL reports: five fabrics/max entries, real authorization, filtered/unfiltered privacy, concurrent multipart Read/Subscribe, write/free/reencode before ACK, immutable bytes/version, both IM/MRP orders and provider OOM cleanup"); return 0;
}

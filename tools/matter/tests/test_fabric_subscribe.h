#include "model/matter_im_subscribe.h"
typedef struct {
    FabFixture* fabric; Matter_Im_Subscribe_T sub;
    uint8_t index; bool filtered,denied; uint16_t exchange; uint64_t now;
    uint8_t expected[2][4096],actual[2][4096]; size_t sizes[2];
    Matter_Tlv_Writer_T writers[2]; Matter_Tlv_Reader_T reader; Matter_Tlv_Element_T token;
    uint32_t version; unsigned reads,parts,releases; bool replaced[2];
} FabricSub;
static Matter_Result_T fs_index(void* u,Matter_Exchange_Session_T session,uint8_t* index) {
    FabricSub* s=u; OC_CHECK(session==1); *index=s->index; return MATTER_OK;
}
static Matter_Im_Status_T fs_allow(void* u,Matter_Exchange_Session_T session,const Matter_Im_Path_T* p,Matter_Im_Privilege_T privilege) {
    FabricSub* s=u; OC_CHECK(session==1 && !p->endpoint && p->cluster==0x3e && p->attribute<2);
    OC_CHECK(privilege==MATTER_IM_VIEW || (!p->attribute && privilege==MATTER_IM_ADMINISTER));
    return s->denied?MATTER_IM_UNSUPPORTED_ACCESS:0;
}
static Matter_Im_Status_T fs_describe(void* u,const Matter_Im_Path_T* p,Matter_Im_Attribute_T* a) {
    FabricSub* s=u; return matter_cluster_describe(s->fabric->o->core,p->attribute,a);
}
static Matter_Im_Status_T fs_read(void* u,const Matter_Im_Path_T* p,bool filtered,Matter_Im_Value_T* v) {
    FabricSub* s=u; OC_CHECK(filtered==s->filtered); ++s->reads;
    return matter_opcreds_read_fabric(s->fabric->o->core,p->attribute,s->index,filtered,v);
}
static uint8_t fs_reserve(void* u,Matter_Exchange_Session_T session,bool keep,uint32_t* id) {
    (void)u; OC_CHECK(session==1 && keep); *id=12; return 0;
}
static void fs_release(void* u,uint32_t id) { FabricSub* s=u; OC_CHECK(id==12 && !s->releases++); }
static void fs_rx(FabricSub* s,uint8_t opcode,const uint8_t* data,size_t size) {
    Matter_Rx_Decision_T d={.session=1,.action=MATTER_RX_EXISTING,.payload=data,.payload_size=size,
        .header={.exchange_id=s->exchange,.protocol_id=1,.opcode=opcode,.exchange_flags=s->exchange==12?MATTER_PROTOCOL_INITIATOR:0}};
    OC_CHECK(matter_im_subscribe_receive(s->sub,&d)==MATTER_OK);
}
static void fs_expected(FabricSub* s) {
    for(unsigned i=0;i<2;++i) {
        Matter_Im_Value_T v; OC_CHECK(!matter_opcreds_read_fabric(s->fabric->o->core,i,s->index,s->filtered,&v));
        OC_CHECK(v.size<=sizeof(s->expected[i])); memcpy(s->expected[i],v.data,v.size); s->sizes[i]=v.size; s->version=v.data_version;
        s->replaced[i]=false;
    }
}
static FabricSub* fs_new(FabFixture* f,bool filtered) {
    FabricSub* s=calloc(1,sizeof(*s)); OC_CHECK(s); s->fabric=f; s->index=1; s->filtered=filtered; s->exchange=12;
    Matter_Im_Subscribe_Port_T p={{s,fs_allow,fs_describe,fs_read,NULL,NULL},fs_reserve,fs_release};
    Matter_Im_Read_Fabric_Port_T fp={fs_index}; Matter_Im_Subscribe_Config_T c={{1,12,false},30000,800,false};
    s->sub=matter_im_subscribe_new_case(&p,&fp,&c,0); OC_CHECK(s->sub); fs_expected(s);
    static const uint8_t request[]={0x15,0x29,0,0x24,1,0,0x24,2,5,0x36,3,
        0x17,0x24,2,0,0x24,3,0x3e,0x24,4,0,0x18,0x17,0x24,2,0,0x24,3,0x3e,0x24,4,1,0x18,0x18,
        0x29,7,0x24,255,13,0x18};
    memcpy(f->wire,request,sizeof(request)); f->wire[sizeof(request)-6]=filtered?0x29:0x28;
    fs_rx(s,3,f->wire,sizeof(request)); return s;
}
static void fs_report(FabricSub* s,bool prime) {
    static const uint8_t success[]={0x15,0x24,0,0,0x24,255,13,0x18};
    bool more;
    do {
        OC_CHECK(matter_im_subscribe_process(s->sub,s->now)==MATTER_PENDING);
        Matter_Im_Subscribe_Message_T out; OC_CHECK(!matter_im_subscribe_output(s->sub,&out) && out.opcode==5);
        OC_CHECK(!matter_tlv_init(&s->reader,out.data,out.size,8)); unsigned depth=0,attr=0; bool append=false; more=false; ++s->parts;
        while(matter_tlv_next(&s->reader,&s->token)==MATTER_TLV_OK) {
            Matter_Tlv_Element_T* e=&s->token;
            if(e->type==MATTER_TLV_END) { --depth; continue; }
            if(depth==1 && e->tag.number==3) more=e->unsigned_value!=0;
            if(depth==4 && e->tag.number==0) OC_CHECK(e->unsigned_value==s->version);
            if(depth==4 && e->tag.number==1) append=false;
            if(depth==5 && e->tag.number==4) { OC_CHECK(e->unsigned_value<2); attr=(unsigned)e->unsigned_value; }
            if(depth==5 && e->tag.number==5) { OC_CHECK(e->type==MATTER_TLV_NULL); append=true; }
            if(depth==4 && e->tag.number==2) {
                if(!append) {
                    OC_CHECK(!s->replaced[attr] && e->type==MATTER_TLV_ARRAY); s->replaced[attr]=true;
                    OC_CHECK(!matter_tlv_writer_init(&s->writers[attr],s->actual[attr],4096,4));
                } else OC_CHECK(s->replaced[attr] && e->type==MATTER_TLV_STRUCTURE);
                e->tag=(Matter_Tlv_Tag_T){0}; OC_CHECK(!matter_tlv_write(&s->writers[attr],e,0));
                unsigned nesting=1;
                while(nesting) {
                    OC_CHECK(!matter_tlv_next(&s->reader,e));
                    if(e->type==MATTER_TLV_END) --nesting;
                    else if(e->type==MATTER_TLV_STRUCTURE || e->type==MATTER_TLV_ARRAY || e->type==MATTER_TLV_LIST) ++nesting;
                    if(nesting || append) OC_CHECK(!matter_tlv_write(&s->writers[attr],e,0));
                }
                continue;
            }
            if(e->type==MATTER_TLV_STRUCTURE || e->type==MATTER_TLV_ARRAY || e->type==MATTER_TLV_LIST) ++depth;
        }
        OC_CHECK(!depth && !matter_im_subscribe_sent_at(s->sub,s->now) && !matter_im_subscribe_confirm(s->sub,s->now));
        fs_rx(s,1,success,sizeof(success));
    } while(more);
    for(unsigned i=0;i<2;++i) {
        size_t size; s->token=(Matter_Tlv_Element_T){.type=MATTER_TLV_END};
        OC_CHECK(s->replaced[i] && !matter_tlv_write(&s->writers[i],&s->token,0) && !matter_tlv_writer_finish(&s->writers[i],&size));
        OC_CHECK(size==s->sizes[i] && !memcmp(s->expected[i],s->actual[i],size));
    }
    OC_CHECK(matter_im_subscribe_process(s->sub,s->now)==MATTER_PENDING);
    if(prime) {
        Matter_Im_Subscribe_Message_T out; OC_CHECK(!matter_im_subscribe_output(s->sub,&out) && out.opcode==4);
        OC_CHECK(!matter_im_subscribe_sent_at(s->sub,s->now) && !matter_im_subscribe_confirm(s->sub,s->now));
    }
    OC_CHECK(matter_im_subscribe_state(s->sub)==MATTER_IM_SUB_IDLE);
}
static void fs_update(FabricSub* s) {
    fs_expected(s); ++s->now; OC_CHECK(!matter_im_subscribe_changed(s->sub));
    OC_CHECK(matter_im_subscribe_process(s->sub,s->now)==MATTER_PENDING && matter_im_subscribe_state(s->sub)==MATTER_IM_SUB_NEED_EXCHANGE);
    Matter_Exchange_Info_T e={1,++s->exchange,true}; OC_CHECK(!matter_im_subscribe_bind_report(s->sub,&e,s->now)); fs_report(s,false);
}
static void fabric_subscriptions(FabFixture* f) {
    /* Five real records force multipart NOCs; exact reassembly also tests that
     * the provider's shared encoding arena cannot corrupt the previous path. */
    for(unsigned filter=0;filter<2;++filter) {
        FabricSub* s=fs_new(f,filter!=0); fs_report(s,true); OC_CHECK(s->reads==2 && (filter || s->parts>1));
        vid_request(f,3,0x6a03,85,0); vid_call(f,1,12,0); fs_update(s); OC_CHECK(s->reads==4);
        vid_request(f,3,0xfff1,0,0); vid_call(f,1,12,0); fs_update(s); OC_CHECK(s->reads==6);
        OC_CHECK(!matter_im_subscribe_delete(s->sub) && s->releases==1); free(s);
    }
    puts("PASS OPCREDS subscriptions: exact Fabrics/NOCs reassembly, five fabrics, filtered/unfiltered, shared scratch, VID update/erase and versions");
}

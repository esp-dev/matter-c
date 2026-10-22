/* Wire-level list reassembly oracle: REPLACE clears, null-index ADD appends.
 * All buffers belong to this heap fixture, including the shared provider scratch. */
typedef struct {
    RichSub rich;
    unsigned entries,bytes,base,expected_base,seen[2],replaces[2],adds[2];
    bool deny,filtered,wrong_type,short_list;
} ListSub;
static Matter_Im_Status_T list_allow(void* u,Matter_Exchange_Session_T token,const Matter_Im_Path_T* p,Matter_Im_Privilege_T privilege) {
    ListSub* l=u; sub_guard(&l->rich.model);
    CHECK(token==1 && p->endpoint==1 && p->cluster==0x91 && (privilege==MATTER_IM_VIEW || privilege==MATTER_IM_ADMINISTER));
    ++l->rich.model.auths; return l->deny?MATTER_IM_UNSUPPORTED_ACCESS:0;
}
static Matter_Im_Status_T list_describe(void* u,const Matter_Im_Path_T* p,Matter_Im_Attribute_T* a) {
    ListSub* l=u; sub_guard(&l->rich.model); CHECK(p->attribute==1 || p->attribute==2);
    *a=(Matter_Im_Attribute_T){p->attribute==1?MATTER_IM_VIEW:MATTER_IM_ADMINISTER,true}; return 0;
}
static Matter_Im_Status_T list_read(void* u,const Matter_Im_Path_T* p,bool filtered,Matter_Im_Value_T* v) {
    ListSub* l=u; RichSub* r=&l->rich; sub_guard(&r->model); ++r->model.reads; CHECK(filtered==l->filtered);
    CHECK(matter_tlv_writer_init(&r->writer,r->scratch,sizeof(r->scratch),4)==MATTER_TLV_OK);
    rich_put(r,MATTER_TLV_ARRAY,-1,0);
    for(unsigned i=0;i<l->entries;++i) {
        if(l->short_list) { rich_put(r,MATTER_TLV_UNSIGNED,-1,l->base+10*p->attribute+i); continue; }
        rich_put(r,MATTER_TLV_STRUCTURE,-1,0); rich_put(r,MATTER_TLV_UNSIGNED,0,l->base+10*p->attribute+i);
        /* Request input is no longer borrowed once receive() has copied it. */
        memset(r->model.input,(int)(l->base+i),l->bytes);
        r->token=(Matter_Tlv_Element_T){.type=MATTER_TLV_BYTES,.tag={.control=1,.number=1},.data=r->model.input,.size=l->bytes};
        CHECK(matter_tlv_write(&r->writer,&r->token,0)==MATTER_TLV_OK); rich_put(r,MATTER_TLV_END,-1,0);
    }
    rich_put(r,MATTER_TLV_END,-1,0); size_t size;
    CHECK(matter_tlv_writer_finish(&r->writer,&size)==MATTER_TLV_OK);
    if(r->malformed) --size;
    *v=(Matter_Im_Value_T){.type=l->wrong_type?MATTER_TLV_STRUCTURE:MATTER_TLV_ARRAY,
        .data=r->scratch,.size=size,.data_version=r->model.version}; return 0;
}
static ListSub* list_new(size_t cap,unsigned entries,unsigned bytes) {
    ListSub* l=calloc(1,sizeof(*l)); CHECK(l); RichSub* r=&l->rich;
    l->entries=entries; l->bytes=bytes; l->filtered=true; r->fabric=1; r->expected_version=7;
    Matter_Im_Subscribe_Port_T p=sub_port(&r->model);
    p.attributes.authorize=list_allow; p.attributes.describe=list_describe; p.attributes.read=list_read;
    Matter_Im_Read_Fabric_Port_T fp={rich_fabric}; Matter_Im_Subscribe_Config_T c={{1,12,false},30000,cap,false};
    r->model.active=matter_im_subscribe_new_case(&p,&fp,&c,0); CHECK(r->model.active); return l;
}
static bool list_report(ListSub* l,Matter_Im_Subscribe_Message_T out) {
    RichSub* r=&l->rich; CHECK(out.opcode==5 && matter_tlv_init(&r->reader,out.data,out.size,8)==MATTER_TLV_OK);
    unsigned depth=0,attr=0; bool more=false,append=false; Matter_Tlv_Result_T result;
    while((result=matter_tlv_next(&r->reader,&r->token))==MATTER_TLV_OK) {
        Matter_Tlv_Element_T* e=&r->token;
        if(e->type==MATTER_TLV_END) { CHECK(depth); --depth; continue; }
        if(depth==1 && e->tag.number==0) CHECK(e->unsigned_value==42);
        if(depth==1 && e->tag.number==3) more=e->unsigned_value!=0;
        if(depth==1 && e->tag.number==4) CHECK(!e->unsigned_value);
        if(depth==4 && e->tag.number==0) CHECK(e->unsigned_value==r->expected_version);
        if(depth==4 && e->tag.number==1) append=false;
        if(depth==5 && e->tag.number==4) { CHECK(e->unsigned_value==1 || e->unsigned_value==2); attr=(unsigned)e->unsigned_value-1; }
        if(depth==5 && e->tag.number==5) { CHECK(e->type==MATTER_TLV_NULL); append=true; }
        if(depth==4 && e->tag.number==2) {
            if(append) { CHECK(e->type==(l->short_list?MATTER_TLV_UNSIGNED:MATTER_TLV_STRUCTURE) && l->replaces[attr]==1); ++l->adds[attr]; }
            else { CHECK(e->type==MATTER_TLV_ARRAY && !l->replaces[attr]); ++l->replaces[attr]; l->seen[attr]=0; }
        }
        if(l->short_list && e->type==MATTER_TLV_UNSIGNED && ((!e->tag.control && depth==5) || (depth==4 && e->tag.number==2))) {
            CHECK(e->unsigned_value==l->expected_base+10*(attr+1)+l->seen[attr]); ++l->seen[attr];
        }
        if(depth==(append?5u:6u) && e->tag.number==0) {
            CHECK(e->type==MATTER_TLV_UNSIGNED && e->unsigned_value==l->expected_base+10*(attr+1)+l->seen[attr]);
        }
        if(depth==(append?5u:6u) && e->tag.number==1) {
            CHECK(e->type==MATTER_TLV_BYTES && e->size==l->bytes);
            for(size_t i=0;i<e->size;++i) CHECK(e->data[i]==l->expected_base+l->seen[attr]);
            ++l->seen[attr];
        }
        if(e->type==MATTER_TLV_STRUCTURE || e->type==MATTER_TLV_ARRAY || e->type==MATTER_TLV_LIST) ++depth;
    }
    CHECK(result==MATTER_TLV_DONE && !depth); return more;
}
static void list_start(ListSub* l,unsigned paths) {
    RichSub* r=&l->rich; rich_request(r,paths,false,false,0);
    r->model.input[r->size-6]=l->filtered?0x29:0x28;
    receive(&r->model,r->model.input,r->size,3,12,true);
}
static void list_tests(void) {
    unsigned short_adds=0;
    for(size_t cap=40;cap<=48;++cap) {
        ListSub* tiny=list_new(cap,3,0); tiny->short_list=true; list_start(tiny,1);
        bool more; unsigned chunks=0;
        do {
            more=list_report(tiny,output(&tiny->rich.model,0)); CHECK(++chunks<8);
            memset(tiny->rich.scratch,0xff,sizeof(tiny->rich.scratch));
            rich_ack(&tiny->rich,true,chunks%2!=0);
        } while(more);
        CHECK(tiny->seen[0]==3 && tiny->rich.model.reads==1); short_adds+=tiny->adds[0];
        rich_prime_finish(&tiny->rich); rich_free(&tiny->rich);
    }
    CHECK(short_adds);
    /* Empty/whole/prefix lists, multiple paths sharing scratch, exact capacity
     * boundaries and multiple ADD IBs packed together. Alternate ACK ordering. */
    for(unsigned entries=0;entries<=12;entries+=6) for(size_t cap=50;cap<=180;++cap) {
        ListSub* l=list_new(cap,entries,2); RichSub* r=&l->rich; list_start(l,2);
        unsigned chunks=0; bool more;
        do {
            Matter_Im_Subscribe_Message_T out=output(&r->model,0);
            more=list_report(l,out); CHECK(++chunks<32 && out.size<=cap);
            memset(r->scratch,0,sizeof(r->scratch)); rich_ack(r,true,chunks%2!=0);
        } while(more);
        CHECK(l->seen[0]==entries && l->seen[1]==entries && l->replaces[0]==1 && l->replaces[1]==1 && r->model.reads==2);
        rich_prime_finish(r); rich_free(r);
    }
    /* Dirty during multipart TX is retained; all old chunks keep old version and
     * contents. New report starts with REPLACE, not continuation of the old list. */
    ListSub* l=list_new(80,12,2); RichSub* r=&l->rich; l->filtered=false; list_start(l,2);
    CHECK(list_report(l,output(&r->model,0))); l->base=40; ++r->model.version;
    CHECK(matter_im_subscribe_changed(r->model.active)==MATTER_OK); rich_ack(r,true,false);
    bool more;
    do { more=list_report(l,output(&r->model,0)); rich_ack(r,true,true); } while(more);
    CHECK(l->seen[0]==12 && l->seen[1]==12 && r->model.reads==2); rich_prime_finish(r);
    CHECK(matter_im_subscribe_process(r->model.active,1999)==MATTER_PENDING && matter_im_subscribe_state(r->model.active)==MATTER_IM_SUB_IDLE);
    rich_update(r,2000); l->expected_base=40; r->expected_version=8;
    memset(l->replaces,0,sizeof(l->replaces)); memset(l->adds,0,sizeof(l->adds));
    do { more=list_report(l,output(&r->model,2000)); rich_ack(r,false,false); } while(more);
    CHECK(l->seen[0]==12 && l->seen[1]==12 && r->model.reads==4);
    CHECK(matter_im_subscribe_process(r->model.active,2000)==MATTER_PENDING);
    /* Unchanged max heartbeat carries no stale ARRAY and does not call read. */
    CHECK(matter_im_subscribe_process(r->model.active,7000)==MATTER_PENDING);
    Matter_Exchange_Info_T e={1,14,true}; CHECK(matter_im_subscribe_bind_report(r->model.active,&e,7000)==MATTER_OK);
    literal(output(&r->model,7000),5,sub_empty,sizeof(sub_empty)); CHECK(r->model.reads==4); rich_free(r);
    /* Revoke inside a list, including live fabric identity changes. Status has no
     * ListIndex and no unsent data; both transport gates precede terminal release. */
    for(unsigned mode=0;mode<3;++mode) {
        l=list_new(80,12,2); r=&l->rich; list_start(l,1); CHECK(list_report(l,output(&r->model,0)));
        if(!mode) l->deny=true; else r->fabric=mode==1?2:0;
        rich_ack(r,true,true); CHECK(!rich_report(r,output(&r->model,0)) && r->seen_status==1);
        rich_ack(r,true,false); CHECK(matter_im_subscribe_process(r->model.active,0)==MATTER_PORT_ERROR && r->model.releases==1 && r->model.reads==1); rich_free(r);
    }
    /* An oversized single item permits empty REPLACE but cannot be byte-split. */
    l=list_new(60,1,100); r=&l->rich; list_start(l,1); CHECK(list_report(l,output(&r->model,0)) && !l->seen[0]); rich_ack(r,true,true);
    Matter_Im_Subscribe_Message_T out=output(&r->model,0); CHECK(out.opcode==1 && out.data[3]==MATTER_IM_RESOURCE_EXHAUSTED); rich_free(r);
    for(unsigned mode=0;mode<2;++mode) {
        l=list_new(100,2,2); r=&l->rich; r->malformed=mode==0; l->wrong_type=mode==1; list_start(l,1);
        out=output(&r->model,0); CHECK(out.opcode==1 && out.data[3]==MATTER_IM_INVALID_ACTION); rich_free(r);
    }
#ifdef MATTER_TEST_ALLOC
    l=list_new(80,12,2); r=&l->rich; list_start(l,1); size_t base=live; fail_at=calls+1;
    out=output(&r->model,0); fail_at=0; CHECK(out.opcode==1 && out.data[3]==MATTER_IM_RESOURCE_EXHAUSTED && live+1==base); rich_free(r); CHECK(!live); /* Parser released after selector OOM. */
#endif
    puts("PASS list Subscribe: whole/empty/prefix REPLACE, ordered ADD, capacity sweep, owned snapshots/version, dirty/min/max, live ACL/fabric, oversized item/schema/OOM");
}

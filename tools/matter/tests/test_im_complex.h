#include "test_im_values.h"
static ImValues* values_new(size_t capacity,Matter_Tlv_Type_T type,unsigned entries) {
    ImValues* m=calloc(1,sizeof(*m)); CHECK(m); values_build(m,type,entries);
    Matter_Im_Read_Port_T p=values_port(m);
    Matter_Im_Read_Config_T c={{1,0x1234,false},10000,capacity,true};
    m->active=matter_im_read_new(&p,&c,0); CHECK(m->active); return m;
}
static void values_delete(ImValues* m) { CHECK(matter_im_read_delete(m->active)==MATTER_OK); free(m); }
static void values_start(ImValues* m) {
    Matter_Rx_Decision_T d=decision(im_request,sizeof(im_request));
    CHECK(matter_im_read_receive(m->active,&d)==MATTER_OK && matter_im_read_process(m->active,0)==MATTER_PENDING);
}
static void values_continue(ImValues* m) {
    CHECK(matter_im_read_sent(m->active)==MATTER_OK && matter_im_read_confirm(m->active,1)==MATTER_OK);
    const uint8_t reply[]={0x15,0x24,0,0,0x24,0xff,13,0x18};
    Matter_Rx_Decision_T d=decision(reply,sizeof(reply)); d.header.opcode=1;
    CHECK(matter_im_read_receive(m->active,&d)==MATTER_OK && matter_im_read_process(m->active,1)==MATTER_PENDING);
}
static void test_im_complex(void) {
#ifdef MATTER_TEST_ALLOC
    ImValues* small=values_new(1024,MATTER_TLV_BYTES,0); small->size=1; small->data[0]='a';
    max_request=0; values_start(small); CHECK(max_request<MATTER_IM_READ_SNAPSHOT_BYTES);
    size_t held=live,bytes=live_bytes;
    CHECK(matter_im_read_sent(small->active)==MATTER_OK && matter_im_read_confirm(small->active,1)==MATTER_OK);
    CHECK(matter_im_read_state(small->active)==MATTER_IM_READ_COMPLETE && live==held && live_bytes==bytes);
    values_delete(small); CHECK(!live && !live_bytes);
#endif
    const Matter_Tlv_Type_T types[]={MATTER_TLV_UTF8,MATTER_TLV_BYTES,MATTER_TLV_STRUCTURE,MATTER_TLV_ARRAY};
    for(unsigned type=0;type<4;++type) for(unsigned small=0;small<2;++small) {
        ImValues* m=values_new(small ? 96 : 1024,types[type],40); values_start(m);
        memset(m->data,0xff,sizeof(m->data)); /* Poison provider after the snapshot. */
        unsigned chunks=0;
        for(;;) {
            Matter_Im_Read_Message_T out; CHECK(matter_im_read_output(m->active,&out)==MATTER_OK && out.opcode==5);
            bool more=values_report(m,out.data,out.size); ++chunks; CHECK(chunks<50);
            if(!more) { CHECK(matter_im_read_sent(m->active)==MATTER_OK && matter_im_read_confirm(m->active,1)==MATTER_OK); break; }
            values_continue(m);
        }
        CHECK(m->reads==1 && matter_im_read_state(m->active)==MATTER_IM_READ_COMPLETE);
        if(type==3) CHECK(m->received==40 && m->replacements==1 && (small ? (m->appends && chunks>1) : (!m->appends && chunks==1)));
        else CHECK(chunks==1 && (type==2 ? m->received==1 : m->scalars==1));
        values_delete(m);
    }
    ImValues* m=values_new(34,MATTER_TLV_ARRAY,0); values_start(m);
    Matter_Im_Read_Message_T out; CHECK(matter_im_read_output(m->active,&out)==MATTER_OK && out.opcode==5);
    CHECK(!values_report(m,out.data,out.size) && m->replacements==1 && !m->received); values_delete(m);
    for(unsigned mode=0;mode<4;++mode) {
        m=values_new(1024,mode&1 ? MATTER_TLV_BYTES : MATTER_TLV_UTF8,0);
        m->null_data=true; m->size=mode<2 ? 0 : 1; values_start(m);
        CHECK(matter_im_read_output(m->active,&out)==MATTER_OK && out.opcode==5);
        if(mode<2) CHECK(out.size==33 && out.data[21]==(mode ? 0x30 : 0x2c) && out.data[22]==2 && out.data[23]==0);
        else CHECK(out.data[22]==MATTER_IM_FAILURE);
        values_delete(m);
    }
    /* Nested arrays/structs remain intact inside a single list item. */
    m=values_new(1024,MATTER_TLV_STRUCTURE,0);
    const uint8_t nested[]={0x15,0x36,0,0x15,0x24,0,1,0x18,0x18,0x18};
    memcpy(m->data,nested,sizeof(nested)); m->size=sizeof(nested); values_start(m);
    CHECK(matter_im_read_output(m->active,&out)==MATTER_OK && out.opcode==5);
    CHECK(out.data[21]==0x35 && out.data[22]==2 && !memcmp(out.data+23,nested+1,sizeof(nested)-1)); values_delete(m);
    /* Two simultaneous instances own independent copies, including after delete. */
    m=values_new(96,MATTER_TLV_ARRAY,40); ImValues* other=values_new(96,MATTER_TLV_ARRAY,40);
    values_start(m); values_start(other); values_delete(m);
    CHECK(matter_im_read_output(other->active,&out)==MATTER_OK && values_report(other,out.data,out.size));
    values_continue(other); values_delete(other);
    /* Arena budget across nine values: 7*2282 bytes fit, two path errors.
     * Consume all list fragments so a later attribute cannot be silently lost. */
    m=values_new(1024,MATTER_TLV_ARRAY,120);
    uint8_t request[109]; memcpy(request,im_request,3);
    for(unsigned i=0;i<9;++i) memcpy(request+3+11*i,im_request+3,11);
    memcpy(request+102,im_request+14,7);
    Matter_Rx_Decision_T many=decision(request,sizeof(request));
    CHECK(m->size==2282 && matter_im_read_receive(m->active,&many)==MATTER_OK && matter_im_read_process(m->active,0)==MATTER_PENDING);
    unsigned errors=0, items=0, replacements=0;
    for(unsigned chunk=0;chunk<100;++chunk) {
        CHECK(matter_im_read_output(m->active,&out)==MATTER_OK && out.opcode==5);
        CHECK(matter_tlv_init(&m->reader,out.data,out.size,8)==MATTER_TLV_OK);
        unsigned depth=0; bool more=false, status_ib=false; Matter_Tlv_Result_T r;
        while((r=matter_tlv_next(&m->reader,&m->token))==MATTER_TLV_OK) {
            Matter_Tlv_Element_T* e=&m->token;
            if(e->type==MATTER_TLV_END) { --depth; continue; }
            if(depth==3) status_ib=e->tag.number==0;
            if(status_ib && depth==5 && e->tag.control==1 && e->tag.number==0 && e->type==MATTER_TLV_UNSIGNED) {
                CHECK(e->unsigned_value==MATTER_IM_RESOURCE_EXHAUSTED); ++errors;
            }
            if(depth==4 && e->tag.number==2 && e->type==MATTER_TLV_ARRAY) ++replacements;
            if(e->type==MATTER_TLV_UTF8) ++items;
            if(depth==1 && e->tag.number==3) more=true;
            if(e->type==MATTER_TLV_STRUCTURE || e->type==MATTER_TLV_ARRAY || e->type==MATTER_TLV_LIST) ++depth;
        }
        CHECK(r==MATTER_TLV_DONE && !depth);
        if(!more) break;
        values_continue(m);
    }
    CHECK(m->reads==9 && errors==2 && replacements==7 && items==840); values_delete(m);
    /* Malformed provider spans, wrong roots, duplicate fields, UTF-8 and budgets. */
    for(unsigned mode=0;mode<8;++mode) {
        m=values_new(1024,mode==3 ? MATTER_TLV_UTF8 : MATTER_TLV_STRUCTURE,0);
        uint8_t code=MATTER_IM_FAILURE;
        if(mode==0) --m->size;
        if(mode==1) m->data[0]=0x16;
        if(mode==2) m->data[5]=0; /* duplicate field tag */
        if(mode==3) m->data[0]=0xff;
        if(mode==4) { m->size=4097; code=MATTER_IM_RESOURCE_EXHAUSTED; }
        if(mode==5) { m->data[m->size++]=0x14; }
        if(mode==6) { m->size=0; }
        if(mode==7) { const uint8_t deep[]={0x15,0x35,0,0x35,0,0x35,0,0x35,0,0x18,0x18,0x18,0x18,0x18}; memcpy(m->data,deep,sizeof(deep)); m->size=sizeof(deep); code=MATTER_IM_RESOURCE_EXHAUSTED; }
        values_start(m); CHECK(matter_im_read_output(m->active,&out)==MATTER_OK && out.opcode==5 && out.data[22]==code);
        values_delete(m);
    }
    /* Non-fragmentable string/struct; empty list prefix then oversized item. */
    for(unsigned mode=0;mode<3;++mode) {
        m=values_new(34,mode==0 ? MATTER_TLV_UTF8 : mode==1 ? MATTER_TLV_STRUCTURE : MATTER_TLV_ARRAY,1);
        values_start(m);
        if(mode==2) { CHECK(matter_im_read_output(m->active,&out)==MATTER_OK && values_report(m,out.data,out.size)); values_continue(m); }
        CHECK(matter_im_read_output(m->active,&out)==MATTER_OK && out.opcode==1 && out.data[3]==MATTER_IM_RESOURCE_EXHAUSTED);
        values_delete(m);
    }
    /* Cancel, timeout and permission revocation after a partial list. */
    for(unsigned mode=0;mode<3;++mode) {
        m=values_new(96,MATTER_TLV_ARRAY,40); values_start(m);
        CHECK(matter_im_read_output(m->active,&out)==MATTER_OK && values_report(m,out.data,out.size));
        if(mode==0) CHECK(matter_im_read_cancel(m->active)==MATTER_OK);
        if(mode==1) CHECK(matter_im_read_process(m->active,10000)==MATTER_PORT_ERROR);
        if(mode==2) { m->deny=true; values_continue(m); CHECK(matter_im_read_output(m->active,&out)==MATTER_OK && out.opcode==5 && out.data[22]==MATTER_IM_UNSUPPORTED_ACCESS); }
        CHECK(m->reads==1); values_delete(m);
    }
#ifdef MATTER_TEST_ALLOC
    for(unsigned allocation=2;allocation<=3;++allocation) {
        m=values_new(96,MATTER_TLV_ARRAY,40);
        Matter_Rx_Decision_T initial=decision(im_request,sizeof(im_request));
        CHECK(matter_im_read_receive(m->active,&initial)==MATTER_OK);
        /* Owned results, then composite snapshot, then chunk plan. */
        fail_at=calls+allocation; CHECK(matter_im_read_process(m->active,0)==MATTER_PENDING); fail_at=0;
        CHECK(matter_im_read_output(m->active,&out)==MATTER_OK);
        CHECK(allocation==2?(out.opcode==5 && out.data[22]==MATTER_IM_RESOURCE_EXHAUSTED):
            (out.opcode==1 && out.data[3]==MATTER_IM_RESOURCE_EXHAUSTED));
        values_delete(m); CHECK(!live);
    }
#endif
    puts("PASS IM composite: owned UTF8/bytes/structure, whole/prefix/ADD lists, reconstruction, malformed spans, limits, OOM and abort");
}

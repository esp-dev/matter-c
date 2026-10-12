/* Included by test_im_read.c; all large scratch is fixture-owned heap. */
typedef struct {
    Matter_Im_Read_T s;
    unsigned reads, auths, descriptions;
    bool denied, mixed, fabric, scope_error;
    uint8_t fabric_index;
    uint64_t base;
    uint8_t input[1024], saved[1024];
    Matter_Tlv_Reader_T reader;
    Matter_Tlv_Element_T element;
    Matter_Im_Read_Message_T out;
} ChunkFixture;
static Matter_Im_Status_T chunk_allow(void* u,Matter_Exchange_Session_T token,const Matter_Im_Path_T* p,Matter_Im_Privilege_T privilege) {
    ChunkFixture* f=u; CHECK(token==1 && p->endpoint==0 && p->cluster==0x28);
    CHECK(privilege==MATTER_IM_VIEW || privilege==MATTER_IM_MANAGE); ++f->auths;
    CHECK(matter_im_read_cancel(f->s)==MATTER_BUSY);
    return f->denied ? MATTER_IM_UNSUPPORTED_ACCESS : MATTER_IM_SUCCESS;
}
static Matter_Im_Status_T chunk_describe(void* u,const Matter_Im_Path_T* p,Matter_Im_Attribute_T* a) {
    ChunkFixture* f=u; ++f->descriptions; *a=(Matter_Im_Attribute_T){MATTER_IM_MANAGE,f->fabric};
    return f->mixed && p->attribute==3 ? MATTER_IM_UNSUPPORTED_ATTRIBUTE : MATTER_IM_SUCCESS;
}
static Matter_Im_Status_T chunk_read(void* u,const Matter_Im_Path_T* p,bool filtered,Matter_Im_Value_T* v) {
    ChunkFixture* f=u; CHECK(filtered); ++f->reads;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.unsigned_value=f->base+p->attribute,.data_version=7};
    return MATTER_IM_SUCCESS;
}
static ChunkFixture* chunk_new(size_t capacity) {
    ChunkFixture* f=calloc(1,sizeof(*f)); CHECK(f); f->base=100;
    Matter_Im_Read_Port_T p={f,chunk_allow,chunk_describe,chunk_read,NULL,NULL};
    Matter_Im_Read_Config_T c={{1,0x1234,false},1000,capacity,true};
    f->s=matter_im_read_new(&p,&c,0); CHECK(f->s); return f;
}
static void chunk_delete(ChunkFixture* f) { CHECK(matter_im_read_delete(f->s)==MATTER_OK); free(f); }
static size_t chunk_request(ChunkFixture* f,unsigned count) {
    memcpy(f->input,im_request,3); size_t n=3;
    for(unsigned i=0;i<count;++i) { memcpy(f->input+n,im_request+3,11); f->input[n+9]=(uint8_t)(2+i); n+=11; }
    memcpy(f->input+n,im_request+14,7); return n+7;
}
static void chunk_start(ChunkFixture* f,unsigned count) {
    size_t n=chunk_request(f,count); Matter_Rx_Decision_T d=decision(f->input,n);
    CHECK(matter_im_read_receive(f->s,&d)==MATTER_OK && matter_im_read_process(f->s,0)==MATTER_PENDING);
    CHECK(matter_im_read_output(f->s,&f->out)==MATTER_OK);
}
static void chunk_status(ChunkFixture* f,uint8_t code,uint64_t now) {
    const uint8_t bytes[]={0x15,0x24,0,code,0x24,0xff,13,0x18};
    Matter_Rx_Decision_T d=decision(bytes,sizeof(bytes)); d.header.opcode=1; d.action=MATTER_RX_EXISTING;
    CHECK(matter_im_read_receive(f->s,&d)==MATTER_OK);
    CHECK(matter_im_read_process(f->s,now)==(code ? MATTER_PORT_ERROR : MATTER_PENDING));
}
static unsigned chunk_report(ChunkFixture* f,bool more,unsigned first,bool errors) {
    CHECK(matter_im_read_output(f->s,&f->out)==MATTER_OK && f->out.opcode==5);
    CHECK(matter_tlv_init(&f->reader,f->out.data,f->out.size,8)==MATTER_TLV_OK);
    unsigned entries=0, values=0, statuses=0; bool flag=false;
    Matter_Tlv_Result_T r;
    while((r=matter_tlv_next(&f->reader,&f->element))==MATTER_TLV_OK) {
        Matter_Tlv_Element_T* e=&f->element;
        if(e->type==MATTER_TLV_STRUCTURE && e->tag.control==0 && e->offset>0) ++entries;
        if(e->type==MATTER_TLV_UNSIGNED && e->tag.control==1 && e->tag.number==2 && e->unsigned_value>=100) {
            CHECK(e->unsigned_value==102+first+values); ++values;
        }
        if(e->type==MATTER_TLV_UNSIGNED && e->tag.control==1 && e->tag.number==0 && e->unsigned_value==0x7e) ++statuses;
        if(e->type==MATTER_TLV_BOOL) { CHECK(e->tag.number==(more ? 3u : 4u) && e->unsigned_value==1); flag=true; }
    }
    CHECK(r==MATTER_TLV_DONE && flag && entries==(errors ? statuses : values)); return entries;
}
static Matter_Result_T chunk_fabric(void* u,Matter_Exchange_Session_T session,uint8_t* index) {
    ChunkFixture* f=u; CHECK(session==1 && matter_im_read_cancel(f->s)==MATTER_BUSY);
    *index=f->fabric_index; return f->scope_error?MATTER_PORT_ERROR:MATTER_OK;
}
static void test_im_fabric_scope(void) {
    for(unsigned mode=0;mode<6;++mode) {
        ChunkFixture* f=chunk_new(33); CHECK(matter_im_read_delete(f->s)==MATTER_OK);
        f->fabric=true; f->fabric_index=mode==0?0:mode==1?255:1; f->scope_error=mode==2;
        Matter_Im_Read_Port_T p={f,chunk_allow,chunk_describe,chunk_read,NULL,NULL};
        Matter_Im_Read_Fabric_Port_T fp={chunk_fabric}; Matter_Im_Read_Config_T c={{1,0x1234,false},1000,33,true};
        f->s=matter_im_read_new_fabric(&p,&fp,&c,0); CHECK(f->s); chunk_start(f,3);
        bool denied=mode==1 || mode==2;
        CHECK(chunk_report(f,true,0,denied)==1 && f->reads==(denied?0u:3u));
        if(mode==0) {
            /* PASE before AddNOC: fabric 0 is valid for reading a list. The
             * provider filters its entries; an old snapshot cannot change owner. */
            CHECK(matter_im_read_sent(f->s)==MATTER_OK && matter_im_read_confirm(f->s,1)==MATTER_OK);
            f->fabric_index=1;
            chunk_status(f,0,2); CHECK(chunk_report(f,true,0,true)==1 && f->reads==3);
        }
        if(mode>=3) {
            CHECK(matter_im_read_sent(f->s)==MATTER_OK && matter_im_read_confirm(f->s,1)==MATTER_OK);
            if(mode==3) f->fabric_index=0; /* Rollback/revocation. */
            if(mode==4) f->fabric_index=2; /* Cannot transfer an old snapshot to another fabric. */
            if(mode==5) f->scope_error=true;
            chunk_status(f,0,2); CHECK(chunk_report(f,true,0,true)==1 && f->reads==3);
        }
        chunk_delete(f);
    }
    puts("PASS IM fabric scope: PASE without fabric, invalid fabric, resolver error, chunk revocation and changed identity");
}
static void test_im_chunks(void) {
    /* 9 concrete paths fit one report, each provider called once. */
    ChunkFixture* f=chunk_new(1024); chunk_start(f,9);
    CHECK(f->reads==9 && chunk_report(f,false,0,false)==9); chunk_delete(f);
    /* Two maximally packed scalar IBs per 56-byte report (23 bytes each). */
    f=chunk_new(56); chunk_start(f,9); unsigned seen=0;
    for(unsigned chunk=0;chunk<5;++chunk) {
        bool more=chunk<4; unsigned n=chunk_report(f,more,seen,false); CHECK(n==(more ? 2u : 1u)); seen+=n;
        memcpy(f->saved,f->out.data,f->out.size); size_t saved_size=f->out.size;
        CHECK(matter_im_read_process(f->s,chunk*10)==MATTER_PENDING);
        CHECK(matter_im_read_output(f->s,&f->out)==MATTER_OK && !memcmp(f->saved,f->out.data,saved_size));
        CHECK(matter_im_read_sent(f->s)==MATTER_OK); f->base=900; /* Frozen snapshots. */
        if(more && chunk%2==0) { /* IM success BEFORE MRP completion cannot overwrite active output. */
            chunk_status(f,0,chunk*10+1);
            CHECK(matter_im_read_state(f->s)==MATTER_IM_READ_IN_FLIGHT);
            CHECK(matter_im_read_output(f->s,&f->out)==MATTER_INVALID_STATE);
        }
        CHECK(matter_im_read_confirm(f->s,chunk*10+2)==MATTER_OK);
        CHECK(matter_im_read_state(f->s)==(more ? MATTER_IM_READ_WAIT_STATUS : MATTER_IM_READ_COMPLETE));
        if(more) {
            if(chunk%2) { CHECK(matter_im_read_process(f->s,chunk*10+2)==MATTER_PENDING); CHECK(matter_im_read_state(f->s)==MATTER_IM_READ_WAIT_STATUS); chunk_status(f,0,chunk*10+3); }
            else CHECK(matter_im_read_process(f->s,chunk*10+3)==MATTER_PENDING);
        }
    }
    CHECK(seen==9 && f->reads==9); chunk_delete(f);
    /* Mixed data/status entries, path exhaustion and full schema validation. */
    f=chunk_new(1024); f->mixed=true; chunk_start(f,3); CHECK(f->reads==2 && f->descriptions==3 && f->out.opcode==5); chunk_delete(f);
    f=chunk_new(1024); chunk_start(f,10); CHECK(!f->auths && f->out.opcode==1 && f->out.data[3]==0xc8); chunk_delete(f);
    f=chunk_new(1024); size_t n=chunk_request(f,9); f->input[3+8*11]=0x15;
    Matter_Rx_Decision_T d=decision(f->input,n); CHECK(matter_im_read_receive(f->s,&d)==MATTER_OK);
    CHECK(matter_im_read_process(f->s,0)==MATTER_PENDING && matter_im_read_output(f->s,&f->out)==MATTER_OK);
    CHECK(!f->auths && f->out.opcode==1 && f->out.data[3]==0x80); chunk_delete(f);
    /* Revocation converts unsent snapshots to status without re-reading. */
    f=chunk_new(33); chunk_start(f,3); CHECK(chunk_report(f,true,0,false)==1);
    CHECK(matter_im_read_sent(f->s)==MATTER_OK && matter_im_read_confirm(f->s,1)==MATTER_OK);
    f->denied=true; chunk_status(f,0,2); CHECK(chunk_report(f,true,0,true)==1 && f->reads==3); chunk_delete(f);
    /* Remote failures (including unknown codes), malformed status, deadline,
     * cancel and duplicate fresh status cannot advance or resurrect a report. */
    for(unsigned mode=0;mode<7;++mode) {
        f=chunk_new(33); chunk_start(f,3); CHECK(matter_im_read_sent(f->s)==MATTER_OK);
        if(mode<2) {
            chunk_status(f,mode ? 0xee : 1,1); uint8_t code=0;
            CHECK(matter_im_read_peer_status(f->s,&code)==MATTER_OK && code==(mode ? 0xee : 1));
            CHECK(matter_im_read_confirm(f->s,2)==MATTER_INVALID_STATE);
        } else if(mode==2) {
            const uint8_t malformed[]={0x15,0x29,0,0x24,0xff,13,0x18}; d=decision(malformed,sizeof(malformed)); d.header.opcode=1;
            CHECK(matter_im_read_receive(f->s,&d)==MATTER_OK && matter_im_read_process(f->s,1)==MATTER_PENDING);
            CHECK(matter_im_read_state(f->s)==MATTER_IM_READ_IN_FLIGHT);
            CHECK(matter_im_read_confirm(f->s,2)==MATTER_OK && matter_im_read_process(f->s,2)==MATTER_PENDING);
            CHECK(matter_im_read_output(f->s,&f->out)==MATTER_OK && f->out.opcode==1 && f->out.data[3]==0x80);
            CHECK(matter_im_read_sent(f->s)==MATTER_OK && matter_im_read_confirm(f->s,3)==MATTER_OK);
        } else {
            CHECK(matter_im_read_confirm(f->s,1)==MATTER_OK);
            if(mode==3) CHECK(matter_im_read_process(f->s,1000)==MATTER_PORT_ERROR);
            if(mode==4) CHECK(matter_im_read_cancel(f->s)==MATTER_OK);
            if(mode==5) { CHECK(matter_im_read_process(f->s,0)==MATTER_INVALID_ARGUMENT); CHECK(matter_im_read_state(f->s)==MATTER_IM_READ_WAIT_STATUS); }
            if(mode==6) { const uint8_t good[]={0x15,0x24,0,0,0x24,0xff,13,0x18}; d=decision(good,sizeof(good)); d.header.opcode=1;
                CHECK(matter_im_read_receive(f->s,&d)==MATTER_OK && matter_im_read_receive(f->s,&d)==MATTER_WOULD_BLOCK); }
        }
        CHECK(f->reads==3); chunk_delete(f);
    }
    puts("PASS IM chunks: 9 paths, maximal packing, frozen snapshots, both completion orders, status errors, revocation and limits");
}

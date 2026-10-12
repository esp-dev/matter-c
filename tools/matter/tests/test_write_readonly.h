/* A read-only list still needs AttributeStatusIB when no list writer exists.
 * Literal TLV independent of the production encoder; all workspaces on heap. */
static uint8_t ro_describe(void* u,const Matter_Im_Path_T* p,Matter_Im_Write_Attribute_T* out) {
    (void)p; (void)out; WriteModel* m=u; ++m->descriptions; return m->describe_error;
}
static uint8_t ro_authorize(void* u,Matter_Exchange_Session_T session,const Matter_Im_Path_T* p,Matter_Im_Privilege_T privilege) {
    (void)p; CHECK(session==1 && privilege==MATTER_IM_VIEW);
    WriteModel* m=u; ++m->auths; return m->deny;
}
static Matter_Result_T ro_index(void* u,Matter_Exchange_Session_T session,uint8_t* index) {
    (void)u; CHECK(session==1); *index=1; return MATTER_OK;
}
static void readonly_lists(void) {
    /* Empty/nonempty REPLACE, ADD, same-path multi-IB and a later chunk. */
    for(unsigned mode=0;mode<7;++mode) for(unsigned transport=0;transport<2;++transport)
    for(unsigned error=0;error<4;++error) {
        WriteModel* m=create(256);
        CHECK(matter_im_write_delete(m->active)==MATTER_OK);
        Matter_Im_Write_Port_T p=write_port(m); p.authorize=ro_authorize; p.describe=ro_describe;
        Matter_Im_Write_Config_T c={{1,0x1234,false},1000,256,!transport};
        Matter_Im_Read_Fabric_Port_T fabric={ro_index};
        m->active=transport?matter_im_write_new_case(&p,&fabric,&c,0):matter_im_write_new(&p,&c,0); CHECK(m->active);
        m->describe_error=error==1?MATTER_IM_UNSUPPORTED_ATTRIBUTE:error==2?MATTER_IM_UNSUPPORTED_CLUSTER:MATTER_IM_UNSUPPORTED_WRITE;
        m->deny=error==3?MATTER_IM_UNSUPPORTED_ACCESS:0;
        unsigned count=mode==3?4:mode==4?5:1;
        size_t n=0;
        const uint8_t prefix[]={0x15,0x28,1,0x36,2};
        const uint8_t path[]={0x15,0x37,1,0x24,2,0,0x24,3,0x3e,0x24,4,4};
        memcpy(m->input,prefix,sizeof(prefix)); n+=sizeof(prefix);
        for(unsigned i=0;i<count;++i) {
            memcpy(m->input+n,path,sizeof(path)); n+=sizeof(path);
            if(mode==2 || i) { m->input[n++]=0x34; m->input[n++]=5; }
            m->input[n++]=0x18;
            if(mode==2 || i) { m->input[n++]=0x24; m->input[n++]=2; m->input[n++]=9; }
            else { m->input[n++]=0x36; m->input[n++]=2;
                if(mode==1) { m->input[n++]=4; m->input[n++]=9; }
                m->input[n++]=0x18;
            }
            m->input[n++]=0x18;
        }
        m->input[n++]=0x18;
        if(mode==5) { m->input[n++]=0x29; m->input[n++]=3; }
        m->input[n++]=0x24; m->input[n++]=255; m->input[n++]=13; m->input[n++]=0x18;
        if(mode==6) --n; /* Malformed outer TLV: no authorization or lookup. */
        Matter_Rx_Decision_T d=decision(m->input,n);
        CHECK(matter_im_write_receive_at(m->active,&d,0)==MATTER_OK && matter_im_write_process(m->active,0)==MATTER_PENDING);
        Matter_Im_Write_Message_T out; CHECK(matter_im_write_output(m->active,&out)==MATTER_OK);
        if(mode==4 || mode==6) { expect(out,mode==4?MATTER_IM_RESOURCE_EXHAUSTED:MATTER_IM_INVALID_ACTION,true); CHECK(!m->auths); }
        else {
            CHECK(out.opcode==7);
            CHECK(matter_tlv_init(&m->reader,out.data,out.size,8)==MATTER_TLV_OK);
            unsigned statuses=0;
            while(matter_tlv_next(&m->reader,&m->token)==MATTER_TLV_OK)
                if(m->token.type==MATTER_TLV_UNSIGNED && m->token.tag.number==0) {
                    CHECK(m->token.unsigned_value==(m->deny?m->deny:m->describe_error)); ++statuses;
                }
            CHECK(statuses==count && m->auths==count && m->descriptions==(m->deny?0:count));
            if(mode==5) {
                CHECK(matter_im_write_sent_at(m->active,1)==MATTER_OK && matter_im_write_confirm(m->active,1)==MATTER_OK);
                CHECK(matter_im_write_state(m->active)==MATTER_IM_WRITE_WAIT_CHUNK);
                /* Reuse same path, final chunk, access revoked in between. */
                memmove(m->input+n-6,m->input+n-4,4); n-=2; d=decision(m->input,n);
                m->deny=MATTER_IM_UNSUPPORTED_ACCESS;
                CHECK(matter_im_write_receive_at(m->active,&d,2)==MATTER_OK && matter_im_write_process(m->active,2)==MATTER_PENDING);
                CHECK(matter_im_write_output(m->active,&out)==MATTER_OK && out.opcode==7 && out.data[20]==MATTER_IM_UNSUPPORTED_ACCESS);
            }
        }
        CHECK(!m->versions && !m->validations && !m->writes && m->version==7 && !m->stored_size);
        release(m);
    }
    puts("PASS read-only Write: PASE/CASE empty/full/ADD/multi/chunks, access precedence, no effects, malformed/bounds"); fflush(stdout);
}

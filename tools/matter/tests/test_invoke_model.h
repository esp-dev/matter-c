#define INV_CHECK(c) do { if (!(c)) { fprintf(stderr,"Invoke:%d: %s\n",__LINE__,#c); abort(); } } while (0)
static const uint8_t timed_request[]={0x15,0x25,0,0xe8,3,0x24,0xff,13,0x18}; /* 1000 ms */
static const uint8_t invoke_request[]={0x15,0x28,0,0x28,1,0x36,2,0x15,0x37,0,
    0x24,0,0,0x24,1,0x30,0x24,2,0,0x18,0x35,1,0x24,0,7,0x18,0x24,2,42,0x18,0x18,0x24,0xff,13,0x18};
static const uint8_t invoke_response[]={0x15,0x29,0,0x36,1,0x15,0x35,0,0x37,0,
    0x24,0,0,0x24,1,0x30,0x24,2,1,0x18,0x35,1,0x24,0,7,0x24,1,1,0x18,
    0x24,2,42,0x18,0x18,0x18,0x24,0xff,13,0x18};
typedef struct {
    Matter_Im_Invoke_T active;
    unsigned auths, descriptions, validations, executions, value, malformed;
    uint8_t deny, describe_error, validation_error;
    bool second_deny;
    Matter_Im_Command_T metadata;
    Matter_Im_Command_Result_T result;
    Matter_Tlv_Reader_T reader;
    Matter_Tlv_Element_T token;
    uint8_t input[1025];
} InvokeModel;
static void invoke_guard(InvokeModel* m) {
    INV_CHECK(matter_im_invoke_cancel(m->active)==MATTER_BUSY && matter_im_invoke_delete(m->active)==MATTER_BUSY);
    INV_CHECK(matter_im_invoke_process(m->active,0)==MATTER_BUSY && matter_im_invoke_sent(m->active)==MATTER_BUSY);
    INV_CHECK(matter_im_invoke_sent_at(m->active,0)==MATTER_BUSY && matter_im_invoke_receive_at(m->active,NULL,0)==MATTER_BUSY);
}
static uint8_t invoke_allow(void* u,Matter_Exchange_Session_T token,const Matter_Im_Command_Path_T* path,Matter_Im_Privilege_T p) {
    InvokeModel* m=u; invoke_guard(m); INV_CHECK(token && path->endpoint==0 && path->cluster==0x30 && path->command==0);
    ++m->auths; INV_CHECK(p==(m->auths==1 ? MATTER_IM_OPERATE : m->metadata.privilege));
    return m->deny && (!m->second_deny || m->auths==2) ? m->deny : 0;
}
static uint8_t invoke_describe(void* u,const Matter_Im_Command_Path_T* path,Matter_Im_Command_T* out) {
    InvokeModel* m=u; (void)path; invoke_guard(m); INV_CHECK(m->auths==1); ++m->descriptions;
    *out=m->metadata; return m->describe_error;
}
static uint8_t invoke_validate(void* u,const Matter_Im_Command_Path_T* path,const uint8_t* data,size_t size) {
    InvokeModel* m=u; (void)path; invoke_guard(m); INV_CHECK(m->auths==2); ++m->validations;
    if(m->validation_error) return m->validation_error;
    INV_CHECK(matter_tlv_init(&m->reader,data,size,4)==MATTER_TLV_OK);
    INV_CHECK(matter_tlv_next(&m->reader,&m->token)==MATTER_TLV_OK && m->token.type==MATTER_TLV_STRUCTURE && !m->token.tag.control);
    bool found=false; Matter_Tlv_Result_T r;
    while((r=matter_tlv_next(&m->reader,&m->token))==MATTER_TLV_OK) {
        if(m->token.type==MATTER_TLV_END) break;
        if(m->token.tag.control==1 && m->token.tag.number==0) {
            if(m->token.type!=MATTER_TLV_UNSIGNED) return MATTER_IM_INVALID_COMMAND;
            if(m->token.unsigned_value>100) return MATTER_IM_CONSTRAINT_ERROR;
            found=true;
        }
        if(m->token.type==MATTER_TLV_STRUCTURE || m->token.type==MATTER_TLV_ARRAY || m->token.type==MATTER_TLV_LIST)
            INV_CHECK(matter_tlv_skip_container(&m->reader)==MATTER_TLV_OK);
    }
    INV_CHECK(r==MATTER_TLV_OK);
    return found ? 0 : MATTER_IM_INVALID_COMMAND;
}
static Matter_Im_Command_Result_T invoke_execute(void* u,const Matter_Im_Command_Path_T* path,const uint8_t* data,size_t size,Matter_Tlv_Writer_T* writer) {
    InvokeModel* m=u; (void)path; invoke_guard(m); INV_CHECK(m->auths==2 && m->validations==1 && !m->executions);
    INV_CHECK(matter_tlv_init(&m->reader,data,size,4)==MATTER_TLV_OK);
    while(matter_tlv_next(&m->reader,&m->token)==MATTER_TLV_OK)
        if(m->token.type==MATTER_TLV_UNSIGNED && m->token.tag.control==1 && m->token.tag.number==0) m->value=(unsigned)m->token.unsigned_value;
    ++m->executions;
    if(writer && !m->result.status) {
        m->token=(Matter_Tlv_Element_T){.type=m->malformed==1 ? MATTER_TLV_ARRAY : MATTER_TLV_STRUCTURE};
        INV_CHECK(matter_tlv_write(writer,&m->token,0)==MATTER_TLV_OK);
        if(m->malformed==1) { m->token.type=MATTER_TLV_END; INV_CHECK(matter_tlv_write(writer,&m->token,0)==MATTER_TLV_OK); return m->result; }
        m->token=(Matter_Tlv_Element_T){.type=MATTER_TLV_UNSIGNED,.tag={.control=1,.number=0},.unsigned_value=m->value};
        INV_CHECK(matter_tlv_write(writer,&m->token,0)==MATTER_TLV_OK);
        m->token.tag.number=m->malformed==2 ? 0 : 1; m->token.unsigned_value=m->executions;
        INV_CHECK(matter_tlv_write(writer,&m->token,0)==MATTER_TLV_OK);
        if(m->malformed!=3) { m->token=(Matter_Tlv_Element_T){.type=MATTER_TLV_END}; INV_CHECK(matter_tlv_write(writer,&m->token,0)==MATTER_TLV_OK); }
    }
    return m->result;
}
static Matter_Im_Invoke_Port_T invoke_port(InvokeModel* m) {
    m->metadata=(Matter_Im_Command_T){.privilege=MATTER_IM_ADMINISTER,.response=true,.response_command=1,.response_capacity=16};
    return (Matter_Im_Invoke_Port_T){m,invoke_allow,invoke_describe,invoke_validate,invoke_execute};
}
#undef INV_CHECK

#define WR_CHECK(c) do { if (!(c)) { fprintf(stderr,"Write:%d: %s\n",__LINE__,#c); abort(); } } while (0)
/* Literal single AttributeDataIB: version 7, path ep0/cluster0x28/attribute2,
 * unsigned data 42. Synthetic writable attribute, not Basic Information schema. */
static const uint8_t write_request[]={0x15,0x28,1,0x36,2,0x15,0x24,0,7,0x37,1,
    0x24,2,0,0x24,3,0x28,0x24,4,2,0x18,0x24,2,42,0x18,0x18,0x24,0xff,13,0x18};
static const uint8_t write_response[]={0x15,0x36,0,0x15,0x37,0,0x24,2,0,0x24,3,0x28,0x24,4,2,
    0x18,0x35,1,0x24,0,0,0x18,0x18,0x18,0x24,0xff,13,0x18};
static const uint8_t write_timed[]={0x15,0x25,0,100,0,0x24,0xff,13,0x18};
typedef struct {
    Matter_Im_Write_T active;
    unsigned auths, descriptions, versions, validations, writes, reads;
    uint32_t version;
    uint8_t deny, describe_error, validation_error;
    bool second_deny, version_error, any_type;
    Matter_Im_Write_Attribute_T metadata;
    Matter_Im_Write_Result_T result;
    Matter_Tlv_Reader_T reader;
    Matter_Tlv_Element_T token;
    uint8_t input[1025], stored[1024];
    size_t stored_size;
} WriteModel;
static void write_guard(WriteModel* m) {
    WR_CHECK(matter_im_write_cancel(m->active)==MATTER_BUSY && matter_im_write_delete(m->active)==MATTER_BUSY);
    WR_CHECK(matter_im_write_process(m->active,0)==MATTER_BUSY && matter_im_write_sent_at(m->active,0)==MATTER_BUSY);
    WR_CHECK(matter_im_write_receive_at(m->active,NULL,0)==MATTER_BUSY && matter_im_write_confirm(m->active,0)==MATTER_BUSY);
}
static uint8_t write_allow(void* u,Matter_Exchange_Session_T token,const Matter_Im_Path_T* p,Matter_Im_Privilege_T privilege) {
    WriteModel* m=u; write_guard(m); WR_CHECK(token && !p->endpoint && p->cluster==0x28 && p->attribute==2);
    ++m->auths; WR_CHECK(privilege==(m->auths==1 ? MATTER_IM_VIEW : m->metadata.privilege));
    return m->deny && (!m->second_deny || m->auths==2) ? m->deny : 0;
}
static uint8_t write_describe(void* u,const Matter_Im_Path_T* p,Matter_Im_Write_Attribute_T* out) {
    WriteModel* m=u; (void)p; write_guard(m); WR_CHECK(m->auths==1); ++m->descriptions;
    *out=m->metadata; return m->describe_error;
}
static Matter_Result_T write_version(void* u,const Matter_Im_Path_T* p,uint32_t* version) {
    WriteModel* m=u; (void)p; write_guard(m); WR_CHECK(m->auths==2); ++m->versions;
    *version=m->version; return m->version_error ? MATTER_PORT_ERROR : MATTER_OK;
}
static uint8_t write_validate(void* u,const Matter_Im_Path_T* p,const uint8_t* data,size_t size) {
    WriteModel* m=u; (void)p; write_guard(m); WR_CHECK(m->auths==2 && !m->writes); ++m->validations;
    if(m->validation_error) return m->validation_error;
    WR_CHECK(matter_tlv_init(&m->reader,data,size,4)==MATTER_TLV_OK && matter_tlv_next(&m->reader,&m->token)==MATTER_TLV_OK);
    WR_CHECK(!m->token.tag.control);
    if(m->any_type) return 0;
    if(m->token.type!=MATTER_TLV_UNSIGNED) return MATTER_IM_INVALID_DATA_TYPE;
    return m->token.unsigned_value>100 ? MATTER_IM_CONSTRAINT_ERROR : 0;
}
static Matter_Im_Write_Result_T write_apply(void* u,const Matter_Im_Path_T* p,const uint8_t* data,size_t size) {
    WriteModel* m=u; (void)p; write_guard(m); WR_CHECK(m->auths==2 && m->validations==1 && !m->writes);
    ++m->writes; WR_CHECK(size<=sizeof(m->stored));
    if(!m->result.status) { memcpy(m->stored,data,size); m->stored_size=size; ++m->version; }
    return m->result;
}
static Matter_Im_Write_Port_T write_port(WriteModel* m) {
    m->metadata=(Matter_Im_Write_Attribute_T){.privilege=MATTER_IM_MANAGE}; m->version=7;
    return (Matter_Im_Write_Port_T){m,write_allow,write_describe,write_version,write_validate,write_apply,NULL,NULL};
}
#undef WR_CHECK

#define WL_CHECK(c) do { if (!(c)) { fprintf(stderr,"Write list:%d: %s\n",__LINE__,#c); abort(); } } while (0)
typedef struct {
    Matter_Im_Write_T active;
    uint32_t version;
    unsigned count, writes, validations, auths;
    bool deny, fail_write;
    uint8_t items[64], input[1024];
    size_t input_size;
    Matter_Tlv_Reader_T reader;
    Matter_Tlv_Element_T token;
} WriteListModel;
static uint8_t wl_allow(void* u,Matter_Exchange_Session_T session,const Matter_Im_Path_T* p,Matter_Im_Privilege_T privilege) {
    WriteListModel* m=u; WL_CHECK(session && !p->endpoint && p->cluster==0x28 && p->attribute==2);
    WL_CHECK(privilege==MATTER_IM_VIEW || privilege==MATTER_IM_MANAGE);
    WL_CHECK(matter_im_write_cancel(m->active)==MATTER_BUSY); ++m->auths;
    return m->deny ? MATTER_IM_UNSUPPORTED_ACCESS : 0;
}
static uint8_t wl_describe(void* u,const Matter_Im_Path_T* p,Matter_Im_Write_Attribute_T* out) {
    (void)u; (void)p; *out=(Matter_Im_Write_Attribute_T){.privilege=MATTER_IM_MANAGE,.list=true}; return 0;
}
static Matter_Result_T wl_version(void* u,const Matter_Im_Path_T* p,uint32_t* v) {
    (void)p; *v=((WriteListModel*)u)->version; return MATTER_OK;
}
static uint8_t wl_scalar_validate(void* u,const Matter_Im_Path_T* p,const uint8_t* d,size_t n) {
    (void)u; (void)p; (void)d; (void)n; abort(); return 1;
}
static Matter_Im_Write_Result_T wl_scalar_write(void* u,const Matter_Im_Path_T* p,const uint8_t* d,size_t n) {
    (void)u; (void)p; (void)d; (void)n; abort(); return (Matter_Im_Write_Result_T){.status=1};
}
static uint8_t wl_validate(void* u,const Matter_Im_Path_T* p,Matter_Im_List_Change_T op,const uint8_t* d,size_t n) {
    WriteListModel* m=u; (void)p; ++m->validations;
    WL_CHECK(matter_im_write_delete(m->active)==MATTER_BUSY);
    WL_CHECK(matter_tlv_init(&m->reader,d,n,4)==MATTER_TLV_OK && matter_tlv_next(&m->reader,&m->token)==MATTER_TLV_OK && !m->token.tag.control);
    if(op==MATTER_IM_LIST_REPLACE) { WL_CHECK(n==2 && d[0]==0x16 && d[1]==0x18); return 0; }
    if(m->token.type!=MATTER_TLV_BYTES || m->token.size!=32) return MATTER_IM_INVALID_DATA_TYPE;
    if(m->token.data[0]>63) return MATTER_IM_CONSTRAINT_ERROR;
    for(size_t i=1;i<32;++i) if(m->token.data[i]!=m->token.data[0]) return MATTER_IM_CONSTRAINT_ERROR;
    return m->count==64 ? MATTER_IM_RESOURCE_EXHAUSTED : 0;
}
static Matter_Im_Write_Result_T wl_write(void* u,const Matter_Im_Path_T* p,Matter_Im_List_Change_T op,const uint8_t* d,size_t n) {
    WriteListModel* m=u; (void)p; (void)n;
    WL_CHECK(matter_im_write_process(m->active,0)==MATTER_BUSY); ++m->writes;
    if(m->fail_write) return (Matter_Im_Write_Result_T){.status=MATTER_IM_FAILURE};
    if(op==MATTER_IM_LIST_REPLACE) m->count=0;
    else { WL_CHECK(d[0]==0x10 && d[1]==32 && m->count<64); m->items[m->count++]=d[2]; }
    ++m->version; return (Matter_Im_Write_Result_T){0};
}
static Matter_Im_Write_Port_T wl_port(WriteListModel* m) {
    return (Matter_Im_Write_Port_T){m,wl_allow,wl_describe,wl_version,wl_scalar_validate,wl_scalar_write,wl_validate,wl_write};
}
/* Literal wire builder, independent of the production TLV writer. */
static void wl_request(WriteListModel* m,bool add,bool more,int version,uint8_t item) {
    static const uint8_t prefix[]={0x15,0x28,1,0x36,2,0x15};
    static const uint8_t path[]={0x37,1,0x24,2,0,0x24,3,0x28,0x24,4,2};
    size_t n=0; memcpy(m->input,prefix,sizeof(prefix)); n+=sizeof(prefix);
    if(version>=0) { m->input[n++]=0x24; m->input[n++]=0; m->input[n++]=(uint8_t)version; }
    memcpy(m->input+n,path,sizeof(path)); n+=sizeof(path);
    if(add) { m->input[n++]=0x34; m->input[n++]=5; }
    m->input[n++]=0x18;
    if(add) { m->input[n++]=0x30; m->input[n++]=2; m->input[n++]=32; memset(m->input+n,item,32); n+=32; }
    else { m->input[n++]=0x36; m->input[n++]=2; m->input[n++]=0x18; }
    m->input[n++]=0x18; m->input[n++]=0x18;
    if(more) { m->input[n++]=0x29; m->input[n++]=3; }
    m->input[n++]=0x24; m->input[n++]=0xff; m->input[n++]=13; m->input[n++]=0x18; m->input_size=n;
}
#undef WL_CHECK

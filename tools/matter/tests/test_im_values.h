#define VALUES_CHECK(c) do { if (!(c)) { fprintf(stderr, "IM values:%d: %s\n",__LINE__,#c); abort(); } } while (0)
/* Shared provider and independent report consumer for unit and real PASE tests. */
typedef struct {
    Matter_Im_Read_T active;
    Matter_Tlv_Writer_T writer;
    Matter_Tlv_Reader_T reader;
    Matter_Tlv_Element_T token;
    uint8_t data[4097];
    size_t size;
    Matter_Tlv_Type_T type;
    unsigned reads, received, replacements, appends, scalars, entries;
    bool deny, null_data, short_list;
} ImValues;
static const uint8_t values_name[]={'w','h','a','t','w','a','t','t',' ',0xc5,0xbc};
static void values_put(ImValues* m,Matter_Tlv_Type_T type,int tag,uint64_t n) {
    m->token=(Matter_Tlv_Element_T){.type=type,.tag={.control=tag<0 ? 0 : 1,.number=tag<0 ? 0 : (uint32_t)tag},
        .unsigned_value=n,.data=values_name,.size=sizeof(values_name)};
    VALUES_CHECK(matter_tlv_write(&m->writer,&m->token,0)==MATTER_TLV_OK);
}
static void values_build(ImValues* m,Matter_Tlv_Type_T type,unsigned entries) {
    m->type=type; m->entries=entries;
    if(type==MATTER_TLV_UTF8 || type==MATTER_TLV_BYTES) {
        memcpy(m->data,values_name,sizeof(values_name)); m->size=sizeof(values_name);
        if(type==MATTER_TLV_BYTES) m->data[0]=0;
        return;
    }
    VALUES_CHECK(matter_tlv_writer_init(&m->writer,m->data,sizeof(m->data),4)==MATTER_TLV_OK);
    if(type==MATTER_TLV_ARRAY) values_put(m,MATTER_TLV_ARRAY,-1,0);
    for(unsigned i=0;i<(type==MATTER_TLV_ARRAY ? entries : 1);++i) {
        values_put(m,MATTER_TLV_STRUCTURE,-1,0);
        values_put(m,MATTER_TLV_UNSIGNED,0,i);
        values_put(m,MATTER_TLV_UTF8,1,0);
        values_put(m,MATTER_TLV_END,-1,0);
    }
    if(type==MATTER_TLV_ARRAY) values_put(m,MATTER_TLV_END,-1,0);
    VALUES_CHECK(matter_tlv_writer_finish(&m->writer,&m->size)==MATTER_TLV_OK);
}
static Matter_Im_Status_T values_allow(void* u,Matter_Exchange_Session_T session,const Matter_Im_Path_T* p,Matter_Im_Privilege_T privilege) {
    ImValues* m=u; (void)session; (void)p; (void)privilege;
    VALUES_CHECK(matter_im_read_cancel(m->active)==MATTER_BUSY);
    return m->deny ? MATTER_IM_UNSUPPORTED_ACCESS : MATTER_IM_SUCCESS;
}
static Matter_Im_Status_T values_describe(void* u,const Matter_Im_Path_T* p,Matter_Im_Attribute_T* a) {
    (void)u; (void)p; *a=(Matter_Im_Attribute_T){MATTER_IM_VIEW,false}; return MATTER_IM_SUCCESS;
}
static Matter_Im_Status_T values_read(void* u,const Matter_Im_Path_T* p,bool filtered,Matter_Im_Value_T* v) {
    ImValues* m=u; (void)p; VALUES_CHECK(filtered); ++m->reads;
    *v=(Matter_Im_Value_T){.type=m->type,.data_version=7,.data=m->null_data ? NULL : m->data,.size=m->size}; return MATTER_IM_SUCCESS;
}
static Matter_Im_Read_Port_T values_port(ImValues* m) {
    return (Matter_Im_Read_Port_T){m,values_allow,values_describe,values_read,NULL,NULL};
}
static void values_next(ImValues* m) { VALUES_CHECK(matter_tlv_next(&m->reader,&m->token)==MATTER_TLV_OK); }
static void values_item(ImValues* m) {
    if(m->short_list) {
        VALUES_CHECK(m->token.type==MATTER_TLV_UNSIGNED && m->token.unsigned_value==m->received+1);
        ++m->received; return;
    }
    VALUES_CHECK(m->token.type==MATTER_TLV_STRUCTURE);
    values_next(m); VALUES_CHECK(m->token.type==MATTER_TLV_UNSIGNED && m->token.tag.number==0 && m->token.unsigned_value==m->received);
    values_next(m); VALUES_CHECK(m->token.type==MATTER_TLV_UTF8 && m->token.tag.number==1 && m->token.size==sizeof(values_name));
    VALUES_CHECK(!memcmp(m->token.data,values_name,sizeof(values_name)));
    values_next(m); VALUES_CHECK(m->token.type==MATTER_TLV_END); ++m->received;
}
static bool values_report(ImValues* m,const uint8_t* data,size_t size) {
    VALUES_CHECK(matter_tlv_init(&m->reader,data,size,8)==MATTER_TLV_OK);
    unsigned depth=0, data_count=0; bool append=false, more=false, suppress=false, version=false;
    Matter_Tlv_Result_T r;
    while((r=matter_tlv_next(&m->reader,&m->token))==MATTER_TLV_OK) {
        Matter_Tlv_Element_T* e=&m->token;
        if(e->type==MATTER_TLV_END) { VALUES_CHECK(depth); --depth; continue; }
        if(depth==2) { append=false; version=false; }
        if(depth==4 && e->tag.control==1 && e->tag.number==0) { VALUES_CHECK(e->unsigned_value==7); version=true; }
        if(depth==5 && e->tag.number==5) { VALUES_CHECK(e->type==MATTER_TLV_NULL); append=true; }
        if(depth==4 && e->tag.control==1 && e->tag.number==2) {
            VALUES_CHECK(version); ++data_count;
            if(m->type==MATTER_TLV_ARRAY) {
                if(append) { VALUES_CHECK(m->replacements); ++m->appends; values_item(m); }
                else {
                    VALUES_CHECK(e->type==MATTER_TLV_ARRAY && !m->replacements); ++m->replacements; m->received=0;
                    values_next(m);
                    while(m->token.type!=MATTER_TLV_END) { values_item(m); values_next(m); }
                }
            } else if(m->type==MATTER_TLV_STRUCTURE) { VALUES_CHECK(!append); values_item(m); }
            else {
                VALUES_CHECK(!append && e->type==m->type && e->size==sizeof(values_name));
                VALUES_CHECK(e->data[0]==(m->type==MATTER_TLV_BYTES ? 0 : values_name[0]));
                VALUES_CHECK(!memcmp(e->data+1,values_name+1,sizeof(values_name)-1)); ++m->scalars;
            }
            continue;
        }
        if(depth==1 && e->tag.number==3) { VALUES_CHECK(e->type==MATTER_TLV_BOOL && e->unsigned_value==1); more=true; }
        if(depth==1 && e->tag.number==4) { VALUES_CHECK(e->type==MATTER_TLV_BOOL && e->unsigned_value==1); suppress=true; }
        if(e->type==MATTER_TLV_STRUCTURE || e->type==MATTER_TLV_ARRAY || e->type==MATTER_TLV_LIST) ++depth;
    }
    VALUES_CHECK(r==MATTER_TLV_DONE && !depth && data_count && more!=suppress);
    return more;
}

#undef VALUES_CHECK

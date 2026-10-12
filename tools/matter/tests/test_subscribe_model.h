#define SUB_CHECK(c) do { if(!(c)) { fprintf(stderr,"Subscribe model:%d: %s\n",__LINE__,#c); abort(); } } while(0)
static const uint8_t sub_request[]={0x15,0x29,0,0x24,1,2,0x24,2,5,0x36,3,0x17,0x24,2,0,0x24,3,0x28,0x24,4,2,0x18,0x18,0x29,7,0x24,0xff,13,0x18};
static const uint8_t sub_success[]={0x15,0x24,0,0,0x24,0xff,13,0x18};
static const uint8_t sub_response[]={0x15,0x24,0,42,0x24,2,5,0x24,0xff,13,0x18};
static const uint8_t sub_report[]={0x15,0x24,0,42,0x36,1,0x15,0x35,1,0x24,0,7,0x37,1,0x24,2,0,0x24,3,0x28,
    0x24,4,2,0x18,0x24,2,9,0x18,0x18,0x18,0x28,4,0x24,0xff,13,0x18};
static const uint8_t sub_empty[]={0x15,0x24,0,42,0x36,1,0x18,0x28,4,0x24,0xff,13,0x18};
typedef struct SubModel {
    Matter_Im_Subscribe_T active;
    struct SubModel* other;
    Matter_Exchange_Session_T session;
    unsigned reads, auths, reserves, releases;
    uint32_t id, version;
    uint64_t value;
    bool deny, fabric, read_error, reserve_error, keep, report_on_version;
    Matter_Tlv_Type_T type;
    uint8_t input[1025];
} SubModel;
static void sub_guard(SubModel* m) {
    SUB_CHECK(matter_im_subscribe_cancel(m->active)==MATTER_BUSY && matter_im_subscribe_delete(m->active)==MATTER_BUSY);
    SUB_CHECK(matter_im_subscribe_changed(m->active)==MATTER_BUSY && matter_im_subscribe_process(m->active,0)==MATTER_BUSY);
    SUB_CHECK(matter_im_subscribe_events_changed(m->active)==MATTER_BUSY && matter_im_subscribe_bind_events(m->active,NULL)==MATTER_BUSY);
    SUB_CHECK(matter_im_subscribe_receive(m->active,NULL)==MATTER_BUSY && matter_im_subscribe_bind_report(m->active,NULL,0)==MATTER_BUSY);
}
static Matter_Im_Status_T sub_allow(void* u,Matter_Exchange_Session_T session,const Matter_Im_Path_T* p,Matter_Im_Privilege_T privilege) {
    SubModel* m=u; sub_guard(m); SUB_CHECK(session && !p->endpoint && p->cluster==0x28 && p->attribute==2 && privilege==MATTER_IM_VIEW);
    ++m->auths; return m->deny ? MATTER_IM_UNSUPPORTED_ACCESS : 0;
}
static Matter_Im_Status_T sub_describe(void* u,const Matter_Im_Path_T* p,Matter_Im_Attribute_T* a) {
    SubModel* m=u; (void)p; sub_guard(m); *a=(Matter_Im_Attribute_T){MATTER_IM_VIEW,m->fabric}; return 0;
}
static Matter_Im_Status_T sub_read(void* u,const Matter_Im_Path_T* p,bool filtered,Matter_Im_Value_T* v) {
    SubModel* m=u; (void)p; sub_guard(m); SUB_CHECK(filtered); ++m->reads;
    *v=(Matter_Im_Value_T){.type=m->type,.unsigned_value=m->value,.signed_value=-9,.data_version=m->version,.report_on_version_change=m->report_on_version};
    return m->read_error ? MATTER_IM_FAILURE : 0;
}
static uint8_t sub_reserve(void* u,Matter_Exchange_Session_T session,bool keep,uint32_t* id) {
    SubModel* m=u; sub_guard(m); SUB_CHECK(session); ++m->reserves; m->keep=keep;
    m->session=session;
    if(!keep && m->other && m->other->session==session) SUB_CHECK(matter_im_subscribe_cancel(m->other->active)==MATTER_OK);
    *id=m->id; return m->reserve_error ? MATTER_IM_RESOURCE_EXHAUSTED : 0;
}
static void sub_release(void* u,uint32_t id) {
    SubModel* m=u; sub_guard(m); SUB_CHECK(id==m->id && !m->releases); ++m->releases;
}
static Matter_Im_Subscribe_Port_T sub_port(SubModel* m) {
    m->id=42; m->version=7; m->value=9; m->type=MATTER_TLV_UNSIGNED;
    return (Matter_Im_Subscribe_Port_T){{m,sub_allow,sub_describe,sub_read,NULL,NULL},sub_reserve,sub_release};
}
#undef SUB_CHECK

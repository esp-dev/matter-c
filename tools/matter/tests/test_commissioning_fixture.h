/* Shared RAM recovery backend, optionally driving actual secure retirement. */
typedef struct {
    RootFixture* f;
    Matter_Root_Commissioning_Config_T config;
    Matter_Root_Invoke_Binding_T binding;
    Matter_Im_Invoke_Port_T invoke;
    unsigned begins,cleanups,regulations,network,saved_network;
    uint8_t radio;
    bool marker,revoked,fail_begin,fail_cleanup,pending_cleanup,fail_regulatory;
    bool window,fail_window;
    Matter_Result_T (*cleanup_hook)(void*);
    void* hook_user;
} GcFixture;
static Matter_Result_T gc_window(void* u,bool* open) {
    GcFixture* g=u; *open=g->window; return g->fail_window?MATTER_PORT_ERROR:MATTER_OK;
}
static Matter_Result_T gc_begin(void* u) {
    GcFixture* g=u; ++g->begins;
    ROOT_CHECK(matter_root_expire(g->f->root)==MATTER_BUSY);
    if(g->fail_begin) return MATTER_PORT_ERROR;
    ROOT_CHECK(!g->marker); g->saved_network=g->network; g->marker=true; return MATTER_OK;
}
static Matter_Result_T gc_cleanup(void* u) {
    GcFixture* g=u; ++g->cleanups;
    ROOT_CHECK(matter_root_delete(g->f->root)==MATTER_BUSY);
    g->revoked=true;
    g->f->denied=MATTER_IM_UNSUPPORTED_ACCESS;
    if(g->cleanup_hook) { Matter_Result_T r=g->cleanup_hook(g->hook_user); if(r!=MATTER_OK) return r; }
    if(g->fail_cleanup) return MATTER_PORT_ERROR;
    if(g->pending_cleanup) return MATTER_PENDING;
    g->network=g->saved_network; g->marker=false; return MATTER_OK;
}
static Matter_Result_T gc_regulatory(void* u,const Matter_Root_Settings_T* s,uint8_t candidate,bool* supported) {
    GcFixture* g=u; ++g->regulations;
    ROOT_CHECK(matter_root_expire(g->f->root)==MATTER_BUSY);
    if(g->fail_regulatory) return MATTER_PORT_ERROR;
    g->f->durable.settings=*s; g->radio=candidate;
    *supported=memcmp(s->location,"ZZ",2)!=0; return MATTER_OK;
}
static GcFixture* gc_fixture(void) {
    GcFixture* g=calloc(1,sizeof(*g)); ROOT_CHECK(g); g->f=root_fixture();
    g->config=(Matter_Root_Commissioning_Config_T){.recommended_seconds=2,.cumulative_seconds=5,
        .location_capability=2,.regulatory_config=2,.concurrent_connection=true,.data_version=13};
    g->network=3; g->radio=2; return g;
}
static void gc_open(GcFixture* g,uint64_t now) {
    Matter_Root_Port_T p=root_port(g->f); Matter_Root_Commissioning_Port_T cp={g,gc_begin,gc_cleanup,gc_regulatory,gc_window};
    g->f->root=matter_root_new_commissioning(&p,&g->config,&cp,now); ROOT_CHECK(g->f->root);
    ROOT_CHECK(matter_root_ports(g->f->root,&g->f->read,&g->f->write)==MATTER_OK);
    ROOT_CHECK(matter_root_invoke_port(g->f->root,g->f->session,&g->binding,&g->invoke)==MATTER_OK);
}
static void gc_release(GcFixture* g,uint64_t now) {
    if(g->f->root) {
        g->fail_cleanup=g->pending_cleanup=false; g->cleanup_hook=NULL;
        Matter_Result_T r=matter_root_expire(g->f->root); ROOT_CHECK(r==MATTER_OK || r==MATTER_PENDING);
        ROOT_CHECK(matter_root_process(g->f->root,now)==MATTER_OK);
    }
    root_release(g->f); free(g);
}
static void gc_request(GcFixture* g,uint32_t command,uint64_t value,const char* country,uint64_t breadcrumb) {
    RootFixture* f=g->f;
    ROOT_CHECK(matter_tlv_writer_init(&f->writer,f->request,sizeof(f->request),6)==MATTER_TLV_OK);
    root_put(f,MATTER_TLV_STRUCTURE,-1,0,NULL,0); root_put(f,MATTER_TLV_BOOL,0,0,NULL,0); root_put(f,MATTER_TLV_BOOL,1,0,NULL,0);
    root_put(f,MATTER_TLV_ARRAY,2,0,NULL,0); root_put(f,MATTER_TLV_STRUCTURE,-1,0,NULL,0); root_put(f,MATTER_TLV_LIST,0,0,NULL,0);
    root_put(f,MATTER_TLV_UNSIGNED,0,0,NULL,0); root_put(f,MATTER_TLV_UNSIGNED,1,0x30,NULL,0); root_put(f,MATTER_TLV_UNSIGNED,2,command,NULL,0);
    root_put(f,MATTER_TLV_END,-1,0,NULL,0); root_put(f,MATTER_TLV_STRUCTURE,1,0,NULL,0);
    if(command!=4) {
        root_put(f,MATTER_TLV_UNSIGNED,0,value,NULL,0);
        if(command==2) root_put(f,MATTER_TLV_UTF8,1,0,(const uint8_t*)country,strlen(country));
        root_put(f,MATTER_TLV_UNSIGNED,command==0?1:2,breadcrumb,NULL,0);
    }
    root_put(f,MATTER_TLV_END,-1,0,NULL,0); root_put(f,MATTER_TLV_END,-1,0,NULL,0); root_put(f,MATTER_TLV_END,-1,0,NULL,0);
    root_put(f,MATTER_TLV_UNSIGNED,255,13,NULL,0); root_put(f,MATTER_TLV_END,-1,0,NULL,0);
    ROOT_CHECK(matter_tlv_writer_finish(&f->writer,&f->request_size)==MATTER_TLV_OK);
}
static void gc_reply(const uint8_t* data,size_t size,uint32_t command,uint8_t code,bool status) {
    const uint8_t response[]={0x15,0x29,0,0x36,1,0x15,0x35,0,0x37,0,0x24,0,0,0x24,1,0x30,0x24,2,(uint8_t)(command+1),
        0x18,0x35,1,0x24,0,code,0x2c,1,0,0x18,0x18,0x18,0x18,0x24,255,13,0x18};
    const uint8_t error[]={0x15,0x29,0,0x36,1,0x15,0x35,1,0x37,0,0x24,0,0,0x24,1,0x30,0x24,2,(uint8_t)command,
        0x18,0x35,1,0x24,0,code,0x18,0x18,0x18,0x18,0x24,255,13,0x18};
    ROOT_CHECK(size==(status?sizeof(error):sizeof(response)) && !memcmp(data,status?error:response,size));
}
static uint64_t gc_scalar(GcFixture* g,uint32_t cluster,uint32_t attribute,uint32_t* version) {
    Matter_Im_Path_T p={0,cluster,attribute}; Matter_Im_Value_T v;
    ROOT_CHECK(g->f->read.read(g->f->root,&p,true,&v)==0 && (v.type==MATTER_TLV_UNSIGNED || v.type==MATTER_TLV_BOOL));
    if(version) *version=v.data_version;
    return v.unsigned_value;
}

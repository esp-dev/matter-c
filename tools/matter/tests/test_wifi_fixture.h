#include "../host/matter_wifi_sim.h"
typedef struct {
    GcFixture* g;
    Matter_Wifi_T wifi; Matter_Wifi_Sim_T sim;
    Matter_Wifi_Sim_Config_T config; Matter_Wifi_Sim_Control_T control;
    Matter_Im_Invoke_Async_Port_T async;
    Matter_Wifi_Completion_T completion;
    uint64_t now;
} WifiFixture;
static Matter_Result_T wf_begin(void* u) {
    WifiFixture* w=u; Matter_Result_T r=gc_begin(w->g); if(r!=MATTER_OK) return r;
    ROOT_CHECK(matter_wifi_checkpoint(w->wifi)==MATTER_OK); return MATTER_OK;
}
static Matter_Result_T wf_cleanup(void* u) {
    WifiFixture* w=u; GcFixture* g=w->g;
    g->revoked=true; g->f->denied=MATTER_IM_UNSUPPORTED_ACCESS;
    if(g->cleanup_hook) { Matter_Result_T r=g->cleanup_hook(g->hook_user); if(r!=MATTER_OK) return r; }
    Matter_Result_T r=matter_wifi_rollback(w->wifi); if(r!=MATTER_OK) return r;
    return gc_cleanup(g);
}
static Matter_Result_T wf_regulatory(void* u,const Matter_Root_Settings_T* s,uint8_t v,bool* supported) {
    return gc_regulatory(((WifiFixture*)u)->g,s,v,supported);
}
static Matter_Wifi_Id_T wf_id(const char* s) {
    Matter_Wifi_Id_T id={0}; id.size=(uint8_t)strlen(s); ROOT_CHECK(id.size<=32); memcpy(id.bytes,s,id.size); return id;
}
static WifiFixture* wf_new_product(uint64_t now,Matter_Exchange_Session_T session,uint16_t product) {
    WifiFixture* w=calloc(1,sizeof(*w)); ROOT_CHECK(w); w->now=now; w->g=gc_fixture();
    w->g->f->durable.product_id=product;
    w->g->f->session=session; w->g->config.recommended_seconds=30; w->g->config.cumulative_seconds=90;
    w->config.initial.enabled=true; w->config.initial.count=1; w->config.initial.networks[0].id=wf_id("old"); w->config.connected=wf_id("old");
    w->config.count=3; w->config.latency_ms=500;
    for(unsigned i=0;i<3;++i) {
        Matter_Wifi_Sim_Ap_T* ap=&w->config.aps[i]; ap->ap.ssid=wf_id(i==2?"guest":"new");
        ap->ap.security=i?8:4; ap->ap.band=i?2:0; ap->ap.channel=i?36:1; ap->ap.rssi=(int8_t)(-30-(int)i*10); ap->ap.bssid[5]=(uint8_t)(i+1);
        ap->credential_size=8; memcpy(ap->credentials,"password",8);
    }
    w->sim=matter_wifi_sim_new(&w->config,now); ROOT_CHECK(w->sim);
    Matter_Wifi_Port_T p=matter_wifi_sim_port(w->sim); Matter_Wifi_Config_T c={3,2,3,5,17,100};
    w->wifi=matter_wifi_new(&c,&p,now); ROOT_CHECK(w->wifi);
    Matter_Root_Port_T rp=root_port(w->g->f); Matter_Root_Commissioning_Port_T cp={w,wf_begin,wf_cleanup,wf_regulatory,NULL};
    w->g->f->root=matter_root_new_commissioning(&rp,&w->g->config,&cp,now); ROOT_CHECK(w->g->f->root);
    ROOT_CHECK(matter_root_attach_wifi(w->g->f->root,w->wifi)==MATTER_OK);
    ROOT_CHECK(matter_root_ports(w->g->f->root,&w->g->f->read,&w->g->f->write)==MATTER_OK);
    ROOT_CHECK(matter_root_wifi_invoke_port(w->g->f->root,session,&w->g->binding,&w->g->invoke,&w->async)==MATTER_OK); return w;
}
static WifiFixture* wf_new(uint64_t now,Matter_Exchange_Session_T session) {
    return wf_new_product(now,session,0x8001);
}
static void wf_tick(WifiFixture* w,uint64_t now) {
    w->now=now;
    Matter_Result_T r=matter_wifi_sim_process(w->sim,w->wifi,now); ROOT_CHECK(r==MATTER_OK || r==MATTER_PENDING);
    r=matter_root_process(w->g->f->root,now); ROOT_CHECK(r==MATTER_OK || r==MATTER_PENDING);
}
static void wf_release(WifiFixture* w) {
    w->control=(Matter_Wifi_Sim_Control_T){0}; matter_wifi_sim_control(w->sim,&w->control);
    gc_release(w->g,w->now);
    ROOT_CHECK(matter_wifi_stop(w->wifi)==MATTER_OK && matter_wifi_delete(w->wifi)==MATTER_OK);
    ROOT_CHECK(matter_wifi_sim_delete(w->sim)==MATTER_OK); free(w);
}
static void wf_request(WifiFixture* w,uint32_t command,const char* id,const char* credentials,uint8_t index,uint64_t breadcrumb) {
    RootFixture* f=w->g->f;
    ROOT_CHECK(matter_tlv_writer_init(&f->writer,f->request,sizeof(f->request),6)==MATTER_TLV_OK);
    root_put(f,MATTER_TLV_STRUCTURE,-1,0,NULL,0); root_put(f,MATTER_TLV_BOOL,0,0,NULL,0); root_put(f,MATTER_TLV_BOOL,1,0,NULL,0);
    root_put(f,MATTER_TLV_ARRAY,2,0,NULL,0); root_put(f,MATTER_TLV_STRUCTURE,-1,0,NULL,0); root_put(f,MATTER_TLV_LIST,0,0,NULL,0);
    root_put(f,MATTER_TLV_UNSIGNED,0,0,NULL,0); root_put(f,MATTER_TLV_UNSIGNED,1,0x31,NULL,0); root_put(f,MATTER_TLV_UNSIGNED,2,command,NULL,0);
    root_put(f,MATTER_TLV_END,-1,0,NULL,0); root_put(f,MATTER_TLV_STRUCTURE,1,0,NULL,0);
    if(id) root_put(f,MATTER_TLV_BYTES,0,0,(const uint8_t*)id,strlen(id));
    if(command==2) root_put(f,MATTER_TLV_BYTES,1,0,(const uint8_t*)credentials,strlen(credentials));
    if(command==8) root_put(f,MATTER_TLV_UNSIGNED,1,index,NULL,0);
    root_put(f,MATTER_TLV_UNSIGNED,command==2 || command==8?2:1,breadcrumb,NULL,0);
    root_put(f,MATTER_TLV_END,-1,0,NULL,0); root_put(f,MATTER_TLV_END,-1,0,NULL,0); root_put(f,MATTER_TLV_END,-1,0,NULL,0);
    root_put(f,MATTER_TLV_UNSIGNED,255,13,NULL,0); root_put(f,MATTER_TLV_END,-1,0,NULL,0);
    ROOT_CHECK(matter_tlv_writer_finish(&f->writer,&f->request_size)==MATTER_TLV_OK);
}
static Matter_Im_Invoke_T wf_start(WifiFixture* w,size_t capacity,uint32_t timeout) {
    RootFixture* f=w->g->f; Matter_Im_Invoke_Config_T c={{f->session,0x4321,false},timeout,capacity,true};
    Matter_Im_Invoke_T im=matter_im_invoke_new_async(&w->g->invoke,&w->async,&c,w->now); ROOT_CHECK(im);
    Matter_Rx_Decision_T rx={.action=MATTER_RX_NEW_RESPONDER,.session=f->session,
        .header={.protocol_id=1,.opcode=8,.exchange_id=0x4321,.exchange_flags=5},.payload=f->request,.payload_size=f->request_size};
    ROOT_CHECK(matter_im_invoke_receive_at(im,&rx,w->now)==MATTER_OK && matter_im_invoke_process(im,w->now)==MATTER_PENDING); return im;
}
static void wf_reply(WifiFixture* w,const uint8_t* data,size_t size,uint32_t command,uint8_t status,bool im_status) {
    RootFixture* f=w->g->f; unsigned depth=0,got_status=0,got_command=0; bool path=false;
    ROOT_CHECK(matter_tlv_init(&f->reader,data,size,8)==MATTER_TLV_OK); Matter_Tlv_Result_T r;
    while((r=matter_tlv_next(&f->reader,&f->token))==MATTER_TLV_OK) {
        Matter_Tlv_Element_T* e=&f->token;
        if(e->type==MATTER_TLV_END) { ROOT_CHECK(depth); --depth; continue; }
        if(depth==3) ROOT_CHECK(e->tag.number==(im_status?1u:0u));
        if(depth==4) path=e->tag.number==0;
        if(depth==5 && path && e->tag.number==1) ROOT_CHECK(e->unsigned_value==0x31);
        if(depth==5 && path && e->tag.number==2) { ROOT_CHECK(e->unsigned_value==(im_status?command:command==0?1:command==6?7:5)); ++got_command; }
        if(depth==5 && !path && e->tag.number==0 && e->type==MATTER_TLV_UNSIGNED && got_command) { ROOT_CHECK(e->unsigned_value==status); ++got_status; }
        if(e->type==MATTER_TLV_STRUCTURE || e->type==MATTER_TLV_ARRAY || e->type==MATTER_TLV_LIST) ++depth;
    }
    ROOT_CHECK(r==MATTER_TLV_DONE && !depth && got_status==1 && got_command==1);
}
static void wf_finish(WifiFixture* w,Matter_Im_Invoke_T im,uint32_t command,uint8_t status,bool im_status) {
    Matter_Im_Invoke_Message_T out; ROOT_CHECK(matter_im_invoke_output(im,&out)==MATTER_OK);
    wf_reply(w,out.data,out.size,command,status,im_status);
    ROOT_CHECK(matter_im_invoke_sent_at(im,w->now)==MATTER_OK && matter_im_invoke_confirm(im,w->now)==MATTER_OK && matter_im_invoke_delete(im)==MATTER_OK);
}
static void wf_command(WifiFixture* w,uint32_t command,const char* id,const char* credentials,uint8_t index,uint64_t crumb,uint8_t code,bool status) {
    wf_request(w,command,id,credentials,index,crumb); Matter_Im_Invoke_T im=wf_start(w,1024,10000);
    if(matter_im_invoke_state(im)==MATTER_IM_INVOKE_PENDING) { wf_tick(w,w->now+500); ROOT_CHECK(matter_im_invoke_process(im,w->now)==MATTER_PENDING); }
    wf_finish(w,im,command,code,status);
}
static void wf_arm(WifiFixture* w,uint16_t seconds) {
    gc_request(w->g,0,seconds,NULL,1); Matter_Im_Invoke_T im=wf_start(w,256,1000);
    Matter_Im_Invoke_Message_T out; ROOT_CHECK(matter_im_invoke_output(im,&out)==MATTER_OK);
    gc_reply(out.data,out.size,0,0,false);
    ROOT_CHECK(matter_im_invoke_delete(im)==MATTER_OK);
}

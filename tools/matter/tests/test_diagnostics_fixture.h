#include "matter_diagnostics_host.h"
typedef struct {
    Matter_Wifi_Sim_Config_T config; Matter_Wifi_Sim_T sim; Matter_Wifi_T wifi;
    Matter_Diagnostics_Host_Image_T image; Matter_Diagnostics_Host_T host; Matter_Diagnostics_T model;
    Matter_Diagnostics_Interface_T iface; Matter_Diagnostics_Port_T port;
    Matter_Tlv_Reader_T reader; Matter_Tlv_Writer_T writer; Matter_Tlv_Element_T e;
    uint8_t response[4096]; size_t response_size;
} DiagFixture;
static inline DiagFixture* diag_fixture(void) {
    DiagFixture* f=calloc(1,sizeof(*f)); DIAG_CHECK(f);
    f->config.initial.enabled=true; f->config.initial.count=1; f->config.connected=(Matter_Wifi_Id_T){3,{'l','a','b'}};
    f->config.initial.networks[0].id=f->config.connected; f->config.count=1; f->config.latency_ms=10;
    f->config.aps[0].ap=(Matter_Wifi_Ap_T){.ssid={3,{'l','a','b'}},.security=8,.bssid={2,3,4,5,6,7},.band=0,.channel=6,.rssi=-42};
    f->sim=matter_wifi_sim_new(&f->config,0); DIAG_CHECK(f->sim);
    Matter_Wifi_Port_T wp=matter_wifi_sim_port(f->sim); Matter_Wifi_Config_T wc={4,2,2,1,17,100};
    f->wifi=matter_wifi_new(&wc,&wp,0); DIAG_CHECK(f->wifi);
    f->iface=(Matter_Diagnostics_Interface_T){.name={'s','i','m','-','w','l','a','n','0'},.name_size=9,.type=1,
        .hardware={0,0,2,3,4,5,6,8},.reachable4=-1,.reachable6=-1,.ipv6_count=1,.ipv6={{0xfe,0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,1}}};
    f->host=matter_diagnostics_host_new(&f->image,f->sim,&f->iface,1,true,0); DIAG_CHECK(f->host);
    matter_diagnostics_host_radio(f->host,3,65000000);
    f->port=matter_diagnostics_host_port(f->host); f->model=matter_diagnostics_new(&f->port,31,41); DIAG_CHECK(f->model); return f;
}
static inline void diag_tick(DiagFixture* f,uint64_t now) {
    DIAG_CHECK(matter_diagnostics_host_process(f->host,now)==MATTER_OK && matter_diagnostics_refresh(f->model)==MATTER_OK);
}
static inline Matter_Im_Value_T diag_read(DiagFixture* f,uint32_t c,uint32_t a,uint8_t fabric) {
    Matter_Im_Value_T v; DIAG_CHECK(!matter_diagnostics_read(f->model,c,a,fabric,&v)); return v;
}
static inline uint8_t diag_command(DiagFixture* f,uint32_t c,uint32_t cmd,const uint8_t* data,size_t n) {
    DIAG_CHECK(matter_tlv_writer_init(&f->writer,f->response,sizeof(f->response),4)==MATTER_TLV_OK);
    uint8_t r=matter_diagnostics_invoke(f->model,c,cmd,data,n,&f->writer).status;
    if(!r && c==0x33 && cmd==1) DIAG_CHECK(matter_tlv_writer_finish(&f->writer,&f->response_size)==MATTER_TLV_OK);
    return r;
}
static inline void diag_release(DiagFixture* f) {
    if(!f) return;
    DIAG_CHECK(matter_diagnostics_delete(f->model)==MATTER_OK && matter_diagnostics_host_delete(f->host)==MATTER_OK);
    DIAG_CHECK(matter_wifi_stop(f->wifi)==MATTER_OK && matter_wifi_delete(f->wifi)==MATTER_OK && matter_wifi_sim_delete(f->sim)==MATTER_OK); free(f);
}

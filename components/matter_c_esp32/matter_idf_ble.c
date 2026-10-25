#include "matter_idf_ble.h"
#include "transport/matter_btp.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/ble_uuid.h"
#include "host/util/util.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "sdkconfig.h"
#if CONFIG_MATTER_C_ESP32_UDP_TRACE
#include <stdio.h>
#define TRACE(...) printf(__VA_ARGS__)
#else
#define TRACE(...) ((void)0)
#endif
#include <stdlib.h>
#include <string.h>

enum { FRAGMENTS=4, FRAGMENT_SIZE=244 };
typedef struct Frame {struct Frame* next;uint32_t generation;uint16_t size;uint8_t bytes[FRAGMENT_SIZE];} Frame;
struct Matter_Idf_Ble {
    Matter_Udp_T module;Matter_Operation_Id_T epoch;Matter_Btp_T engine;
    portMUX_TYPE lock;Frame *frames,*free,*head,*tail;
    uint32_t generation,observed,closed;uint16_t conn,tx_handle,rx_handle;
    uint16_t vendor,product,discriminator,advertised;
    uint8_t address_type;bool synced,connected,subscribed,fault,indication_done;
    int indication_status;bool enabled,initialized,indicating,busy,cancelled,receive_enabled;
    uint64_t request,now,connected_at,last_data,advertising_at,indication_at,retry_at,stalled_at;
    struct ble_gatt_chr_def characteristics[3];struct ble_gatt_svc_def services[2];
};
/* Hardware host callbacks are global in NimBLE. Ownership is exclusive until
 * host stop/task deletion/controller deinit have formed the callback barrier. */
static Matter_Idf_Ble_T host;
static const ble_uuid16_t service=BLE_UUID16_INIT(0xfff6);
static const ble_uuid128_t rx_uuid=BLE_UUID128_INIT(0x11,0x9d,0x9f,0x42,0x9c,0x4f,0x9f,0x95,0x59,0x45,0x3d,0x26,0xf5,0x2e,0xee,0x18);
static const ble_uuid128_t tx_uuid=BLE_UUID128_INIT(0x12,0x9d,0x9f,0x42,0x9c,0x4f,0x9f,0x95,0x59,0x45,0x3d,0x26,0xf5,0x2e,0xee,0x18);
static void wipe(void* p,size_t n){volatile uint8_t* b=p;while(n--)*b++=0;}
static int access_characteristic(uint16_t conn,uint16_t attr,struct ble_gatt_access_ctxt* c,void* user){
    Matter_Idf_Ble_T s=user;
    if(c->op==BLE_GATT_ACCESS_OP_READ_CHR&&attr==s->tx_handle)return 0;
    if(c->op!=BLE_GATT_ACCESS_OP_WRITE_CHR||attr!=s->rx_handle)return BLE_ATT_ERR_WRITE_NOT_PERMITTED;
    unsigned size=OS_MBUF_PKTLEN(c->om);if(!size||size>FRAGMENT_SIZE)return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
    portENTER_CRITICAL(&s->lock);
    Frame* f=s->connected&&s->conn==conn?s->free:NULL;
    if(f){s->free=f->next;f->generation=s->generation;}else s->fault=true;
    portEXIT_CRITICAL(&s->lock);
    if(!f)return BLE_ATT_ERR_INSUFFICIENT_RES;
    int rc=os_mbuf_copydata(c->om,0,size,f->bytes);f->size=size;f->next=NULL;
    portENTER_CRITICAL(&s->lock);
    if(rc){f->next=s->free;s->free=f;s->fault=true;}
    else {if(s->tail)s->tail->next=f;else s->head=f;s->tail=f;}
    portEXIT_CRITICAL(&s->lock);
    return rc?BLE_ATT_ERR_UNLIKELY:0;
}
static int gap_event(struct ble_gap_event* e,void* user){
    Matter_Idf_Ble_T s=user;portENTER_CRITICAL(&s->lock);
    if(e->type==BLE_GAP_EVENT_CONNECT&&!e->connect.status){
        s->connected=true;s->conn=e->connect.conn_handle;s->subscribed=false;s->fault=false;
        if(s->generation==UINT32_MAX)s->fault=true;else ++s->generation;
    }else if(e->type==BLE_GAP_EVENT_DISCONNECT){s->connected=false;s->subscribed=false;s->conn=BLE_HS_CONN_HANDLE_NONE;}
    else if(e->type==BLE_GAP_EVENT_SUBSCRIBE&&e->subscribe.attr_handle==s->tx_handle)s->subscribed=e->subscribe.cur_indicate!=0;
    else if(e->type==BLE_GAP_EVENT_NOTIFY_TX&&e->notify_tx.attr_handle==s->tx_handle&&e->notify_tx.status){
        s->indication_done=true;s->indication_status=e->notify_tx.status;
    }
    portEXIT_CRITICAL(&s->lock);return 0;
}
static void sync_host(void){
    Matter_Idf_Ble_T s=host;uint8_t type;int rc=ble_hs_util_ensure_addr(0);
    if(!rc)rc=ble_hs_id_infer_auto(0,&type);
    portENTER_CRITICAL(&s->lock);if(rc)s->fault=true;else{s->address_type=type;s->synced=true;}portEXIT_CRITICAL(&s->lock);
}
static void reset_host(int reason){(void)reason;if(host){portENTER_CRITICAL(&host->lock);host->fault=true;host->synced=false;portEXIT_CRITICAL(&host->lock);}}
static void host_task(void* unused){(void)unused;nimble_port_run();for(;;)vTaskSuspend(NULL);}
static Matter_Result_T initialize(Matter_Idf_Ble_T s){
    if(host)return MATTER_BUSY;
    s->frames=calloc(FRAGMENTS,sizeof(*s->frames));if(!s->frames)return MATTER_LIMIT_REACHED;
    for(unsigned i=0;i<FRAGMENTS;++i){s->frames[i].next=s->free;s->free=&s->frames[i];}
    if(nimble_port_init()!=ESP_OK){free(s->frames);s->frames=s->free=NULL;return MATTER_PORT_ERROR;}
    host=s;ble_hs_cfg.sync_cb=sync_host;ble_hs_cfg.reset_cb=reset_host;
    ble_svc_gap_init();ble_svc_gatt_init();
    s->characteristics[0]=(struct ble_gatt_chr_def){.uuid=&rx_uuid.u,.access_cb=access_characteristic,.arg=s,.flags=BLE_GATT_CHR_F_WRITE,.val_handle=&s->rx_handle};
    s->characteristics[1]=(struct ble_gatt_chr_def){.uuid=&tx_uuid.u,.access_cb=access_characteristic,.arg=s,.flags=BLE_GATT_CHR_F_READ|BLE_GATT_CHR_F_INDICATE,.val_handle=&s->tx_handle};
    s->services[0]=(struct ble_gatt_svc_def){.type=BLE_GATT_SVC_TYPE_PRIMARY,.uuid=&service.u,.characteristics=s->characteristics};
    int rc=ble_gatts_count_cfg(s->services);if(!rc)rc=ble_gatts_add_svcs(s->services);
    if(!rc)rc=ble_svc_gap_device_name_set("Matter-C6");
    if(rc){nimble_port_deinit();host=NULL;free(s->frames);s->frames=s->free=NULL;return MATTER_PORT_ERROR;}
    s->initialized=true;nimble_port_freertos_init(host_task);TRACE("MATTER_BLE host=1\n");return MATTER_OK;
}
static Matter_Result_T shutdown_host(Matter_Idf_Ble_T s){
    if(nimble_port_stop())return MATTER_PENDING;
    nimble_port_freertos_deinit(); /* Delete stopped task before freeing callback state. */
    if(nimble_port_deinit()!=ESP_OK)return MATTER_PORT_ERROR;
    host=NULL;s->initialized=s->synced=s->fault=false;s->head=s->tail=s->free=NULL;
    wipe(s->frames,FRAGMENTS*sizeof(*s->frames));free(s->frames);s->frames=NULL;
    TRACE("MATTER_BLE host=0\n");
    return MATTER_OK;
}
static Matter_Result_T activate(void* u,Matter_Operation_Id_T epoch){Matter_Idf_Ble_T s=u;s->epoch=epoch;return MATTER_OK;}
static void deactivate(void* u,Matter_Operation_Id_T epoch){(void)epoch;Matter_Idf_Ble_T s=u;s->epoch=0;s->enabled=false;}
static Matter_Result_T send_packet(void* u,uint64_t id,const Matter_Udp_Datagram_T* d){
    Matter_Idf_Ble_T s=u;
    if(d->path.transport!=MATTER_TRANSPORT_BTP||d->path.interface_id!=s->observed||!s->engine||s->request)return MATTER_OFFLINE;
    Matter_Result_T r=matter_btp_send(s->engine,d->data,d->size);if(r==MATTER_OK){s->request=id;s->last_data=s->now;}return r;
}
static void cancel(void* u,uint64_t id){Matter_Idf_Ble_T s=u;if(s->request==id)s->cancelled=true;}
static void detach(void* u){Matter_Idf_Ble_T s=u;s->module=NULL;}
Matter_Idf_Ble_T matter_idf_ble_new(Matter_T owner,uint16_t vendor,uint16_t product,const Matter_Udp_Listener_T* listener){
    Matter_Idf_Ble_T s=calloc(1,sizeof(*s));if(!s)return NULL;
    s->lock=(portMUX_TYPE)portMUX_INITIALIZER_UNLOCKED;s->vendor=vendor;s->product=product;s->conn=BLE_HS_CONN_HANDLE_NONE;s->receive_enabled=true;
    Matter_Udp_Port_T port={s,activate,deactivate,send_packet,cancel,detach};s->module=matter_udp_new(owner,&port,listener);
    if(!s->module){free(s);return NULL;}return s;
}
Matter_Udp_T matter_idf_ble_module(Matter_Idf_Ble_T s){return s?s->module:NULL;}
void matter_idf_ble_window(Matter_Idf_Ble_T s,bool enabled,uint16_t discriminator){if(s){s->enabled=enabled;s->discriminator=discriminator;}}
void matter_idf_ble_receive_enabled(Matter_Idf_Ble_T s,bool enabled){if(s)s->receive_enabled=enabled;}
uint32_t matter_idf_ble_closed_take(Matter_Idf_Ble_T s){if(!s)return 0;uint32_t n=s->closed;s->closed=0;return n;}
static void end_session(Matter_Idf_Ble_T s){
    TRACE("MATTER_BLE closed=%lu\n",(unsigned long)s->observed);
    if(s->observed)s->closed=s->observed;
    s->observed=0;matter_btp_delete(s->engine);s->engine=NULL;s->indicating=false;
    if(s->request){uint64_t id=s->request;s->request=0;(void)matter_udp_complete(s->module,id,s->cancelled?MATTER_OPERATION_CANCELLED:MATTER_OPERATION_FAILED);}
    s->cancelled=false;s->stalled_at=0;
}
static Matter_Result_T advertise(Matter_Idf_Ble_T s){
    uint8_t data[]={0, (uint8_t)s->discriminator,(uint8_t)(s->discriminator>>8),(uint8_t)s->vendor,(uint8_t)(s->vendor>>8),(uint8_t)s->product,(uint8_t)(s->product>>8),0};
    uint8_t service_data[10]={0xf6,0xff};memcpy(service_data+2,data,sizeof(data));
    struct ble_hs_adv_fields fields={.flags=BLE_HS_ADV_F_DISC_GEN|BLE_HS_ADV_F_BREDR_UNSUP,.uuids16=(ble_uuid16_t*)&service,.num_uuids16=1,.uuids16_is_complete=1,
        .svc_data_uuid16=service_data,.svc_data_uuid16_len=sizeof(service_data),.name=(uint8_t*)"Matter-C6",.name_len=9,.name_is_complete=1};
    int rc=ble_gap_adv_set_fields(&fields);if(rc)return MATTER_PORT_ERROR;
    struct ble_gap_adv_params params={.conn_mode=BLE_GAP_CONN_MODE_UND,.disc_mode=BLE_GAP_DISC_MODE_GEN,.itvl_min=32,.itvl_max=48};
    rc=ble_gap_adv_start(s->address_type,NULL,BLE_HS_FOREVER,&params,gap_event,s);
    if(!rc){s->advertised=s->discriminator;s->advertising_at=s->now;TRACE("MATTER_BLE advertising=1\n");}return rc?MATTER_PORT_ERROR:MATTER_OK;
}
Matter_Result_T matter_idf_ble_process(Matter_Idf_Ble_T s,uint64_t now){
    if(!s)return MATTER_INVALID_ARGUMENT;
    if(s->busy)return MATTER_BUSY;
    s->busy=true;s->now=now;
    Matter_Result_T result=MATTER_OK;
    if(s->enabled&&!s->initialized){if(now<s->retry_at)goto done;result=initialize(s);if(result!=MATTER_OK){s->retry_at=now+1000;goto done;}}
    if(!s->initialized)goto done;
    portENTER_CRITICAL(&s->lock);
    bool connected=s->connected,subscribed=s->subscribed,fault=s->fault,synced=s->synced,confirmed=s->indication_done;
    uint16_t conn=s->conn;uint32_t generation=s->generation;int status=s->indication_status;s->indication_done=false;
    portEXIT_CRITICAL(&s->lock);
    if(s->observed&&(!connected||s->observed!=generation))end_session(s);
    if(connected&&!s->observed){s->observed=generation;s->connected_at=s->last_data=now;TRACE("MATTER_BLE connected=%lu\n",(unsigned long)generation);}
    if(confirmed&&s->indicating){s->indicating=false;if(status!=BLE_HS_EDONE)fault=true;}
    if(synced&&(!s->enabled||s->advertised!=s->discriminator)&&ble_gap_adv_active())(void)ble_gap_adv_stop();
    if(synced&&s->enabled&&!connected&&!ble_gap_adv_active()){result=advertise(s);if(result!=MATTER_OK)goto done;}
    if(connected){
        if(s->cancelled||(!s->epoch)||(!s->enabled&&now-s->last_data>=30000)||(!s->engine&&now-s->connected_at>=5000)||
            (s->indicating&&now-s->indication_at>=15000)||(s->stalled_at&&now-s->stalled_at>=15000))fault=true;
        if(s->engine&&matter_btp_process(s->engine,now)!=MATTER_OK&&!s->indicating)fault=true;
        if(fault){(void)ble_gap_terminate(conn,BLE_ERR_REM_USER_CONN_TERM);goto done;}
        const uint8_t* bytes;size_t size;
        if(s->engine&&matter_btp_received(s->engine,&bytes,&size)==MATTER_OK){
            if(!s->receive_enabled)goto transmit;
            Matter_Udp_Datagram_T d={.path={.interface_id=s->observed,.transport=MATTER_TRANSPORT_BTP},.data=bytes,.size=size};
            result=matter_udp_receive(s->module,s->epoch,&d,false);matter_btp_received_release(s->engine);s->last_data=now;
            goto transmit; /* Deliver at most one SDU per owner iteration. */
        }
        portENTER_CRITICAL(&s->lock);Frame* f=s->head;if(f){s->head=f->next;if(!s->head)s->tail=NULL;}portEXIT_CRITICAL(&s->lock);
        if(f){
            if(f->generation==s->observed){
                if(!s->engine)s->engine=matter_btp_new(ble_att_mtu(conn),now);
                Matter_Result_T r=s->engine?matter_btp_receive(s->engine,f->bytes,f->size,now):MATTER_LIMIT_REACHED;
                if(r!=MATTER_OK){TRACE("MATTER_BLE rx_error=%u size=%u\n",(unsigned)r,(unsigned)f->size);fault=true;}
            }
            portENTER_CRITICAL(&s->lock);wipe(f->bytes,f->size);f->next=s->free;s->free=f;portEXIT_CRITICAL(&s->lock);
            if(fault){(void)ble_gap_terminate(conn,BLE_ERR_REM_USER_CONN_TERM);goto done;}
        }
transmit:
        if(s->request&&!s->indicating){
            Matter_Result_T r=matter_btp_send_take(s->engine);
            if(r!=MATTER_PENDING){uint64_t id=s->request;s->request=0;TRACE("MATTER_BLE tx=%llu outcome=%u\n",(unsigned long long)id,(unsigned)r);result=matter_udp_complete(s->module,id,r==MATTER_OK?MATTER_OPERATION_SUCCEEDED:MATTER_OPERATION_FAILED);}
        }
        if(subscribed&&s->engine&&!s->indicating&&matter_btp_output(s->engine,&bytes,&size,now)==MATTER_OK){
            struct os_mbuf* data=ble_hs_mbuf_from_flat(bytes,size);
            if(data){int rc=ble_gatts_indicate_custom(conn,s->tx_handle,data);if(!rc){s->stalled_at=0;s->indicating=true;s->indication_at=now;if(matter_btp_sent(s->engine,now)!=MATTER_OK)(void)ble_gap_terminate(conn,BLE_ERR_REM_USER_CONN_TERM);}else if(!s->stalled_at)s->stalled_at=now;}
            else if(!s->stalled_at)s->stalled_at=now;
        }
    }else {
        portENTER_CRITICAL(&s->lock);
        if(!s->connected){Frame* f=s->head;while(f){Frame* next=f->next;wipe(f->bytes,f->size);f->next=s->free;s->free=f;f=next;}s->head=s->tail=NULL;}
        portEXIT_CRITICAL(&s->lock);
        if(!s->enabled)result=shutdown_host(s);
    }
done:
    s->busy=false;return result;
}
Matter_Result_T matter_idf_ble_delete(Matter_Idf_Ble_T s){
    if(!s)return MATTER_OK;
    if(s->busy||s->initialized||s->request||s->engine)return MATTER_BUSY;
    Matter_Result_T r=matter_udp_delete(s->module);if(r==MATTER_OK){wipe(s,sizeof(*s));free(s);}return r;
}

#include "matter_idf_network.h"
#include "matter_idf_ble.h"
#include "matter_idf_udp.h"
#include "esp_netif_ip_addr.h"
#include <stdlib.h>
struct Matter_Idf_Network {
    Matter_Udp_T module;Matter_Idf_Udp_T udp;Matter_Idf_Ble_T ble;esp_netif_t* iface;
    Matter_Operation_Id_T epoch;uint64_t request,child;uint8_t transport;
    bool delivered,ble_first,busy;
};
static void received(void* u,const Matter_Udp_Datagram_T* d){
    Matter_Idf_Network_T s=u;
    if(s->epoch&&!s->delivered){s->delivered=true;(void)matter_udp_receive(s->module,s->epoch,d,false);}
}
static void completed(Matter_Idf_Network_T s,uint8_t transport,uint64_t child,Matter_Operation_Result_T outcome){
    if(s->request&&s->child==child&&s->transport==transport){uint64_t id=s->request;s->request=s->child=0;(void)matter_udp_complete(s->module,id,outcome);}
}
static void udp_sent(void* u,uint64_t id,Matter_Operation_Result_T outcome){completed(u,MATTER_TRANSPORT_UDP,id,outcome);}
static void ble_sent(void* u,uint64_t id,Matter_Operation_Result_T outcome){completed(u,MATTER_TRANSPORT_BTP,id,outcome);}
static Matter_Result_T activate(void* u,Matter_Operation_Id_T epoch){
    Matter_Idf_Network_T s=u;Matter_Result_T r=matter_udp_start(matter_idf_ble_module(s->ble));
    if(r==MATTER_OK)s->epoch=epoch;
    return r;
}
static void deactivate(void* u,Matter_Operation_Id_T epoch){
    (void)epoch;Matter_Idf_Network_T s=u;s->epoch=0;matter_idf_ble_window(s->ble,false,0);
    (void)matter_udp_stop(matter_idf_ble_module(s->ble));(void)matter_udp_stop(matter_idf_udp_module(s->udp));
}
static Matter_Result_T send_packet(void* u,uint64_t id,const Matter_Udp_Datagram_T* d){
    Matter_Idf_Network_T s=u;if(s->request)return MATTER_WOULD_BLOCK;
    Matter_Udp_T child=d->path.transport==MATTER_TRANSPORT_BTP?matter_idf_ble_module(s->ble):matter_idf_udp_module(s->udp);
    uint64_t token;Matter_Result_T r=matter_udp_send(child,d,&token);
    if(r==MATTER_PENDING){s->request=id;s->child=token;s->transport=d->path.transport;return MATTER_OK;}return r;
}
static void cancel(void* u,uint64_t id){
    Matter_Idf_Network_T s=u;if(s->request!=id)return;
    (void)matter_udp_stop(s->transport==MATTER_TRANSPORT_BTP?matter_idf_ble_module(s->ble):matter_idf_udp_module(s->udp));
}
static void detach(void* u){((Matter_Idf_Network_T)u)->module=NULL;}
Matter_Idf_Network_T matter_idf_network_new(Matter_T owner,esp_netif_t* iface,uint16_t port,uint16_t vendor,uint16_t product,const Matter_Udp_Listener_T* listener){
    if(!owner||!iface)return NULL;
    Matter_Idf_Network_T s=calloc(1,sizeof(*s));if(!s)return NULL;s->iface=iface;
    Matter_Udp_Listener_T ul={s,received,udp_sent},bl={s,received,ble_sent};
    s->udp=matter_idf_udp_new(owner,iface,port,&ul);s->ble=matter_idf_ble_new(owner,vendor,product,&bl);
    Matter_Udp_Port_T p={s,activate,deactivate,send_packet,cancel,detach};
    if(s->udp&&s->ble)s->module=matter_udp_new(owner,&p,listener);
    if(!s->module){(void)matter_idf_udp_delete(s->udp);(void)matter_idf_ble_delete(s->ble);free(s);return NULL;}return s;
}
Matter_Udp_T matter_idf_network_module(Matter_Idf_Network_T s){return s?s->module:NULL;}
void matter_idf_network_window(Matter_Idf_Network_T s,bool enabled,uint16_t discriminator){if(s)matter_idf_ble_window(s->ble,enabled&&s->epoch,discriminator);}
uint32_t matter_idf_network_closed_take(Matter_Idf_Network_T s){return s?matter_idf_ble_closed_take(s->ble):0;}
Matter_Result_T matter_idf_network_process(Matter_Idf_Network_T s,uint64_t now){
    if(!s)return MATTER_INVALID_ARGUMENT;
    if(s->busy)return MATTER_BUSY;
    s->busy=true;s->delivered=false;
    Matter_Udp_T udp=matter_idf_udp_module(s->udp),ble=matter_idf_ble_module(s->ble);esp_ip6_addr_t ip;
    if(s->epoch&&!matter_udp_is_active(udp)&&esp_netif_get_ip6_linklocal(s->iface,&ip)==ESP_OK)(void)matter_udp_start(udp);
    if(s->ble_first){
        matter_idf_ble_receive_enabled(s->ble,true);(void)matter_idf_ble_process(s->ble,now);
        matter_idf_udp_receive_enabled(s->udp,!s->delivered);(void)matter_idf_udp_process(s->udp);
    }else {
        matter_idf_udp_receive_enabled(s->udp,true);(void)matter_idf_udp_process(s->udp);
        matter_idf_ble_receive_enabled(s->ble,!s->delivered);(void)matter_idf_ble_process(s->ble,now);
    }
    s->ble_first=!s->ble_first;(void)matter_udp_process(udp);(void)matter_udp_process(ble);s->busy=false;return MATTER_OK;
}
Matter_Result_T matter_idf_network_delete(Matter_Idf_Network_T s){
    if(!s)return MATTER_OK;
    if(s->busy||s->request||matter_udp_is_active(s->module)||matter_udp_is_active(matter_idf_udp_module(s->udp))||matter_udp_is_active(matter_idf_ble_module(s->ble)))return MATTER_BUSY;
    Matter_Result_T r=matter_idf_ble_delete(s->ble);if(r!=MATTER_OK)return r;
    s->ble=NULL;
    r=matter_idf_udp_delete(s->udp);if(r!=MATTER_OK)return r;
    s->udp=NULL;
    r=matter_udp_delete(s->module);if(r==MATTER_OK)free(s);return r;
}

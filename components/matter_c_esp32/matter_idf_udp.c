#include "matter_idf_udp.h"
#include "matter_idf_ip6_internal.h"
#include <stdlib.h>
#include <string.h>
#include "lwip/udp.h"
#include "lwip/tcpip.h"
#include "lwip/ip6.h"
#include "esp_netif_net_stack.h"
#include "esp_timer.h"
enum { RX_MAX=8 };
typedef struct Rx { struct Rx* next; Matter_Udp_Datagram_T packet; uint8_t bytes[MATTER_UDP_MAX_PAYLOAD]; } Rx;
struct Matter_Idf_Udp {
    Matter_Udp_T module; struct netif* iface; struct udp_pcb* pcb;
    Rx *free,*head,*tail; unsigned count; uint32_t pressure,observed_pressure;
    uint16_t port; uint32_t interface_id; Matter_Operation_Id_T epoch;
    uint64_t pending,idle_until; bool busy; Matter_Idf_Udp_Stats_T stats;
};
static Matter_Result_T error(err_t e) {
    return e==ERR_OK?MATTER_OK:e==ERR_MEM || e==ERR_BUF?MATTER_WOULD_BLOCK:
        e==ERR_RTE || e==ERR_IF?MATTER_OFFLINE:MATTER_PORT_ERROR;
}
static void receive(void* user,struct udp_pcb* pcb,struct pbuf* p,const ip_addr_t* peer,u16_t port) {
    Matter_Idf_Udp_T s=user; (void)pcb;
    if(!s->epoch || !IP_IS_V6(peer) || ip_current_input_netif()!=s->iface || !p->tot_len) goto drop;
    if(p->tot_len>MATTER_UDP_MAX_PAYLOAD || 40u+IP6H_PLEN(ip6_current_header())>1280u) {
        ++s->stats.oversize; goto drop;
    }
    if(!matter_idf_ip6_headers((const uint8_t*)ip6_current_header(),ip_current_header_tot_len())) {
        ++s->stats.extensions; goto drop;
    }
    if(!s->free) { ++s->pressure; goto drop; }
    Rx* rx=s->free; s->free=rx->next; rx->next=NULL;
    Matter_Udp_Datagram_T* d=&rx->packet;
    memcpy(d->path.local.address,ip_2_ip6(ip_current_dest_addr())->addr,16);
    memcpy(d->path.peer.address,ip_2_ip6(peer)->addr,16);
    d->path.local.port=s->port; d->path.peer.port=port;
    d->path.interface_id=s->interface_id;
    d->data=rx->bytes; d->size=p->tot_len; pbuf_copy_partial(p,rx->bytes,p->tot_len,0);
    if(s->tail) s->tail->next=rx; else s->head=rx;
    s->tail=rx;
    ++s->stats.received; pbuf_free(p); return;
drop:
    ++s->stats.dropped; pbuf_free(p);
}
static Matter_Result_T activate(void* user,Matter_Operation_Id_T epoch) {
    Matter_Idf_Udp_T s=user;
    Rx* rx=calloc(1,sizeof(*rx)); if(!rx) return MATTER_WOULD_BLOCK;
    LOCK_TCPIP_CORE();
    err_t e=ERR_IF;
    if(netif_is_up(s->iface) && netif_is_link_up(s->iface)) {
        s->pcb=udp_new_ip_type(IPADDR_TYPE_V6); e=s->pcb?ERR_OK:ERR_MEM;
        /* Wi-Fi stop/start removes/re-adds the same netif with a new index.
         * A PCB's cached bind_netif index would silently reject all later RX.
         * Filter the live input interface in receive; TX selects it explicitly. */
        if(!e) e=udp_bind(s->pcb,IP6_ADDR_ANY,s->port);
        if(!e) { s->free=rx; s->count=1; s->stats.rx_buffers=1;
            if(!s->stats.rx_buffer_peak) s->stats.rx_buffer_peak=1;
            s->epoch=epoch; udp_recv(s->pcb,receive,s); }
        else if(s->pcb) { udp_remove(s->pcb); s->pcb=NULL; }
    }
    UNLOCK_TCPIP_CORE(); if(e) free(rx); return error(e);
}
static void deactivate(void* user,Matter_Operation_Id_T epoch) {
    Matter_Idf_Udp_T s=user; (void)epoch;
    LOCK_TCPIP_CORE(); s->epoch=0;
    if(s->pcb) { udp_remove(s->pcb); s->pcb=NULL; }
    Rx *idle=s->free,*ready=s->head;
    s->free=s->head=s->tail=NULL; s->count=0; s->stats.rx_buffers=0; UNLOCK_TCPIP_CORE();
    while(idle) { Rx* next=idle->next; free(idle); idle=next; }
    while(ready) { Rx* next=ready->next; free(ready); ready=next; }
    /* A locally accepted send still has its deferred completion. */
}
static bool zero(const uint8_t* p) { for(unsigned i=0;i<16;++i) if(p[i]) return false; return true; }
static Matter_Result_T send_packet(void* user,uint64_t request,const Matter_Udp_Datagram_T* d) {
    Matter_Idf_Udp_T s=user; const Matter_Udp_Path_T* path=&d->path;
    unsigned index=netif_get_index(s->iface);
    if(s->pending || path->local.port!=s->port || (path->interface_id && path->interface_id!=s->interface_id) ||
        zero(path->peer.address) || path->peer.address[0]==0xff ||
        (path->peer.address[0]==0xfe && (path->peer.address[1]&0xc0)==0x80 && !path->interface_id)) return MATTER_PORT_ERROR;
    ip_addr_t peer,local; IP_SET_TYPE_VAL(peer,IPADDR_TYPE_V6); IP_SET_TYPE_VAL(local,IPADDR_TYPE_V6);
    memcpy(ip_2_ip6(&peer)->addr,path->peer.address,16); ip6_addr_set_zone(ip_2_ip6(&peer),index);
    memcpy(ip_2_ip6(&local)->addr,path->local.address,16); ip6_addr_set_zone(ip_2_ip6(&local),index);
    LOCK_TCPIP_CORE(); err_t e=ERR_IF;
    if(s->epoch && s->pcb && netif_is_link_up(s->iface)) {
        bool valid=zero(path->local.address);
        for(unsigned i=0;i<LWIP_IPV6_NUM_ADDRESSES;++i)
            if(ip6_addr_isvalid(netif_ip6_addr_state(s->iface,i)) &&
                !memcmp(netif_ip6_addr(s->iface,i)->addr,path->local.address,16)) valid=true;
        if(valid) {
            struct pbuf* p=pbuf_alloc(PBUF_TRANSPORT,d->size,PBUF_RAM); e=p?ERR_OK:ERR_MEM;
            if(p) {
                e=pbuf_take(p,d->data,d->size);
                if(!e) e=zero(path->local.address)?udp_sendto_if(s->pcb,p,&peer,path->peer.port,s->iface):
                    udp_sendto_if_src(s->pcb,p,&peer,path->peer.port,s->iface,&local);
                pbuf_free(p);
            }
        } else e=ERR_ARG;
    }
    UNLOCK_TCPIP_CORE();
    if(!e) { s->pending=request; ++s->stats.sent; } return error(e);
}
static void cancel(void* user,uint64_t id) { (void)user; (void)id; /* Completed OS send wins cancellation. */ }
static void detach(void* user) { Matter_Idf_Udp_T s=user; deactivate(s,s->epoch); s->module=NULL; }
Matter_Idf_Udp_T matter_idf_udp_new(Matter_T owner,esp_netif_t* iface,uint16_t port,const Matter_Udp_Listener_T* listener) {
    if(!owner || !iface || !port) return NULL;
    Matter_Idf_Udp_T s=calloc(1,sizeof(*s)); if(!s) return NULL;
    s->iface=esp_netif_get_netif_impl(iface); s->port=port;
    if(!s->iface) { free(s); return NULL; }
    /* Core paths retain an adapter scope key, not a transient OS index.
     * The same borrowed netif receives a new lwIP index on Wi-Fi stop/start.
     * Keep its identity stable; translate to the current zone only for TX. */
    s->interface_id=netif_get_index(s->iface);
    Matter_Udp_Port_T p={s,activate,deactivate,send_packet,cancel,detach};
    s->module=matter_udp_new(owner,&p,listener); if(!s->module) { free(s); return NULL; } return s;
}
Matter_Udp_T matter_idf_udp_module(Matter_Idf_Udp_T s) { return s?s->module:NULL; }
/* Only the owner allocates. Raw RX takes stable preallocated slots under the
 * TCP/IP lock. Observed overflow doubles bounded headroom; OOM keeps the existing
 * FIFO intact. Ten seconds without RX release the extra cached free slots. */
static void rx_capacity(Matter_Idf_Udp_T s,uint64_t now) {
    LOCK_TCPIP_CORE();
    bool pressure=s->pressure!=s->observed_pressure;
    s->observed_pressure=s->pressure;
    unsigned target=pressure && s->count<RX_MAX?s->count*2:s->count;
    if(target>RX_MAX) target=RX_MAX;
    bool active=s->epoch!=0;
    UNLOCK_TCPIP_CORE();
    while(active && s->count<target) {
        Rx* rx=calloc(1,sizeof(*rx)); if(!rx) break;
        LOCK_TCPIP_CORE(); rx->next=s->free; s->free=rx; ++s->count;
        s->stats.rx_buffers=s->count;
        if(s->count>s->stats.rx_buffer_peak) s->stats.rx_buffer_peak=s->count;
        UNLOCK_TCPIP_CORE();
    }
    Rx* retired=NULL;
    LOCK_TCPIP_CORE();
    if(pressure || s->head) s->idle_until=now+10000;
    if(!s->head && now>=s->idle_until) while(s->count>1 && s->free) {
        Rx* rx=s->free; s->free=rx->next; rx->next=retired; retired=rx; --s->count;
    }
    s->stats.rx_buffers=s->count;
    UNLOCK_TCPIP_CORE();
    while(retired) { Rx* next=retired->next; free(retired); retired=next; }
}
Matter_Result_T matter_idf_udp_process(Matter_Idf_Udp_T s) {
    if(!s) return MATTER_INVALID_ARGUMENT;
    if(s->busy) return MATTER_BUSY;
    s->busy=true;
    rx_capacity(s,(uint64_t)esp_timer_get_time()/1000);
    Matter_Result_T r=MATTER_WOULD_BLOCK;
    if(s->pending) {
        uint64_t id=s->pending; s->pending=0;
        r=matter_udp_complete(s->module,id,MATTER_OPERATION_SUCCEEDED);
        if(r==MATTER_BUSY) { s->pending=id; s->busy=false; return r; }
        /* A continuous TX stream must not starve already queued RX/ACKs.
         * complete has released the module's callback guard before returning;
         * deliver one RX in the same owner turn, retaining the outer guard. */
    }
    LOCK_TCPIP_CORE();
    Rx* rx=s->head; Matter_Operation_Id_T epoch=s->epoch;
    bool deliver=rx && epoch;
    if(deliver) { s->head=rx->next; if(!s->head) s->tail=NULL; }
    UNLOCK_TCPIP_CORE();
    if(deliver) {
        r=matter_udp_receive(s->module,epoch,&rx->packet,false);
        LOCK_TCPIP_CORE(); rx->packet.size=0; rx->next=s->free; s->free=rx; UNLOCK_TCPIP_CORE();
    }
    s->busy=false; return r;
}
Matter_Result_T matter_idf_udp_delete(Matter_Idf_Udp_T s) {
    if(!s) return MATTER_OK;
    if(s->busy || s->pending) return MATTER_BUSY;
    Matter_Result_T r=matter_udp_delete(s->module); if(r==MATTER_OK) free(s); return r;
}
Matter_Idf_Udp_Stats_T matter_idf_udp_stats(Matter_Idf_Udp_T s) {
    Matter_Idf_Udp_Stats_T result={0};
    if(s) { LOCK_TCPIP_CORE(); result=s->stats; UNLOCK_TCPIP_CORE(); } return result;
}

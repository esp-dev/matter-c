#include "matter_idf_multicast.h"
#include "clusters/matter_light_groups.h"
#include "esp_netif_net_stack.h"
#include "lwip/tcpip.h"
#include "lwip/mld6.h"
#include <stdlib.h>
#include <string.h>
typedef struct Membership {struct Membership* next;uint8_t address[16];} Membership;
struct Matter_Idf_Multicast {struct netif* iface;Membership* head;unsigned count;bool up;};
static void address(Matter_Idf_Multicast_T m,const uint8_t bytes[16],ip6_addr_t* out) {
    memset(out,0,sizeof(*out));memcpy(out->addr,bytes,16);
    ip6_addr_assign_zone(out,IP6_MULTICAST,m->iface);
}
static Matter_Result_T joined(Matter_Idf_Multicast_T m,const ip6_addr_t* a,bool restore) {
    struct mld_group* g=mld6_lookfor_group(m->iface,a);
    if(restore&&g)return MATTER_OK;
    if(g&&g->use==UINT8_MAX)return MATTER_LIMIT_REACHED;
    err_t e=mld6_joingroup_netif(m->iface,a);
    return e==ERR_OK?MATTER_OK:e==ERR_MEM?MATTER_LIMIT_REACHED:MATTER_PORT_ERROR;
}
Matter_Idf_Multicast_T matter_idf_multicast_new(esp_netif_t* iface) {
    if(!iface)return NULL;
    struct netif* netif=esp_netif_get_netif_impl(iface);
    if(!netif||!esp_netif_get_netif_impl_index(iface))return NULL;
    Matter_Idf_Multicast_T m=calloc(1,sizeof(*m));if(m)m->iface=netif;return m;
}
Matter_Result_T matter_idf_multicast_join(void* u,const uint8_t bytes[16]) {
    Matter_Idf_Multicast_T m=u;if(!m||!bytes||bytes[0]!=0xff)return MATTER_INVALID_ARGUMENT;
    for(Membership* n=m->head;n;n=n->next)if(!memcmp(bytes,n->address,16))return MATTER_OK;
    if(m->count>=MATTER_LIGHT_GROUP_MEMBERSHIPS)return MATTER_LIMIT_REACHED;
    Membership* n=calloc(1,sizeof(*n));if(!n)return MATTER_LIMIT_REACHED;
    ip6_addr_t a;address(m,bytes,&a);
    LOCK_TCPIP_CORE();Matter_Result_T r=joined(m,&a,false);UNLOCK_TCPIP_CORE();
    if(r!=MATTER_OK){free(n);return r;}
    memcpy(n->address,bytes,16);n->next=m->head;m->head=n;++m->count;return MATTER_OK;
}
Matter_Result_T matter_idf_multicast_leave(void* u,const uint8_t bytes[16]) {
    Matter_Idf_Multicast_T m=u;if(!m||!bytes)return MATTER_INVALID_ARGUMENT;
    Membership** link=&m->head;
    while(*link&&memcmp((*link)->address,bytes,16))link=&(*link)->next;
    if(!*link)return MATTER_OK;
    ip6_addr_t a;address(m,bytes,&a);
    LOCK_TCPIP_CORE();
    err_t e=mld6_lookfor_group(m->iface,&a)?mld6_leavegroup_netif(m->iface,&a):ERR_OK;
    UNLOCK_TCPIP_CORE();
    if(e!=ERR_OK)return MATTER_PORT_ERROR;
    Membership* n=*link;*link=n->next;free(n);--m->count;return MATTER_OK;
}
Matter_Result_T matter_idf_multicast_process(Matter_Idf_Multicast_T m) {
    if(!m)return MATTER_INVALID_ARGUMENT;
    Matter_Result_T result=MATTER_OK;
    LOCK_TCPIP_CORE();
    bool up=netif_is_up(m->iface)&&netif_is_link_up(m->iface);
    for(Membership* n=m->head;n;n=n->next) {
        ip6_addr_t a;address(m,n->address,&a);Matter_Result_T r=joined(m,&a,true);
        if(r!=MATTER_OK)result=r;
    }
    if(up&&!m->up)mld6_report_groups(m->iface);
    m->up=up;UNLOCK_TCPIP_CORE();return result;
}
Matter_Result_T matter_idf_multicast_delete(Matter_Idf_Multicast_T m) {
    if(!m)return MATTER_OK;
    if(m->head)return MATTER_BUSY;
    free(m);return MATTER_OK;
}

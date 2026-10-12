#include "matter_ota_apply.h"
#include "../codec/matter_tlv_validate.h"
#include <stdlib.h>
#include <string.h>
struct Matter_Ota_Apply {
    Matter_Ota_Apply_Port_T port; Matter_Ota_Apply_Context_T context;
    uint64_t now,due,deadline,job; bool active,cancelling,cancelled,terminal,proceed;
    uint8_t state,published,reason,args[48]; size_t args_size;
    Matter_Ota_Apply_Result_T result;
    Matter_Tlv_Validation_Workspace_T validation; Matter_Tlv_Tag_T tags[32];
};
static uint64_t after(uint64_t n,uint64_t d) { return n>UINT64_MAX-d?UINT64_MAX:n+d; }
static void erase(void* data,size_t n) { volatile uint8_t* p=data; while(n--) *p++=0; }
Matter_Ota_Apply_T matter_ota_apply_new(const Matter_Ota_Apply_Port_T* p,uint64_t now) {
    if(!p || !p->generation || !p->start || !p->take || !p->cancel || !p->state || !p->ready || !p->done) return NULL;
    Matter_Ota_Apply_T a=calloc(1,sizeof(*a)); if(a) { a->port=*p; a->now=now; } return a;
}
Matter_Result_T matter_ota_apply_begin(Matter_Ota_Apply_T a,const Matter_Ota_Apply_Context_T* c,uint64_t now) {
    if(!a || !c || now<a->now || !c->artifact || !c->generation || !c->provider.fabric || c->provider.fabric==255 ||
        !c->provider.node || c->provider.node>UINT64_C(0xffffffefffffffff) || c->provider.endpoint==65535 ||
        c->token_size<8 || c->token_size>32) return MATTER_INVALID_ARGUMENT;
    if(a->active) return MATTER_BUSY;
    if(a->port.generation(a->port.user,c->provider.fabric)!=c->generation) return MATTER_INVALID_STATE;
    a->context=*c; a->now=a->due=now; a->active=true;
    a->cancelled=a->cancelling=a->terminal=a->proceed=false; a->state=5; a->published=0; a->reason=1;
    /* Anonymous fields: UpdateToken[0] octstr, NewVersion[1] uint32. */
    uint8_t* p=a->args; *p++=0x15; *p++=0x30; *p++=0; *p++=(uint8_t)c->token_size;
    memcpy(p,c->token,c->token_size); p+=c->token_size; *p++=0x26; *p++=1;
    for(unsigned i=0;i<4;++i) *p++=(uint8_t)(c->version>>(8*i));
    *p++=0x18; a->args_size=(size_t)(p-a->args); return MATTER_OK;
}
static bool decode(Matter_Ota_Apply_T a,const uint8_t* d,size_t n,uint8_t* action,uint32_t* delay) {
    const Matter_Tlv_Validation_Options_T opt={1024,128,2048,4,false,0,0}; Matter_Tlv_Validation_Report_T report;
    Matter_Tlv_Reader_T r; Matter_Tlv_Element_T e; unsigned seen=0;
    if(!d || !n || d[0]!=0x15 || matter_tlv_validate(d,n,&opt,&a->validation,a->tags,32,&report)!=MATTER_TLV_OK ||
        matter_tlv_init(&r,d,n,4)!=MATTER_TLV_OK || matter_tlv_next(&r,&e)!=MATTER_TLV_OK) return false;
    while(matter_tlv_next(&r,&e)==MATTER_TLV_OK && e.type!=MATTER_TLV_END) {
        if(e.tag.control!=1) return false;
        if(e.tag.number>1) {
            if((e.type==MATTER_TLV_STRUCTURE || e.type==MATTER_TLV_ARRAY || e.type==MATTER_TLV_LIST) && matter_tlv_skip_container(&r)!=MATTER_TLV_OK) return false;
            continue;
        }
        if(e.type!=MATTER_TLV_UNSIGNED || e.unsigned_value>UINT32_MAX) return false;
        if(!e.tag.number) { if(e.unsigned_value>2) return false; *action=(uint8_t)e.unsigned_value; }
        else *delay=(uint32_t)e.unsigned_value;
        seen|=1u<<e.tag.number;
    }
    return seen==3 && matter_tlv_next(&r,&e)==MATTER_TLV_DONE;
}
static void finish(Matter_Ota_Apply_T a,Matter_Ota_Apply_Result_T r) {
    a->terminal=true; a->result=r; a->state=r==MATTER_OTA_APPLY_ACCEPTED?5:1; a->reason=r==MATTER_OTA_APPLY_ACCEPTED?1:2;
}
Matter_Result_T matter_ota_apply_process(Matter_Ota_Apply_T a,uint64_t now) {
    if(!a || now<a->now) return MATTER_INVALID_ARGUMENT;
    a->now=now; if(!a->active) return MATTER_OK;
    bool live=a->port.generation(a->port.user,a->context.provider.fabric)==a->context.generation;
    if(!a->terminal && (a->cancelling || !live || (a->job && now>=a->deadline))) {
        finish(a,a->cancelling?MATTER_OTA_APPLY_CANCELLED:!live?MATTER_OTA_APPLY_INVALIDATED:MATTER_OTA_APPLY_ERROR);
    }
    if(a->job && a->terminal && !a->cancelled) { a->port.cancel(a->port.user,a->job); a->cancelled=true; }
    if(a->job) {
        uint8_t im=0,action=0; uint32_t delay=0; const uint8_t* d=NULL; size_t n=0;
        Matter_Result_T r=a->port.take(a->port.user,a->job,&im,&d,&n);
        if(r!=MATTER_PENDING) {
            a->job=0;
            if(!a->terminal) {
                if(r!=MATTER_OK || im || !decode(a,d,n,&action,&delay)) finish(a,MATTER_OTA_APPLY_ERROR);
                else if(action==2) finish(a,MATTER_OTA_APPLY_DISCONTINUED);
                else {
                    if(delay>86400) delay=86400;
                    if(action==1 && delay<120) delay=120;
                    a->due=after(now,(uint64_t)delay*1000); a->proceed=action==0;
                    a->state=action==1?6:5; a->reason=delay?4:1;
                }
            }
        }
    }
    if(a->job) return MATTER_PENDING;
    if(a->state!=a->published) {
        Matter_Result_T r=a->port.state(a->port.user,a->state,a->reason,a->context.version,now);
        if(r!=MATTER_OK) return r;
        a->published=a->state;
    }
    if(a->terminal) {
        a->port.done(a->port.user,&a->context,a->result);
        erase(&a->context,sizeof(a->context)); erase(a->args,sizeof(a->args)); a->active=false; return MATTER_OK;
    }
    if(now<a->due) return MATTER_PENDING;
    /* Check again after port callbacks: no stale fabric may grant application. */
    if(a->port.generation(a->port.user,a->context.provider.fabric)!=a->context.generation) {
        finish(a,MATTER_OTA_APPLY_INVALIDATED); return MATTER_PENDING;
    }
    if(a->proceed) {
        Matter_Result_T r=a->port.ready(a->port.user,&a->context);
        finish(a,r==MATTER_OK?MATTER_OTA_APPLY_ACCEPTED:MATTER_OTA_APPLY_REJECTED); return MATTER_PENDING;
    }
    if(a->state!=5) { a->state=5; a->reason=1; return MATTER_PENDING; }
    Matter_Result_T r=a->port.start(a->port.user,&a->context.provider,a->args,a->args_size,&a->job);
    if(r==MATTER_BUSY || r==MATTER_WOULD_BLOCK) { a->job=0; return MATTER_PENDING; }
    if(r!=MATTER_PENDING || !a->job) { a->job=0; finish(a,MATTER_OTA_APPLY_ERROR); }
    else a->deadline=after(now,65000);
    return MATTER_PENDING;
}
bool matter_ota_apply_busy(Matter_Ota_Apply_T a) { return a && a->active; }
void matter_ota_apply_cancel(Matter_Ota_Apply_T a) { if(a) a->cancelling=true; }
Matter_Result_T matter_ota_apply_delete(Matter_Ota_Apply_T a) {
    if(!a) return MATTER_OK;
    if(a->active) return MATTER_BUSY;
    erase(a,sizeof(*a)); free(a); return MATTER_OK;
}

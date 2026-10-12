#include "matter_opcreds_host.h"
#include "crypto/matter_attestation_cert.h"
#include <stdlib.h>
#include <string.h>
struct Matter_Opcreds_Host {
    Matter_Crypto_Port_T crypto; Matter_Credentials_Port_T credentials;
    void* user;
    Matter_Result_T (*challenge)(void*, Matter_Exchange_Session_T, uint8_t[16]);
    Matter_Result_T (*timestamp)(void*, uint32_t*);
    void* collision_user; bool (*collision)(void*,const uint8_t[65]);
    uint64_t serial, staged, current;
    bool busy;
    uint8_t dac[32], pending_key[32], current_key[32], point[65];
    Matter_Attestation_Identity_T identity;
};
static void erase(void* p,size_t n) { volatile uint8_t* b=p; while(n--) *b++=0; }
Matter_Opcreds_Host_T matter_opcreds_host_new(const Matter_Opcreds_Host_Config_T* c,
    const Matter_Crypto_Port_T* p,const Matter_Credentials_Port_T* cp) {
    if(!c || !p || !cp || !c->dac_private || !c->challenge || !c->timestamp ||
        !p->p256_scalar || !p->p256_base || !p->ecdsa_sign || !p->equal || !cp->csr_create) return NULL;
    Matter_Opcreds_Host_T h=calloc(1,sizeof(*h)); if(!h) return NULL;
    h->crypto=*p; h->credentials=*cp; h->user=c->user; h->challenge=c->challenge; h->timestamp=c->timestamp;
    if(matter_attestation_cert_verify(cp,c->identity.dac,c->identity.pai,c->trusted_paa,c->vendor_id,c->product_id,&h->identity)!=MATTER_OK ||
        p->p256_base(p->user,c->dac_private,32,h->point)!=MATTER_OK || !p->equal(h->point,h->identity.public_key,65)) {
        erase(h,sizeof(*h)); free(h); return NULL;
    }
    memcpy(h->dac,c->dac_private,32); erase(h->point,65); return h;
}
static Matter_Result_T challenge(void* u,Matter_Exchange_Session_T s,uint8_t out[16]) {
    Matter_Opcreds_Host_T h=u; return h->challenge(h->user,s,out);
}
static Matter_Result_T timestamp(void* u,uint32_t* out) {
    Matter_Opcreds_Host_T h=u; return h->timestamp(h->user,out);
}
static Matter_Result_T sign(void* u,const uint8_t* data,size_t n,uint8_t out[64]) {
    Matter_Opcreds_Host_T h=u;
    if(h->busy) return MATTER_BUSY;
    h->busy=true; Matter_Result_T r=h->crypto.ecdsa_sign(h->crypto.user,h->dac,data,n,out); h->busy=false; return r;
}
static Matter_Result_T prepare(void* u,uint64_t* handle,uint8_t* csr,size_t capacity,size_t* size) {
    Matter_Opcreds_Host_T h=u;
    if(!handle || !csr || !size || capacity!=MATTER_CREDENTIALS_MAX_CSR) return MATTER_INVALID_ARGUMENT;
    if(h->busy) return MATTER_BUSY;
    if(h->staged || h->serial==UINT64_MAX) return MATTER_INVALID_STATE;
    *handle=0; *size=0; h->busy=true;
    Matter_Result_T r=h->crypto.p256_scalar(h->crypto.user,h->pending_key);
    if(r==MATTER_OK && h->current && h->crypto.equal(h->pending_key,h->current_key,32)) r=MATTER_PORT_ERROR;
    if(r==MATTER_OK && h->collision) {
        r=h->crypto.p256_base(h->crypto.user,h->pending_key,32,h->point);
        if(r==MATTER_OK && h->collision(h->collision_user,h->point)) r=MATTER_PORT_ERROR;
        erase(h->point,65);
    }
    if(r==MATTER_OK) r=h->credentials.csr_create(h->credentials.user,h->pending_key,csr,capacity,size);
    if(r==MATTER_OK) { h->staged=++h->serial; *handle=h->staged; }
    else { erase(h->pending_key,32); erase(csr,capacity); *size=0; }
    h->busy=false; return r;
}
static Matter_Result_T publish(void* u,uint64_t handle) {
    Matter_Opcreds_Host_T h=u;
    if(h->busy) return MATTER_BUSY;
    if(!handle || handle!=h->staged) return MATTER_INVALID_STATE;
    erase(h->current_key,32); memcpy(h->current_key,h->pending_key,32); erase(h->pending_key,32);
    h->current=handle; h->staged=0; return MATTER_OK;
}
static Matter_Result_T discard(void* u,uint64_t handle) {
    Matter_Opcreds_Host_T h=u;
    if(h->busy) return MATTER_BUSY;
    if(handle && h->staged==handle) { erase(h->pending_key,32); h->staged=0; }
    if(handle && h->current==handle) { erase(h->current_key,32); h->current=0; }
    return MATTER_OK;
}
Matter_Opcreds_Port_T matter_opcreds_host_port(Matter_Opcreds_Host_T h) {
    return (Matter_Opcreds_Port_T){h,challenge,timestamp,sign,prepare,publish,discard};
}
Matter_Result_T matter_opcreds_host_candidate(Matter_Opcreds_Host_T h,uint8_t out[65]) {
    if(!h || !out) return MATTER_INVALID_ARGUMENT;
    if(h->busy) return MATTER_BUSY;
    if(!h->current) return MATTER_INVALID_STATE;
    h->busy=true; Matter_Result_T r=h->crypto.p256_base(h->crypto.user,h->current_key,32,out); h->busy=false; return r;
}
Matter_Result_T matter_opcreds_host_delete(Matter_Opcreds_Host_T h) {
    if(!h) return MATTER_INVALID_ARGUMENT;
    if(h->busy) return MATTER_BUSY;
    if(h->staged || h->current || h->collision) return MATTER_INVALID_STATE;
    erase(h,sizeof(*h)); free(h); return MATTER_OK;
}

Matter_Result_T matter_opcreds_host_consume(Matter_Opcreds_Host_T h,uint64_t handle,void* user,
    Matter_Result_T (*store)(void*,const uint8_t[32])) {
    if(!h || !store || !handle) return MATTER_INVALID_ARGUMENT;
    if(h->busy) return MATTER_BUSY;
    if(handle!=h->current) return MATTER_INVALID_STATE;
    h->busy=true; Matter_Result_T r=store(user,h->current_key);
    if(r==MATTER_OK) { erase(h->current_key,32); h->current=0; }
    h->busy=false; return r;
}
Matter_Result_T matter_opcreds_host_collision(Matter_Opcreds_Host_T h,void* user,bool (*exists)(void*,const uint8_t[65])) {
    if(!h) return MATTER_INVALID_ARGUMENT;
    if(h->busy) return MATTER_BUSY;
    if(exists && h->collision) return MATTER_INVALID_STATE;
    h->collision=exists; h->collision_user=user; return MATTER_OK;
}

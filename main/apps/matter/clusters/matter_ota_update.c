#include "matter_ota_update.h"
#include "../codec/matter_tlv_validate.h"
#include <stdlib.h>
#include <string.h>
typedef struct {
    uint8_t phase,fingerprint[32]; Matter_Ota_Signed_T image,previous; Matter_Ota_Apply_Context_T context;
} Record;
struct Matter_Ota_Update {
    Matter_Store_Blob_Port_T blob; Matter_Crypto_Port_T crypto; uint8_t key[65];
    uint16_t vendor,product; uint32_t initial; bool installed,booted,rollback,legacy;
    Record record,work; uint8_t bytes[512];
    Matter_Tlv_Validation_Workspace_T validation; Matter_Tlv_Tag_T tags[16];
};
static void erase(void* p,size_t n) { volatile uint8_t* b=p; while(n--) *b++=0; }
static uint64_t le(const uint8_t* p,unsigned n) { uint64_t v=0; for(unsigned i=0;i<n;++i) v|=(uint64_t)p[i]<<(8*i); return v; }
static bool empty(const Matter_Ota_Signed_T* image) {
    for(unsigned i=0;i<56;++i) if(image->manifest[i]) return false;
    for(unsigned i=0;i<64;++i) if(image->signature[i]) return false;
    return true;
}
static void restore_image(Matter_Ota_Signed_T* image) {
    image->body_size=le(image->manifest+16,8); memcpy(image->digest,image->manifest+24,32);
}
static bool authentic(Matter_Ota_Update_T u,uint32_t version,const Matter_Ota_Signed_T* image) {
    const uint8_t* m=image->manifest;
    return !memcmp(m,"WWOTA001",8) && le(m+8,2)==u->vendor && le(m+10,2)==u->product &&
        le(m+12,4)==version && image->body_size && le(m+16,8)==image->body_size &&
        !memcmp(m+24,image->digest,32) && u->crypto.ecdsa_verify(u->crypto.user,u->key,m,56,image->signature)==MATTER_OK;
}
static bool put(Matter_Tlv_Writer_T* w,Matter_Tlv_Type_T type,int tag,uint64_t v,const void* p,size_t n) {
    Matter_Tlv_Element_T e={.type=type,.tag={.control=tag<0?0:1,.number=tag<0?0:(uint32_t)tag},.unsigned_value=v,.data=p,.size=n};
    return matter_tlv_write(w,&e,0)==MATTER_TLV_OK;
}
static Matter_Result_T save(Matter_Ota_Update_T u) {
    Record* r=&u->work; Matter_Tlv_Writer_T w; size_t n;
    bool ok=matter_tlv_writer_init(&w,u->bytes,sizeof(u->bytes),2)==MATTER_TLV_OK && put(&w,MATTER_TLV_STRUCTURE,-1,0,NULL,0) &&
        put(&w,MATTER_TLV_UNSIGNED,0,2,NULL,0) && put(&w,MATTER_TLV_UNSIGNED,1,r->phase,NULL,0) &&
        put(&w,MATTER_TLV_BYTES,2,0,r->image.manifest,56) && put(&w,MATTER_TLV_BYTES,3,0,r->image.signature,64) &&
        put(&w,MATTER_TLV_UNSIGNED,4,r->context.provider.node,NULL,0) && put(&w,MATTER_TLV_UNSIGNED,5,r->context.provider.endpoint,NULL,0) &&
        put(&w,MATTER_TLV_UNSIGNED,6,r->context.provider.fabric,NULL,0) && put(&w,MATTER_TLV_BYTES,7,0,r->context.token,r->context.token_size) &&
        put(&w,MATTER_TLV_BYTES,8,0,r->fingerprint,32) && put(&w,MATTER_TLV_BYTES,9,0,r->previous.manifest,56) &&
        put(&w,MATTER_TLV_BYTES,10,0,r->previous.signature,64) && put(&w,MATTER_TLV_END,-1,0,NULL,0) && matter_tlv_writer_finish(&w,&n)==MATTER_TLV_OK;
    Matter_Result_T result=ok?u->blob.replace(u->blob.user,u->bytes,n):MATTER_INVALID_ARGUMENT;
    if(result==MATTER_OK) { u->record=u->work; u->installed=true; }
    erase(u->bytes,sizeof(u->bytes)); erase(&u->work,sizeof(u->work)); return result;
}
static bool decode(Matter_Ota_Update_T u,size_t n) {
    const Matter_Tlv_Validation_Options_T opt={512,64,1024,2,false,0,0}; Matter_Tlv_Validation_Report_T report;
    Matter_Tlv_Reader_T r; Matter_Tlv_Element_T e; unsigned seen=0; Record* o=&u->work;
    if(!n || u->bytes[0]!=0x15 || matter_tlv_validate(u->bytes,n,&opt,&u->validation,u->tags,16,&report)!=MATTER_TLV_OK ||
        matter_tlv_init(&r,u->bytes,n,2)!=MATTER_TLV_OK || matter_tlv_next(&r,&e)!=MATTER_TLV_OK) return false;
    while(matter_tlv_next(&r,&e)==MATTER_TLV_OK && e.type!=MATTER_TLV_END) {
        if(e.tag.control!=1 || e.tag.number>10) return false;
        unsigned t=e.tag.number; seen|=1u<<t;
        if(t==2 || t==3 || t==7 || t==8 || t==9 || t==10) {
            if(e.type!=MATTER_TLV_BYTES || ((t==2 || t==9) && e.size!=56) || ((t==3 || t==10) && e.size!=64) ||
                (t==7 && e.size>32) || (t==8 && e.size!=32)) return false;
            void* out=t==2?(void*)o->image.manifest:t==3?(void*)o->image.signature:t==7?(void*)o->context.token:
                t==8?(void*)o->fingerprint:t==9?(void*)o->previous.manifest:(void*)o->previous.signature;
            memcpy(out,e.data,e.size); if(t==7) o->context.token_size=e.size;
        } else {
            uint64_t v=e.unsigned_value; if(e.type!=MATTER_TLV_UNSIGNED) return false;
            if(t==0) { if(v!=1 && v!=2) return false; u->legacy=v==1; }
            if(t==1) { if(v>3) return false; o->phase=(uint8_t)v; }
            if(t==4) { if(v>UINT64_C(0xffffffefffffffff)) return false; o->context.provider.node=v; }
            if(t==5) { if(v>=65535) return false; o->context.provider.endpoint=(uint16_t)v; }
            if(t==6) { if(v>=255) return false; o->context.provider.fabric=(uint8_t)v; }
        }
    }
    o->context.version=empty(&o->image)?u->initial:(uint32_t)le(o->image.manifest+12,4);
    restore_image(&o->image); restore_image(&o->previous);
    uint32_t previous=empty(&o->previous)?u->initial:(uint32_t)le(o->previous.manifest+12,4);
    bool valid_image=empty(&o->image)?(!o->phase && !u->legacy):
        o->context.version>u->initial && authentic(u,o->context.version,&o->image);
    bool valid_previous=o->phase>=2 && !u->legacy?
        previous<o->context.version && (empty(&o->previous) || (previous>u->initial && authentic(u,previous,&o->previous))):empty(&o->previous);
    uint8_t zero[32]={0};
    return seen==(u->legacy?511u:2047u) && (!u->legacy || o->phase<=2) &&
        matter_tlv_next(&r,&e)==MATTER_TLV_DONE && valid_image && valid_previous && (o->phase?
        (o->context.provider.node && o->context.provider.fabric && o->context.token_size>=8):
        (!o->context.provider.node && !o->context.provider.endpoint && !o->context.provider.fabric && !o->context.token_size && !memcmp(o->fingerprint,zero,32)));
}
Matter_Ota_Update_T matter_ota_update_new(const Matter_Store_Blob_Port_T* b,const Matter_Crypto_Port_T* p,
    const uint8_t key[65],uint16_t vendor,uint16_t product,uint32_t initial) {
    if(!b || !b->read || !b->replace || !p || !p->ecdsa_verify || !key || key[0]!=4) return NULL;
    Matter_Ota_Update_T u=calloc(1,sizeof(*u)); if(!u) return NULL;
    u->blob=*b; u->crypto=*p; memcpy(u->key,key,65); u->vendor=vendor; u->product=product; u->initial=initial;
    size_t n=0; Matter_Result_T result=b->read(b->user,u->bytes,sizeof(u->bytes),&n);
    if(result==MATTER_OK) {
        if(!decode(u,n)) goto fail;
        u->installed=true; u->record=u->work;
        if(u->record.phase==2) {
            /* V1 had already installed the image and retained no fallback.
             * Preserve that meaning; new V2 candidates require confirmation. */
            u->work.phase=u->legacy?1:3;
            if(save(u)!=MATTER_OK) goto fail;
            u->booted=u->legacy;
        } else if(u->record.phase==3) {
            /* A previous process began a trial but never confirmed it. */
            u->work.image=u->record.previous; u->work.phase=0;
            memset(&u->work.previous,0,sizeof(u->work.previous));
            memset(&u->work.context,0,sizeof(u->work.context)); memset(u->work.fingerprint,0,32);
            if(save(u)!=MATTER_OK) goto fail;
            u->rollback=true;
        }
    } else if(result!=MATTER_OFFLINE) goto fail;
    erase(&u->work,sizeof(u->work)); erase(u->bytes,sizeof(u->bytes)); return u;
fail: matter_ota_update_delete(u); return NULL;
}
void matter_ota_update_delete(Matter_Ota_Update_T u) { if(u) { erase(u,sizeof(*u)); free(u); } }
uint32_t matter_ota_update_version(Matter_Ota_Update_T u) { return !u?0:u->installed && !empty(&u->record.image)?(uint32_t)le(u->record.image.manifest+12,4):u->initial; }
bool matter_ota_update_booted(Matter_Ota_Update_T u) { return u && u->booted; }
bool matter_ota_update_trial(Matter_Ota_Update_T u) { return u && u->record.phase==3; }
bool matter_ota_update_rolled_back(Matter_Ota_Update_T u) { return u && u->rollback; }
Matter_Result_T matter_ota_update_confirm(Matter_Ota_Update_T u) {
    if(!matter_ota_update_trial(u)) return MATTER_INVALID_STATE;
    u->work=u->record; u->work.phase=1; memset(&u->work.previous,0,sizeof(u->work.previous));
    Matter_Result_T r=save(u); if(r==MATTER_OK) u->booted=true; return r;
}
Matter_Result_T matter_ota_update_verify(Matter_Ota_Update_T u,uint32_t version,const Matter_Ota_Signed_T* image) {
    return u && image && version>matter_ota_update_version(u) && authentic(u,version,image)?MATTER_OK:MATTER_INVALID_ARGUMENT;
}
Matter_Result_T matter_ota_update_accept(Matter_Ota_Update_T u,const Matter_Ota_Apply_Context_T* c,const uint8_t fp[32],const Matter_Ota_Signed_T* image) {
    if(!u || !c || !fp || !c->provider.fabric || c->provider.fabric==255 || !c->provider.node ||
        c->provider.node>UINT64_C(0xffffffefffffffff) || c->provider.endpoint==65535 || c->token_size<8 || c->token_size>32 ||
        matter_ota_update_verify(u,c->version,image)!=MATTER_OK) return MATTER_INVALID_ARGUMENT;
    if(u->installed && u->record.phase) return MATTER_BUSY;
    memset(&u->work,0,sizeof(u->work)); u->work.phase=2;
    if(u->installed) u->work.previous=u->record.image;
    u->work.image=*image; u->work.context=*c; memcpy(u->work.fingerprint,fp,32);
    return save(u);
}
const Matter_Ota_Apply_Context_T* matter_ota_update_pending(Matter_Ota_Update_T u) {
    return u && u->installed && u->record.phase==1?&u->record.context:NULL;
}
Matter_Result_T matter_ota_update_claim(Matter_Ota_Update_T u,const uint8_t fp[32],bool live,Matter_Ota_Apply_Context_T* out) {
    if(!u || !fp || !out || !matter_ota_update_pending(u)) return MATTER_INVALID_STATE;
    bool match=live && !memcmp(fp,u->record.fingerprint,32);
    Matter_Ota_Apply_Context_T context=u->record.context;
    u->work=u->record; u->work.phase=0; memset(&u->work.context,0,sizeof(u->work.context)); memset(u->work.fingerprint,0,32);
    Matter_Result_T r=save(u); if(r==MATTER_OK && match) *out=context;
    erase(&context,sizeof(context)); return r==MATTER_OK && !match?MATTER_OFFLINE:r;
}

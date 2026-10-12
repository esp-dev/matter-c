#include "matter_meter_source.h"
#include "../model/matter_cluster_internal.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>

enum { ARENA=8192 };
typedef struct {
    Matter_Source_Port_T port; Matter_Source_Config_T config;
    Matter_Source_Channel_T channels[MATTER_SOURCE_MAX_CHANNELS];
    Matter_Source_Snapshot_T pending,saved;
    uint8_t bytes[2][ARENA],ids[48]; size_t offset[2][6],size[2][6],used[2],ids_size;
    Matter_Tlv_Writer_T writer; Matter_Tlv_Element_T token; Matter_Tlv_Reader_T reader;
    uint32_t version; uint64_t now,last_ready; unsigned active;
    bool busy,have_saved,dirty;
} Source;
Matter_Result_T matter_meter_source_scale(double value,int8_t exponent,int64_t* out) {
    if(!out || exponent < -6 || exponent > 6 || !isfinite(value)) return MATTER_INVALID_ARGUMENT;
    double scaled=value;
    for(int i=exponent;i<0;++i) scaled*=10;
    for(int i=0;i<exponent;++i) scaled/=10;
    if(!isfinite(scaled) || scaled < -(double)MATTER_SOURCE_LIMIT || scaled > (double)MATTER_SOURCE_LIMIT) return MATTER_INVALID_ARGUMENT;
    int64_t n=(int64_t)scaled; double fraction=scaled-(double)n;
    if(fraction>=0.5) ++n; else if(fraction<=-0.5) --n;
    *out=n; return MATTER_OK;
}
Matter_Result_T matter_meter_source_epoch(int64_t unix_seconds,uint32_t* out) {
    if(!out || unix_seconds<INT64_C(946684800) || unix_seconds>INT64_C(946684800)+UINT32_MAX) return MATTER_INVALID_ARGUMENT;
    *out=(uint32_t)(unix_seconds-INT64_C(946684800)); return MATTER_OK;
}
static Matter_Result_T destroy(void* u) { Source* m=u; if(m->busy) return MATTER_BUSY; free(m); return MATTER_OK; }
static Matter_Result_T version(void* u,uint32_t* v) { Source* m=u; if(m->busy) return MATTER_BUSY; *v=m->version; return MATTER_OK; }
static bool put(Source* m,Matter_Tlv_Type_T type,int tag,uint64_t n) {
    m->token=(Matter_Tlv_Element_T){.type=type,.tag={.control=tag<0?0:1,.number=tag<0?0:(uint32_t)tag},.unsigned_value=n,.signed_value=(int64_t)n};
    return matter_tlv_write(&m->writer,&m->token,0)==MATTER_TLV_OK;
}
#define U(t,n) put(m,MATTER_TLV_UNSIGNED,t,n)
#define S(t,n) put(m,MATTER_TLV_SIGNED,t,(uint64_t)(n))
#define N(t) put(m,MATTER_TLV_NULL,t,0)
#define O(type,t) put(m,type,t,0)
#define E() O(MATTER_TLV_END,-1)
static bool text(Source* m,int tag,const Matter_Source_Text_T* s) {
    if(!s->known) return N(tag);
    if(s->size>MATTER_SOURCE_TEXT_BYTES) return false;
    m->token=(Matter_Tlv_Element_T){.type=MATTER_TLV_UTF8,.tag={.control=1,.number=(uint32_t)tag},.data=(const uint8_t*)s->text,.size=s->size};
    return matter_tlv_write(&m->writer,&m->token,0)==MATTER_TLV_OK;
}
static bool stamp(Source* m,const Matter_Source_Snapshot_T* s) { return U(20,s->generation) && U(21,s->sequence) && (s->utc_known?U(22,s->epoch_s):N(22)); }
static bool encode(Source* m,unsigned bank,const Matter_Source_Snapshot_T* s,unsigned quality) {
    m->used[bank]=0;
    for(unsigned a=0;a<6;++a) {
        m->offset[bank][a]=m->used[bank]; size_t left=ARENA-m->used[bank];
        if(left>MATTER_IM_READ_MAX_VALUE) left=MATTER_IM_READ_MAX_VALUE;
        if(matter_tlv_writer_init(&m->writer,m->bytes[bank]+m->used[bank],left,4)!=MATTER_TLV_OK) return false;
        if(!O(a==1?MATTER_TLV_STRUCTURE:MATTER_TLV_ARRAY,-1)) return false;
        if(a==0) {
            for(unsigned i=0;i<MATTER_SOURCE_METADATA_FIELDS;++i)
                if(!O(MATTER_TLV_STRUCTURE,-1) || !U(0,i) || !text(m,1,&s->metadata[i]) || !stamp(m,s) || !E()) return false;
        } else if(a==1) {
            if(!U(0,quality) || !U(1,s->status) || !U(2,s->sampled_ms) || !U(3,s->interval_ms) ||
                !(s->tariff?U(4,s->tariff):N(4)) || !(s->conversion_known?S(5,s->conversion_mantissa):N(5)) ||
                !(s->link_flags_known?put(m,MATTER_TLV_BOOL,6,s->encryption):N(6)) ||
                !(s->link_flags_known?put(m,MATTER_TLV_BOOL,7,s->authentication):N(7)) ||
                !(s->conversion_known?S(8,s->conversion_exponent):N(8)) || !stamp(m,s)) return false;
        } else for(size_t i=0;i<m->config.count;++i) {
            const Matter_Source_Channel_T* c=&m->channels[i]; const Matter_Source_Value_T* v=&s->values[i];
            if(c->group!=a) continue;
            if(!O(MATTER_TLV_STRUCTURE,-1) || !U(0,c->key) || !U(1,c->quantity) || !U(2,c->phase) || !U(3,c->tariff) ||
                !U(4,c->direction) || !U(5,c->quadrant) || !U(6,c->unit) || !S(7,c->exponent) ||
                !(quality==MATTER_SOURCE_FRESH && v->available?S(8,v->value):N(8)) || !U(9,v->origin) || !stamp(m,s)) return false;
            if(a==MATTER_SOURCE_VOLUME) {
                unsigned k=c->key;
                if(!text(m,10,&s->volume[k].id) || !(s->volume[k].utc_known?U(11,s->volume[k].epoch_s):N(11)) ||
                    !(s->volume[k].type_known?U(12,s->volume[k].type):N(12))) return false;
            }
            if(!E()) return false;
        }
        if(!E() || matter_tlv_writer_finish(&m->writer,&m->size[bank][a])!=MATTER_TLV_OK) return false;
        /* Reader checks UTF-8 and exact container balance before publication. */
        if(matter_tlv_init(&m->reader,m->bytes[bank]+m->used[bank],m->size[bank][a],4)!=MATTER_TLV_OK) return false;
        Matter_Tlv_Result_T r; size_t tokens=0;
        while((r=matter_tlv_next(&m->reader,&m->token))==MATTER_TLV_OK) if(++tokens>1024) return false;
        if(r!=MATTER_TLV_DONE) return false;
        m->used[bank]+=m->size[bank][a];
    }
    return true;
}
static uint8_t read(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    Source* m=u; (void)q; if(m->busy) return MATTER_IM_FAILURE;
    unsigned id=*(const uint32_t*)ref;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.data_version=m->version};
    static const uint8_t empty[]={0x16,0x18};
    if(id<6) { v->type=id==1?MATTER_TLV_STRUCTURE:MATTER_TLV_ARRAY; v->data=m->bytes[m->active]+m->offset[m->active][id]; v->size=m->size[m->active][id]; }
    else if(id==0xfffb) { v->type=MATTER_TLV_ARRAY; v->data=m->ids; v->size=m->ids_size; }
    else if(id==0xfff8 || id==0xfff9) { v->type=MATTER_TLV_ARRAY; v->data=empty; v->size=sizeof(empty); }
    else v->unsigned_value=id==0xfffd?1:0;
    return MATTER_IM_SUCCESS;
}
Matter_Cluster_T matter_meter_source_new(const Matter_Source_Port_T* p,const Matter_Source_Config_T* c,uint64_t now) {
    if(!p || !p->snapshot || !c || !c->vendor || c->vendor>0xfff4 || c->cluster_suffix<0xfc00 || c->cluster_suffix==0xffff ||
        !c->max_age_ms || !c->channels || !c->count || c->count>MATTER_SOURCE_MAX_CHANNELS) return NULL;
    unsigned counts[4]={0};
    for(size_t i=0;i<c->count;++i) {
        const Matter_Source_Channel_T* d=&c->channels[i];
        if(d->group<2 || d->group>5 || d->phase>3 || d->unit>MATTER_SOURCE_LITRE || d->exponent < -6 || d->exponent > 6 ||
            d->direction>2 || d->quadrant>2 || (d->group==5 && d->key>=4) || ++counts[d->group-2]>32) return NULL;
        for(size_t j=0;j<i;++j) if(d->group==c->channels[j].group && d->key==c->channels[j].key) return NULL;
    }
    Source* m=calloc(1,sizeof(*m)); if(!m) return NULL;
    m->port=*p; m->config=*c; memcpy(m->channels,c->channels,c->count*sizeof(*c->channels)); m->config.channels=m->channels;
    m->version=c->data_version; m->now=m->last_ready=now;
    if(!encode(m,0,&m->saved,MATTER_SOURCE_UNAVAILABLE)) { free(m); return NULL; }
    Matter_Cluster_Config_T config={.id=((uint32_t)c->vendor<<16)|c->cluster_suffix,.attributes=11,.callbacks={.ctx=m,.version=version,.destroy=destroy}};
    Matter_Cluster_T h=matter_cluster_new(&config); if(!h) { free(m); return NULL; }
    static const uint32_t ids[]={0,1,2,3,4,5,0xfff8,0xfff9,0xfffb,0xfffc,0xfffd};
    if(matter_tlv_writer_init(&m->writer,m->ids,sizeof(m->ids),1)!=MATTER_TLV_OK || !O(MATTER_TLV_ARRAY,-1)) goto fail;
    for(unsigned i=0;i<11;++i) {
        Matter_Attribute_Def_T a={.id=ids[i],.read_access={MATTER_IM_VIEW,false},.read=read,.ref=&ids[i]};
        if(matter_cluster_add_attribute(h,&a)!=MATTER_OK || !U(-1,ids[i])) goto fail;
    }
    if(!E() || matter_tlv_writer_finish(&m->writer,&m->ids_size)!=MATTER_TLV_OK || matter_cluster_seal(h)!=MATTER_OK) goto fail;
    return h;
fail: matter_cluster_abandon(h); free(m); return NULL;
}
static bool valid(Source* m,const Matter_Source_Snapshot_T* s,uint64_t now) {
    if(s->sampled_ms>now || (s->conversion_known && (s->conversion_mantissa<=0 || s->conversion_mantissa>MATTER_SOURCE_LIMIT ||
        s->conversion_exponent < -18 || s->conversion_exponent > 18))) return false;
    if(m->have_saved && (s->generation<m->saved.generation || s->sampled_ms<m->saved.sampled_ms ||
        (s->generation==m->saved.generation && s->sequence<m->saved.sequence))) return false;
    for(size_t i=0;i<m->config.count;++i) if(s->values[i].origin>3 || (s->values[i].available &&
        (s->values[i].value < -MATTER_SOURCE_LIMIT || s->values[i].value > MATTER_SOURCE_LIMIT))) return false;
    return true;
}
static bool same_text(const Matter_Source_Text_T* a,const Matter_Source_Text_T* b) {
    return a->known==b->known && (!a->known || (a->size==b->size && a->size<=MATTER_SOURCE_TEXT_BYTES && !memcmp(a->text,b->text,a->size)));
}
static bool same(Source* m,const Matter_Source_Snapshot_T* s) {
    const Matter_Source_Snapshot_T* p=&m->saved;
    if(s->sampled_ms!=p->sampled_ms || s->interval_ms!=p->interval_ms || s->online!=p->online || s->status!=p->status ||
        s->tariff!=p->tariff || s->utc_known!=p->utc_known || (s->utc_known && s->epoch_s!=p->epoch_s) ||
        s->conversion_known!=p->conversion_known || (s->conversion_known && (s->conversion_mantissa!=p->conversion_mantissa || s->conversion_exponent!=p->conversion_exponent)) ||
        s->link_flags_known!=p->link_flags_known || (s->link_flags_known && (s->encryption!=p->encryption || s->authentication!=p->authentication))) return false;
    for(unsigned i=0;i<MATTER_SOURCE_METADATA_FIELDS;++i) if(!same_text(&s->metadata[i],&p->metadata[i])) return false;
    for(size_t i=0;i<m->config.count;++i) if(s->values[i].available!=p->values[i].available || s->values[i].origin!=p->values[i].origin ||
        (s->values[i].available && s->values[i].value!=p->values[i].value)) return false;
    for(unsigned i=0;i<MATTER_SOURCE_VOLUMES;++i) if(!same_text(&s->volume[i].id,&p->volume[i].id) ||
        s->volume[i].utc_known!=p->volume[i].utc_known || (s->volume[i].utc_known && s->volume[i].epoch_s!=p->volume[i].epoch_s) ||
        s->volume[i].type_known!=p->volume[i].type_known || (s->volume[i].type_known && s->volume[i].type!=p->volume[i].type)) return false;
    return true;
}
Matter_Result_T matter_meter_source_refresh(Matter_Cluster_T h,uint64_t now,bool* ready) {
    Source* m=matter_cluster_context(h,destroy); if(!m || !ready || now<m->now) return MATTER_INVALID_ARGUMENT;
    if(m->busy || matter_cluster_in_use(h)) return MATTER_BUSY;
    m->busy=true; m->now=now; memset(&m->pending,0,sizeof(m->pending)); unsigned next=m->active^1u;
    Matter_Result_T r=m->port.snapshot(m->port.user,&m->pending);
    unsigned quality=!m->pending.online?MATTER_SOURCE_UNAVAILABLE:now-m->pending.sampled_ms>=m->config.max_age_ms?MATTER_SOURCE_STALE:MATTER_SOURCE_FRESH;
    if(r==MATTER_OK && valid(m,&m->pending,now) && (!m->have_saved || m->pending.generation!=m->saved.generation ||
        m->pending.sequence!=m->saved.sequence || same(m,&m->pending)) && encode(m,next,&m->pending,quality)) {
        m->saved=m->pending; m->have_saved=true;
    } else {
        r=MATTER_PORT_ERROR;
        if(!encode(m,next,&m->saved,MATTER_SOURCE_INVALID)) { m->busy=false; *ready=false; return r; }
    }
    if(m->used[next]!=m->used[m->active] || memcmp(m->bytes[next],m->bytes[m->active],m->used[next])) { ++m->version; m->dirty=true; }
    m->active=next; *ready=m->dirty && now-m->last_ready>=1000;
    if(*ready) { m->dirty=false; m->last_ready=now; }
    m->busy=false; return r;
}

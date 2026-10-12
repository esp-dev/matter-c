#include "matter_epm.h"
#include "../model/matter_cluster_internal.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>

typedef struct {
    Matter_Epm_Port_T legacy; Matter_Epm_Multi_Port_T port;
    Matter_Epm_Measurement_T measurements[MATTER_EPM_MAX_MEASUREMENTS]; size_t count;
    Matter_Epm_Sample_T old_sample; Matter_Epm_Multi_Sample_T pending,published;
    uint32_t version,max_age; uint64_t now,last_ready;
    bool polyphase,dirty,busy;
    Matter_Tlv_Writer_T writer; Matter_Tlv_Element_T token;
    uint8_t accuracy[3072],ids[96]; size_t accuracy_size,ids_size;
} Epm;
static Matter_Result_T destroy(void* u) { Epm* m=u; if(m->busy) return MATTER_BUSY; free(m); return MATTER_OK; }
static Matter_Result_T version(void* u,uint32_t* v) { Epm* m=u; if(m->busy) return MATTER_BUSY; *v=m->version; return MATTER_OK; }
Matter_Result_T matter_epm_from_watts(double watts,int64_t* out) {
    if(!out || !isfinite(watts) || watts < -(double)MATTER_EPM_LIMIT/1000.0 || watts > (double)MATTER_EPM_LIMIT/1000.0) return MATTER_INVALID_ARGUMENT;
    double scaled=watts*1000.0;
    if(scaled < -(double)MATTER_EPM_LIMIT || scaled > (double)MATTER_EPM_LIMIT) return MATTER_INVALID_ARGUMENT;
    /* Range was checked BEFORE the float-to-integer cast. No libm rounding call. */
    int64_t value=(int64_t)scaled; double fraction=scaled-(double)value;
    if(fraction>=0.5) ++value;
    else if(fraction<=-0.5) --value;
    *out=value; return MATTER_OK;
}
static unsigned measurement_type(uint32_t id) {
    if(id>=4 && id<=14) return id-3;
    if(id==17 || id==18) return id-5;
    return 0;
}
static bool valid(const Matter_Epm_Measurement_T* c,bool polyphase) {
    if(!measurement_type(c->attribute) || (c->attribute==18 && !polyphase) || !c->range_count || c->range_count>MATTER_EPM_MAX_RANGES) return false;
    int64_t min=c->attribute==14?0:c->attribute==17?-10000:-MATTER_EPM_LIMIT;
    int64_t max=c->attribute==14?1000000:c->attribute==17?10000:MATTER_EPM_LIMIT;
    for(unsigned i=0;i<c->range_count;++i) {
        const Matter_Epm_Accuracy_Range_T* r=&c->ranges[i];
        if(r->min_mw<min || r->max_mw>max || r->min_mw>=r->max_mw || !r->fields || (r->fields&~3) ||
            ((r->fields&1) && r->percent_max>10000) || ((r->fields&2) && r->fixed_max_mw>(uint64_t)MATTER_EPM_LIMIT-1) ||
            (i && r->min_mw!=c->ranges[i-1].max_mw+1)) return false;
    }
    return true;
}
static bool put(Epm* m,Matter_Tlv_Type_T type,int tag,uint64_t n,int64_t signed_n) {
    m->token=(Matter_Tlv_Element_T){.type=type,.tag={.control=tag<0?0:1,.number=tag<0?0:(uint32_t)tag},.unsigned_value=n,.signed_value=signed_n};
    return matter_tlv_write(&m->writer,&m->token,0)==MATTER_TLV_OK;
}
#define P(type,tag,n) put(m,type,tag,n,0)
#define S(tag,n) put(m,MATTER_TLV_SIGNED,tag,0,n)
#define END() P(MATTER_TLV_END,-1,0)
static bool accuracy(Epm* m) {
    if(matter_tlv_writer_init(&m->writer,m->accuracy,sizeof(m->accuracy),4)!=MATTER_TLV_OK || !P(MATTER_TLV_ARRAY,-1,0)) return false;
    for(size_t j=0;j<m->count;++j) {
        const Matter_Epm_Measurement_T* c=&m->measurements[j];
        if(!P(MATTER_TLV_STRUCTURE,-1,0) || !P(MATTER_TLV_UNSIGNED,0,measurement_type(c->attribute)) ||
            !P(MATTER_TLV_BOOL,1,c->measured) || !S(2,c->ranges[0].min_mw) || !S(3,c->ranges[c->range_count-1].max_mw) || !P(MATTER_TLV_ARRAY,4,0)) return false;
        for(unsigned i=0;i<c->range_count;++i) {
            const Matter_Epm_Accuracy_Range_T* r=&c->ranges[i];
            if(!P(MATTER_TLV_STRUCTURE,-1,0) || !S(0,r->min_mw) || !S(1,r->max_mw) ||
                ((r->fields&1) && !P(MATTER_TLV_UNSIGNED,2,r->percent_max)) ||
                ((r->fields&2) && !P(MATTER_TLV_UNSIGNED,5,r->fixed_max_mw)) || !END()) return false;
        }
        if(!END() || !END()) return false;
    }
    return END() && matter_tlv_writer_finish(&m->writer,&m->accuracy_size)==MATTER_TLV_OK;
}
static uint8_t read(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* v) {
    Epm* m=u; (void)q; if(m->busy) return MATTER_IM_FAILURE;
    uint32_t id=*(const uint32_t*)ref;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.data_version=m->version};
    static const uint8_t empty[]={0x16,0x18};
    switch(id) {
    case 0: v->unsigned_value=2; break;
    case 1: v->unsigned_value=m->count; break;
    case 2: v->type=MATTER_TLV_ARRAY; v->data=m->accuracy; v->size=m->accuracy_size; break;
    case 0xfff8: case 0xfff9: v->type=MATTER_TLV_ARRAY; v->data=empty; v->size=sizeof(empty); break;
    case 0xfffb: v->type=MATTER_TLV_ARRAY; v->data=m->ids; v->size=m->ids_size; break;
    case 0xfffc: v->unsigned_value=m->polyphase?6:2; break;
    case 0xfffd: v->unsigned_value=3; break;
    default:
        for(size_t i=0;i<m->count;++i) if(m->measurements[i].attribute==id) {
            v->type=(m->published.available&(1u<<i))?MATTER_TLV_SIGNED:MATTER_TLV_NULL;
            v->signed_value=m->published.values[i]; return 0;
        }
        return MATTER_IM_UNSUPPORTED_ATTRIBUTE;
    }
    return 0;
}
static Matter_Cluster_T create(Epm* m) {
    if(!accuracy(m)) { free(m); return NULL; }
    Matter_Cluster_Config_T c={.id=MATTER_EPM_CLUSTER,.attributes=8+m->count,.callbacks={.ctx=m,.version=version,.destroy=destroy}};
    Matter_Cluster_T h=matter_cluster_new(&c); if(!h) { free(m); return NULL; }
    static const uint32_t ids[]={0,1,2,0xfff8,0xfff9,0xfffb,0xfffc,0xfffd};
    for(size_t i=0;i<8+m->count;++i) {
        const uint32_t* id=i<8?&ids[i]:&m->measurements[i-8].attribute;
        Matter_Attribute_Def_T a={.id=*id,.read_access={MATTER_IM_VIEW,false},.read=read,.ref=id};
        if(matter_cluster_add_attribute(h,&a)!=MATTER_OK) goto fail;
    }
    if(matter_tlv_writer_init(&m->writer,m->ids,sizeof(m->ids),1)!=MATTER_TLV_OK || !P(MATTER_TLV_ARRAY,-1,0)) goto fail;
    for(size_t i=0;i<8+m->count;++i) { uint32_t id; if(!matter_cluster_attribute_at(h,i,&id) || !P(MATTER_TLV_UNSIGNED,-1,id)) goto fail; }
    if(!END() || matter_tlv_writer_finish(&m->writer,&m->ids_size)!=MATTER_TLV_OK) goto fail;
    (void)matter_cluster_seal(h); return h;
fail: matter_cluster_abandon(h); free(m); return NULL;
}
#undef P
#undef S
#undef END
Matter_Cluster_T matter_epm_new_multi(const Matter_Epm_Multi_Port_T* p,const Matter_Epm_Multi_Config_T* c,uint64_t now) {
    if(!p || !p->snapshot || !c || !c->measurements || !c->count || c->count>MATTER_EPM_MAX_MEASUREMENTS || !c->max_age_ms) return NULL;
    bool active=false;
    for(size_t i=0;i<c->count;++i) {
        if(!valid(&c->measurements[i],c->polyphase)) return NULL;
        active|=c->measurements[i].attribute==8;
        for(size_t j=0;j<i;++j) if(c->measurements[i].attribute==c->measurements[j].attribute) return NULL;
    }
    if(!active) return NULL;
    Epm* m=calloc(1,sizeof(*m)); if(!m) return NULL;
    m->port=*p; m->count=c->count; memcpy(m->measurements,c->measurements,c->count*sizeof(*c->measurements));
    m->version=c->data_version; m->max_age=c->max_age_ms; m->polyphase=c->polyphase; m->now=m->last_ready=now;
    return create(m);
}
Matter_Cluster_T matter_epm_new(const Matter_Epm_Port_T* p,const Matter_Epm_Config_T* c,uint64_t now) {
    if(!p || !p->snapshot || !c || !c->max_age_ms) return NULL;
    Epm* m=calloc(1,sizeof(*m)); if(!m) return NULL;
    m->legacy=*p; m->count=1; m->measurements[0].attribute=8;
    m->measurements[0].range_count=c->range_count; m->measurements[0].measured=c->measured;
    memcpy(m->measurements[0].ranges,c->ranges,sizeof(c->ranges));
    if(!valid(&m->measurements[0],c->polyphase)) { free(m); return NULL; }
    m->version=c->data_version; m->max_age=c->max_age_ms; m->polyphase=c->polyphase; m->now=m->last_ready=now;
    return create(m);
}
Matter_Result_T matter_epm_refresh(Matter_Cluster_T h,uint64_t now,bool* ready) {
    Epm* m=matter_cluster_context(h,destroy);
    if(!m || !ready) return MATTER_INVALID_ARGUMENT;
    if(m->busy || matter_cluster_in_use(h)) return MATTER_BUSY;
    if(now<m->now) return MATTER_INVALID_ARGUMENT;
    m->busy=true; m->now=now; memset(&m->pending,0,sizeof(m->pending));
    Matter_Result_T r;
    if(m->legacy.snapshot) {
        memset(&m->old_sample,0,sizeof(m->old_sample)); r=m->legacy.snapshot(m->legacy.user,&m->old_sample);
        m->pending.values[0]=m->old_sample.active_mw; m->pending.available=m->old_sample.available?1:0; m->pending.sampled_ms=m->old_sample.sampled_ms;
    } else r=m->port.snapshot(m->port.user,&m->pending);
    uint16_t mask=(uint16_t)((1u<<m->count)-1);
    if(r!=MATTER_OK || (m->pending.available&~mask) || (m->pending.available && m->pending.sampled_ms>now)) {
        r=MATTER_PORT_ERROR; m->pending.available=0;
    } else if(now-m->pending.sampled_ms>=m->max_age) m->pending.available=0;
    bool changed=false;
    for(size_t i=0;i<m->count;++i) {
        const Matter_Epm_Measurement_T* c=&m->measurements[i]; uint16_t bit=(uint16_t)(1u<<i);
        if((m->pending.available&bit) && (m->pending.values[i]<c->ranges[0].min_mw || m->pending.values[i]>c->ranges[c->range_count-1].max_mw)) {
            m->pending.available&=(uint16_t)~bit; r=MATTER_PORT_ERROR;
        }
        if(!(m->pending.available&bit)) m->pending.values[i]=0;
        changed|=((m->pending.available^m->published.available)&bit)!=0 || ((m->pending.available&bit) && m->pending.values[i]!=m->published.values[i]);
    }
    if(changed) { ++m->version; m->dirty=true; }
    m->published=m->pending; *ready=m->dirty && now-m->last_ready>=1000;
    if(*ready) { m->dirty=false; m->last_ready=now; }
    m->busy=false; return r==MATTER_OK?MATTER_OK:MATTER_PORT_ERROR;
}

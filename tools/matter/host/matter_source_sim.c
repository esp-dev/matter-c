#include "matter_source_sim.h"
#include <string.h>
static Matter_Result_T snapshot(void* u,Matter_Source_Snapshot_T* out) { *out=((Matter_Source_Sim_T*)u)->snapshot; return MATTER_OK; }
static void text(Matter_Source_Text_T* out,const char* value) {
    size_t n=strlen(value); if(n>sizeof(out->text)) return;
    memcpy(out->text,value,n); out->size=(uint8_t)n; out->known=true;
}
static void channel(Matter_Source_Sim_T* s,unsigned group,unsigned key,unsigned quantity,unsigned phase,unsigned tariff,unsigned direction,unsigned quadrant,unsigned unit,int exponent) {
    s->channels[s->count++]=(Matter_Source_Channel_T){(uint16_t)key,(uint8_t)group,(uint8_t)quantity,(uint8_t)phase,(uint8_t)tariff,(uint8_t)direction,(uint8_t)quadrant,(uint8_t)unit,(int8_t)exponent};
}
Matter_Cluster_T matter_source_sim_new(Matter_Source_Sim_T* s,uint16_t vendor,uint32_t version,uint64_t now) {
    if(!s) return NULL;
    memset(s,0,sizeof(*s)); unsigned key=0;
    /* Energy: active +/- total,T1,T2; reactive +/-; four separate quadrants. */
    for(unsigned kind=1;kind<=2;++kind) for(unsigned d=1;d<=2;++d) for(unsigned t=0;t<3;++t)
        channel(s,2,key++,kind,0,t,d,0,kind==1?MATTER_SOURCE_WH:MATTER_SOURCE_VARH,-3);
    for(unsigned d=1;d<=2;++d) for(unsigned q=1;q<=2;++q) for(unsigned t=0;t<3;++t)
        channel(s,2,key++,2,0,t,d,q,MATTER_SOURCE_VARH,-3);
    key=0;
    for(unsigned kind=1;kind<=2;++kind) for(unsigned d=1;d<=2;++d) for(unsigned phase=0;phase<4;++phase)
        channel(s,3,key++,kind,phase,0,d,0,kind==1?MATTER_SOURCE_W:MATTER_SOURCE_VAR,-3);
    channel(s,3,key++,3,0,0,0,0,MATTER_SOURCE_VA,-3);
    for(unsigned kind=4;kind<=6;++kind) for(unsigned phase=1;phase<=3;++phase)
        channel(s,3,key++,kind,phase,0,0,0,kind==4?MATTER_SOURCE_V:MATTER_SOURCE_A,-3);
    channel(s,3,key++,7,0,0,0,0,MATTER_SOURCE_RATIO,-4);
    key=0;
    for(unsigned d=1;d<=2;++d) for(unsigned t=0;t<3;++t) channel(s,4,key++,1,0,t,d,0,MATTER_SOURCE_W,-3);
    for(unsigned i=0;i<4;++i) channel(s,5,i,8,0,0,0,0,i==3?MATTER_SOURCE_UNKNOWN_UNIT:MATTER_SOURCE_M3,-6);
    Matter_Source_Config_T config={vendor,0xfc01,version,3000,s->channels,s->count};
    Matter_Source_Port_T port={s,snapshot}; return matter_meter_source_new(&port,&config,now);
}
void matter_source_sim_sample(Matter_Source_Sim_T* sim,uint64_t now,uint64_t seconds,int64_t imported,int64_t exported) {
    Matter_Source_Snapshot_T* s=&sim->snapshot; uint64_t previous=s->sampled_ms; memset(s,0,sizeof(*s));
    unsigned cycle=(unsigned)(seconds%24);
    s->generation=1; s->sequence=seconds+1; s->sampled_ms=cycle>=18 && cycle<22 && previous?previous:now;
    s->interval_ms=1000; s->online=cycle<18 || cycle>=20; s->status=s->online?1:2;
    s->tariff=cycle<12?1:2; s->conversion_known=true; s->conversion_mantissa=1;
    s->link_flags_known=true; s->encryption=true; s->authentication=true;
    /* Synthetic UTC is fixed epoch + sequence, never a claim about host time. */
    s->utc_known=true; s->epoch_s=800000000+(uint32_t)seconds;
    static const char* const meta[]={"SIM-0001","Three phase simulator","Synthetic meter source","SIM","1.0","virtual","SIM","example","0","verified-test-identity"};
    for(unsigned i=0;i<10;++i) text(&s->metadata[i],meta[i]);
    for(size_t i=0;i<sim->count;++i) {
        const Matter_Source_Channel_T* c=&sim->channels[i]; Matter_Source_Value_T* v=&s->values[i];
        v->available=true; v->origin=MATTER_SOURCE_SYNTHETIC;
        if(c->group==2) {
            v->value=INT64_C(100000000)+(int64_t)c->key*1000000+(int64_t)seconds*10;
            if(c->key==0) v->value=imported;
            if(c->key==3) v->value=exported;
            if(c->key==2 && cycle>=8 && cycle<12) v->available=false; /* T1 does not fabricate T2 */
        } else if(c->group==3) {
            static const int64_t base[]={1984000,1800000,0,184000,750000,0,750000,0,
                350000,300000,0,50000,100000,0,100000,0,1500000,230125,231000,229500,
                10000,4000,1000,10000,-4000,1000,9500};
            v->value=base[c->key];
            if(c->key<2) v->value+=(int64_t)(seconds%5)*1000;
            if(c->quantity==6) v->origin=MATTER_SOURCE_DERIVED;
            if(c->phase==3 && seconds%20>=15) v->available=false;
        } else if(c->group==4) v->value=(int64_t)(c->key+1)*1000000; /* six independent maxima */
        else {
            v->value=123456789+(int64_t)c->key*1000000+(int64_t)seconds;
            /* Unknown unit remains explicitly unknown; preserve the source
             * numeric register without labelling it m3 or mapping it to EEM. */
            text(&s->volume[c->key].id,"SIM-VOLUME"); s->volume[c->key].type=7+c->key; s->volume[c->key].type_known=true;
            s->volume[c->key].epoch_s=s->epoch_s; s->volume[c->key].utc_known=c->key!=2;
        }
    }
}

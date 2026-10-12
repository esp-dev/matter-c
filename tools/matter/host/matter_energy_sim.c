#include "matter_energy_sim.h"
static int64_t power(const Matter_Energy_Sim_T* s,uint64_t now) {
    uint64_t elapsed=now-s->epoch;
    if(s->mode==1) return 990000+(int64_t)((elapsed/2000)%21)*1000;
    if(s->mode==2) return -3000000+(int64_t)((elapsed/5000)%21)*1000;
    return elapsed/1000%10<5?3600000:-1800000;
}
Matter_Result_T matter_energy_sim_init(Matter_Energy_Sim_T* s,const int64_t raw[2],uint64_t now) {
    if(!s || !raw || raw[0]<0 || raw[1]<0 || raw[0]>MATTER_EEM_LIMIT || raw[1]>MATTER_EEM_LIMIT) return MATTER_INVALID_ARGUMENT;
    *s=(Matter_Energy_Sim_T){.raw={raw[0],raw[1]},.last=now,.epoch=now,.power=3600000}; return MATTER_OK;
}
Matter_Result_T matter_energy_sim_sample(Matter_Energy_Sim_T* s,uint64_t now) {
    if(!s || now<s->last || s->mode>2) return MATTER_INVALID_ARGUMENT;
    /* Small host-only transaction copy, no partial update on failure. */
    Matter_Energy_Sim_T next=*s; uint64_t delta=now-s->last;
    for(unsigned i=0;i<2;++i) {
        uint64_t mw=s->mode?(i==0?(s->power>0?(uint64_t)s->power:0):(s->power<0?(uint64_t)-s->power:0)):(i==0?3600000:1800000);
        if(mw && delta>(UINT64_MAX-s->remainder[i])/mw) return MATTER_LIMIT_REACHED;
        uint64_t integrated=mw*delta+s->remainder[i],energy=integrated/3600000;
        if(energy>(uint64_t)(MATTER_EEM_LIMIT-s->raw[i])) return MATTER_LIMIT_REACHED;
        next.raw[i]+=(int64_t)energy; next.remainder[i]=integrated%3600000;
    }
    next.last=now; next.power=power(s,now); *s=next; return MATTER_OK;
}
uint8_t matter_energy_sim_trigger(Matter_Energy_Sim_T* s,uint64_t event,uint64_t now) {
    /* SDK embeds target endpoint in bits32..47; zero is its legacy form. */
    unsigned endpoint=(unsigned)((event>>32)&0xffff);
    if(endpoint>1) return MATTER_IM_INVALID_COMMAND;
    event&=~(UINT64_C(0xffff)<<32);
    const uint64_t first=UINT64_C(0x0091000000000000);
    if(event<first || event>first+2) return MATTER_IM_INVALID_COMMAND;
    if(matter_energy_sim_sample(s,now)!=MATTER_OK) return MATTER_IM_FAILURE;
    s->mode=(unsigned)(event-first); s->epoch=now; s->power=power(s,now); return MATTER_IM_SUCCESS;
}

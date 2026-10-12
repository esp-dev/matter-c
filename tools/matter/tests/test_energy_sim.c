#include "matter_energy_sim.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"energy-sim:%d: %s\n",__LINE__,#x); exit(1); } } while(0)
int main(void) {
    Matter_Energy_Sim_T s,other,before; const int64_t raw[]={10000,20000};
    const uint64_t stop=UINT64_C(0x0091000000000000);
    CHECK(matter_energy_sim_init(&s,raw,100)==MATTER_OK); other=s;
    CHECK(matter_energy_sim_sample(&s,1100)==MATTER_OK && s.raw[0]==11000 && s.raw[1]==20500);
    CHECK(matter_energy_sim_trigger(&s,stop+1,1100)==0);
    CHECK(matter_energy_sim_sample(&s,4100)==MATTER_OK && s.power==991000 && s.raw[0]==11825 && s.raw[1]==20500);
    CHECK(matter_energy_sim_sample(&s,7100)==MATTER_OK && s.power==993000 && s.raw[0]==12650 && s.remainder[0]==3000000);
    before=s; CHECK(matter_energy_sim_trigger(&s,stop+3,7100)==MATTER_IM_INVALID_COMMAND && !memcmp(&s,&before,sizeof(s)));
    CHECK(matter_energy_sim_trigger(&s,stop+(UINT64_C(2)<<32)+1,7100)==MATTER_IM_INVALID_COMMAND && !memcmp(&s,&before,sizeof(s)));
    CHECK(matter_energy_sim_trigger(&s,stop+2,7099)==MATTER_IM_FAILURE && !memcmp(&s,&before,sizeof(s)));
    CHECK(matter_energy_sim_trigger(&s,stop+(UINT64_C(1)<<32)+2,7100)==0);
    CHECK(matter_energy_sim_sample(&s,13100)==MATTER_OK && s.raw[0]==12650 && s.raw[1]==25500 && s.power==-2999000);
    CHECK(matter_energy_sim_trigger(&s,stop,13100)==0);
    CHECK(matter_energy_sim_sample(&s,14100)==MATTER_OK && s.raw[0]==13650 && s.raw[1]==26000);
    CHECK(other.raw[0]==10000 && other.raw[1]==20000 && !other.mode);
    before=s; CHECK(matter_energy_sim_sample(&s,UINT64_MAX)==MATTER_LIMIT_REACHED && !memcmp(&s,&before,sizeof(s)));
    s.raw[1]=MATTER_EEM_LIMIT; before=s;
    CHECK(matter_energy_sim_sample(&s,15100)==MATTER_LIMIT_REACHED && !memcmp(&s,&before,sizeof(s)));
    CHECK(matter_energy_sim_init(&s,(const int64_t[]){-1,0},0)==MATTER_INVALID_ARGUMENT);
    puts("PASS energy simulation: integration, directions, stop, isolation, backwards time, overflow"); return 0;
}

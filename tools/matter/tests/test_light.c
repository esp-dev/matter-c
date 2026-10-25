#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "test_alloc_bytes.h"
#define CHECK(x) do { if(!(x)){fprintf(stderr,"light:%d: %s\n",__LINE__,#x);abort();} }while(0)
#define calloc matter_test_calloc
#define free matter_test_free
#include "../../../main/apps/matter/clusters/matter_light.c"
#undef calloc
#undef free
typedef struct { Matter_Light_State_T state; Matter_Light_T light; bool fail,reenter; unsigned writes; } Disk;
static Matter_Result_T load(void* u,Matter_Light_State_T* s){*s=((Disk*)u)->state;return MATTER_OK;}
static Matter_Result_T save(void* u,const Matter_Light_State_T* s){Disk* d=u;
    if(d->reenter){CHECK(matter_light_process(d->light,500)==MATTER_BUSY);CHECK(matter_light_delete(d->light)==MATTER_BUSY);}
    if(d->fail)return MATTER_PORT_ERROR;
    d->state=*s;++d->writes;return MATTER_OK;
}
static const Matter_Cluster_Request_T request={.session=1,.fabric=1,.is_case=true};
static uint8_t call(Matter_Light_T l,unsigned k,uint32_t id,const uint8_t* d,size_t n){
    Matter_Im_Command_Result_T result={0};uint64_t token=0;
    CHECK(matter_cluster_start(l->clusters[k],id,&request,d,n,NULL,&result,&token)==MATTER_OK&&!token);return result.status;
}
static uint64_t read_u(Matter_Light_T l,unsigned k,uint32_t id){Matter_Im_Value_T v;CHECK(!matter_cluster_read(l->clusters[k],id,&request,&v));return v.unsigned_value;}
static uint8_t write_u(Matter_Light_T l,unsigned k,uint32_t id,unsigned v){uint8_t d[]={5,(uint8_t)v,(uint8_t)(v>>8)};return matter_cluster_write(l->clusters[k],id,&request,d,sizeof(d)).status;}
int main(void){
    Disk disk={0};matter_light_defaults(&disk.state);Matter_Light_Port_T port={&disk,load,save};
    for(size_t i=1;i<6;++i){fail_at=calls+i;CHECK(!matter_light_new(&port,10,0,false));fail_at=0;CHECK(!live&&!live_bytes);}
    Matter_Light_T l=disk.light=matter_light_new(&port,10,0,false);CHECK(l);
    CHECK(read_u(l,ONOFF,0xfffc)==1&&read_u(l,LEVEL,0xfffc)==3&&read_u(l,COLOR,0xfffc)==25);
    const uint8_t empty[]={0x15,0x18};
    CHECK(!call(l,ONOFF,0,empty,sizeof(empty))&&!read_u(l,ONOFF,0));
    const uint8_t level[]={0x15,0x24,0,254,0x25,1,10,0,0x18};
    CHECK(!call(l,LEVEL,0,level,sizeof(level))&&read_u(l,LEVEL,0)==127); /* ExecuteIfOff is clear. */
    CHECK(!call(l,ONOFF,1,empty,sizeof(empty))&&read_u(l,ONOFF,0));
    disk.fail=true;uint32_t before=l->versions[LEVEL];
    CHECK(call(l,LEVEL,0,level,sizeof(level))==MATTER_IM_FAILURE&&read_u(l,LEVEL,0)==127&&l->versions[LEVEL]==before);
    disk.fail=false;disk.reenter=true;
    CHECK(!call(l,LEVEL,0,level,sizeof(level))&&read_u(l,LEVEL,1)==10);
    disk.reenter=false;CHECK(matter_light_process(l,500)==MATTER_OK&&read_u(l,LEVEL,0)==190);
    CHECK(matter_light_process(l,1000)==MATTER_OK&&read_u(l,LEVEL,0)==254&&!read_u(l,LEVEL,1));
    uint8_t hue[]={0x15,0x24,0,85,0x24,1,254,0x25,2,0,0,0x18};
    fail_at=calls+1;CHECK(call(l,COLOR,6,hue,sizeof(hue))==MATTER_IM_RESOURCE_EXHAUSTED);fail_at=0;
    CHECK(!call(l,COLOR,6,hue,sizeof(hue))&&read_u(l,COLOR,0)==85);
    uint8_t rgb[3];matter_light_pixels(l,rgb);CHECK(rgb[1]==255&&!rgb[0]&&rgb[2]<=3);
    CHECK(l->state.x<25000&&l->state.y>35000); /* HS updates scene XY too. */
    for(unsigned h=0;h<=254;++h)for(unsigned s=16;s<=254;s+=17){Matter_Light_State_T v=l->state;v.hue=(uint8_t)h;v.saturation=(uint8_t)s;v.mode=0;matter_light_color_normalize(&v);matter_light_color_hue_from_xy(&v);int delta=abs((int)v.hue-(int)h);CHECK(delta<=1||delta>=253);}
    uint8_t move[]={0x15,0x24,0,1,0x24,1,100,0x18};CHECK(!call(l,COLOR,1,move,sizeof(move)));
    CHECK(matter_light_process(l,5000)==MATTER_OK&&l->ramp[1].active&&read_u(l,COLOR,0)<=254);
    CHECK(!call(l,COLOR,0x47,empty,sizeof(empty))&&!l->ramp[1].active);
    const uint8_t xy[]={0x15,0x25,0,0x10,0x50,0x25,1,0x10,0x54,0x25,2,0,0,0x18};
    CHECK(!call(l,COLOR,7,xy,sizeof(xy))&&read_u(l,COLOR,8)==1&&read_u(l,COLOR,3)==0x5010);
    const uint8_t temp[]={0x15,0x25,0,250,0,0x25,1,0,0,0x18};
    CHECK(!call(l,COLOR,10,temp,sizeof(temp))&&read_u(l,COLOR,8)==2&&read_u(l,COLOR,7)==250);
    CHECK(!write_u(l,COLOR,0x4010,333));CHECK(!write_u(l,ONOFF,0x4003,1));CHECK(!write_u(l,LEVEL,0x4000,10));
    CHECK(write_u(l,ONOFF,0x4003,3)==MATTER_IM_CONSTRAINT_ERROR);
    const uint8_t identify[]={0x15,0x25,0,1,0,0x18};CHECK(!call(l,IDENTIFY,0,identify,sizeof(identify))&&matter_light_identifying(l));
    CHECK(matter_light_process(l,6000)==MATTER_OK&&!matter_light_identifying(l));
    CHECK(!write_u(l,IDENTIFY,0,65535));
    const uint8_t timed[]={0x15,0x24,0,0,0x25,1,10,0,0x25,2,20,0,0x18};
    CHECK(!call(l,ONOFF,0x42,timed,sizeof(timed))&&read_u(l,ONOFF,0));
    CHECK(matter_light_process(l,7000)==MATTER_OK&&!read_u(l,ONOFF,0)&&!read_u(l,ONOFF,0x4002));
    CHECK(matter_light_delete(l)==MATTER_OK&&!live&&!live_bytes);
    Matter_Light_State_T before_cold=disk.state;
    l=matter_light_new(&port,100,0,false);CHECK(l&&read_u(l,ONOFF,0)&&read_u(l,LEVEL,0)==10&&read_u(l,COLOR,7)==333);
    CHECK(matter_light_delete(l)==MATTER_OK);
    l=matter_light_new(&port,100,0,true);CHECK(l&&read_u(l,ONOFF,0)&&read_u(l,LEVEL,0)==10&&read_u(l,COLOR,7)==333);
    CHECK(matter_light_delete(l)==MATTER_OK);disk.state=before_cold;
    l=matter_light_new(&port,100,0,true);CHECK(l&&!read_u(l,ONOFF,0)&&read_u(l,LEVEL,0)==254&&read_u(l,COLOR,7)==250);
    CHECK(matter_light_delete(l)==MATTER_OK&&!live&&!live_bytes);
    disk.state.start_on=2;disk.state.on=false;
    l=matter_light_new(&port,100,0,false);CHECK(l&&disk.state.on);CHECK(matter_light_delete(l)==MATTER_OK);
    l=matter_light_new(&port,100,0,false);CHECK(l&&!disk.state.on);CHECK(matter_light_delete(l)==MATTER_OK);
    disk.fail=true;CHECK(!matter_light_new(&port,100,0,false)&&!disk.state.on);disk.fail=false;CHECK(!live&&!live_bytes);
    puts("PASS light: LT/OO/XY/CT/HS, transitions, off options, OOM/store failure/reentry, Identify, pixels, timed off, cold/OTA startup");
    return 0;
}

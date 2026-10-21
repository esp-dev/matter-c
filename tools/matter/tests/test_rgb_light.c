#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "test_alloc_bytes.h"
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"RGB:%d: %s\n",__LINE__,#x); abort(); } } while(0)
/* Compile the portable example model, never the IDF/RMT adapter. */
#define calloc matter_test_calloc
#define free matter_test_free
#include "../../../examples/esp32-runtime/main/rgb_light.c"
#undef calloc
#undef free
static const Matter_Cluster_Request_T request={.session=1,.fabric=1,.is_case=true};
static uint8_t invoke(Matter_Lab_Rgb_T s,unsigned kind,uint32_t id,const uint8_t* bytes,size_t size) {
    Matter_Im_Command_Result_T result; uint64_t token=0;
    CHECK(matter_cluster_start(s->clusters[kind],id,&request,bytes,size,NULL,&result,&token)==MATTER_OK && !token);
    return result.status;
}
static uint64_t value(Matter_Lab_Rgb_T s,unsigned kind,uint32_t id) {
    Matter_Im_Value_T out; CHECK(!matter_cluster_read(s->clusters[kind],id,&request,&out)); return out.unsigned_value;
}
int main(void) {
    for(unsigned position=1;position<=4;++position) {
        fail_at=calls+position; CHECK(!matter_lab_rgb_new(10,0)); fail_at=0; CHECK(!live && !live_bytes);
    }
    Matter_Lab_Rgb_T s=matter_lab_rgb_new(10,0); CHECK(s);
    const uint8_t empty[]={0x15,0x18}; uint8_t rgb[3]; uint32_t generation=0;
    CHECK(matter_lab_rgb_pixels(s,rgb,&generation) && !rgb[0] && !rgb[1] && !rgb[2]);
    CHECK(!invoke(s,ONOFF,1,empty,sizeof(empty)) && value(s,ONOFF,0)==1);
    CHECK(matter_lab_rgb_pixels(s,rgb,&generation) && rgb[0]==127 && !rgb[1] && !rgb[2]);
    CHECK(!matter_lab_rgb_pixels(s,rgb,&generation));
    uint8_t hue[]={0x15,0x24,0,85,0x24,1,254,0x25,2,0,0,0x24,3,0,0x24,4,0,0x18};
    CHECK(!matter_cluster_validate_command(s->clusters[COLOR],6,&request,hue,sizeof(hue)));
    CHECK(!invoke(s,COLOR,6,hue,sizeof(hue)) && value(s,COLOR,0)==85 && value(s,COLOR,1)==254);
    CHECK(matter_lab_rgb_pixels(s,rgb,&generation) && !rgb[0] && rgb[1]==127 && !rgb[2]);
    uint8_t level[]={0x15,0x24,0,254,0x25,1,10,0,0x24,2,0,0x24,3,0,0x18};
    CHECK(!invoke(s,LEVEL,0,level,sizeof(level)) && value(s,LEVEL,1)==10);
    CHECK(matter_lab_rgb_process(s,500)==MATTER_OK && value(s,LEVEL,0)==190);
    CHECK(matter_lab_rgb_process(s,1000)==MATTER_OK && value(s,LEVEL,0)==254 && !value(s,LEVEL,1));
    size_t held=live_bytes; uint32_t version_before=s->versions[COLOR];
    fail_at=calls+1;
    CHECK(matter_cluster_validate_command(s->clusters[COLOR],6,&request,hue,sizeof(hue))==MATTER_IM_RESOURCE_EXHAUSTED);
    fail_at=calls+1; CHECK(invoke(s,COLOR,6,hue,sizeof(hue))==MATTER_IM_RESOURCE_EXHAUSTED);
    fail_at=0; CHECK(live_bytes==held && s->versions[COLOR]==version_before && value(s,COLOR,0)==85);
    hue[3]=255; CHECK(invoke(s,COLOR,6,hue,sizeof(hue))==MATTER_IM_CONSTRAINT_ERROR);
    CHECK(value(s,COLOR,0)==85 && s->versions[COLOR]==version_before);
    hue[3]=170; hue[9]=10; CHECK(!invoke(s,COLOR,6,hue,sizeof(hue)));
    CHECK(matter_cluster_process(s->clusters[COLOR],1500)==MATTER_OK);
    const uint8_t stop[]={0x15,0x24,0,0,0x24,1,0,0x18};
    CHECK(!invoke(s,COLOR,0x47,stop,sizeof(stop))); uint64_t stopped=value(s,COLOR,0);
    CHECK(matter_cluster_process(s->clusters[COLOR],2000)==MATTER_OK && value(s,COLOR,0)==stopped);
    CHECK(!invoke(s,ONOFF,0,empty,sizeof(empty))); version_before=s->versions[COLOR];
    CHECK(!invoke(s,COLOR,6,hue,sizeof(hue)) && s->versions[COLOR]==version_before);
    CHECK(matter_lab_rgb_pixels(s,rgb,&generation) && !rgb[0] && !rgb[1] && !rgb[2]);
    for(unsigned k=0;k<KINDS;++k) {
        Matter_Im_Value_T out; CHECK(!matter_cluster_read(s->clusters[k],0xfffb,&request,&out));
        CHECK(out.type==MATTER_TLV_ARRAY && out.data && out.size);
    }
    CHECK(matter_cluster_retain(s->clusters[COLOR])==MATTER_OK);
    CHECK(matter_lab_rgb_delete(s)==MATTER_BUSY && live_bytes==held);
    CHECK(matter_cluster_release(s->clusters[COLOR])==MATTER_OK);
    CHECK(matter_lab_rgb_delete(s)==MATTER_OK && !live && !live_bytes);
    puts("PASS RGB lab: standard commands, transitions/stop, ExecuteIfOff, HSV pixels, validation/OOM atomicity and pinned lifetime");
    return 0;
}

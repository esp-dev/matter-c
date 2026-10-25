#include "matter_light.h"
#include "matter_light_internal.h"
#include "../model/matter_cluster_internal.h"
#include "../codec/matter_fields_internal.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>

enum { IDENTIFY,ONOFF,LEVEL,COLOR,KINDS, NULL_VALUE=65535 };
typedef struct { struct Matter_Light* owner; unsigned kind; } Server;
typedef struct { uint64_t start,end; int32_t from,to; bool active,wrap,off,repeat; } Ramp;
struct Matter_Light {
    Matter_Light_Port_T port; Matter_Light_State_T state;
    Matter_Light_Scenes_Port* scenes;size_t pins;
    Server servers[KINDS]; Matter_Cluster_T clusters[KINDS]; uint32_t versions[KINDS];
    uint64_t now,identify_end,effect_start,effect_end,on_end,off_end,last_report[2];
    uint16_t on_time,off_wait; uint8_t effect; bool global_scene,busy;
    Matter_Light_State_T global;
    Ramp ramp[6]; /* level, hue, saturation, x, y, temperature, independent axes */
    uint8_t encoded[192];
};
static const uint32_t ids[]={3,6,8,0x300},revisions[]={6,6,7,9},features[]={0,1,3,25};
static const uint32_t identify_attrs[]={0,1,0xfff8,0xfff9,0xfffb,0xfffc,0xfffd};
static const uint32_t on_attrs[]={0,0x4000,0x4001,0x4002,0x4003,0xfff8,0xfff9,0xfffb,0xfffc,0xfffd};
static const uint32_t level_attrs[]={0,1,2,3,15,17,0x4000,0xfff8,0xfff9,0xfffb,0xfffc,0xfffd};
static const uint32_t color_attrs[]={0,1,2,3,4,7,8,15,16,0x4001,0x400a,0x400b,0x400c,0x400d,0x4010,0xfff8,0xfff9,0xfffb,0xfffc,0xfffd};
static const uint32_t identify_cmd[]={0,0x40},on_cmd[]={0,1,2,0x40,0x41,0x42},level_cmd[]={0,1,2,3,4,5,6,7};
static const uint32_t color_cmd[]={0,1,2,3,4,5,6,7,8,9,10,0x47,0x4b,0x4c};
typedef struct { const uint32_t* p; size_t n; } List;
#define LIST(x) {x,sizeof(x)/sizeof(*(x))}
static const List attrs[]={LIST(identify_attrs),LIST(on_attrs),LIST(level_attrs),LIST(color_attrs)};
static const List cmds[]={LIST(identify_cmd),LIST(on_cmd),LIST(level_cmd),LIST(color_cmd)};
static void changed(Matter_Light_T l,unsigned k) { ++l->versions[k]; }
static void color_xy(const Matter_Light_State_T* s,double* x,double* y) {
    *x=s->x/65536.0;*y=s->y/65536.0;
    if(s->mode==2){double temp=1000000.0/s->temperature,t2=temp*temp,t3=t2*temp;
        *x=temp<=4000?-.2661239e9/t3-.2343580e6/t2+.8776956e3/temp+.179910:-3.0258469e9/t3+2.1070379e6/t2+.2226347e3/temp+.240390;
        *y=temp<=2222?-1.1063814*(*x)*(*x)*(*x)-1.34811020*(*x)*(*x)+2.18555832*(*x)-.20219683:temp<=4000?-.9549476*(*x)*(*x)*(*x)-1.37418593*(*x)*(*x)+2.09137015*(*x)-.16748867:3.0817580*(*x)*(*x)*(*x)-5.87338670*(*x)*(*x)+3.75112997*(*x)-.37001483;}
}
void matter_light_color_rgb(const Matter_Light_State_T* s,double rgb[3]) {
    double r=0,g=0,b=0;
    if(s->mode==0){double h=s->hue*6.0/254,sat=s->saturation/254.0;int sector=(int)h;double f=h-sector,p=1-sat,q=1-sat*f,t=1-sat*(1-f);
        switch(sector%6){case 0:r=1;g=t;b=p;break;case 1:r=q;g=1;b=p;break;case 2:r=p;g=1;b=t;break;case 3:r=p;g=q;b=1;break;case 4:r=t;g=p;b=1;break;default:r=1;g=p;b=q;}}
    else {double x,y;color_xy(s,&x,&y);double X=y>.00001?x/y:0,Z=y>.00001?(1-x-y)/y:0;
        if(y>.00001){r=3.2406*X-1.5372-.4986*Z;g=-.9689*X+1.8758+.0415*Z;b=.0557*X-.2040+1.057*Z;}
        double max=fmax(r,fmax(g,b));if(max<1)max=1;r=fmax(0,r/max);g=fmax(0,g/max);b=fmax(0,b/max);}
    rgb[0]=r;rgb[1]=g;rgb[2]=b;
}
void matter_light_color_hue_from_xy(Matter_Light_State_T* s) {
    Matter_Light_State_T xy=*s;xy.mode=1;double rgb[3];matter_light_color_rgb(&xy,rgb);
    double max=fmax(rgb[0],fmax(rgb[1],rgb[2])),min=fmin(rgb[0],fmin(rgb[1],rgb[2])),delta=max-min;
    if(delta>.000001){double h=max==rgb[0]?(rgb[1]-rgb[2])/delta:max==rgb[1]?2+(rgb[2]-rgb[0])/delta:4+(rgb[0]-rgb[1])/delta;if(h<0)h+=6;s->hue=(uint8_t)(h*254/6+.5);}
    s->saturation=max>.000001?(uint8_t)(delta/max*254+.5):0;
}
void matter_light_color_normalize(Matter_Light_State_T* s) {
    if(s->mode==0){double rgb[3];matter_light_color_rgb(s,rgb);double X=.4124*rgb[0]+.3576*rgb[1]+.1805*rgb[2],Y=.2126*rgb[0]+.7152*rgb[1]+.0722*rgb[2],Z=.0193*rgb[0]+.1192*rgb[1]+.9505*rgb[2],total=X+Y+Z;
        if(total>.000001){s->x=(uint16_t)(X/total*65536+.5);s->y=(uint16_t)(Y/total*65536+.5);}}
    else {if(s->mode==2){double x,y;color_xy(s,&x,&y);s->x=(uint16_t)(x*65536+.5);s->y=(uint16_t)(y*65536+.5);}matter_light_color_hue_from_xy(s);}
}
static bool valid(const Matter_Light_State_T* s) {
    return s->level && s->level<=254 && s->hue<=254 && s->saturation<=254 && s->mode<=2 &&
        s->x<=65279 && s->y<=65279 && s->temperature>=153 && s->temperature<=500 &&
        (s->start_temperature==NULL_VALUE || (s->start_temperature>=153 && s->start_temperature<=500)) &&
        (s->on_level==NULL_VALUE || (s->on_level>=1 && s->on_level<=254)) &&
        (s->start_level==NULL_VALUE || s->start_level<=254) && (s->start_on==NULL_VALUE || s->start_on<=2) &&
        s->options_level<=3 && s->options_color<=1;
}
void matter_light_defaults(Matter_Light_State_T* s) {
    if(s) *s=(Matter_Light_State_T){.x=20493,.y=21561,.temperature=250,.start_temperature=NULL_VALUE,
        .on_level=NULL_VALUE,.start_level=NULL_VALUE,.start_on=NULL_VALUE,.level=127,.saturation=254,.on=true};
}
static void visible(Matter_Light_T l,const Matter_Light_State_T* next) {
    Matter_Light_State_T old=l->state; l->state=*next;
    if(old.on!=next->on || old.start_on!=next->start_on) changed(l,ONOFF);
    if(old.level!=next->level || old.options_level!=next->options_level || old.on_level!=next->on_level || old.start_level!=next->start_level) changed(l,LEVEL);
    if(old.hue!=next->hue || old.saturation!=next->saturation || old.x!=next->x || old.y!=next->y ||
        old.temperature!=next->temperature || old.mode!=next->mode || old.options_color!=next->options_color || old.start_temperature!=next->start_temperature) changed(l,COLOR);
    if(next->on && !old.on && !l->on_time) { l->off_wait=0; l->off_end=0; }
    if(!next->on && old.on) { l->on_time=0; l->on_end=0; }
}
static uint8_t publish_raw(Matter_Light_T l,const Matter_Light_State_T* next) {
    if(!valid(next)) return MATTER_IM_CONSTRAINT_ERROR;
    if(!memcmp(&l->state,next,sizeof(*next))) return 0;
    l->busy=true; Matter_Result_T r=l->port.store(l->port.user,next); l->busy=false;
    if(r!=MATTER_OK) return r==MATTER_LIMIT_REACHED?MATTER_IM_RESOURCE_EXHAUSTED:MATTER_IM_FAILURE;
    visible(l,next);return 0;
}
static uint8_t publish(Matter_Light_T l,const Matter_Light_State_T* next) {
    if(!valid(next))return MATTER_IM_CONSTRAINT_ERROR;
    Matter_Light_State_T normalized=*next;
    if(next->mode!=l->state.mode||(next->mode==0&&(next->hue!=l->state.hue||next->saturation!=l->state.saturation))||
        (next->mode==1&&(next->x!=l->state.x||next->y!=l->state.y))||(next->mode==2&&next->temperature!=l->state.temperature))matter_light_color_normalize(&normalized);
    return publish_raw(l,&normalized);
}
static int axis(const Matter_Light_State_T* s,unsigned i) {
    return i==0?s->level:i==1?s->hue:i==2?s->saturation:i==3?s->x:i==4?s->y:s->temperature;
}
static void set_axis(Matter_Light_State_T* s,unsigned i,int v) {
    if(i==0) s->level=(uint8_t)v; else if(i==1) s->hue=(uint8_t)v; else if(i==2) s->saturation=(uint8_t)v;
    else if(i==3) s->x=(uint16_t)v; else if(i==4) s->y=(uint16_t)v; else s->temperature=(uint16_t)v;
}
static void ramp(Matter_Light_T l,unsigned i,int from,int to,uint32_t ms,bool wrap,bool off) {
    l->ramp[i]=(Ramp){l->now,l->now+ms,from,to,ms!=0,wrap,off,false};
    if(ms) set_axis(&l->state,i,from);
}
static uint64_t remaining(Matter_Light_T l,unsigned k) {
    uint64_t end=0; for(unsigned i=k==LEVEL?0:1;i<(k==LEVEL?1:6);++i)
        if(l->ramp[i].active) { if(l->ramp[i].repeat) return 65534; if(l->ramp[i].end>end) end=l->ramp[i].end; }
    return end>l->now?(end-l->now+99)/100:0;
}
static bool emit(Matter_Tlv_Writer_T* w,Matter_Tlv_Type_T type,int tag,uint64_t value) {
    Matter_Tlv_Element_T e={.type=type,.unsigned_value=value};
    if(tag>=0) e.tag=(Matter_Tlv_Tag_T){.control=1,.number=(uint32_t)tag};
    return matter_tlv_write(w,&e,0)==MATTER_TLV_OK;
}
static uint8_t read_attr(void* user,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* out) {
    (void)q; Server* s=user; Matter_Light_T l=s->owner; if(l->busy) return MATTER_IM_FAILURE;
    unsigned k=s->kind; uint32_t id=*(const uint32_t*)ref; Matter_Light_State_T* v=&l->state;
    *out=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.data_version=l->versions[k]};
    if(id==0xfff8 || id==0xfff9 || id==0xfffb) {
        List list=id==0xfffb?attrs[k]:id==0xfff9?cmds[k]:(List){NULL,0};
        Matter_Tlv_Writer_T w; if(matter_tlv_writer_init(&w,l->encoded,sizeof(l->encoded),1)!=MATTER_TLV_OK || !emit(&w,MATTER_TLV_ARRAY,-1,0)) return MATTER_IM_FAILURE;
        for(size_t i=0;i<list.n;++i) if(!emit(&w,MATTER_TLV_UNSIGNED,-1,list.p[i])) return MATTER_IM_FAILURE;
        if(!emit(&w,MATTER_TLV_END,-1,0) || matter_tlv_writer_finish(&w,&out->size)!=MATTER_TLV_OK) return MATTER_IM_FAILURE;
        out->type=MATTER_TLV_ARRAY; out->data=l->encoded; return 0;
    }
    uint64_t n=0;
    if(id==0xfffc) n=features[k]; else if(id==0xfffd) n=revisions[k];
    else if(k==IDENTIFY) n=id?1:l->identify_end>l->now?(l->identify_end-l->now+999)/1000:0;
    else if(k==ONOFF) {
        n=id==0?v->on:id==0x4000?l->global_scene:id==0x4001?l->on_time:id==0x4002?l->off_wait:v->start_on;
        if(id==0 || id==0x4000) out->type=MATTER_TLV_BOOL;
    } else if(k==LEVEL) n=id==0?v->level:id==1?remaining(l,k):id==2?1:id==3?254:id==15?v->options_level:id==17?v->on_level:v->start_level;
    else n=id==0?v->hue:id==1?v->saturation:id==2?remaining(l,k):id==3?v->x:id==4?v->y:id==7?v->temperature:
        id==8||id==0x4001?v->mode:id==15?v->options_color:id==16?NULL_VALUE:id==0x400a?25:id==0x400b||id==0x400d?153:id==0x400c?500:v->start_temperature;
    if(n==NULL_VALUE && ((k==COLOR&&(id==16||id==0x4010)) || (k==LEVEL&&(id==17||id==0x4000)) || (k==ONOFF&&id==0x4003))) out->type=MATTER_TLV_NULL;
    else out->unsigned_value=n;
    return 0;
}
static uint8_t write_attr(void* user,const void* ref,const uint8_t* d,size_t n,bool apply) {
    Server* s=user; Matter_Light_T l=s->owner; if(l->busy) return MATTER_IM_FAILURE;
    Matter_Tlv_Reader_T r; Matter_Tlv_Element_T e; uint32_t id=*(const uint32_t*)ref;
    if(matter_tlv_init(&r,d,n,1)!=MATTER_TLV_OK || matter_tlv_next(&r,&e)!=MATTER_TLV_OK || e.tag.control ||
        (e.type!=MATTER_TLV_UNSIGNED && e.type!=MATTER_TLV_NULL)) return MATTER_IM_INVALID_DATA_TYPE;
    bool is_null=e.type==MATTER_TLV_NULL;
    uint64_t value=is_null?NULL_VALUE:e.unsigned_value;
    bool timer=s->kind==ONOFF && (id==0x4001||id==0x4002);
    if(e.type==MATTER_TLV_UNSIGNED && value>((s->kind==IDENTIFY||timer)?65535:65534)) return MATTER_IM_CONSTRAINT_ERROR;
    if(matter_tlv_next(&r,&e)!=MATTER_TLV_DONE) return MATTER_IM_INVALID_DATA_TYPE;
    if(s->kind==IDENTIFY) {
        if(is_null) return MATTER_IM_CONSTRAINT_ERROR;
        if(value*1000>UINT64_MAX-l->now) return MATTER_IM_CONSTRAINT_ERROR;
        if(apply) { l->identify_end=l->now+value*1000; changed(l,IDENTIFY); } return 0;
    }
    if(timer) {
        if(is_null || value*100>UINT64_MAX-l->now) return MATTER_IM_CONSTRAINT_ERROR;
        if(apply) { if(id==0x4001){l->on_time=(uint16_t)value;if(l->on_end)l->on_end=value==65535?0:l->now+value*100;}
            else {l->off_wait=(uint16_t)value;if(l->off_end)l->off_end=value==65535?0:l->now+value*100;}changed(l,ONOFF); }
        return 0;
    }
    Matter_Light_State_T next=l->state;
    if(s->kind==ONOFF) next.start_on=(uint16_t)value;
    else if(s->kind==LEVEL) { if(id==15) { if(value>3) return MATTER_IM_CONSTRAINT_ERROR; next.options_level=(uint8_t)value; }
        else if(id==17) next.on_level=(uint16_t)value; else next.start_level=(uint16_t)value; }
    else { if(id==15) { if(value>1) return MATTER_IM_CONSTRAINT_ERROR; next.options_color=(uint8_t)value; } else next.start_temperature=(uint16_t)value; }
    return !valid(&next)?MATTER_IM_CONSTRAINT_ERROR:apply?publish(l,&next):0;
}
static uint8_t validate_attr(void* u,const void* ref,const Matter_Cluster_Request_T* q,const uint8_t* d,size_t n) { (void)q; return write_attr(u,ref,d,n,false); }
static Matter_Im_Write_Result_T store_attr(void* u,const void* ref,const Matter_Cluster_Request_T* q,const uint8_t* d,size_t n) { (void)q; return (Matter_Im_Write_Result_T){.status=write_attr(u,ref,d,n,true)}; }
static bool options(Matter_Fields* in,unsigned at,unsigned allowed,unsigned stored,bool* execute,Matter_Light_T l) {
    uint64_t mask=0,override=0;
    if(!matter_field_u(in,at,allowed,false,false,&mask) || !matter_field_u(in,at+1,allowed,false,false,&override)) return false;
    *execute=l->state.on || (((stored&~(unsigned)mask)|((unsigned)override&(unsigned)mask))&1); return true;
}
static uint8_t command(Server* server,uint32_t id,const uint8_t* data,size_t size,bool apply,uint8_t fabric) {
    Matter_Light_T l=server->owner; if(l->busy) return MATTER_IM_FAILURE;
    uint8_t error; Matter_Fields* in=matter_fields(data,size,4,&error); if(!in) return error;
    Matter_Light_State_T next=l->state,old=l->state;
    unsigned k=server->kind,mask=0; uint64_t a=0,b=0,c=0,d=0,e=0; int rate_x=0,rate_y=0;
    uint32_t ms=0; int target[6]={0}; bool wraps[6]={false},execute=true,off=false,recalled=false;
    if(k==IDENTIFY) {
        if(!matter_field_u(in,0,id?255:65535,true,false,&a) || (id && (!matter_field_u(in,1,255,true,false,&b) || b || (a>2 && a!=11 && a!=254 && a!=255))) || (!id&&a*1000>UINT64_MAX-l->now)) goto constraint;
        if(apply) { if(!id) l->identify_end=l->now+a*1000;
            else { if(a==255) l->effect_end=0; else if(a==254) { if(l->effect_end>l->now+1000) l->effect_end=l->now+1000; }
                else { l->effect=(uint8_t)a; l->effect_start=l->now; l->effect_end=l->now+(a==0||a==2?1000:a==1?15000:8000); } }
            changed(l,IDENTIFY); }
        goto done;
    }
    if(k==ONOFF) {
        if(id<=2) next.on=id==2?!next.on:id==1;
        else if(id==0x40) {
            if(!matter_field_u(in,0,1,true,false,&a) || !matter_field_u(in,1,2,true,false,&b) || (a==1&&b)) goto constraint;
            next.on=false;
        } else if(id==0x41) {
            if(!l->global_scene) {
                if(l->scenes&&apply){l->busy=true;error=l->scenes->load(l->scenes->user,fabric,&next,&recalled);l->busy=false;if(error)goto done;}
                else next=l->global;
            }
            next.on=true;
        }
        else {
            if(!matter_field_u(in,0,1,true,false,&a)||!matter_field_u(in,1,65534,true,false,&b)||!matter_field_u(in,2,65534,true,false,&c)) goto constraint;
            if((a&1)&&!next.on) goto done;
            if(!next.on && l->off_wait) {
                if(apply) { if(c<l->off_wait)l->off_wait=(uint16_t)c;l->off_end=l->now+(uint64_t)l->off_wait*100;changed(l,ONOFF); }
                goto done;
            }
            next.on=true;
        }
        if(next.on && !old.on && next.on_level!=NULL_VALUE) next.level=(uint8_t)next.on_level;
    } else if(k==LEVEL) {
        unsigned operation=id&3;
        if(operation==3) { if(!options(in,0,3,next.options_level,&execute,l)) goto constraint; }
        else if(operation==0) {
            if(!matter_field_u(in,0,254,true,false,&a)||!matter_field_u(in,1,65535,true,true,&b)||!options(in,2,3,next.options_level,&execute,l)) goto constraint;
            target[0]=(int)(a?a:1); ms=b==NULL_VALUE?0:(uint32_t)b*100;
        } else if(operation==1) {
            if(!matter_field_u(in,0,1,true,false,&a)||!matter_field_u(in,1,254,true,true,&b)||!options(in,2,3,next.options_level,&execute,l) || b==0) goto constraint;
            if(b==NULL_VALUE) b=50;
            target[0]=a?1:254; ms=(uint32_t)((uint64_t)abs(target[0]-old.level)*1000/b);
        } else {
            if(!matter_field_u(in,0,1,true,false,&a)||!matter_field_u(in,1,254,true,false,&b)||!matter_field_u(in,2,65535,true,true,&c)||!options(in,3,3,next.options_level,&execute,l)) goto constraint;
            int t=old.level+(a?-(int)b:(int)b); target[0]=t<1?1:t>254?254:t; ms=c==NULL_VALUE?0:(uint32_t)c*100;
        }
        if(id>=4 || operation==3) execute=true;
        if(!execute) goto done;
        if(operation!=3) {
            mask=1; next.level=(uint8_t)target[0];
            if(id>=4) { off=operation==0?a==0:target[0]==1; next.on=!off; if(ms && off) next.on=old.on; }
            if((next.options_level&2) && next.mode==2) next.temperature=(uint16_t)(500-(next.level-1)*347/253);
        }
    } else {
        if(id==0x47) { if(!options(in,0,1,next.options_color,&execute,l)) goto constraint; }
        else if(id<=6) {
            unsigned opt=id==0||id==2||id==6?3:2;
            if(!options(in,opt,1,next.options_color,&execute,l) || !matter_field_u(in,0,254,true,false,&a)) goto constraint;
            if(id==0) {
                if(!matter_field_u(in,1,3,true,false,&b)||!matter_field_u(in,2,65534,true,false,&c)) goto constraint;
                int delta=(int)a-old.hue;
                if((b==0&&delta>127)||(b==1&&delta>=0&&delta<128)||(b==3&&delta>0)) delta-=255;
                else if((b==0&&delta<-127)||(b==1&&delta<0&&delta>-128)||(b==2&&delta<0)) delta+=255;
                target[1]=old.hue+delta; wraps[1]=true; mask=2; ms=(uint32_t)c*100;
            } else if(id==1||id==4) {
                if((a!=0&&a!=1&&a!=3)||!matter_field_u(in,1,254,true,false,&b)||(a&&b==0)) goto constraint;
                unsigned axis_id=id==1?1:2; if(a) { target[axis_id]=axis_id==1?old.hue+(a==1?255:-255):a==1?254:0; mask=1u<<axis_id;
                    ms=(uint32_t)((uint64_t)abs(target[axis_id]-axis(&old,axis_id))*1000/b); wraps[axis_id]=axis_id==1; }
            } else if(id==2||id==5) {
                if((a!=1&&a!=3)||!matter_field_u(in,1,254,true,false,&b)||!matter_field_u(in,2,65534,true,false,&c)) goto constraint;
                unsigned axis_id=id==2?1:2; int t=axis(&old,axis_id)+(a==1?(int)b:-(int)b);
                if(axis_id==1) { wraps[1]=true; target[1]=t; } else target[2]=t<0?0:t>254?254:t;
                mask=1u<<axis_id; ms=(uint32_t)c*100;
            } else if(id==3) { if(!matter_field_u(in,1,65534,true,false,&b)) goto constraint; mask=4; target[2]=(int)a; ms=(uint32_t)b*100; }
            else { if(!matter_field_u(in,1,254,true,false,&b)||!matter_field_u(in,2,65534,true,false,&c)) goto constraint;
                int delta=(int)a-old.hue; if(delta>127)delta-=255; if(delta<-127)delta+=255;
                mask=6; target[1]=old.hue+delta; wraps[1]=true; target[2]=(int)b; ms=(uint32_t)c*100; }
            next.mode=0;
        } else if(id==7||id==9) {
            if(!options(in,3,1,next.options_color,&execute,l)||!matter_field_u(in,2,65534,true,false,&c)) goto constraint;
            if(id==7) { if(!matter_field_u(in,0,65279,true,false,&a)||!matter_field_u(in,1,65279,true,false,&b)) goto constraint; target[3]=(int)a; target[4]=(int)b; }
            else { if(!matter_field_i(in,0,&rate_x)||!matter_field_i(in,1,&rate_y)) goto constraint;
                int x=old.x+rate_x,y=old.y+rate_y; target[3]=x<0?0:x>65279?65279:x; target[4]=y<0?0:y>65279?65279:y; }
            mask=24; ms=(uint32_t)c*100; next.mode=1;
        } else if(id==8) {
            if(!matter_field_i(in,0,&rate_x)||!matter_field_i(in,1,&rate_y)||!options(in,2,1,next.options_color,&execute,l)) goto constraint;
            /* A rate pair is normalized to a common bounded movement duration. */
            uint32_t dx=rate_x?(uint32_t)((uint64_t)(rate_x>0?65279-old.x:old.x)*1000/abs(rate_x)):UINT32_MAX;
            uint32_t dy=rate_y?(uint32_t)((uint64_t)(rate_y>0?65279-old.y:old.y)*1000/abs(rate_y)):UINT32_MAX;
            ms=dx<dy?dx:dy; if(ms==UINT32_MAX) ms=0;
            target[3]=(int)(old.x+(int64_t)rate_x*ms/1000); target[4]=(int)(old.y+(int64_t)rate_y*ms/1000); mask=24; next.mode=1;
        } else if(id==10) {
            if(!matter_field_u(in,0,65279,true,false,&a)||!matter_field_u(in,1,65534,true,false,&b)||!options(in,2,1,next.options_color,&execute,l)) goto constraint;
            target[5]=a<153?153:a>500?500:(int)a; mask=32; ms=(uint32_t)b*100; next.mode=2;
        } else {
            if(!matter_field_u(in,0,3,true,false,&a)||(a!=0&&a!=1&&a!=3)||!matter_field_u(in,1,65535,true,false,&b)||
                !matter_field_u(in,2,id==0x4b?65279:65534,true,false,&c)||!matter_field_u(in,3,65279,true,false,&d)||!options(in,id==0x4b?4:5,1,next.options_color,&execute,l)) goto constraint;
            if(id==0x4b) { if(!c||c<153)c=153;if(!d||d>500)d=500;if(c>d||(a&&!b))goto constraint;
                if(a) {target[5]=a==1?(int)d:(int)c;mask=32;ms=(uint32_t)((uint64_t)abs(target[5]-old.temperature)*1000/b);} }
            else {
                if(!matter_field_u(in,4,65279,true,false,&e)||!a)goto constraint;
                uint64_t min=d?d:153,max=e?e:500;if(min<153)min=153;if(max>500)max=500;if(min>max)goto constraint;
                int t=old.temperature+(a==1?(int)b:-(int)b);target[5]=t<(int)min?(int)min:t>(int)max?(int)max:t;mask=32;ms=(uint32_t)c*100;
            }
            next.mode=2;
        }
        if(!execute) goto done;
        for(unsigned i=1;i<6;++i) if(mask&(1u<<i)) set_axis(&next,i,wraps[i]?(target[i]%255+255)%255:target[i]);
    }
    if(ms>UINT64_MAX-l->now) goto constraint;
    if(!apply) goto done;
    if(k==ONOFF&&id==0x40&&l->global_scene&&l->scenes) {
        if(!valid(&next)){error=MATTER_IM_CONSTRAINT_ERROR;goto done;}
        l->busy=true;error=l->scenes->save(l->scenes->user,fabric,&old,&next);l->busy=false;if(error)goto done;
        visible(l,&next);
    } else {error=recalled?publish_raw(l,&next):publish(l,&next); if(error) goto done;}
    if(k==ONOFF) {
        bool previous=l->global_scene;
        if(id==0x40) { if(l->global_scene) l->global=old; l->global_scene=false; }
        else if(next.on) l->global_scene=true;
        if(previous!=l->global_scene)changed(l,ONOFF);
        if(recalled)l->scenes->recalled(l->scenes->user,fabric);
        if(id==0x42) { l->on_time=l->on_time>(uint16_t)b?l->on_time:(uint16_t)b; l->off_wait=(uint16_t)c;
            l->on_end=l->on_time?l->now+(uint64_t)l->on_time*100:0; l->off_end=0; }
        if(!next.on || next.level!=old.level) l->ramp[0].active=false;
        if(!next.on&&old.on&&l->off_wait&&l->off_wait!=65535)l->off_end=l->now+(uint64_t)l->off_wait*100;
    } else if(k==LEVEL) {
        if((id&3)==3) l->ramp[0].active=false;
        else { ramp(l,0,old.level,target[0],ms,false,off); if(id>=4 && next.on!=old.on) l->global_scene=true; }
    } else if(k==COLOR) {
        if(id==0x47) for(unsigned i=1;i<6;++i)l->ramp[i].active=false;
        else {
            if(next.mode!=old.mode) for(unsigned i=1;i<6;++i) l->ramp[i].active=false;
            if((id==1||id==4||id==0x4b)&&!a) l->ramp[id==1?1:id==4?2:5].active=false;
            for(unsigned i=1;i<6;++i) if(mask&(1u<<i))ramp(l,i,axis(&old,i),target[i],ms,wraps[i],false);
            if(id==1&&a)l->ramp[1].repeat=true;
        }
    }
    if(k==COLOR)matter_light_color_normalize(&l->state);
    goto done;
constraint: error=MATTER_IM_CONSTRAINT_ERROR;
done: free(in); return error;
}
static uint8_t validate_command(void* u,const void* ref,const Matter_Cluster_Request_T* q,const uint8_t* d,size_t n) { return command(u,*(const uint32_t*)ref,d,n,false,q->fabric); }
static Matter_Result_T invoke(void* u,const void* ref,const Matter_Cluster_Request_T* q,const uint8_t* d,size_t n,Matter_Tlv_Writer_T* w,Matter_Im_Command_Result_T* out,uint64_t* token) {
    (void)w;*token=0;out->status=command(u,*(const uint32_t*)ref,d,n,true,q->fabric);return MATTER_OK;
}
static Matter_Result_T version(void* u,uint32_t* out) { Server* s=u;*out=s->owner->versions[s->kind];return MATTER_OK; }
Matter_Light_T matter_light_new(const Matter_Light_Port_T* p,uint32_t seed,uint64_t now,bool ota) {
    if(!p||!p->load||!p->store)return NULL;
    Matter_Light_T l=calloc(1,sizeof(*l)); if(!l)return NULL;l->port=*p;l->now=now;l->global_scene=true;
    if(p->load(p->user,&l->state)!=MATTER_OK||!valid(&l->state))goto bad;
    Matter_Light_State_T restored=l->state;
    if(!ota) { if(l->state.start_on!=NULL_VALUE) l->state.on=l->state.start_on==2?!l->state.on:l->state.start_on==1;
        if(l->state.start_level!=NULL_VALUE) l->state.level=(uint8_t)(l->state.start_level?l->state.start_level:1);
        if(l->state.start_temperature!=NULL_VALUE) { l->state.temperature=l->state.start_temperature;l->state.mode=2; } }
    matter_light_color_normalize(&l->state);l->global=l->state;
    for(unsigned k=0;k<KINDS;++k) {
        l->versions[k]=seed+k;l->servers[k]=(Server){l,k};
        Matter_Cluster_Config_T cfg={.id=ids[k],.attributes=(uint16_t)attrs[k].n,.commands=(uint16_t)cmds[k].n,.callbacks={.ctx=&l->servers[k],.version=version}};
        l->clusters[k]=matter_cluster_new(&cfg);if(!l->clusters[k])goto bad;
        for(size_t i=0;i<attrs[k].n;++i) {
            uint32_t id=attrs[k].p[i];bool writable=(k==IDENTIFY&&id==0)||(k==ONOFF&&id>=0x4001&&id<=0x4003)||(k==LEVEL&&(id==15||id==17||id==0x4000))||(k==COLOR&&(id==15||id==0x4010));
            Matter_Attribute_Def_T a={.id=id,.ref=&attrs[k].p[i],.read_access={MATTER_IM_VIEW,false},.read=read_attr};
            if(writable){a.write_access.privilege=(id==0x4003||id==0x4000||id==0x4010)?MATTER_IM_MANAGE:MATTER_IM_OPERATE;a.validate=validate_attr;a.write=store_attr;}
            if(matter_cluster_add_attribute(l->clusters[k],&a)!=MATTER_OK)goto bad;
        }
        for(size_t i=0;i<cmds[k].n;++i) {
            Matter_Command_Def_T c={.id=cmds[k].p[i],.ref=&cmds[k].p[i],.access={.privilege=k==IDENTIFY?MATTER_IM_MANAGE:MATTER_IM_OPERATE},.validate=validate_command,.start=invoke};
            if(matter_cluster_add_command(l->clusters[k],&c)!=MATTER_OK)goto bad;
        }
        if(matter_cluster_seal(l->clusters[k])!=MATTER_OK)goto bad;
    }
    /* StartUpOnOff=Toggle must toggle the last durable operating state, rather
     * than repeatedly applying the same old value on subsequent cold boots.
     * Publish this only after every construction allocation has succeeded. */
    if(memcmp(&restored,&l->state,sizeof(restored))) {
        l->busy=true;Matter_Result_T r=p->store(p->user,&l->state);l->busy=false;if(r!=MATTER_OK)goto bad;
    }
    return l;
bad:(void)matter_light_delete(l);return NULL;
}
Matter_Result_T matter_light_attach(Matter_Light_T l,Matter_Root_T root,uint16_t endpoint) {
    if(!l||!root)return MATTER_INVALID_ARGUMENT;
    Matter_Root_Endpoint_Config_T e={.endpoint=endpoint,.revision=5,.device_type=0x10d,.data_version=l->versions[0]};
    Matter_Result_T r=matter_root_add_endpoint(root,&e);if(r!=MATTER_OK)return r;
    for(unsigned k=0;k<KINDS;++k)if((r=matter_root_attach_cluster_at(root,endpoint,l->clusters[k]))!=MATTER_OK)return r;
    return MATTER_OK;
}
Matter_Cluster_T matter_light_cluster(Matter_Light_T l,uint32_t id) { if(l)for(unsigned k=0;k<KINDS;++k)if(ids[k]==id)return l->clusters[k];return NULL; }
Matter_Result_T matter_light_process(Matter_Light_T l,uint64_t now) {
    if(!l||now<l->now)return MATTER_INVALID_ARGUMENT;
    if(l->busy)return MATTER_BUSY;
    bool identifying=l->identify_end>l->now;l->now=now;
    if(identifying&&l->identify_end<=now)changed(l,IDENTIFY);
    bool color_moved=false;
    for(unsigned i=0;i<6;++i) {
        Ramp* r=&l->ramp[i];if(!r->active)continue;
        if(i)color_moved=true;
        uint64_t duration=r->end-r->start;
        uint64_t elapsed=r->repeat?(now-r->start)%duration:now>=r->end?duration:now-r->start;
        int v=r->from+(int)((int64_t)(r->to-r->from)*(int64_t)elapsed/(int64_t)(r->end-r->start));
        set_axis(&l->state,i,r->wrap?(v%255+255)%255:v);
        unsigned k=i?COLOR:LEVEL;
        if(now>=r->end&&!r->repeat){r->active=false;if(r->off&&l->state.on){l->state.on=false;changed(l,ONOFF);}changed(l,k);}
        else if(now-l->last_report[i?1:0]>=1000){l->last_report[i?1:0]=now;changed(l,k);}
    }
    if(color_moved)matter_light_color_normalize(&l->state);
    if(l->on_end) {
        if(now>=l->on_end) { Matter_Light_State_T n=l->state;n.on=false;uint8_t e=publish(l,&n);if(e)return MATTER_PORT_ERROR;l->on_end=0;l->off_wait=0;l->off_end=0;changed(l,ONOFF); }
        else l->on_time=(uint16_t)((l->on_end-now+99)/100);
    }
    if(l->off_end){l->off_wait=now>=l->off_end?0:(uint16_t)((l->off_end-now+99)/100);if(!l->off_wait)l->off_end=0;}
    return MATTER_OK;
}
Matter_Result_T matter_light_state(Matter_Light_T l,Matter_Light_State_T* out){if(!l||!out)return MATTER_INVALID_ARGUMENT;if(l->busy)return MATTER_BUSY;*out=l->state;return MATTER_OK;}
Matter_Result_T matter_light_recall(Matter_Light_T l,const Matter_Light_State_T* next,uint32_t ms){
    if(!l||!next||!valid(next)||ms>UINT64_MAX-l->now)return MATTER_INVALID_ARGUMENT;
    if(l->busy)return MATTER_BUSY;
    Matter_Light_State_T old=l->state;if(publish_raw(l,next))return MATTER_PORT_ERROR;
    for(unsigned i=0;i<6;++i)ramp(l,i,axis(&old,i),axis(next,i),ms,false,false);
    return MATTER_OK;
}
bool matter_light_identifying(Matter_Light_T l){return l&&l->identify_end>l->now;}
static uint8_t channel(double v){if(v<0)v=0;if(v>1)v=1;return(uint8_t)(v*255+.5);}
void matter_light_pixels(Matter_Light_T l,uint8_t rgb[3]) {
    if(!l||!rgb)return;
    double color[3],v=l->state.level/254.0;matter_light_color_rgb(&l->state,color);double r=color[0]*v,g=color[1]*v,b=color[2]*v;
    if(!l->state.on)r=g=b=0;
    if(l->identify_end>l->now){r=g=b=(l->now/250)%2?.25:0;}
    else if(l->effect_end>l->now){uint64_t t=l->now-l->effect_start;r=g=b=0;if(l->effect==2)g=.25;else if(l->effect==11){r=.25;g=.06;}else if(l->effect==1)r=g=b=(1+sin((double)t/1000*6.2831853))*.125;else if(t<500)r=g=b=.25;}
    rgb[0]=channel(r);rgb[1]=channel(g);rgb[2]=channel(b);
}
Matter_Result_T matter_light_delete(Matter_Light_T l){
    if(!l)return MATTER_INVALID_ARGUMENT;
    if(l->busy||l->pins)return MATTER_BUSY;
    for(unsigned k=0;k<KINDS;++k)if(l->clusters[k]&&(matter_cluster_pins(l->clusters[k])||matter_cluster_in_use(l->clusters[k])))return MATTER_BUSY;
    for(unsigned k=0;k<KINDS;++k)if(l->clusters[k])(void)matter_cluster_delete(l->clusters[k]);
    free(l->scenes);free(l);return MATTER_OK;
}
Matter_Result_T matter_light_pin(Matter_Light_T l){if(!l)return MATTER_INVALID_ARGUMENT;if(l->busy||l->pins==SIZE_MAX)return MATTER_BUSY;++l->pins;return MATTER_OK;}
Matter_Result_T matter_light_unpin(Matter_Light_T l){if(!l||!l->pins)return MATTER_INVALID_ARGUMENT;if(l->busy)return MATTER_BUSY;--l->pins;return MATTER_OK;}
Matter_Result_T matter_light_bind_scenes(Matter_Light_T l,const Matter_Light_Scenes_Port* p){
    if(!l)return MATTER_INVALID_ARGUMENT;
    if(l->busy)return MATTER_BUSY;
    for(unsigned k=0;k<KINDS;++k)if(matter_cluster_pins(l->clusters[k]))return MATTER_BUSY;
    if(!p){free(l->scenes);l->scenes=NULL;return MATTER_OK;}
    if(l->scenes)return MATTER_INVALID_STATE;
    if(!p->save||!p->load||!p->recalled)return MATTER_INVALID_ARGUMENT;
    l->scenes=calloc(1,sizeof(*l->scenes));if(!l->scenes)return MATTER_LIMIT_REACHED;*l->scenes=*p;return MATTER_OK;
}

#include "rgb_light.h"
#include "model/matter_cluster_internal.h"
#include "codec/matter_tlv_validate.h"
#include "codec/matter_tlv_writer.h"
#include <stdlib.h>
#include <string.h>

enum { ONOFF, LEVEL, COLOR, KINDS };
typedef struct { struct Matter_Lab_Rgb* light; unsigned kind; } Server;
typedef struct {
    Matter_Tlv_Validation_Workspace_T validation; Matter_Tlv_Tag_T tags[16];
    Matter_Tlv_Reader_T reader; Matter_Tlv_Element_T element;
    uint64_t fields[5]; unsigned seen;
} Command;
struct Matter_Lab_Rgb {
    Server servers[KINDS]; Matter_Cluster_T clusters[KINDS];
    uint32_t versions[KINDS],generation; uint64_t now;
    uint8_t hue,saturation,level,options[2]; bool on;
    struct { uint64_t start,end; uint8_t from[2],target[2]; bool active; } transitions[2];
    uint8_t encoded[80]; Matter_Tlv_Writer_T writer; Matter_Tlv_Element_T token;
};
static const uint32_t cluster_ids[]={6,8,0x300};
static const uint32_t revisions[]={6,7,9};
static const uint32_t on_attributes[]={0,0xfff8,0xfff9,0xfffb,0xfffc,0xfffd};
static const uint32_t level_attributes[]={0,1,2,3,15,0xfff8,0xfff9,0xfffb,0xfffc,0xfffd};
static const uint32_t color_attributes[]={0,1,2,8,15,16,0x4001,0x400a,0xfff8,0xfff9,0xfffb,0xfffc,0xfffd};
static const uint32_t on_commands[]={0,1,2};
static const uint32_t level_commands[]={0,3,4,7};
static const uint32_t color_commands[]={6,0x47};
static const uint32_t* attributes(unsigned kind,size_t* count) {
    *count=kind==ONOFF?sizeof(on_attributes)/sizeof(*on_attributes):kind==LEVEL?sizeof(level_attributes)/sizeof(*level_attributes):sizeof(color_attributes)/sizeof(*color_attributes);
    return kind==ONOFF?on_attributes:kind==LEVEL?level_attributes:color_attributes;
}
static const uint32_t* commands(unsigned kind,size_t* count) {
    *count=kind==ONOFF?3:kind==LEVEL?4:2; return kind==ONOFF?on_commands:kind==LEVEL?level_commands:color_commands;
}
static void changed(Matter_Lab_Rgb_T s,unsigned kind) { ++s->versions[kind]; ++s->generation; }
static Matter_Result_T version(void* user,uint32_t* out) { Server* server=user; *out=server->light->versions[server->kind]; return MATTER_OK; }
static Matter_Result_T process(void* user,uint64_t now) {
    Server* server=user; Matter_Lab_Rgb_T s=server->light;
    if(now<s->now) return MATTER_INVALID_ARGUMENT;
    s->now=now;
    for(unsigned k=0;k<2;++k) {
        if(!s->transitions[k].active) continue;
        uint64_t start=s->transitions[k].start,end=s->transitions[k].end;
        uint64_t elapsed=now>=end?end-start:now-start,duration=end-start;
        uint8_t* values[]={k?&s->hue:&s->level,&s->saturation};
        bool update=false;
        for(unsigned i=0;i<(k?2u:1u);++i) {
            int delta=(int)s->transitions[k].target[i]-s->transitions[k].from[i];
            if(k && !i) { if(delta>127) delta-=255; if(delta< -127) delta+=255; }
            int value=(int)s->transitions[k].from[i]+(int)((int64_t)delta*(int64_t)elapsed/(int64_t)duration);
            if(k && !i) value=(value+255)%255;
            if(*values[i]!=(uint8_t)value) { *values[i]=(uint8_t)value; update=true; }
        }
        if(now>=end) { s->transitions[k].active=false; update=true; }
        if(update) changed(s,k+1);
    }
    return MATTER_OK;
}
static uint64_t remaining(Matter_Lab_Rgb_T s,unsigned k) {
    return s->transitions[k-1].active?(s->transitions[k-1].end-s->now+99)/100:0;
}
Matter_Result_T matter_lab_rgb_process(Matter_Lab_Rgb_T s,uint64_t now) {
    return s?process(&s->servers[0],now):MATTER_INVALID_ARGUMENT;
}
static bool list(Matter_Lab_Rgb_T s,const uint32_t* ids,size_t count) {
    if(matter_tlv_writer_init(&s->writer,s->encoded,sizeof(s->encoded),1)!=MATTER_TLV_OK) return false;
    s->token=(Matter_Tlv_Element_T){.type=MATTER_TLV_ARRAY};
    if(matter_tlv_write(&s->writer,&s->token,0)!=MATTER_TLV_OK) return false;
    for(size_t i=0;i<count;++i) {
        s->token=(Matter_Tlv_Element_T){.type=MATTER_TLV_UNSIGNED,.unsigned_value=ids[i]};
        if(matter_tlv_write(&s->writer,&s->token,0)!=MATTER_TLV_OK) return false;
    }
    s->token=(Matter_Tlv_Element_T){.type=MATTER_TLV_END};
    return matter_tlv_write(&s->writer,&s->token,0)==MATTER_TLV_OK;
}
static uint8_t read_value(void* user,const void* ref,const Matter_Cluster_Request_T* request,Matter_Im_Value_T* out) {
    (void)request; Server* server=user; Matter_Lab_Rgb_T s=server->light; unsigned k=server->kind;
    uint32_t id=*(const uint32_t*)ref;
    *out=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.data_version=s->versions[k],.report_on_version_change=true};
    if(id==0xfff8 || id==0xfff9 || id==0xfffb) {
        size_t count=0; const uint32_t* ids=id==0xfffb?attributes(k,&count):id==0xfff9?commands(k,&count):NULL;
        if(!list(s,ids,count) || matter_tlv_writer_finish(&s->writer,&out->size)!=MATTER_TLV_OK) return MATTER_IM_FAILURE;
        out->type=MATTER_TLV_ARRAY; out->data=s->encoded;
    } else if(id==0xfffc) out->unsigned_value=k==ONOFF?0:1;
    else if(id==0xfffd) out->unsigned_value=revisions[k];
    else if(k==ONOFF) { out->type=MATTER_TLV_BOOL; out->unsigned_value=s->on; }
    else if(id==15) out->unsigned_value=s->options[k-1];
    else if(k==LEVEL) out->unsigned_value=id==0?s->level:id==1?remaining(s,k):id==2?1:254;
    else if(id==16) out->type=MATTER_TLV_NULL;
    else out->unsigned_value=id==0?s->hue:id==1?s->saturation:id==2?remaining(s,k):id==0x400a?1:0;
    return MATTER_IM_SUCCESS;
}
static uint8_t decode(Command* c,const uint8_t* data,size_t size,unsigned required,unsigned fields) {
    const Matter_Tlv_Validation_Options_T opt={1024,128,1024,4,false,0,0}; Matter_Tlv_Validation_Report_T report;
    if(matter_tlv_validate(data,size,&opt,&c->validation,c->tags,16,&report)!=MATTER_TLV_OK ||
        matter_tlv_init(&c->reader,data,size,4)!=MATTER_TLV_OK || matter_tlv_next(&c->reader,&c->element)!=MATTER_TLV_OK ||
        c->element.type!=MATTER_TLV_STRUCTURE || c->element.tag.control) return MATTER_IM_INVALID_COMMAND;
    while(matter_tlv_next(&c->reader,&c->element)==MATTER_TLV_OK) {
        Matter_Tlv_Element_T* e=&c->element;
        if(e->type==MATTER_TLV_END) return (c->seen&required)==required && matter_tlv_next(&c->reader,e)==MATTER_TLV_DONE?0:MATTER_IM_INVALID_COMMAND;
        if(e->tag.control!=1) return MATTER_IM_INVALID_COMMAND;
        if(e->tag.number<fields) {
            if(e->type!=MATTER_TLV_UNSIGNED || c->seen&(1u<<e->tag.number)) return MATTER_IM_INVALID_COMMAND;
            c->seen|=1u<<e->tag.number; c->fields[e->tag.number]=e->unsigned_value;
        } else if(e->type==MATTER_TLV_STRUCTURE || e->type==MATTER_TLV_ARRAY || e->type==MATTER_TLV_LIST) {
            if(matter_tlv_skip_container(&c->reader)!=MATTER_TLV_OK) return MATTER_IM_INVALID_COMMAND;
        }
    }
    return MATTER_IM_INVALID_COMMAND;
}
static uint8_t command(Server* server,uint32_t id,const uint8_t* data,size_t size,bool apply) {
    Matter_Lab_Rgb_T s=server->light; unsigned k=server->kind;
    bool stop=k!=ONOFF && (id==3 || id==7 || id==0x47);
    unsigned required=k==ONOFF || stop?0:k==LEVEL?3:7;
    unsigned fields=k==ONOFF?0:stop?2:k==LEVEL?4:5;
    Command* c=calloc(1,sizeof(*c)); if(!c) return MATTER_IM_RESOURCE_EXHAUSTED;
    uint8_t result=decode(c,data,size,required,fields);
    unsigned option=stop?0:k==LEVEL?2:3;
    if(!result && k!=ONOFF && ((c->seen&(1u<<option)) && c->fields[option]>1)) result=MATTER_IM_CONSTRAINT_ERROR;
    if(!result && k!=ONOFF && ((c->seen&(1u<<(option+1))) && c->fields[option+1]>1)) result=MATTER_IM_CONSTRAINT_ERROR;
    if(!result && !stop && k!=ONOFF && (c->fields[0]>254 || (k==LEVEL?c->fields[1]>65534:c->fields[1]>254 || c->fields[2]>65534))) result=MATTER_IM_CONSTRAINT_ERROR;
    if(!result && !stop && k!=ONOFF && c->fields[k==LEVEL?1:2]*100>UINT64_MAX-s->now) result=MATTER_IM_CONSTRAINT_ERROR;
    if(!result && apply) {
        if(k==ONOFF) { bool on=id==2?!s->on:id==1; if(s->on!=on) { s->on=on; changed(s,ONOFF); } }
        else {
            unsigned options=s->options[k-1];
            if(c->seen&(1u<<option)) options=(options&~(unsigned)c->fields[option])|((unsigned)c->fields[option+1]&(unsigned)c->fields[option]);
            if(s->on || options&1 || (k==LEVEL && (id==4 || id==7))) {
                s->transitions[k-1].active=false;
                if(!stop) {
                    s->transitions[k-1].from[0]=k==LEVEL?s->level:s->hue;
                    s->transitions[k-1].from[1]=s->saturation;
                    s->transitions[k-1].target[0]=k==LEVEL?(c->fields[0]?c->fields[0]:1):(uint8_t)c->fields[0];
                    s->transitions[k-1].target[1]=(uint8_t)c->fields[1];
                    if(k==LEVEL && id==4) { bool on=c->fields[0]!=0; if(s->on!=on) { s->on=on; changed(s,ONOFF); } }
                    uint64_t duration=c->fields[k==LEVEL?1:2]*100;
                    s->transitions[k-1].start=s->now; s->transitions[k-1].end=s->now+duration;
                    if(duration) s->transitions[k-1].active=true;
                    else if(k==LEVEL) s->level=s->transitions[0].target[0];
                    else { s->hue=s->transitions[1].target[0]; s->saturation=s->transitions[1].target[1]; }
                }
                changed(s,k);
            }
        }
    }
    free(c); return result;
}
static uint8_t validate_command(void* user,const void* ref,const Matter_Cluster_Request_T* q,const uint8_t* data,size_t size) {
    (void)q; return command(user,*(const uint32_t*)ref,data,size,false);
}
static Matter_Result_T start_command(void* user,const void* ref,const Matter_Cluster_Request_T* q,const uint8_t* data,size_t size,Matter_Tlv_Writer_T* writer,Matter_Im_Command_Result_T* out,uint64_t* token) {
    (void)q; (void)writer; (void)token;
    *out=(Matter_Im_Command_Result_T){.status=command(user,*(const uint32_t*)ref,data,size,true)}; return MATTER_OK;
}
Matter_Lab_Rgb_T matter_lab_rgb_new(uint32_t seed,uint64_t now) {
    Matter_Lab_Rgb_T s=calloc(1,sizeof(*s)); if(!s) return NULL;
    s->now=now; s->level=127; s->saturation=254; s->generation=1;
    for(unsigned k=0;k<KINDS;++k) {
        s->servers[k]=(Server){s,k}; s->versions[k]=seed+k;
        size_t count,ncommands; const uint32_t* ids=attributes(k,&count); const uint32_t* cmd=commands(k,&ncommands);
        Matter_Cluster_Config_T config={.id=cluster_ids[k],.attributes=(uint16_t)count,.commands=(uint16_t)ncommands,
            .callbacks={.ctx=&s->servers[k],.version=version,.process=process}};
        Matter_Cluster_T h=s->clusters[k]=matter_cluster_new(&config); if(!h) goto fail;
        for(size_t i=0;i<count;++i) {
            Matter_Attribute_Def_T a={.id=ids[i],.ref=&ids[i],.read_access={MATTER_IM_VIEW,false},.read=read_value};
            if(matter_cluster_add_attribute(h,&a)!=MATTER_OK) goto fail;
        }
        for(size_t i=0;i<ncommands;++i) {
            Matter_Command_Def_T c={.id=cmd[i],.ref=&cmd[i],.access={.privilege=MATTER_IM_OPERATE},.validate=validate_command,.start=start_command};
            if(matter_cluster_add_command(h,&c)!=MATTER_OK) goto fail;
        }
        if(matter_cluster_seal(h)!=MATTER_OK) goto fail;
    }
    return s;
fail:
    (void)matter_lab_rgb_delete(s); return NULL;
}
Matter_Result_T matter_lab_rgb_attach(Matter_Lab_Rgb_T s,Matter_Root_T root) {
    if(!s || !root) return MATTER_INVALID_ARGUMENT;
    Matter_Root_Endpoint_Config_T config={1,5,0x10d,s->versions[0]};
    Matter_Result_T r=matter_root_add_endpoint(root,&config); if(r) return r;
    for(unsigned i=0;i<KINDS;++i) { r=matter_root_attach_cluster_at(root,1,s->clusters[i]); if(r) return r; }
    return MATTER_OK;
}
Matter_Result_T matter_lab_rgb_delete(Matter_Lab_Rgb_T s) {
    if(!s) return MATTER_OK;
    for(unsigned i=0;i<KINDS;++i) if(s->clusters[i] && (matter_cluster_in_use(s->clusters[i]) || matter_cluster_pins(s->clusters[i]))) return MATTER_BUSY;
    for(unsigned i=0;i<KINDS;++i) if(s->clusters[i]) {
        Matter_Result_T r=matter_cluster_delete(s->clusters[i]); if(r) return r; s->clusters[i]=NULL;
    }
    memset(s,0,sizeof(*s)); free(s); return MATTER_OK;
}
bool matter_lab_rgb_pixels(Matter_Lab_Rgb_T s,uint8_t rgb[3],uint32_t* generation) {
    if(!s || !rgb || !generation || *generation==s->generation) return false;
    *generation=s->generation;
    unsigned hue=(unsigned)s->hue*6,region=hue/255,fraction=hue%255;
    unsigned v=s->on?(unsigned)s->level*255/254:0,sat=(unsigned)s->saturation*255/254;
    unsigned p=v*(255-sat)/255,q=v*(255-sat*fraction/255)/255,t=v*(255-sat*(255-fraction)/255)/255;
    switch(region) {
    case 0: rgb[0]=v; rgb[1]=t; rgb[2]=p; break;
    case 1: rgb[0]=q; rgb[1]=v; rgb[2]=p; break;
    case 2: rgb[0]=p; rgb[1]=v; rgb[2]=t; break;
    case 3: rgb[0]=p; rgb[1]=q; rgb[2]=v; break;
    case 4: rgb[0]=t; rgb[1]=p; rgb[2]=v; break;
    default: rgb[0]=v; rgb[1]=p; rgb[2]=q; break;
    }
    return true;
}

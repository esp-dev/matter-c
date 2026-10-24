#include "matter_ota_requestor.h"
#include "../model/matter_cluster_internal.h"
#include "../codec/matter_tlv_validate.h"
#include <stdlib.h>
#include <string.h>
/* Borrow metadata only while parsing this synchronous command. The queued public
 * offer owns its copy before start returns; validation needs no 512-byte copy. */
typedef struct {
    Matter_Ota_Provider_T provider; uint16_t vendor; uint8_t reason;
    size_t metadata_size; const uint8_t* metadata;
} Ota_Announcement;
typedef struct {
    Matter_Tlv_Reader_T reader,metadata_reader; Matter_Tlv_Element_T e,meta;
    Matter_Tlv_Validation_Workspace_T validation; Matter_Tlv_Tag_T tags[128];
    Matter_Ota_Provider_T candidate; Ota_Announcement parsed;
} Ota_Parse;
typedef struct {
    Matter_Tlv_Writer_T writer; Matter_Tlv_Element_T e; uint8_t encoded[256];
} Ota_Encode;
typedef struct {
    Matter_Ota_Requestor_Port_T port; Matter_Events_T events;
    Matter_Ota_Provider_T defaults[5],snapshot[5],selected;
    uint64_t default_generation[5],generation[5],selected_generation;
    bool offer_default[5],busy; Matter_Ota_Offer_T* offers[5];
    uint32_t version; uint8_t state; int progress; bool possible;
    Ota_Parse* parse; Ota_Encode* encoding;
} Ota;
/* Input scratch dies before return. Only accepted queued offers and a borrowed
 * provider encoding survive an operation; IM copies that encoding synchronously. */
static void clear_encoded(Ota* m) { free(m->encoding); m->encoding=NULL; }
static bool encoded_new(Ota* m) {
    clear_encoded(m); m->encoding=calloc(1,sizeof(*m->encoding)); return m->encoding!=NULL;
}
static void parse_end(Ota* m) { free(m->parse); m->parse=NULL; m->busy=false; }
static bool parse_begin(Ota* m) { m->busy=true; m->parse=calloc(1,sizeof(*m->parse)); return m->parse!=NULL; }
static bool equal(const Matter_Ota_Provider_T* a,const Matter_Ota_Provider_T* b) {
    return a->fabric==b->fabric && a->node==b->node && a->endpoint==b->endpoint;
}
static bool valid(const Matter_Ota_Provider_T* p) {
    return p->fabric && p->fabric<255 && p->node && p->node<=UINT64_C(0xffffffefffffffff) && p->endpoint<65535;
}
static Matter_Result_T refresh(Ota* m) {
    if(m->port.load(m->port.user,m->snapshot)!=MATTER_OK) return MATTER_PORT_ERROR;
    for(unsigned i=0;i<5;++i) if(m->snapshot[i].fabric) {
        if(!valid(&m->snapshot[i]) || !m->port.generation(m->port.user,m->snapshot[i].fabric)) return MATTER_PORT_ERROR;
        for(unsigned j=0;j<i;++j) if(m->snapshot[j].fabric==m->snapshot[i].fabric) return MATTER_PORT_ERROR;
    }
    bool changed=false;
    for(unsigned i=0;i<5;++i) {
        uint64_t gen=m->snapshot[i].fabric?m->port.generation(m->port.user,m->snapshot[i].fabric):0;
        bool different=!equal(&m->defaults[i],&m->snapshot[i]);
        if(different || gen!=m->default_generation[i]) m->offer_default[i]=gen!=0;
        changed|=different; m->defaults[i]=m->snapshot[i]; m->default_generation[i]=gen;
    }
    if(changed) ++m->version;
    return MATTER_OK;
}
static Matter_Result_T destroy(void* u) {
    Ota* m=u; if(m->busy) return MATTER_BUSY;
    for(unsigned i=0;i<5;++i) free(m->offers[i]);
    clear_encoded(m); free(m); return MATTER_OK;
}
static Matter_Result_T version(void* u,uint32_t* out) { *out=((Ota*)u)->version; return MATTER_OK; }
static void select_offer(Ota* m,const Matter_Ota_Offer_T* offer,uint64_t gen) {
    if(gen && m->port.generation(m->port.user,offer->provider.fabric)==gen && m->port.select(m->port.user,offer)) {
        m->selected=offer->provider; m->selected_generation=gen;
    }
}
static Matter_Result_T process(void* u,uint64_t now) {
    (void)now; Ota* m=u; if(m->busy) return MATTER_BUSY;
    m->busy=true; clear_encoded(m); Matter_Result_T r=refresh(m);
    Matter_Ota_Offer_T* offer=NULL;
    if(r==MATTER_OK) for(unsigned i=0;i<5;++i) if(m->offer_default[i]) {
        offer=calloc(1,sizeof(*offer));
        /* Keep flags and queued offers for retry. Returning an allocation error
         * here would stop runtime process before dispatch could drain ACK/TX and
         * release memory. Delivery waits; unrelated IM/transport work continues. */
        if(!offer) { m->busy=false; return MATTER_OK; }
        break;
    }
    if(r==MATTER_OK) for(unsigned i=0;i<5;++i) {
        if(m->offer_default[i]) {
            memset(offer,0,sizeof(*offer)); offer->provider=m->defaults[i]; m->offer_default[i]=false;
            select_offer(m,offer,m->default_generation[i]);
        }
        if(m->generation[i]) { select_offer(m,m->offers[i],m->generation[i]); m->generation[i]=0; }
        free(m->offers[i]); m->offers[i]=NULL;
    }
    free(offer); m->busy=false; return r;
}
Matter_Result_T matter_ota_requestor_selected(Matter_Cluster_T c,Matter_Ota_Provider_T* out) {
    Ota* m=matter_cluster_context(c,destroy); if(!m || !out) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    if(!m->selected_generation || m->port.generation(m->port.user,m->selected.fabric)!=m->selected_generation) return MATTER_INVALID_STATE;
    *out=m->selected; return MATTER_OK;
}
static bool next(Ota* m) { return matter_tlv_next(&m->parse->reader,&m->parse->e)==MATTER_TLV_OK; }
static bool skip(Ota* m) {
    return (m->parse->e.type!=MATTER_TLV_STRUCTURE && m->parse->e.type!=MATTER_TLV_ARRAY && m->parse->e.type!=MATTER_TLV_LIST) || matter_tlv_skip_container(&m->parse->reader)==MATTER_TLV_OK;
}
static bool input(Ota* m,const uint8_t* d,size_t n) {
    const Matter_Tlv_Validation_Options_T opt={1024,256,2048,4,false,0,0}; Matter_Tlv_Validation_Report_T report;
    return matter_tlv_validate(d,n,&opt,&m->parse->validation,m->parse->tags,128,&report)==MATTER_TLV_OK &&
        matter_tlv_init(&m->parse->reader,d,n,4)==MATTER_TLV_OK && next(m) && !m->parse->e.tag.control;
}
static bool metadata(Ota* m,const uint8_t* d,size_t n) {
    const Matter_Tlv_Validation_Options_T opt={512,256,2048,4,false,0,0}; Matter_Tlv_Validation_Report_T report;
    if(n>512 || matter_tlv_validate(d,n,&opt,&m->parse->validation,m->parse->tags,128,&report)!=MATTER_TLV_OK ||
        matter_tlv_init(&m->parse->metadata_reader,d,n,4)!=MATTER_TLV_OK ||
        matter_tlv_next(&m->parse->metadata_reader,&m->parse->meta)!=MATTER_TLV_OK || m->parse->meta.tag.control || m->parse->meta.type!=MATTER_TLV_LIST) return false;
    while(matter_tlv_next(&m->parse->metadata_reader,&m->parse->meta)==MATTER_TLV_OK) {
        if(m->parse->meta.type==MATTER_TLV_END) return matter_tlv_next(&m->parse->metadata_reader,&m->parse->meta)==MATTER_TLV_DONE;
        if(m->parse->meta.tag.control<6) return false;
        if((m->parse->meta.type==MATTER_TLV_STRUCTURE || m->parse->meta.type==MATTER_TLV_ARRAY || m->parse->meta.type==MATTER_TLV_LIST) &&
            matter_tlv_skip_container(&m->parse->metadata_reader)!=MATTER_TLV_OK) return false;
    }
    return false;
}
static bool access(Ota* m,const Matter_Cluster_Request_T* q) {
    return q->is_case && q->fabric && q->fabric<255 && m->port.generation(m->port.user,q->fabric);
}
static uint8_t parse_announcement(Ota* m,const Matter_Cluster_Request_T* q,const uint8_t* d,size_t n) {
    if(!access(m,q)) return MATTER_IM_UNSUPPORTED_ACCESS;
    if(!input(m,d,n) || m->parse->e.type!=MATTER_TLV_STRUCTURE) return MATTER_IM_INVALID_COMMAND;
    memset(&m->parse->parsed,0,sizeof(m->parse->parsed)); m->parse->parsed.provider.fabric=q->fabric; unsigned seen=0;
    while(next(m)) {
        if(m->parse->e.type==MATTER_TLV_END) return (seen&23)==23 && valid(&m->parse->parsed.provider) &&
            matter_tlv_next(&m->parse->reader,&m->parse->e)==MATTER_TLV_DONE?0:MATTER_IM_INVALID_COMMAND;
        if(m->parse->e.tag.control!=1) return MATTER_IM_INVALID_COMMAND;
        unsigned tag=m->parse->e.tag.number;
        if(tag>4) { if(!skip(m)) return MATTER_IM_INVALID_COMMAND; continue; }
        if(seen&(1u<<tag)) return MATTER_IM_INVALID_COMMAND;
        seen|=1u<<tag;
        if(tag==3) {
            if(m->parse->e.type!=MATTER_TLV_BYTES || !metadata(m,m->parse->e.data,m->parse->e.size)) return MATTER_IM_INVALID_COMMAND;
            m->parse->parsed.metadata_size=m->parse->e.size; m->parse->parsed.metadata=m->parse->e.data; continue;
        }
        if(m->parse->e.type!=MATTER_TLV_UNSIGNED) return MATTER_IM_INVALID_COMMAND;
        uint64_t v=m->parse->e.unsigned_value;
        if(tag==0) m->parse->parsed.provider.node=v;
        if(tag==1) { if(v>65535) return MATTER_IM_INVALID_COMMAND; m->parse->parsed.vendor=(uint16_t)v; }
        if(tag==2) { if(v>2) return MATTER_IM_INVALID_COMMAND; m->parse->parsed.reason=(uint8_t)v; }
        if(tag==4) { if(v>=65535) return MATTER_IM_INVALID_COMMAND; m->parse->parsed.provider.endpoint=(uint16_t)v; }
    }
    return MATTER_IM_INVALID_COMMAND;
}
static uint8_t validate_command(void* u,const void* ref,const Matter_Cluster_Request_T* q,const uint8_t* d,size_t n) {
    (void)ref; Ota* m=u; if(m->busy) return MATTER_IM_FAILURE;
    if(!access(m,q)) return MATTER_IM_UNSUPPORTED_ACCESS;
    uint8_t status=parse_begin(m)?parse_announcement(m,q,d,n):MATTER_IM_RESOURCE_EXHAUSTED;
    parse_end(m); return status;
}
static Matter_Result_T start(void* u,const void* ref,const Matter_Cluster_Request_T* q,const uint8_t* d,size_t n,
    Matter_Tlv_Writer_T* w,Matter_Im_Command_Result_T* out,uint64_t* token) {
    (void)ref; (void)w; Ota* m=u; *token=0; *out=(Matter_Im_Command_Result_T){.status=MATTER_IM_FAILURE};
    if(m->busy) return MATTER_OK;
    if(!access(m,q)) { out->status=MATTER_IM_UNSUPPORTED_ACCESS; return MATTER_OK; }
    out->status=parse_begin(m)?parse_announcement(m,q,d,n):MATTER_IM_RESOURCE_EXHAUSTED;
    if(!out->status) {
        unsigned slot=5;
        for(unsigned i=0;i<5;++i) if(m->generation[i] && m->offers[i]->provider.fabric==q->fabric) { slot=i; break; }
        if(slot==5) for(unsigned i=0;i<5;++i) if(!m->generation[i] || m->generation[i]!=m->port.generation(m->port.user,m->offers[i]->provider.fabric)) { slot=i; break; }
        if(slot<5) {
            Matter_Ota_Offer_T* offer=m->offers[slot];
            if(!offer) offer=calloc(1,sizeof(*offer));
            if(!offer) out->status=MATTER_IM_RESOURCE_EXHAUSTED;
            else {
                const Ota_Announcement* parsed=&m->parse->parsed;
                *offer=(Matter_Ota_Offer_T){.provider=parsed->provider,.announced=true,.vendor=parsed->vendor,
                    .reason=parsed->reason,.metadata_size=parsed->metadata_size};
                if(parsed->metadata_size) memcpy(offer->metadata,parsed->metadata,parsed->metadata_size);
                m->offers[slot]=offer; m->generation[slot]=m->port.generation(m->port.user,q->fabric);
            }
        }
    }
    parse_end(m); return MATTER_OK;
}
static uint8_t parse_provider(Ota* m,uint8_t fabric) {
    if(m->parse->e.type!=MATTER_TLV_STRUCTURE || m->parse->e.tag.control) return MATTER_IM_INVALID_DATA_TYPE;
    unsigned seen=0; m->parse->candidate=(Matter_Ota_Provider_T){.fabric=fabric};
    while(next(m)) {
        if(m->parse->e.type==MATTER_TLV_END) return seen==3 && valid(&m->parse->candidate)?0:MATTER_IM_CONSTRAINT_ERROR;
        if(m->parse->e.tag.control!=1) return MATTER_IM_INVALID_DATA_TYPE;
        unsigned tag=m->parse->e.tag.number;
        if(tag!=1 && tag!=2) { if(!skip(m)) return MATTER_IM_INVALID_DATA_TYPE; continue; } /* Ignore wire FabricIndex. */
        unsigned bit=1u<<(tag-1); if(seen&bit) return MATTER_IM_CONSTRAINT_ERROR; seen|=bit;
        if(m->parse->e.type!=MATTER_TLV_UNSIGNED) return MATTER_IM_INVALID_DATA_TYPE;
        if(tag==1) m->parse->candidate.node=m->parse->e.unsigned_value;
        else { if(m->parse->e.unsigned_value>=65535) return MATTER_IM_CONSTRAINT_ERROR; m->parse->candidate.endpoint=(uint16_t)m->parse->e.unsigned_value; }
    }
    return MATTER_IM_INVALID_DATA_TYPE;
}
static uint8_t parse_list(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_List_Change_T op,const uint8_t* d,size_t n) {
    (void)ref; Ota* m=u; if(!access(m,q)) return MATTER_IM_UNSUPPORTED_ACCESS;
    if(!input(m,d,n)) return MATTER_IM_INVALID_DATA_TYPE;
    m->parse->candidate=(Matter_Ota_Provider_T){0};
    if(op==MATTER_IM_LIST_REPLACE) {
        if(m->parse->e.type!=MATTER_TLV_ARRAY || !next(m)) return MATTER_IM_INVALID_DATA_TYPE;
        if(m->parse->e.type!=MATTER_TLV_END) {
            uint8_t status=parse_provider(m,q->fabric); if(status) return status;
            if(!next(m) || m->parse->e.type!=MATTER_TLV_END) return MATTER_IM_CONSTRAINT_ERROR;
        }
    } else if(op==MATTER_IM_LIST_ADD) {
        for(unsigned i=0;i<5;++i) if(m->defaults[i].fabric==q->fabric) return MATTER_IM_CONSTRAINT_ERROR;
        uint8_t status=parse_provider(m,q->fabric); if(status) return status;
    } else return MATTER_IM_INVALID_ACTION;
    return matter_tlv_next(&m->parse->reader,&m->parse->e)==MATTER_TLV_DONE?0:MATTER_IM_INVALID_DATA_TYPE;
}
static uint8_t validate_list(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_List_Change_T op,const uint8_t* d,size_t n) {
    Ota* m=u; if(m->busy) return MATTER_IM_FAILURE;
    if(!access(m,q)) return MATTER_IM_UNSUPPORTED_ACCESS;
    uint8_t status=parse_begin(m)?parse_list(u,ref,q,op,d,n):MATTER_IM_RESOURCE_EXHAUSTED;
    parse_end(m); return status;
}
static Matter_Im_Write_Result_T write_list(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_List_Change_T op,const uint8_t* d,size_t n) {
    Ota* m=u; if(m->busy) return (Matter_Im_Write_Result_T){.status=MATTER_IM_FAILURE};
    if(!access(m,q)) return (Matter_Im_Write_Result_T){.status=MATTER_IM_UNSUPPORTED_ACCESS};
    uint8_t status=parse_begin(m)?parse_list(u,ref,q,op,d,n):MATTER_IM_RESOURCE_EXHAUSTED;
    if(status) goto done;
    unsigned slot=5;
    for(unsigned i=0;i<5;++i) if(m->defaults[i].fabric==q->fabric) { slot=i; break; }
    if(slot==5) for(unsigned i=0;i<5;++i) if(!m->defaults[i].fabric) { slot=i; break; }
    if(slot==5) { status=MATTER_IM_RESOURCE_EXHAUSTED; goto done; }
    uint64_t gen=m->parse->candidate.fabric?m->port.generation(m->port.user,q->fabric):0;
    /* Successful port store is the commit: no fallible read after that commit. */
    Matter_Result_T r=m->port.store(m->port.user,q->fabric,m->parse->candidate.fabric?&m->parse->candidate:NULL);
    if(r==MATTER_OK) {
        bool changed=!equal(&m->parse->candidate,&m->defaults[slot]);
        if(changed) { m->defaults[slot]=m->parse->candidate; ++m->version; }
        if(changed || m->default_generation[slot]!=gen) m->offer_default[slot]=gen!=0;
        m->default_generation[slot]=gen;
    }
    status=r==MATTER_OK?0:MATTER_IM_FAILURE;
done:
    parse_end(m); return (Matter_Im_Write_Result_T){.status=status};
}
static bool put(Ota* m,Matter_Tlv_Type_T type,int tag,uint64_t value) {
    m->encoding->e=(Matter_Tlv_Element_T){.type=type,.tag={.control=tag<0?0:1,.number=tag<0?0:(unsigned)tag},.unsigned_value=value};
    return matter_tlv_write(&m->encoding->writer,&m->encoding->e,0)==MATTER_TLV_OK;
}
static bool begin(Ota* m,Matter_Tlv_Type_T type) { return matter_tlv_writer_init(&m->encoding->writer,m->encoding->encoded,sizeof(m->encoding->encoded),4)==MATTER_TLV_OK && put(m,type,-1,0); }
static bool finish(Ota* m,size_t* n) { return put(m,MATTER_TLV_END,-1,0) && matter_tlv_writer_finish(&m->encoding->writer,n)==MATTER_TLV_OK; }
static const uint32_t attrs[]={0,1,2,3,0xfff8,0xfff9,0xfffb,0xfffc,0xfffd};
static uint8_t read(void* u,const void* ref,const Matter_Cluster_Request_T* q,Matter_Im_Value_T* out) {
    Ota* m=u; if(m->busy) return MATTER_IM_FAILURE;
    clear_encoded(m); uint32_t id=*(const uint32_t*)ref;
    *out=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.data_version=m->version};
    if(id==1) { out->type=MATTER_TLV_BOOL; out->unsigned_value=m->possible; return 0; }
    if(id==2) { out->unsigned_value=m->state; return 0; }
    if(id==3) { out->type=m->progress<0?MATTER_TLV_NULL:MATTER_TLV_UNSIGNED; out->unsigned_value=m->progress<0?0:(unsigned)m->progress; return 0; }
    if(id==0xfffc || id==0xfffd) { out->unsigned_value=id==0xfffd; return 0; }
    m->busy=true; Matter_Result_T refreshed=id==0?refresh(m):MATTER_OK; m->busy=false;
    if(refreshed!=MATTER_OK) return MATTER_IM_FAILURE;
    if(!encoded_new(m)) return MATTER_IM_RESOURCE_EXHAUSTED;
    if(!begin(m,MATTER_TLV_ARRAY)) goto failed;
    if(id==0) for(unsigned i=0;i<5;++i) {
        const Matter_Ota_Provider_T* p=&m->defaults[i];
        if(!p->fabric || (q->filtered && p->fabric!=q->fabric)) continue;
        if(!put(m,MATTER_TLV_STRUCTURE,-1,0) || !put(m,MATTER_TLV_UNSIGNED,1,p->node) ||
            !put(m,MATTER_TLV_UNSIGNED,2,p->endpoint) || !put(m,MATTER_TLV_UNSIGNED,254,p->fabric) || !put(m,MATTER_TLV_END,-1,0)) goto failed;
    }
    if(id==0xfff9 && !put(m,MATTER_TLV_UNSIGNED,-1,0)) goto failed;
    if(id==0xfffb) for(unsigned i=0;i<9;++i) if(!put(m,MATTER_TLV_UNSIGNED,-1,attrs[i])) goto failed;
    size_t size; if(!finish(m,&size)) goto failed;
    *out=(Matter_Im_Value_T){.type=MATTER_TLV_ARRAY,.data=m->encoding->encoded,.size=size,.data_version=m->version};
    return 0;
failed:
    clear_encoded(m); return MATTER_IM_FAILURE;
}
static Matter_Result_T event(Ota* m,uint32_t id,uint64_t now) {
    size_t n; if(!finish(m,&n)) return MATTER_INVALID_STATE;
    Matter_Event_Path_T path={0,MATTER_OTA_REQUESTOR_CLUSTER,id};
    return matter_events_append(m->events,&path,id==1?2:1,now,false,m->encoding->encoded,n);
}
Matter_Result_T matter_ota_requestor_state(Matter_Cluster_T c,bool possible,uint8_t state,int progress,uint8_t reason,uint32_t target,uint64_t now) {
    Ota* m=matter_cluster_context(c,destroy); if(!m || state>8 || progress< -1 || progress>100 || reason>4) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    if(m->state==state && m->progress==progress && m->possible==possible) return MATTER_OK;
    m->busy=true; clear_encoded(m); Matter_Result_T r=MATTER_OK;
    if(m->state!=state) {
        if(!encoded_new(m)) { m->busy=false; return MATTER_LIMIT_REACHED; }
        if(!begin(m,MATTER_TLV_STRUCTURE) || !put(m,MATTER_TLV_UNSIGNED,0,m->state) || !put(m,MATTER_TLV_UNSIGNED,1,state) ||
            !put(m,MATTER_TLV_UNSIGNED,2,reason) || !put(m,state==4 || state==5 || state==7?MATTER_TLV_UNSIGNED:MATTER_TLV_NULL,3,target)) r=MATTER_INVALID_STATE;
        else r=event(m,0,now);
    }
    if(r==MATTER_OK) { m->state=state; m->progress=progress; m->possible=possible; ++m->version; }
    clear_encoded(m); m->busy=false; return r;
}
Matter_Result_T matter_ota_requestor_applied(Matter_Cluster_T c,uint32_t version_value,uint16_t product,uint64_t now) {
    Ota* m=matter_cluster_context(c,destroy); if(!m) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    m->busy=true;
    if(!encoded_new(m)) { m->busy=false; return MATTER_LIMIT_REACHED; }
    Matter_Result_T r=begin(m,MATTER_TLV_STRUCTURE) && put(m,MATTER_TLV_UNSIGNED,0,version_value) && put(m,MATTER_TLV_UNSIGNED,1,product)?event(m,1,now):MATTER_INVALID_STATE;
    clear_encoded(m); m->busy=false; return r;
}
Matter_Result_T matter_ota_requestor_error(Matter_Cluster_T c,uint32_t version_value,uint64_t bytes,int progress,const int64_t* code,uint64_t now) {
    Ota* m=matter_cluster_context(c,destroy); if(!m || progress< -1 || progress>100) return MATTER_INVALID_ARGUMENT;
    if(m->busy) return MATTER_BUSY;
    int64_t saved_code=code?*code:0;
    m->busy=true;
    if(!encoded_new(m)) { m->busy=false; return MATTER_LIMIT_REACHED; }
    Matter_Result_T r=MATTER_INVALID_STATE;
    if(begin(m,MATTER_TLV_STRUCTURE) && put(m,MATTER_TLV_UNSIGNED,0,version_value) && put(m,MATTER_TLV_UNSIGNED,1,bytes) &&
        put(m,progress<0?MATTER_TLV_NULL:MATTER_TLV_UNSIGNED,2,progress<0?0:(unsigned)progress)) {
        m->encoding->e=(Matter_Tlv_Element_T){.type=code?MATTER_TLV_SIGNED:MATTER_TLV_NULL,.tag={.control=1,.number=3},.signed_value=saved_code};
        if(matter_tlv_write(&m->encoding->writer,&m->encoding->e,0)==MATTER_TLV_OK) r=event(m,2,now);
    }
    clear_encoded(m); m->busy=false; return r;
}
Matter_Cluster_T matter_ota_requestor_new(const Matter_Ota_Requestor_Port_T* p,Matter_Events_T events,uint32_t dv,bool possible) {
    if(!p || !p->load || !p->store || !p->generation || !p->select || !events) return NULL;
    Ota* m=calloc(1,sizeof(*m)); if(!m) return NULL;
    m->port=*p; m->events=events; m->version=dv; m->possible=possible; m->state=1; m->progress=-1;
    if(refresh(m)!=MATTER_OK) { free(m); return NULL; } m->version=dv;
    Matter_Cluster_Config_T cfg={.id=MATTER_OTA_REQUESTOR_CLUSTER,.attributes=9,.commands=1,.events=3,.callbacks={m,version,process,NULL,destroy}};
    Matter_Cluster_T c=matter_cluster_new(&cfg); if(!c) { free(m); return NULL; }
    for(unsigned i=0;i<9;++i) {
        Matter_Attribute_Def_T a={.id=attrs[i],.read_access={MATTER_IM_VIEW,i==0},.ref=&attrs[i],.read=read};
        if(!i) { a.write_access=(Matter_Im_Write_Attribute_T){MATTER_IM_ADMINISTER,false,true,true}; a.validate_list=validate_list; a.write_list=write_list; }
        if(matter_cluster_add_attribute(c,&a)!=MATTER_OK) goto fail;
    }
    Matter_Command_Def_T command={.id=0,.access={.privilege=MATTER_IM_ADMINISTER},.validate=validate_command,.start=start};
    if(matter_cluster_add_command(c,&command)!=MATTER_OK) goto fail;
    for(unsigned i=0;i<3;++i) { Matter_Event_Def_T e={i,MATTER_IM_VIEW,i==1?2:1,false}; if(matter_cluster_add_event(c,&e)!=MATTER_OK) goto fail; }
    (void)matter_cluster_seal(c); return c;
fail: matter_cluster_abandon(c); free(m); return NULL;
}

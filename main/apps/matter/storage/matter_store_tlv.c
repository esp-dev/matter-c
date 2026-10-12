#include "matter_store_tlv.h"
#include "../codec/matter_tlv_internal.h"
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
/* Schema 2 appends label_size/label to each record. Schema 1 imports with an
 * empty label; schema3 adds the credential rollback image. Schema4 adds VVS/VVSC. Schema5 adds EEM/event high-water. Schema6 adds default OTA providers. Schema7 adds explicit EEM register mode/mask. New publications use 7. Ordinals of old fields stay fixed. */
typedef enum { U8,U16,U32,U64,I64,SIZE,BOOL,BYTES,OBJECT } Kind;
typedef struct Field { const char* name; Kind kind; size_t offset,count,stride; const struct Field* children; } Field;
#define F(T,m,k) {#m,k,offsetof(T,m),1,sizeof(((T*)0)->m),NULL}
#define H(T,m) {#m,BYTES,offsetof(T,m),sizeof(((T*)0)->m),1,NULL}
#define A(T,m,k,n) {#m,k,offsetof(T,m),n,sizeof(((T*)0)->m[0]),NULL}
#define O(T,m,s) {#m,OBJECT,offsetof(T,m),1,sizeof(((T*)0)->m),s}
#define OA(T,m,s,n) {#m,OBJECT,offsetof(T,m),n,sizeof(((T*)0)->m[0]),s}
#define LAST {NULL,U8,0,0,0,NULL}
static const Field id[]={F(Matter_Wifi_Id_T,size,U8),H(Matter_Wifi_Id_T,bytes),LAST};
static const Field network[]={O(Matter_Wifi_Network_T,id,id),F(Matter_Wifi_Network_T,credential_size,U8),H(Matter_Wifi_Network_T,credentials),LAST};
static const Field settings[]={F(Matter_Wifi_Settings_T,count,U8),F(Matter_Wifi_Settings_T,enabled,BOOL),OA(Matter_Wifi_Settings_T,networks,network,4),LAST};
static const Field wifi[]={O(Matter_Store_Wifi_T,settings,settings),O(Matter_Store_Wifi_T,connected,id),F(Matter_Store_Wifi_T,pending,BOOL),LAST};
static const Field target[]={F(Matter_Acl_Target_T,cluster,U32),F(Matter_Acl_Target_T,device_type,U32),F(Matter_Acl_Target_T,endpoint,U16),F(Matter_Acl_Target_T,present,U8),LAST};
static const Field entry[]={A(Matter_Acl_Entry_T,subjects,U64,4),OA(Matter_Acl_Entry_T,targets,target,3),F(Matter_Acl_Entry_T,privilege,U8),F(Matter_Acl_Entry_T,auth_mode,U8),F(Matter_Acl_Entry_T,subject_count,U8),F(Matter_Acl_Entry_T,target_count,U8),F(Matter_Acl_Entry_T,subjects_null,BOOL),F(Matter_Acl_Entry_T,targets_null,BOOL),LAST};
static const Field acl_fabric[]={OA(Matter_Acl_Fabric_T,entries,entry,4),F(Matter_Acl_Fabric_T,index,U8),F(Matter_Acl_Fabric_T,count,U8),LAST};
static const Field acl[]={OA(Matter_Acl_View_T,fabrics,acl_fabric,5),F(Matter_Acl_View_T,version,U32),LAST};
static const Field keyset[]={A(Matter_Groupkey_Set_T,times,U64,3),F(Matter_Groupkey_Set_T,id,U16),F(Matter_Groupkey_Set_T,count,U8),LAST};
static const Field key_fabric[]={OA(Matter_Groupkey_Fabric_T,sets,keyset,4),F(Matter_Groupkey_Fabric_T,index,U8),LAST};
static const Field groupkey[]={OA(Matter_Groupkey_View_T,fabrics,key_fabric,5),F(Matter_Groupkey_View_T,version,U32),LAST};
static const Field record[]={H(Matter_Fabric_Record_T,discovery_instance),F(Matter_Fabric_Record_T,index,U8),H(Matter_Fabric_Record_T,root_public),H(Matter_Fabric_Record_T,operational_public),H(Matter_Fabric_Record_T,compressed_id),F(Matter_Fabric_Record_T,vendor,U16),F(Matter_Fabric_Record_T,noc_size,U16),F(Matter_Fabric_Record_T,icac_size,U16),F(Matter_Fabric_Record_T,root_size,U16),F(Matter_Fabric_Record_T,fabric_id,U64),F(Matter_Fabric_Record_T,node_id,U64),F(Matter_Fabric_Record_T,admin_subject,U64),H(Matter_Fabric_Record_T,noc),H(Matter_Fabric_Record_T,icac),H(Matter_Fabric_Record_T,root),F(Matter_Fabric_Record_T,label_size,U8),H(Matter_Fabric_Record_T,label),F(Matter_Fabric_Record_T,vvs_size,U8),H(Matter_Fabric_Record_T,vvs),F(Matter_Fabric_Record_T,vvsc_size,U16),H(Matter_Fabric_Record_T,vvsc),LAST};
static const Field view[]={F(Matter_Fabric_View_T,revision,U32),F(Matter_Fabric_View_T,count,U8),F(Matter_Fabric_View_T,pending_index,U8),F(Matter_Fabric_View_T,root_ready,BOOL),F(Matter_Fabric_View_T,added,BOOL),F(Matter_Fabric_View_T,root_size,U16),H(Matter_Fabric_View_T,root),OA(Matter_Fabric_View_T,records,record,5),LAST};
static const Field fabrics[]={O(Matter_Store_Fabrics_T,view,view),O(Matter_Store_Fabrics_T,acl,acl),O(Matter_Store_Fabrics_T,groupkey,groupkey),H(Matter_Store_Fabrics_T,groupkeys),H(Matter_Store_Fabrics_T,keys),F(Matter_Store_Fabrics_T,next_index,U8),F(Matter_Store_Fabrics_T,saved_next,U8),F(Matter_Store_Fabrics_T,journal,BOOL),O(Matter_Store_Fabrics_T,previous,record),H(Matter_Store_Fabrics_T,previous_key),LAST};
static const Field root[]={F(Matter_Root_Settings_T,node_label_size,SIZE),H(Matter_Root_Settings_T,node_label),H(Matter_Root_Settings_T,location),LAST};
static const Field eem[]={F(Matter_Eem_Checkpoint_T,generation,U64),A(Matter_Eem_Checkpoint_T,raw_mwh,I64,2),A(Matter_Eem_Checkpoint_T,total_mwh,I64,2),F(Matter_Eem_Checkpoint_T,initialized,BOOL),F(Matter_Eem_Checkpoint_T,registers,BOOL),F(Matter_Eem_Checkpoint_T,register_mask,U8),LAST};
static const Field ota[]={F(Matter_Ota_Provider_T,node,U64),F(Matter_Ota_Provider_T,endpoint,U16),F(Matter_Ota_Provider_T,fabric,U8),LAST};
static const Field schema[]={F(Matter_Store_Data_T,schema,U32),O(Matter_Store_Data_T,fabrics,fabrics),O(Matter_Store_Data_T,wifi,wifi),O(Matter_Store_Data_T,root,root),F(Matter_Store_Data_T,hours,U32),F(Matter_Store_Data_T,reboots,U16),O(Matter_Store_Data_T,eem,eem),F(Matter_Store_Data_T,event_high,U64),OA(Matter_Store_Data_T,ota,ota,5),LAST};
typedef struct { Matter_Store_Data_T data; Matter_Tlv_Reader_T reader; Matter_Tlv_Writer_T writer; Matter_Tlv_Element_T e; } Codec;
static void wipe(void* p,size_t n) { volatile unsigned char* b=p; while(n--) *b++=0; }
static bool put(Codec* c,Matter_Tlv_Type_T type,int tag,uint64_t v,const void* data,size_t n) {
    c->e=(Matter_Tlv_Element_T){.type=type,.tag={.control=tag<0?0:1,.number=tag<0?0:(unsigned)tag},.unsigned_value=v,.data=data,.size=n};
    return matter_tlv_write(&c->writer,&c->e,0)==MATTER_TLV_OK;
}
static bool encode_object(Codec*,const Field*,const void*,int);
static bool encode_value(Codec* c,const Field* f,const unsigned char* p,int tag) {
    if(f->kind==OBJECT) return encode_object(c,f->children,p,tag);
    if(f->kind==I64) {
        c->e=(Matter_Tlv_Element_T){.type=MATTER_TLV_SIGNED,.tag={.control=tag<0?0:1,.number=tag<0?0:(unsigned)tag},.signed_value=*(const int64_t*)p};
        return matter_tlv_write(&c->writer,&c->e,0)==MATTER_TLV_OK;
    }
    if(f->kind==BYTES) return put(c,MATTER_TLV_BYTES,tag,0,p,f->count);
    uint64_t v=f->kind==U8?*(const uint8_t*)p:f->kind==U16?*(const uint16_t*)p:f->kind==U32?*(const uint32_t*)p:
        f->kind==U64?*(const uint64_t*)p:f->kind==BOOL?*(const bool*)p:*(const size_t*)p;
    return put(c,f->kind==BOOL?MATTER_TLV_BOOL:MATTER_TLV_UNSIGNED,tag,v,NULL,0);
}
static bool encode_object(Codec* c,const Field* fields,const void* object,int tag) {
    if(!put(c,MATTER_TLV_STRUCTURE,tag,0,NULL,0)) return false;
    for(unsigned t=0;fields[t].name;++t) {
        if(fields==eem && t==4 && c->data.schema<7) break;
        if(fields==schema && t==6 && c->data.schema<5) break;
        if(fields==schema && t==8 && c->data.schema<6) break;
        if(fields==record && t==15 && c->data.schema==1) break;
        if(fields==record && t==17 && c->data.schema<4) break;
        if(fields==fabrics && t==8 && c->data.schema<3) break;
        const Field* f=&fields[t]; const unsigned char* p=(const unsigned char*)object+f->offset;
        if(f->count>1 && f->kind!=BYTES) {
            if(!put(c,MATTER_TLV_ARRAY,(int)t,0,NULL,0)) return false;
            for(size_t i=0;i<f->count;++i) if(!encode_value(c,f,p+i*f->stride,-1)) return false;
            if(!put(c,MATTER_TLV_END,-1,0,NULL,0)) return false;
        } else if(!encode_value(c,f,p,(int)t)) return false;
    }
    return put(c,MATTER_TLV_END,-1,0,NULL,0);
}
static bool next(Codec* c) { return matter_tlv_next(&c->reader,&c->e)==MATTER_TLV_OK; }
static bool end(Codec* c) { return next(c) && c->e.type==MATTER_TLV_END && !c->e.tag.control; }
static bool decode_object(Codec*,const Field*,void*);
static bool decode_value(Codec* c,const Field* f,unsigned char* p) {
    if(f->kind==OBJECT) return decode_object(c,f->children,p);
    if(f->kind==BYTES) {
        if(c->e.type!=MATTER_TLV_BYTES || c->e.size!=f->count) return false;
        memcpy(p,c->e.data,f->count); return true;
    }
    if(f->kind==I64) { if(c->e.type!=MATTER_TLV_SIGNED) return false; *(int64_t*)p=c->e.signed_value; return true; }
    if(f->kind==BOOL) { if(c->e.type!=MATTER_TLV_BOOL) return false; *(bool*)p=c->e.unsigned_value!=0; return true; }
    uint64_t v=c->e.unsigned_value,max=f->kind==U8?UINT8_MAX:f->kind==U16?UINT16_MAX:f->kind==U32?UINT32_MAX:f->kind==SIZE?SIZE_MAX:UINT64_MAX;
    if(c->e.type!=MATTER_TLV_UNSIGNED || v>max) return false;
    if(f->kind==U8) *(uint8_t*)p=(uint8_t)v;
    else if(f->kind==U16) *(uint16_t*)p=(uint16_t)v;
    else if(f->kind==U32) *(uint32_t*)p=(uint32_t)v;
    else if(f->kind==U64) *(uint64_t*)p=v;
    else *(size_t*)p=(size_t)v;
    return true;
}
static bool decode_object(Codec* c,const Field* fields,void* object) {
    if(c->e.type!=MATTER_TLV_STRUCTURE) return false;
    for(unsigned t=0;fields[t].name;++t) {
        if(fields==eem && t==4 && c->data.schema<7) break;
        if(fields==schema && t==6 && c->data.schema<5) break;
        if(fields==schema && t==8 && c->data.schema<6) break;
        if(fields==record && t==15 && c->data.schema==1) break;
        if(fields==record && t==17 && c->data.schema<4) break;
        if(fields==fabrics && t==8 && c->data.schema<3) break;
        const Field* f=&fields[t]; unsigned char* p=(unsigned char*)object+f->offset;
        if(!next(c) || c->e.tag.control!=1 || c->e.tag.number!=t) return false;
        if(f->count>1 && f->kind!=BYTES) {
            if(c->e.type!=MATTER_TLV_ARRAY) return false;
            for(size_t i=0;i<f->count;++i) if(!next(c) || c->e.tag.control || !decode_value(c,f,p+i*f->stride)) return false;
            if(!end(c)) return false;
        } else if(!decode_value(c,f,p)) return false;
    }
    return end(c);
}
Matter_Result_T matter_store_tlv_encode(const Matter_Store_Data_T* d,uint8_t* out,size_t cap,size_t* n) {
    if(!d || !out || !n || !cap || cap>MATTER_STORE_BLOB_MAX || !matter_store_data_valid(d)) return MATTER_INVALID_ARGUMENT;
    *n=0; Codec* c=calloc(1,sizeof(*c)); if(!c) return MATTER_LIMIT_REACHED;
    c->data.schema=d->schema;
    bool ok=matter_tlv_writer_init(&c->writer,out,cap,16)==MATTER_TLV_OK && encode_object(c,schema,d,-1) && matter_tlv_writer_finish(&c->writer,n)==MATTER_TLV_OK;
    if(!ok) wipe(out,cap);
    wipe(c,sizeof(*c)); free(c); return ok?MATTER_OK:MATTER_LIMIT_REACHED;
}
Matter_Result_T matter_store_tlv_decode(const uint8_t* data,size_t n,Matter_Store_Data_T* out) {
    if(!out || !data || !n || n>MATTER_STORE_BLOB_MAX) return MATTER_INVALID_ARGUMENT;
    Codec* c=calloc(1,sizeof(*c)); if(!c) return MATTER_LIMIT_REACHED;
    bool ok=matter_tlv_init(&c->reader,data,n,16)==MATTER_TLV_OK && next(c) && !c->e.tag.control && decode_object(c,schema,&c->data) &&
        matter_tlv_next(&c->reader,&c->e)==MATTER_TLV_DONE && matter_store_data_valid(&c->data);
    if(ok) { c->data.schema=7; *out=c->data; }
    wipe(c,sizeof(*c)); free(c); return ok?MATTER_OK:MATTER_INVALID_ARGUMENT;
}
static bool acl_subject(uint64_t v,unsigned mode) {
    return mode==3?(v && v<=65535):((v && v<=UINT64_C(0xffffffefffffffff)) ||
        ((v>>32)==UINT64_C(0xfffffffd) && ((v>>16)&65535) && (v&65535)));
}
static bool vid_valid(const Matter_Fabric_Record_T* r,uint32_t schema) {
    return (r->vvs_size==0 || r->vvs_size==85) && r->vvsc_size<=400 &&
        !(r->icac_size && r->vvsc_size) && (schema>=4 || (!r->vvs_size && !r->vvsc_size));
}
bool matter_store_data_valid(const Matter_Store_Data_T* d) {
    if(!d || (d->schema!=1 && d->schema!=2 && d->schema!=3 && d->schema!=4 && d->schema!=5 && d->schema!=6 && d->schema!=7) || d->root.node_label_size>32 || !valid_utf8(d->root.node_label,d->root.node_label_size) ||
        d->root.location[0]<'A' || d->root.location[0]>'Z' || d->root.location[1]<'A' || d->root.location[1]>'Z') return false;
    const Matter_Eem_Checkpoint_T* e=&d->eem;
    if((d->schema<7 && (e->registers || e->register_mask)) || e->register_mask>3 ||
        (e->registers ? (e->initialized!=!!e->register_mask) : e->register_mask!=0) ||
        (d->schema<5 && (e->initialized || d->event_high)) ||
        (!e->initialized && (e->registers || e->generation || e->raw_mwh[0] || e->raw_mwh[1] || e->total_mwh[0] || e->total_mwh[1]))) return false;
    for(unsigned i=0;i<2;++i) if(e->raw_mwh[i]<0 || e->raw_mwh[i]>MATTER_EEM_LIMIT || e->total_mwh[i]<0 || e->total_mwh[i]>MATTER_EEM_LIMIT || (e->registers && e->total_mwh[i]!=e->raw_mwh[i])) return false;
    const Matter_Store_Wifi_T* w=&d->wifi;
    if(w->settings.count>4 || w->connected.size>32) return false;
    for(unsigned i=0;i<w->settings.count;++i) {
        const Matter_Wifi_Network_T* n=&w->settings.networks[i]; unsigned z=n->credential_size;
        if(!n->id.size || n->id.size>32 || !(z==0 || z==5 || (z>=8 && z<=64))) return false;
        if(z==64) for(unsigned k=0;k<z;++k) if(!((n->credentials[k]>='0' && n->credentials[k]<='9') || (n->credentials[k]>='a' && n->credentials[k]<='f') || (n->credentials[k]>='A' && n->credentials[k]<='F'))) return false;
        for(unsigned j=0;j<i;++j) if(n->id.size==w->settings.networks[j].id.size && !memcmp(n->id.bytes,w->settings.networks[j].id.bytes,n->id.size)) return false;
    }
    const Matter_Store_Fabrics_T* f=&d->fabrics; const Matter_Fabric_View_T* v=&f->view;
    for(unsigned i=0;i<5;++i) {
        const Matter_Ota_Provider_T* p=&d->ota[i];
        if(!p->fabric) { if(p->node || p->endpoint) return false; continue; }
        if(d->schema<6 || p->fabric==255 || !p->node || p->node>UINT64_C(0xffffffefffffffff) || p->endpoint==65535) return false;
        bool live=false; for(unsigned j=0;j<5;++j) if(v->records[j].index==p->fabric) live=true;
        if(!live) return false;
        for(unsigned j=0;j<i;++j) if(d->ota[j].fabric==p->fabric) return false;
    }
    const Matter_Fabric_Record_T* old=&f->previous; bool updated=old->index!=0;
    if(!vid_valid(old,d->schema)) return false;
    if(updated && (d->schema<3 || !v->added || old->index!=v->pending_index || v->root_ready ||
        !old->node_id || old->node_id>UINT64_C(0xffffffefffffffff) || !old->noc_size || old->noc_size>400 ||
        old->icac_size>400 || !old->root_size || old->root_size>400 || old->operational_public[0]!=4 || old->discovery_instance[33])) return false;
    if(!updated) {
        /* As for empty live slots, index controls presence. Do not inspect C
         * structure padding: the persisted schema contains named fields only. */
        for(unsigned i=0;i<32;++i) if(f->previous_key[i]) return false;
    }
    if(!f->next_index || f->next_index==255 || (f->journal && (!f->saved_next || f->saved_next==255)) || v->count>5 || v->root_size>400 ||
        v->root_ready!=(v->root_size!=0) || v->added!=(v->pending_index!=0) || (v->added && !v->root_ready && !updated) ||
        f->journal!=(v->root_ready || updated)) return false;
    unsigned count=0,pending=0;
    for(unsigned i=0;i<5;++i) {
        const Matter_Fabric_Record_T* r=&v->records[i]; const Matter_Acl_Fabric_T* a=&f->acl.fabrics[i]; const Matter_Groupkey_Fabric_T* g=&f->groupkey.fabrics[i];
        if(!vid_valid(r,d->schema)) return false;
        if(r->label_size>32 || (d->schema==1 && r->label_size) || !valid_utf8(r->label,r->label_size)) return false;
        if(r->index!=a->index || r->index!=g->index || r->index==255) return false;
        if(!r->index) continue;
        ++count; if(r->index==v->pending_index) {
            ++pending;
            if(updated && (old->fabric_id!=r->fabric_id || old->admin_subject!=r->admin_subject || old->root_size!=r->root_size ||
                memcmp(old->root,r->root,400) || memcmp(old->root_public,r->root_public,65) ||
                memcmp(old->compressed_id,r->compressed_id,8))) return false;
        }
        if(!r->fabric_id || !r->node_id || r->node_id>UINT64_C(0xffffffefffffffff) || !r->vendor || !acl_subject(r->admin_subject,2) ||
            !r->root_size || r->root_size>400 || !r->noc_size || r->noc_size>400 || r->icac_size>400 ||
            r->root_public[0]!=4 || r->operational_public[0]!=4 || r->discovery_instance[33] || a->count>4) return false;
        for(unsigned j=0;j<i;++j) if(v->records[j].index==r->index || (v->records[j].index && v->records[j].fabric_id==r->fabric_id && !memcmp(v->records[j].root_public,r->root_public,65))) return false;
        if(g->sets[0].id || !g->sets[0].count) return false;
        for(unsigned j=0;j<4;++j) {
            const Matter_Groupkey_Set_T* set=&g->sets[j]; if(set->count>3) return false;
            if(!set->count) continue;
            if(j && !set->times[0]) return false;
            for(unsigned k=1;k<set->count;++k) if(set->times[k]<=set->times[k-1]) return false;
            for(unsigned k=0;k<j;++k) if(g->sets[k].count && g->sets[k].id==set->id) return false;
        }
        for(unsigned j=0;j<a->count;++j) {
            const Matter_Acl_Entry_T* e=&a->entries[j];
            if((e->privilege!=1 && e->privilege!=3 && e->privilege!=4 && e->privilege!=5) || (e->auth_mode!=2 && e->auth_mode!=3) ||
                (e->auth_mode==3 && e->privilege==5) || e->subject_count>4 || e->target_count>3 ||
                (e->subjects_null && e->subject_count) || (e->targets_null && e->target_count)) return false;
            for(unsigned k=0;k<e->subject_count;++k) if(!acl_subject(e->subjects[k],e->auth_mode)) return false;
            for(unsigned k=0;k<e->target_count;++k) if(!e->targets[k].present || e->targets[k].present>7 || (e->targets[k].present&6)==6) return false;
        }
    }
    return count==v->count && pending==(v->added?1u:0u);
}

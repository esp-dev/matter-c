#include "matter_store_internal.h"
#include "matter_compat.h"
#include "matter_host_limits.h"
#include <stdlib.h>
#include <string.h>
typedef struct Resumption_Node {
    struct Resumption_Node* next;
    Matter_Case_Resumption_T value;
} Resumption_Node;
enum { UNDO_RECORD=1, UNDO_KEY=2, UNDO_ACL=4, UNDO_GROUP=8, UNDO_GROUPKEYS=16, UNDO_PREVIOUS=32,
    UNDO_SLOT=UNDO_RECORD|UNDO_KEY|UNDO_ACL|UNDO_GROUP|UNDO_GROUPKEYS };
typedef struct { size_t offset,size,saved; } Undo_Range;
typedef struct {
    size_t size,count;
    Undo_Range ranges[10];
    /* Every saved range starts at uint64_t alignment, as do the DTO's records. */
    uint64_t data[];
} Fabric_Undo;
struct Matter_Fabric_Host {
    Fabric_Undo* backup;
    Matter_Fabric_Host_Image_T image; Matter_Opcreds_Host_T keys;
    Matter_Crypto_Port_T crypto; Matter_Credentials_Port_T credentials;
    Matter_Cert_Time_Policy_T time;
    Matter_Fabric_Host_Control_T control;
    Matter_Fabric_Host_Events_T events; Matter_Acl_Entry_T bootstrap;
    bool busy,reset_requested; unsigned slot;
    uint32_t case_revision[5],next_case_revision;
    Resumption_Node* resumption;
    uint64_t credential_revision[5],next_credential_revision;
    Matter_Exchange_Session_T update_session;
    Matter_Exchange_Session_T session;
    Matter_Fabric_Record_T work;
    Matter_Operational_Identity_T identity, root_identity;
    uint8_t public_key[65], ipk[16], salt[8], groupwork[3][16];
};
Matter_Result_T matter_fabric_host_bind_events(Matter_Fabric_Host_T h,const Matter_Fabric_Host_Events_T* p) {
    if(!h || !p || !p->acl || !p->log || !p->admin) return MATTER_INVALID_ARGUMENT;
    if(h->busy) return MATTER_BUSY;
    if(h->events.log) return MATTER_INVALID_STATE;
    h->events=*p; return MATTER_OK;
}
static void erase(void* p,size_t n) { volatile uint8_t* b=p; while(n--) *b++=0; }
static void clear_resumptions(Matter_Fabric_Host_T h,uint8_t index) {
    Resumption_Node** link=&h->resumption;
    while(*link) {
        Resumption_Node* node=*link;
        if(!index || node->value.identity.fabric_index==index) {
            *link=node->next; erase(node,sizeof(*node)); free(node);
        } else link=&node->next;
    }
}
Matter_Fabric_Host_Image_T matter_fabric_host_image_new(void) {
    Matter_Fabric_Host_Image_T i=calloc(1,sizeof(*i)); if(i) { i->data.next_index=1; i->data.acl.version=1; i->data.groupkey.version=1; } return i;
}
Matter_Result_T matter_fabric_host_image_delete(Matter_Fabric_Host_Image_T i) {
    if(!i) return MATTER_INVALID_ARGUMENT;
    if(i->attached || i->persist.publish) return MATTER_BUSY;
    erase(i,sizeof(*i)); free(i); return MATTER_OK;
}
static void clear_backup(Matter_Fabric_Host_T h) {
    if(h->backup) { erase(h->backup,h->backup->size); free(h->backup); h->backup=NULL; }
}
static void undo_range(Fabric_Undo* b,size_t offset,size_t size) {
    b->ranges[b->count++]=(Undo_Range){offset,size,b->size};
    b->size+=(size+sizeof(uint64_t)-1)/sizeof(uint64_t)*sizeof(uint64_t);
}
static bool before(Matter_Fabric_Host_T h,unsigned slot,unsigned fields) {
    /* A mutation touches at most one slot. Keep the stable live image and save
     * only its modified ranges, including all journal/header state. The small
     * descriptor is stack-only; certificate/key bytes always live on the heap. */
    Fabric_Undo layout={.size=sizeof(Fabric_Undo)};
    Matter_Store_Fabrics_T* d=&h->image->data;
#define SAVE(member) undo_range(&layout,(size_t)((uint8_t*)&d->member-(uint8_t*)d),sizeof(d->member))
    undo_range(&layout,0,offsetof(Matter_Fabric_View_T,records));
    SAVE(acl.version); SAVE(groupkey.version);
    undo_range(&layout,offsetof(Matter_Store_Fabrics_T,next_index),
        offsetof(Matter_Store_Fabrics_T,previous)-offsetof(Matter_Store_Fabrics_T,next_index));
    if(slot<5) {
        if(fields&UNDO_RECORD) SAVE(view.records[slot]);
        if(fields&UNDO_KEY) SAVE(keys[slot]);
        if(fields&UNDO_ACL) SAVE(acl.fabrics[slot]);
        if(fields&UNDO_GROUP) SAVE(groupkey.fabrics[slot]);
        if(fields&UNDO_GROUPKEYS) SAVE(groupkeys[slot]);
    }
    if(fields&UNDO_PREVIOUS) undo_range(&layout,offsetof(Matter_Store_Fabrics_T,previous),
        sizeof(*d)-offsetof(Matter_Store_Fabrics_T,previous));
#undef SAVE
    h->backup=calloc(1,layout.size); if(!h->backup) return false;
    memcpy(h->backup,&layout,sizeof(layout));
    for(size_t j=0;j<layout.count;++j) {
        const Undo_Range* r=&layout.ranges[j];
        memcpy((uint8_t*)h->backup+r->saved,(const uint8_t*)d+r->offset,r->size);
    }
    return true;
}
static void restore_backup(Matter_Fabric_Host_T h) {
    for(size_t j=0;j<h->backup->count;++j) {
        const Undo_Range* r=&h->backup->ranges[j];
        memcpy((uint8_t*)&h->image->data+r->offset,(const uint8_t*)h->backup+r->saved,r->size);
    }
}
static const void* previous(Matter_Fabric_Host_T h,const void* current,size_t size) {
    size_t offset=(size_t)((const uint8_t*)current-(const uint8_t*)&h->image->data);
    for(size_t j=0;j<h->backup->count;++j) {
        const Undo_Range* r=&h->backup->ranges[j];
        if(offset>=r->offset && offset-r->offset<=r->size && size<=r->size-(offset-r->offset))
            return (const uint8_t*)h->backup+r->saved+(offset-r->offset);
    }
    return current; /* Unmodified slot/field: the live bytes are also the old bytes. */
}
static void removed(Matter_Fabric_Host_T h,uint8_t index) {
    if(h->events.log) (void)matter_events_forget_fabric(h->events.log,index);
    if(h->events.removed) h->events.removed(h->events.user,index);
}
static Matter_Result_T after(Matter_Fabric_Host_T h) {
    Matter_Result_T r=MATTER_OK;
    unsigned changed=0;
    for(unsigned j=0;j<5;++j) {
        const Matter_Fabric_Record_T* b=&h->image->data.view.records[j],*a=previous(h,b,sizeof(*b));
        if(a->index!=b->index || a->noc_size!=b->noc_size || a->icac_size!=b->icac_size ||
            memcmp(a->noc,b->noc,400) || memcmp(a->icac,b->icac,400) || memcmp(previous(h,h->image->data.keys[j],32),h->image->data.keys[j],32)) ++changed;
    }
    if(changed>UINT64_MAX-h->next_credential_revision || h->next_case_revision>UINT32_MAX-5) {
        restore_backup(h); clear_backup(h); return MATTER_LIMIT_REACHED;
    }
    if(h->image->persist.publish) {
        r=h->image->persist.publish(h->image->persist.user,&h->image->data,NULL,false);
        if(r!=MATTER_OK) restore_backup(h);
    }
    if(r==MATTER_OK) for(unsigned j=0;j<5;++j) {
        /* Label changes do not change operational identity. Other fabrics must
         * not invalidate this one's in-progress CASE snapshot. */
        const Matter_Fabric_Record_T* b=&h->image->data.view.records[j],*a=previous(h,b,sizeof(*b));
        if(a->index && a->index!=b->index) removed(h,a->index);
        if(a->index!=b->index || a->noc_size!=b->noc_size || a->icac_size!=b->icac_size ||
            memcmp(a->noc,b->noc,400) || memcmp(a->icac,b->icac,400) ||
            memcmp(previous(h,h->image->data.keys[j],32),h->image->data.keys[j],32)) h->credential_revision[j]=++h->next_credential_revision;
        if(a->index!=b->index || a->noc_size!=b->noc_size || a->icac_size!=b->icac_size ||
            memcmp(a->noc,b->noc,400) || memcmp(a->icac,b->icac,400) || memcmp(previous(h,h->image->data.keys[j],32),h->image->data.keys[j],32) ||
            memcmp(previous(h,h->image->data.groupkeys[j][0],sizeof(h->image->data.groupkeys[j][0])),h->image->data.groupkeys[j][0],sizeof(h->image->data.groupkeys[j][0])) ||
            memcmp(previous(h,&h->image->data.groupkey.fabrics[j].sets[0],sizeof(h->image->data.groupkey.fabrics[j].sets[0])),&h->image->data.groupkey.fabrics[j].sets[0],sizeof(h->image->data.groupkey.fabrics[j].sets[0]))) {
            h->case_revision[j]=++h->next_case_revision;
            if(a->index) clear_resumptions(h,a->index);
        }
    }
    clear_backup(h);
    return r;
}
static const Matter_Fabric_View_T* view(void* u) { return &((Matter_Fabric_Host_T)u)->image->data.view; }
static Matter_Result_T rollback(void* u) {
    Matter_Fabric_Host_T h=u; Matter_Fabric_Host_Image_T i=h->image; Matter_Fabric_View_T* v=&i->data.view;
    if(h->busy) return MATTER_BUSY;
    if(h->control.fail_rollback) return MATTER_PORT_ERROR;
    unsigned pending=5;
    if(i->data.journal) for(unsigned j=0;j<5;++j)
        if(v->pending_index && v->records[j].index==v->pending_index) pending=j;
    if(!before(h,pending,UNDO_SLOT|UNDO_PREVIOUS)) return MATTER_LIMIT_REACHED;
    if(i->data.journal) {
        for(unsigned j=0;j<5;++j) if(v->pending_index && v->records[j].index==v->pending_index) {
            if(i->data.previous.index) {
                h->work=i->data.previous; /* Labels/ACL/IPK changes are independent. */
                h->work.label_size=v->records[j].label_size; memcpy(h->work.label,v->records[j].label,32);
                v->records[j]=h->work; erase(&h->work,sizeof(h->work)); memcpy(i->data.keys[j],i->data.previous_key,32);
                continue;
            }
            erase(&v->records[j],sizeof(v->records[j])); erase(i->data.keys[j],32); erase(i->data.groupkeys[j],sizeof(i->data.groupkeys[j]));
            erase(&i->data.groupkey.fabrics[j],sizeof(i->data.groupkey.fabrics[j])); ++i->data.groupkey.version;
            erase(&i->data.acl.fabrics[j],sizeof(i->data.acl.fabrics[j])); ++i->data.acl.version; --v->count;
        }
        i->data.next_index=i->data.saved_next; i->data.journal=false; ++v->revision;
    }
    erase(&i->data.previous,sizeof(i->data.previous)); erase(i->data.previous_key,32);
    v->root_ready=v->added=false; v->root_size=0; erase(v->root,400);
    v->pending_index=v->pase_index=0; v->pase_session=0; h->busy=true; Matter_Result_T result=after(h); h->busy=false;
    if(result==MATTER_OK) h->update_session=0;
    return result;
}
static bool collision(void* u,const uint8_t p[65]) {
    Matter_Fabric_Host_T h=u;
    for(unsigned j=0;j<5;++j) if(h->image->data.view.records[j].index && !memcmp(h->image->data.view.records[j].operational_public,p,65)) return true;
    return false;
}
Matter_Fabric_Host_T matter_fabric_host_new(Matter_Fabric_Host_Image_T i,Matter_Opcreds_Host_T keys,
    const Matter_Crypto_Port_T* crypto,const Matter_Credentials_Port_T* cp,const Matter_Cert_Time_Policy_T* time) {
    if(!i || i->attached || !keys || !crypto || !crypto->hkdf_sha256 || !crypto->equal || !crypto->ecdsa_sign || !crypto->ecdsa_verify || !cp || !cp->cert_verify_chain ||
        !time || time->mode!=MATTER_CERT_TIME_SUPPLIED) return NULL;
    Matter_Fabric_Host_T h=calloc(1,sizeof(*h)); if(!h) return NULL;
    h->image=i; h->keys=keys; h->crypto=*crypto; h->credentials=*cp; h->time=*time;
    if(matter_opcreds_host_collision(keys,h,collision)!=MATTER_OK) { free(h); return NULL; }
    if(rollback(h)!=MATTER_OK) { matter_opcreds_host_collision(keys,NULL,NULL); erase(h,sizeof(*h)); free(h); return NULL; }
    i->attached=true; return h;
}
static uint8_t root(void* u,Matter_Cert_Tlv_T cert) {
    Matter_Fabric_Host_T h=u; Matter_Fabric_Host_Image_T i=h->image; Matter_Fabric_View_T* v=&i->data.view;
    if(h->busy) return MATTER_IM_FAILURE;
    if(v->added || (v->root_ready && (v->root_size!=cert.size || memcmp(v->root,cert.data,cert.size)))) return MATTER_IM_CONSTRAINT_ERROR;
    h->busy=true;
    Matter_Result_T r=matter_operational_cert_verify_root(&h->crypto,cert);
    bool duplicate=false;
    for(unsigned j=0;j<5;++j) if(v->records[j].index && v->records[j].root_size==cert.size && !memcmp(v->records[j].root,cert.data,cert.size)) duplicate=true;
    /* The pending RCAC has its own journal slot. Fabric capacity is reported by
     * AddNOC as NOCResponse.TableFull (Core 11.18.6.8), not an IM error here. */
    uint8_t status=r!=MATTER_OK?MATTER_IM_INVALID_COMMAND:h->control.fail_store?MATTER_IM_FAILURE:0;
    if(!status && !v->root_ready) {
        if(!before(h,5,0)) { h->busy=false; return MATTER_IM_FAILURE; }
        i->data.saved_next=i->data.next_index; i->data.journal=true;
        memcpy(v->root,cert.data,cert.size); v->root_size=(uint16_t)cert.size; v->root_ready=true;
        if(!duplicate || MATTER_CSA_COMPAT_PENDING_ROOT) ++v->revision;
        if(after(h)!=MATTER_OK) status=MATTER_IM_FAILURE;
    }
    h->busy=false; return status;
}
static Matter_Result_T store(void* u,const uint8_t key[32]) {
    Matter_Fabric_Host_T h=u; Matter_Fabric_Host_Image_T i=h->image; Matter_Fabric_View_T* v=&i->data.view;
    h->bootstrap=(Matter_Acl_Entry_T){.privilege=5,.auth_mode=2,.subjects={h->work.admin_subject},.subject_count=1,.targets_null=true};
    if(h->events.log) {
        Matter_Cluster_Request_T q={0};
        Matter_Result_T r=h->events.admin(h->events.user,h->session,&q); if(r!=MATTER_OK) return r;
        q.fabric=h->work.index;
        r=matter_acl_prepare_added(h->events.acl,&q,&h->bootstrap); if(r!=MATTER_OK) return r;
    }
    if(!before(h,h->slot,UNDO_SLOT)) {
        if(h->events.log) matter_acl_finish_added(h->events.acl,false);
        return MATTER_LIMIT_REACHED;
    }
    /* Single owner transaction. CSR is consumed only after durable publication.
     * Every cryptographic preflight has already run.
     * ACL, KeySet0 and discovery registry are materialized in this SAME image.
     * No external callback or allocation can observe a partially installed entry. */
    v->records[h->slot]=h->work; memcpy(i->data.keys[h->slot],key,32); memcpy(i->data.groupkeys[h->slot][0][0],h->ipk,16);
    Matter_Groupkey_Fabric_T* g=&i->data.groupkey.fabrics[h->slot];
    memset(g,0,sizeof(*g)); g->index=h->work.index; g->sets[0].count=1; ++i->data.groupkey.version;
    Matter_Acl_Fabric_T* acl=&i->data.acl.fabrics[h->slot];
    memset(acl,0,sizeof(*acl)); acl->index=h->work.index; acl->count=1;
    acl->entries[0]=h->bootstrap;
    ++i->data.acl.version;
    ++v->count; ++v->revision; v->added=true; v->pending_index=v->pase_index=h->work.index; v->pase_session=h->session;
    i->data.next_index=h->work.index==254?1:(uint8_t)(h->work.index+1);
    Matter_Result_T result=after(h);
    if(h->events.log) matter_acl_finish_added(h->events.acl,result==MATTER_OK);
    return result;
}
static Matter_Result_T install(void* u,Matter_Exchange_Session_T session,uint64_t candidate,const Matter_Fabric_Add_T* a,uint8_t* status,uint8_t* index) {
    Matter_Fabric_Host_T h=u; Matter_Fabric_View_T* v=&h->image->data.view; *status=0; *index=0;
    if(h->busy) return MATTER_BUSY;
    if(!v->root_ready || v->added) return MATTER_INVALID_STATE;
    h->busy=true; bool invalid_node=false; Matter_Result_T result=MATTER_OK;
    erase(&h->work,sizeof(h->work)); h->session=session;
    if(matter_operational_cert_inspect(a->noc,MATTER_CERT_NOC,&h->identity,&invalid_node)!=MATTER_OK) { *status=invalid_node?2:3; goto done; }
    if(matter_operational_cert_verify(&h->credentials,a->noc,a->icac,(Matter_Cert_Tlv_T){v->root,v->root_size},
        h->identity.fabric_id,&h->time,&h->identity)!=MATTER_OK) { *status=3; goto done; }
    if(matter_opcreds_host_candidate(h->keys,h->public_key)!=MATTER_OK || memcmp(h->public_key,h->identity.public_key,65)) { *status=1; goto done; }
    if(matter_operational_cert_inspect((Matter_Cert_Tlv_T){v->root,v->root_size},MATTER_CERT_RCAC,&h->root_identity,&invalid_node)!=MATTER_OK) { *status=3; goto done; }
    h->slot=5;
    for(unsigned j=0;j<5;++j) {
        const Matter_Fabric_Record_T* r=&v->records[j];
        if(!r->index) { if(h->slot==5) h->slot=j; }
        else if(r->fabric_id==h->identity.fabric_id && !memcmp(r->root_public,h->root_identity.public_key,65)) { *status=9; goto done; }
    }
    if(h->slot==5) { *status=5; goto done; }
    h->work.index=h->image->data.next_index;
    for(unsigned tries=0;tries<254;++tries) {
        bool used=false; for(unsigned j=0;j<5;++j) if(v->records[j].index==h->work.index) used=true;
        if(!used) break;
        h->work.index=h->work.index==254?1:(uint8_t)(h->work.index+1);
    }
    h->work.fabric_id=h->identity.fabric_id; h->work.node_id=h->identity.node_id; h->work.vendor=a->vendor; h->work.admin_subject=a->admin_subject;
    memcpy(h->work.root_public,h->root_identity.public_key,65); memcpy(h->work.operational_public,h->identity.public_key,65);
    for(unsigned j=0;j<8;++j) h->salt[7-j]=(uint8_t)(h->identity.fabric_id>>(8*j));
    static const uint8_t info[]="CompressedFabric";
    if(h->crypto.hkdf_sha256(h->crypto.user,h->work.root_public+1,64,h->salt,8,info,16,h->work.compressed_id,8)!=MATTER_OK) { result=MATTER_PORT_ERROR; goto done; }
    static const char hex[]="0123456789ABCDEF";
    for(unsigned j=0;j<8;++j) {
        h->work.discovery_instance[2*j]=hex[h->work.compressed_id[j]>>4]; h->work.discovery_instance[2*j+1]=hex[h->work.compressed_id[j]&15];
        uint8_t n=(uint8_t)(h->work.node_id>>(8*(7-j)));
        h->work.discovery_instance[17+2*j]=hex[n>>4]; h->work.discovery_instance[18+2*j]=hex[n&15];
    }
    h->work.discovery_instance[16]='-'; h->work.discovery_instance[33]=0;
    h->work.root_size=v->root_size; memcpy(h->work.root,v->root,v->root_size);
    h->work.noc_size=(uint16_t)a->noc.size; memcpy(h->work.noc,a->noc.data,a->noc.size);
    h->work.icac_size=(uint16_t)a->icac.size; if(a->icac.size) memcpy(h->work.icac,a->icac.data,a->icac.size);
    if(h->crypto.hkdf_sha256(h->crypto.user,a->ipk,16,h->work.compressed_id,8,
        (const uint8_t*)"GroupKey v1.0",13,h->ipk,16)!=MATTER_OK) { result=MATTER_PORT_ERROR; goto done; }
    if(h->control.fail_store || h->control.fail_acl || h->control.fail_discovery) { result=MATTER_PORT_ERROR; goto done; }
    result=matter_opcreds_host_consume(h->keys,candidate,h,store);
    if(result==MATTER_OK) *index=h->work.index;
done:
    erase(h->ipk,16); erase(&h->work,sizeof(h->work)); h->busy=false; return result;
}
static Matter_Result_T store_update(void* u,const uint8_t key[32]) {
    Matter_Fabric_Host_T h=u; Matter_Store_Fabrics_T* d=&h->image->data;
    if(!before(h,h->slot,UNDO_RECORD|UNDO_KEY|UNDO_PREVIOUS)) return MATTER_LIMIT_REACHED;
    d->previous=d->view.records[h->slot]; memcpy(d->previous_key,d->keys[h->slot],32);
    d->view.records[h->slot]=h->work; memcpy(d->keys[h->slot],key,32);
    d->saved_next=d->next_index; d->journal=true; d->view.added=true; d->view.pending_index=h->work.index;
    ++d->view.revision;
    Matter_Result_T r=after(h); if(r==MATTER_OK) h->update_session=h->session; return r;
}
static Matter_Result_T update(void* u,Matter_Exchange_Session_T session,uint8_t index,uint64_t candidate,
    Matter_Cert_Tlv_T noc,Matter_Cert_Tlv_T icac,uint8_t* status) {
    Matter_Fabric_Host_T h=u; Matter_Fabric_View_T* v=&h->image->data.view; *status=0;
    if(h->busy) return MATTER_BUSY;
    if(v->added || v->root_ready || h->next_credential_revision==UINT64_MAX) return MATTER_INVALID_STATE;
    h->slot=5; for(unsigned j=0;j<5;++j) if(v->records[j].index==index) h->slot=j;
    if(h->slot==5) return MATTER_INVALID_STATE;
    h->busy=true; h->session=session; bool invalid_node=false; Matter_Result_T result=MATTER_OK;
    h->work=v->records[h->slot];
    /* NOCStruct cannot contain both ICAC and VVSC. Keep the existing metadata
     * and candidate untouched; administrator must remove VVSC first. */
    if(icac.size && h->work.vvsc_size) { *status=3; goto done; }
    if(matter_operational_cert_inspect(noc,MATTER_CERT_NOC,&h->identity,&invalid_node)!=MATTER_OK) { *status=invalid_node?2:3; goto done; }
    if(matter_operational_cert_verify(&h->credentials,noc,icac,(Matter_Cert_Tlv_T){h->work.root,h->work.root_size},
        h->work.fabric_id,&h->time,&h->identity)!=MATTER_OK) { *status=3; goto done; }
    if(matter_opcreds_host_candidate(h->keys,h->public_key)!=MATTER_OK || memcmp(h->public_key,h->identity.public_key,65)) { *status=1; goto done; }
    h->work.node_id=h->identity.node_id; memcpy(h->work.operational_public,h->identity.public_key,65);
    erase(h->work.noc,400); erase(h->work.icac,400);
    h->work.noc_size=(uint16_t)noc.size; h->work.icac_size=(uint16_t)icac.size;
    memcpy(h->work.noc,noc.data,noc.size); if(icac.size) memcpy(h->work.icac,icac.data,icac.size);
    static const char hex[]="0123456789ABCDEF";
    for(unsigned j=0;j<8;++j) {
        uint8_t n=(uint8_t)(h->work.node_id>>(8*(7-j)));
        h->work.discovery_instance[17+2*j]=hex[n>>4]; h->work.discovery_instance[18+2*j]=hex[n&15];
    }
    if(h->control.fail_store || h->control.fail_discovery) { result=MATTER_PORT_ERROR; goto done; }
    result=matter_opcreds_host_consume(h->keys,candidate,h,store_update);
done:
    erase(&h->work,sizeof(h->work)); h->busy=false; return result;
}
static Matter_Result_T label(void* u,uint8_t index,const uint8_t* value,size_t size) {
    Matter_Fabric_Host_T h=u;
    if(!index || index==255 || (size && !value)) return MATTER_INVALID_ARGUMENT;
    if(h->busy || size>32 || h->control.fail_store) return MATTER_PORT_ERROR;
    for(unsigned j=0;j<5;++j) if(h->image->data.view.records[j].index==index) {
        Matter_Fabric_Record_T* f=&h->image->data.view.records[j];
        if(f->label_size==size && (!size || !memcmp(f->label,value,size))) return MATTER_OK;
        if(!before(h,j,UNDO_RECORD)) return MATTER_LIMIT_REACHED;
        erase(f->label,32); if(size) memcpy(f->label,value,size); f->label_size=(uint8_t)size;
        ++h->image->data.view.revision; h->busy=true; Matter_Result_T r=after(h); h->busy=false; return r;
    }
    return MATTER_INVALID_STATE;
}
static Matter_Result_T remove_fabric(void* u,uint8_t index) {
    Matter_Fabric_Host_T h=u; Matter_Store_Fabrics_T* d=&h->image->data; Matter_Fabric_View_T* v=&d->view;
    if(!index || index==255) return MATTER_INVALID_ARGUMENT;
    if(h->busy || h->control.fail_store) return MATTER_PORT_ERROR;
    if(h->next_case_revision==UINT32_MAX) return MATTER_LIMIT_REACHED;
    for(unsigned j=0;j<5;++j) if(v->records[j].index==index) {
        bool clears_journal=v->pending_index==index || v->count==1;
        if(!before(h,j,UNDO_SLOT|(clears_journal?UNDO_PREVIOUS:0))) return MATTER_LIMIT_REACHED;
        h->busy=true;
        erase(&v->records[j],sizeof(v->records[j])); erase(d->keys[j],sizeof(d->keys[j])); erase(d->groupkeys[j],sizeof(d->groupkeys[j]));
        erase(&d->acl.fabrics[j],sizeof(d->acl.fabrics[j])); erase(&d->groupkey.fabrics[j],sizeof(d->groupkey.fabrics[j]));
        --v->count; ++v->revision; ++d->acl.version; ++d->groupkey.version;
        if(clears_journal) {
            v->pending_index=v->pase_index=0; v->pase_session=0; v->added=v->root_ready=false;
            v->root_size=0; erase(v->root,sizeof(v->root)); d->journal=false;
            erase(&d->previous,sizeof(d->previous)); erase(d->previous_key,32);
        }
        Matter_Result_T r;
        if(!v->count && h->image->persist.reset) {
            d->next_index=1; d->saved_next=0;
            r=h->image->persist.reset(h->image->persist.user,d);
            if(r!=MATTER_OK) restore_backup(h); else {
                h->case_revision[j]=++h->next_case_revision; clear_resumptions(h,0); removed(h,index);
            }
            clear_backup(h);
        } else r=after(h);
        if(r==MATTER_OK && clears_journal) h->update_session=0;
        if(r==MATTER_OK && !v->count) h->reset_requested=true;
        h->busy=false; return r;
    }
    return MATTER_INVALID_STATE;
}
static Matter_Result_T vid(void* u,uint8_t index,const Matter_Fabric_Vid_T* a) {
    Matter_Fabric_Host_T h=u;
    if(!a || !index || index==255 || (!a->vendor_present && !a->vvs_present && !a->vvsc_present) ||
        (a->vendor_present && (!a->vendor || a->vendor>0xfff4)) ||
        (a->vvs_present && ((a->vvs.size!=0 && a->vvs.size!=85) || (a->vvs.size && !a->vvs.data))) ||
        (a->vvsc_present && (a->vvsc.size>400 || (a->vvsc.size && !a->vvsc.data)))) return MATTER_INVALID_ARGUMENT;
    if(h->busy || h->control.fail_store) return MATTER_PORT_ERROR;
    for(unsigned j=0;j<5;++j) if(h->image->data.view.records[j].index==index) {
        Matter_Fabric_Record_T* f=&h->image->data.view.records[j];
        if(a->vvsc_present && f->icac_size) return MATTER_INVALID_ARGUMENT;
        h->work=*f;
        if(a->vendor_present) h->work.vendor=a->vendor;
        if(a->vvs_present) { erase(h->work.vvs,85); h->work.vvs_size=(uint8_t)a->vvs.size; if(a->vvs.size) memcpy(h->work.vvs,a->vvs.data,a->vvs.size); }
        if(a->vvsc_present) { erase(h->work.vvsc,400); h->work.vvsc_size=(uint16_t)a->vvsc.size; if(a->vvsc.size) memcpy(h->work.vvsc,a->vvsc.data,a->vvsc.size); }
        bool changed=f->vendor!=h->work.vendor || f->vvs_size!=h->work.vvs_size || f->vvsc_size!=h->work.vvsc_size ||
            memcmp(f->vvs,h->work.vvs,85) || memcmp(f->vvsc,h->work.vvsc,400);
        Matter_Result_T r=MATTER_OK;
        if(changed && !before(h,j,UNDO_RECORD)) r=MATTER_LIMIT_REACHED;
        else if(changed) { *f=h->work; ++h->image->data.view.revision; h->busy=true; r=after(h); h->busy=false; }
        erase(&h->work,sizeof(h->work)); return r;
    }
    return MATTER_INVALID_STATE;
}
static Matter_Result_T vid_sign(void* u,uint8_t index,const uint8_t* p,size_t n,uint8_t sig[64]) { return matter_fabric_host_sign(u,index,p,n,sig); }
Matter_Fabric_Port_T matter_fabric_host_port(Matter_Fabric_Host_T h) { return (Matter_Fabric_Port_T){h,view,root,install,rollback,label,remove_fabric,update,vid,vid_sign}; }
bool matter_fabric_host_reset_requested(Matter_Fabric_Host_T h) { return h && h->reset_requested; }
Matter_Result_T matter_fabric_host_commit_ready(Matter_Fabric_Host_T h,uint8_t index) {
    if(!h || !index || index==255) return MATTER_INVALID_ARGUMENT;
    if(h->busy) return MATTER_BUSY;
    const Matter_Fabric_View_T* v=&h->image->data.view;
    if(h->image->data.journal || v->added || v->pending_index)
        return h->image->data.journal && v->added && v->pending_index==index?MATTER_OK:MATTER_INVALID_STATE;
    /* Network-only fail-safe: Root has checked the owning fabric. Require that
     * it still exists; no credential journal is needed for this transaction. */
    for(unsigned i=0;i<5;++i) if(v->records[i].index==index) return MATTER_OK;
    return MATTER_INVALID_STATE;
}
Matter_Result_T matter_fabric_host_apply_commit(Matter_Fabric_Host_T h) {
    if(!h) return MATTER_INVALID_ARGUMENT;
    if(h->busy) return MATTER_BUSY;
    Matter_Fabric_View_T* v=&h->image->data.view;
    if(h->image->data.journal!=v->added || (!v->added && v->pending_index)) return MATTER_INVALID_STATE;
    erase(&h->image->data.previous,sizeof(h->image->data.previous)); erase(h->image->data.previous_key,32);
    h->image->data.journal=false; v->pase_session=0; v->pase_index=0; v->added=v->root_ready=false; v->pending_index=0; v->root_size=0; erase(v->root,400); return MATTER_OK;
}
Matter_Result_T matter_fabric_host_publish_commit(Matter_Fabric_Host_T h,const Matter_Store_Wifi_T* wifi) {
    if(!h || h->busy) return MATTER_INVALID_STATE;
    if(!h->image->persist.publish) return MATTER_OK;
    /* Encode the committed projection without changing the pending live view.
     * The commissioning owner applies it only after durable publication. */
    h->busy=true;
    Matter_Result_T r=h->image->persist.publish(h->image->persist.user,&h->image->data,wifi,true);
    h->busy=false; return r;
}
Matter_Result_T matter_fabric_host_commit(Matter_Fabric_Host_T h) {
    if(!h) return MATTER_INVALID_ARGUMENT;
    if(h->busy) return MATTER_BUSY;
    if(!h->image->data.journal || !h->image->data.view.added) return MATTER_INVALID_STATE;
    Matter_Result_T r=matter_fabric_host_commit_ready(h,h->image->data.view.pending_index); if(r!=MATTER_OK) return r;
    r=matter_fabric_host_publish_commit(h,NULL); return r==MATTER_OK?matter_fabric_host_apply_commit(h):r;
}
Matter_Result_T matter_fabric_host_delete(Matter_Fabric_Host_T h) {
    if(!h) return MATTER_INVALID_ARGUMENT;
    if(h->busy) return MATTER_BUSY;
    Matter_Result_T r=matter_opcreds_host_collision(h->keys,NULL,NULL); if(r!=MATTER_OK) return r;
    h->image->attached=false; clear_resumptions(h,0); erase(h,sizeof(*h)); free(h); return MATTER_OK;
}
static unsigned slot(Matter_Fabric_Host_T h,uint8_t index) {
    for(unsigned j=0;j<5;++j) if(index && h->image->data.view.records[j].index==index) return j;
    return 5;
}
uint64_t matter_fabric_host_credential_revision(Matter_Fabric_Host_T h,uint8_t index,Matter_Exchange_Session_T* session) {
    if(!h || !session) return 0;
    unsigned j=slot(h,index); *session=h->update_session; return j<5?h->credential_revision[j]:0;
}
Matter_Result_T matter_fabric_host_sign(Matter_Fabric_Host_T h,uint8_t index,const uint8_t* data,size_t n,uint8_t sig[64]) {
    if(!h || !sig || (!data && n)) return MATTER_INVALID_ARGUMENT;
    if(h->busy) return MATTER_BUSY;
    unsigned j=slot(h,index); if(j==5) return MATTER_INVALID_STATE;
    h->busy=true; Matter_Result_T r=h->crypto.ecdsa_sign(h->crypto.user,h->image->data.keys[j],data,n,sig); h->busy=false; return r;
}
static const Matter_Acl_View_T* acl_view(void* u) { return &((Matter_Fabric_Host_T)u)->image->data.acl; }
static uint8_t acl_store(void* u,uint8_t index,const Matter_Acl_Entry_T* entries,size_t count) {
    Matter_Fabric_Host_T h=u;
    if(h->busy || count>MATTER_ACL_ENTRIES || (count && !entries)) return MATTER_IM_FAILURE;
    unsigned j=slot(h,index); if(j==5) return MATTER_IM_UNSUPPORTED_ACCESS;
    if(h->control.fail_store || h->control.fail_acl) return MATTER_IM_FAILURE;
    if(!before(h,j,UNDO_ACL)) return MATTER_IM_FAILURE;
    Matter_Acl_Fabric_T* f=&h->image->data.acl.fabrics[j];
    if(f->count!=count || memcmp(f->entries,entries,count*sizeof(*entries))) {
        memset(f->entries,0,sizeof(f->entries)); if(count) memcpy(f->entries,entries,count*sizeof(*entries));
        f->count=(uint8_t)count; ++h->image->data.acl.version;
    }
    h->busy=true; Matter_Result_T result=after(h); h->busy=false;
    return result==MATTER_OK?0:MATTER_IM_FAILURE;
}
Matter_Acl_Port_T matter_fabric_host_acl_port(Matter_Fabric_Host_T h) { return (Matter_Acl_Port_T){h,acl_view,acl_store}; }
bool matter_fabric_host_case_authorize(Matter_Fabric_Host_T h,uint8_t index,uint64_t node,const uint32_t* cats,size_t count,Matter_Im_Privilege_T privilege) {
    return h && !h->busy && matter_acl_grants(&h->image->data.acl,index,node,cats,count,NULL,privilege,NULL);
}
void matter_fabric_host_control(Matter_Fabric_Host_T h,const Matter_Fabric_Host_Control_T* c) { if(h && c && !h->busy) h->control=*c; }

static Matter_Result_T case_load(void* u,unsigned slot,Matter_Case_Fabric_T* out) {
    Matter_Fabric_Host_T h=u;
    if(!h || !out || slot>=15) return MATTER_INVALID_ARGUMENT;
    if(h->busy) return MATTER_BUSY;
    unsigned candidate=slot/5; slot%=5;
    const Matter_Fabric_Record_T* r=&h->image->data.view.records[slot]; if(!r->index) return MATTER_INVALID_STATE;
    const Matter_Groupkey_Set_T* set=&h->image->data.groupkey.fabrics[slot].sets[0];
    unsigned enabled=set->count;
    if(enabled && set->times[enabled-1]==UINT64_MAX) --enabled;
    if(candidate>=enabled) return MATTER_INVALID_STATE;
    /* No synchronized operational clock: second newest enabled key first.
     * Remaining candidates let responders accept every installed IPK epoch. */
    unsigned epoch=enabled==3?(candidate==0?1:candidate==1?0:2):candidate;
    memset(out,0,sizeof(*out)); h->busy=true;
    Matter_Result_T result=MATTER_OK;
    memcpy(out->ipk,h->image->data.groupkeys[slot][0][epoch],16);
    if(result==MATTER_OK) {
        out->index=r->index; out->revision=h->case_revision[slot]; out->fabric_id=r->fabric_id; out->node_id=r->node_id;
        out->noc_size=r->noc_size; out->icac_size=r->icac_size; out->root_size=r->root_size;
        memcpy(out->noc,r->noc,r->noc_size); memcpy(out->icac,r->icac,r->icac_size); memcpy(out->root,r->root,r->root_size); memcpy(out->root_public,r->root_public,65);
    } else erase(out,sizeof(*out));
    h->busy=false; return result;
}
static Matter_Result_T case_valid(void* u,uint8_t index,uint32_t revision) {
    Matter_Fabric_Host_T h=u;
    if(!h || h->busy) return MATTER_INVALID_STATE;
    unsigned j=slot(h,index); return j==5 || h->case_revision[j]!=revision?MATTER_INVALID_STATE:MATTER_OK;
}
static Matter_Result_T case_sign(void* u,uint8_t index,const uint8_t* p,size_t n,uint8_t sig[64]) { return matter_fabric_host_sign(u,index,p,n,sig); }
#include "matter_fabric_resumption_internal.h"
Matter_Case_Port_T matter_fabric_host_case_port(Matter_Fabric_Host_T h) {
    return (Matter_Case_Port_T){h,15,case_load,case_valid,case_sign,resume_find,resume_save};
}

static const Matter_Groupkey_View_T* groupkey_view(void* u) { return &((Matter_Fabric_Host_T)u)->image->data.groupkey; }
static uint8_t groupkey_store(void* u,uint8_t index,const Matter_Groupkey_Set_T* set,const uint8_t keys[3][16]) {
    Matter_Fabric_Host_T h=u; unsigned j=slot(h,index);
    if(h->busy || !set || !keys || !set->count || set->count>3) return MATTER_IM_FAILURE;
    if(j==5) return MATTER_IM_UNSUPPORTED_ACCESS;
    Matter_Groupkey_Fabric_T* f=&h->image->data.groupkey.fabrics[j]; unsigned dest=MATTER_GROUPKEY_SETS;
    for(unsigned i=0;i<MATTER_GROUPKEY_SETS;++i) {
        if(f->sets[i].count && f->sets[i].id==set->id) { dest=i; break; }
        if(!f->sets[i].count && dest==MATTER_GROUPKEY_SETS) dest=i;
    }
    if(dest==MATTER_GROUPKEY_SETS) return MATTER_IM_RESOURCE_EXHAUSTED;
    if(h->control.fail_store) return MATTER_IM_FAILURE;
    h->busy=true; erase(h->groupwork,sizeof(h->groupwork)); uint8_t status=0;
    for(unsigned i=0;i<set->count;++i) if(set->times[i]!=UINT64_MAX &&
        h->crypto.hkdf_sha256(h->crypto.user,keys[i],16,h->image->data.view.records[j].compressed_id,8,
            (const uint8_t*)"GroupKey v1.0",13,h->groupwork[i],16)!=MATTER_OK) { status=MATTER_IM_FAILURE; break; }
    if(!status && !before(h,j,UNDO_GROUP|UNDO_GROUPKEYS)) status=MATTER_IM_FAILURE;
    if(!status && (memcmp(&f->sets[dest],set,sizeof(*set)) || memcmp(h->image->data.groupkeys[j][dest],h->groupwork,sizeof(h->groupwork)))) {
        f->sets[dest]=*set; memcpy(h->image->data.groupkeys[j][dest],h->groupwork,sizeof(h->groupwork)); ++h->image->data.groupkey.version;
        if(!set->id) ++h->image->data.view.revision; /* Invalidate in-progress CASE snapshots. */
    }
    if(!status && after(h)!=MATTER_OK) status=MATTER_IM_FAILURE;
    clear_backup(h); erase(h->groupwork,sizeof(h->groupwork)); h->busy=false; return status;
}
static uint8_t groupkey_remove(void* u,uint8_t index,uint16_t id) {
    Matter_Fabric_Host_T h=u; unsigned j=slot(h,index);
    if(h->busy) return MATTER_IM_FAILURE;
    if(!id) return MATTER_IM_INVALID_COMMAND;
    if(j==5) return MATTER_IM_UNSUPPORTED_ACCESS;
    Matter_Groupkey_Fabric_T* f=&h->image->data.groupkey.fabrics[j];
    for(unsigned i=0;i<MATTER_GROUPKEY_SETS;++i) if(f->sets[i].count && f->sets[i].id==id) {
        if(h->control.fail_store) return MATTER_IM_FAILURE;
        if(!before(h,j,UNDO_GROUP|UNDO_GROUPKEYS)) return MATTER_IM_FAILURE;
        erase(&f->sets[i],sizeof(f->sets[i])); erase(h->image->data.groupkeys[j][i],sizeof(h->image->data.groupkeys[j][i]));
        ++h->image->data.groupkey.version; h->busy=true; Matter_Result_T result=after(h); h->busy=false;
        return result==MATTER_OK?0:MATTER_IM_FAILURE;
    }
    return MATTER_GROUPKEY_NOT_FOUND;
}
Matter_Groupkey_Port_T matter_fabric_host_groupkey_port(Matter_Fabric_Host_T h) {
    return (Matter_Groupkey_Port_T){h,groupkey_view,groupkey_store,groupkey_remove};
}
Matter_Result_T matter_fabric_host_group_key(Matter_Fabric_Host_T h,uint8_t index,uint16_t id,unsigned epoch,uint8_t out[16]) {
    if(!h||!out||!id||epoch>=3)return MATTER_INVALID_ARGUMENT;
    if(h->busy)return MATTER_BUSY;
    unsigned j=slot(h,index);if(j==5)return MATTER_OFFLINE;
    const Matter_Groupkey_Fabric_T* f=&h->image->data.groupkey.fabrics[j];
    for(unsigned i=0;i<MATTER_GROUPKEY_SETS;++i)if(f->sets[i].count&&f->sets[i].id==id) {
        if(epoch>=f->sets[i].count||f->sets[i].times[epoch]==UINT64_MAX)return MATTER_OFFLINE;
        memcpy(out,h->image->data.groupkeys[j][i][epoch],16);return MATTER_OK;
    }
    return MATTER_OFFLINE;
}

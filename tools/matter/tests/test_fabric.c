#include <stdio.h>
#include "matter_compat.h"
#include <stdlib.h>
#include <string.h>
#include "crypto/matter_crypto_mbedtls.h"
#include "test_opcreds_fixture.h"
#include "test_fabric_fixture.h"
#include "test_synthetic_operational_vectors.h"
#include "test_vid.h"
#include "test_fabric_subscribe.h"
#ifdef MATTER_TEST_ALLOC
static size_t live,calls,fail_at;
void* matter_test_calloc(size_t n,size_t z) { if(++calls==fail_at) return NULL; void* p=calloc(n,z); if(p) ++live; return p; }
void matter_test_free(void* p) { if(p) { OC_CHECK(live); --live; } free(p); }
#endif
static Matter_Result_T two_sessions(void* u,Matter_Exchange_Session_T s,uint8_t out[16]) {
    OcFixture* o=u; if(s!=1 && s!=2) return MATTER_INVALID_STATE;
    memcpy(out,o->challenge,16); if(s==2) out[0]^=1; return MATTER_OK;
}
static void read_count(FabFixture* f,unsigned count) {
    Matter_Im_Value_T v; OC_CHECK(matter_opcreds_read_session(f->o->core,3,1,true,&v)==0 && v.unsigned_value==count);
    OC_CHECK(matter_opcreds_read_session(f->o->core,2,1,true,&v)==0 && v.unsigned_value==5);
}
static void root_count(FabFixture* f,unsigned count) {
    Matter_Im_Value_T v; OC_CHECK(!matter_opcreds_read_fabric(f->o->core,4,1,false,&v));
    OC_CHECK(!matter_tlv_init(&f->reader,v.data,v.size,2));
    OC_CHECK(!matter_tlv_next(&f->reader,&f->e) && f->e.type==MATTER_TLV_ARRAY);
    unsigned seen=0;
    while(matter_tlv_next(&f->reader,&f->e)==MATTER_TLV_OK && f->e.type!=MATTER_TLV_END) {
        OC_CHECK(f->e.type==MATTER_TLV_BYTES && f->e.size && f->e.size<=400); ++seen;
    }
    OC_CHECK(f->e.type==MATTER_TLV_END && seen==count && matter_tlv_next(&f->reader,&f->e)==MATTER_TLV_DONE);
}
static void full_table_root(FabFixture* f) {
    const Matter_Fabric_View_T* v=f->port.view(f->host);
    Matter_Fabric_Record_T* saved=malloc(sizeof(v->records)); OC_CHECK(saved);
    memcpy(saved,v->records,sizeof(v->records));
    OC_CHECK(v->count==MATTER_FABRIC_CAPACITY && !v->root_ready);
    /* A distinct, independently signed test root must reach AddNOC, even when
     * every fabric slot is occupied. A broken signature still fails admission. */
    memcpy(f->changed,synthetic_root_tlv,sizeof(synthetic_root_tlv));
    f->changed[sizeof(synthetic_root_tlv)-2]^=1;
    fab_request(f,11,(Matter_Cert_Tlv_T){f->changed,sizeof(synthetic_root_tlv)},(Matter_Cert_Tlv_T){0},0);
    fab_call(f,1,11,true,MATTER_IM_INVALID_COMMAND,0);
    fab_request(f,11,FAB_CERT(synthetic_root_tlv),(Matter_Cert_Tlv_T){0},0);
    f->control.fail_store=true; matter_fabric_host_control(f->host,&f->control);
    fab_call(f,1,11,true,MATTER_IM_FAILURE,0);
    f->control.fail_store=false; matter_fabric_host_control(f->host,&f->control);
    OC_CHECK(!v->root_ready && !memcmp(saved,v->records,sizeof(v->records)));
    for(unsigned restart=0;restart<2;++restart) {
        fab_csr(f,23);
        fab_request(f,11,FAB_CERT(synthetic_root_tlv),(Matter_Cert_Tlv_T){0},0);
        fab_call(f,1,11,true,0,0); fab_call(f,1,11,true,0,0);
        Matter_Im_Value_T value;
        OC_CHECK(matter_opcreds_read_session(f->o->core,4,1,false,&value)==0);
        OC_CHECK(matter_tlv_init(&f->reader,value.data,value.size,2)==MATTER_TLV_OK);
        unsigned pending=0;
        while(matter_tlv_next(&f->reader,&f->e)==MATTER_TLV_OK)
            if(f->e.type==MATTER_TLV_BYTES && f->e.size==sizeof(synthetic_root_tlv) &&
                !memcmp(f->e.data,synthetic_root_tlv,f->e.size)) ++pending;
        OC_CHECK(pending==1);
        fab_request(f,11,FAB_CERT(fab_root),(Matter_Cert_Tlv_T){0},0);
        fab_call(f,1,11,true,MATTER_IM_CONSTRAINT_ERROR,0);
        fab_request(f,6,FAB_CERT(synthetic_noc_tlv),FAB_CERT(synthetic_icac_tlv),55);
        fab_call(f,1,6,true,0,5); /* TableFull, not IM ResourceExhausted. */
        OC_CHECK(v->root_ready && !v->added && !v->pending_index);
        OC_CHECK(matter_opcreds_rollback(f->o->core)==MATTER_OK);
        if(restart) {
            /* Leave a root-only journal for recovery; the failed AddNOC's CSR
             * is volatile and was explicitly discarded by the rollback above. */
            fab_request(f,11,FAB_CERT(synthetic_root_tlv),(Matter_Cert_Tlv_T){0},0);
            fab_call(f,1,11,true,0,0); fab_restart(f);
        }
        v=f->port.view(f->host); read_count(f,MATTER_FABRIC_CAPACITY);
        OC_CHECK(!v->root_ready && !v->root_size && !memcmp(saved,v->records,sizeof(v->records)));
        for(unsigned i=0;i<MATTER_FABRIC_CAPACITY;++i) {
            OC_CHECK(matter_fabric_host_sign(f->host,saved[i].index,f->ipk,sizeof(f->ipk),f->signature)==MATTER_OK);
            OC_CHECK(f->o->crypto.ecdsa_verify(f->o->crypto.user,saved[i].operational_public,
                f->ipk,sizeof(f->ipk),f->signature)==MATTER_OK);
        }
    }
    free(saved);
}
static uint8_t unused_validate(void* u,const void* ref,const Matter_Cluster_Request_T* q,const uint8_t* d,size_t n) {
    (void)u; (void)ref; (void)q; (void)d; (void)n; return MATTER_IM_INVALID_COMMAND;
}
static Matter_Result_T unused_start(void* u,const void* ref,const Matter_Cluster_Request_T* q,const uint8_t* d,size_t n,
    Matter_Tlv_Writer_T* w,Matter_Im_Command_Result_T* out,uint64_t* token) {
    (void)u; (void)ref; (void)q; (void)d; (void)n; (void)w;
    *out=(Matter_Im_Command_Result_T){.status=MATTER_IM_INVALID_COMMAND}; *token=0; return MATTER_OK;
}
static void profile_publication(FabFixture* f) {
    for(unsigned mode=0;mode<3;++mode) {
        Matter_Cluster_T c=matter_opcreds_new(&f->o->config.identity,&f->o->port); OC_CHECK(c);
        uint32_t before=matter_opcreds_version(c); Matter_Im_Command_T command;
        if(mode==0) {
            OC_CHECK(matter_cluster_retain(c)==MATTER_OK);
            OC_CHECK(matter_opcreds_attach_fabrics(c,f->model)==MATTER_INVALID_STATE);
            OC_CHECK(matter_cluster_attribute_count(c)==5 && matter_opcreds_version(c)==before);
            OC_CHECK(matter_cluster_release(c)==MATTER_OK);
        } else if(mode==1) {
            /* Occupied command capacity must not partially append the six attributes. */
            Matter_Command_Def_T collision={.id=11,.access={.privilege=MATTER_IM_ADMINISTER},.validate=unused_validate,.start=unused_start};
            OC_CHECK(matter_cluster_add_command(c,&collision)==MATTER_OK);
            OC_CHECK(matter_opcreds_attach_fabrics(c,f->model)==MATTER_LIMIT_REACHED);
            OC_CHECK(matter_cluster_attribute_count(c)==5 && matter_opcreds_version(c)==before);
            OC_CHECK(matter_cluster_command(c,6,&command)==MATTER_IM_UNSUPPORTED_COMMAND);
        } else {
            OC_CHECK(matter_opcreds_attach_fabrics(c,f->model)==MATTER_OK);
            OC_CHECK(matter_cluster_attribute_count(c)==11 && matter_cluster_command(c,6,&command)==0);
            OC_CHECK(matter_cluster_seal(c)==MATTER_OK && matter_cluster_delete(c)==MATTER_OK); continue;
        }
        OC_CHECK(matter_cluster_delete(c)==MATTER_OK);
    }
}
static void manage(FabFixture* f,uint8_t accessing,uint32_t cmd,const char* label,uint8_t target,uint8_t im,uint8_t noc) {
    OC_CHECK(matter_tlv_writer_init(&f->writer,f->args,sizeof(f->args),2)==MATTER_TLV_OK);
    fab_put(f,MATTER_TLV_STRUCTURE,-1,0,NULL,0);
    fab_put(f,cmd==9?MATTER_TLV_UTF8:MATTER_TLV_UNSIGNED,0,target,(const uint8_t*)label,label?strlen(label):0);
    fab_put(f,MATTER_TLV_END,-1,0,NULL,0); OC_CHECK(matter_tlv_writer_finish(&f->writer,&f->args_size)==MATTER_TLV_OK);
    Matter_Cluster_Request_T q={.session=77,.fabric=accessing,.is_case=true}; uint64_t token;
    OC_CHECK(matter_tlv_writer_init(&f->writer,f->response,sizeof(f->response),2)==MATTER_TLV_OK);
    OC_CHECK(matter_cluster_start(f->o->core,cmd,&q,f->args,f->args_size,&f->writer,&f->result,&token)==MATTER_OK && !token && f->result.status==im);
    if(!im) {
        OC_CHECK(matter_tlv_writer_finish(&f->writer,&f->response_size)==MATTER_TLV_OK);
        OC_CHECK(matter_tlv_init(&f->reader,f->response,f->response_size,2)==MATTER_TLV_OK);
        OC_CHECK(matter_tlv_next(&f->reader,&f->e)==MATTER_TLV_OK && matter_tlv_next(&f->reader,&f->e)==MATTER_TLV_OK && f->e.unsigned_value==noc);
    }
}
static void rollback_isolation(const Matter_Crypto_Port_T* crypto,const Matter_Credentials_Port_T* cp) {
    FabFixture* f=fab_new(crypto,cp);
    for(unsigned i=0;i<2;++i) {
        fab_csr(f,10+i); fab_request(f,11,FAB_CERT(fab_root),(Matter_Cert_Tlv_T){0},0); fab_call(f,1,11,true,0,0);
        fab_request(f,6,i?FAB_CERT(fab_noc1):FAB_CERT(fab_noc0),(Matter_Cert_Tlv_T){0},55); fab_call(f,1,6,true,0,0);
        if(!i) OC_CHECK(matter_fabric_host_commit(f->host)==MATTER_OK);
    }
    Matter_Case_Port_T cases=matter_fabric_host_case_port(f->host);
    Matter_Case_Fabric_T* snapshot=calloc(1,sizeof(*snapshot)); OC_CHECK(snapshot && cases.load(cases.user,0,snapshot)==MATTER_OK);
    FabricSub* sub=fs_new(f,false); fs_report(sub,true);
    OC_CHECK(matter_opcreds_pending_fabric(f->o->core)==2 && matter_opcreds_rollback(f->o->core)==MATTER_OK);
    fs_update(sub); OC_CHECK(!matter_im_subscribe_delete(sub->sub)); free(sub);
    OC_CHECK(f->port.view(f->host)->count==1 && cases.valid(cases.user,1,snapshot->revision)==MATTER_OK);
    OC_CHECK(matter_fabric_host_sign(f->host,1,f->ipk,16,f->signature)==MATTER_OK && matter_fabric_host_sign(f->host,2,f->ipk,16,f->signature)==MATTER_INVALID_STATE);
    free(snapshot); fab_free(f);
    puts("PASS pending fabric rollback preserves another fabric and its CASE snapshot");
}
/* Exercise the SAME generic validation/start/poll path as the host. Legacy
 * matter_opcreds_start is PASE-only and cannot catch CASE adapter restrictions. */
static void case_call(FabFixture* f,uint32_t cmd,bool armed,uint8_t im,uint8_t noc) {
    Matter_Cluster_Request_T q={.session=1,.fabric=1,.is_case=true,.armed=armed};
    OC_CHECK(matter_tlv_writer_init(&f->writer,f->response,sizeof(f->response),3)==MATTER_TLV_OK);
    Matter_Result_T r=matter_cluster_start(f->o->core,cmd,&q,f->args,f->args_size,
        cmd==11?NULL:&f->writer,&f->result,&f->token);
    for(unsigned i=0;i<8 && r==MATTER_PENDING;++i) {
        Matter_Result_T step=matter_cluster_process(f->o->core,0);
        OC_CHECK(step==MATTER_OK || step==MATTER_PENDING);
        r=matter_cluster_poll(f->o->core,f->token,cmd==11?NULL:&f->writer,&f->result);
    }
    OC_CHECK(r==MATTER_OK && f->result.status==im);
    if(!im && cmd==6) {
        OC_CHECK(matter_tlv_writer_finish(&f->writer,&f->response_size)==MATTER_TLV_OK);
        OC_CHECK(matter_tlv_init(&f->reader,f->response,f->response_size,2)==MATTER_TLV_OK);
        OC_CHECK(matter_tlv_next(&f->reader,&f->e)==MATTER_TLV_OK &&
            matter_tlv_next(&f->reader,&f->e)==MATTER_TLV_OK && f->e.unsigned_value==noc);
    }
}
static void case_addition(const Matter_Crypto_Port_T* crypto,const Matter_Credentials_Port_T* cp) {
    FabFixture* f=fab_new(crypto,cp);
    fab_csr(f,10); fab_request(f,11,FAB_CERT(fab_root),(Matter_Cert_Tlv_T){0},0); fab_call(f,1,11,true,0,0);
    fab_request(f,6,FAB_CERT(fab_noc0),(Matter_Cert_Tlv_T){0},55); fab_call(f,1,6,true,0,0);
    OC_CHECK(matter_fabric_host_commit(f->host)==MATTER_OK);
    OC_CHECK(matter_fabric_host_commit_ready(f->host,1)==MATTER_OK);
    OC_CHECK(matter_fabric_host_commit_ready(f->host,2)==MATTER_INVALID_STATE);
    OC_CHECK(matter_fabric_host_commit(f->host)==MATTER_INVALID_STATE); /* No second credential commit. */
    fab_request(f,11,FAB_CERT(fab_root),(Matter_Cert_Tlv_T){0},0);
    case_call(f,11,false,0xca,0); /* Fail-safe remains required through CASE. */
    fab_request(f,11,(Matter_Cert_Tlv_T){fab_root,sizeof(fab_root)-1},(Matter_Cert_Tlv_T){0},0);
    case_call(f,11,true,MATTER_IM_INVALID_COMMAND,0);
    fab_request(f,11,FAB_CERT(fab_root),(Matter_Cert_Tlv_T){0},0);
    f->control.fail_store=true; matter_fabric_host_control(f->host,&f->control);
    case_call(f,11,true,MATTER_IM_FAILURE,0);
    OC_CHECK(!f->port.view(f->host)->root_ready && f->port.view(f->host)->count==1);
    f->control.fail_store=false; matter_fabric_host_control(f->host,&f->control);
    uint32_t before_root=f->port.view(f->host)->revision;
    case_call(f,11,true,0,0);
    OC_CHECK(f->port.view(f->host)->revision==before_root+(MATTER_CSA_COMPAT_PENDING_ROOT?1u:0u));
    case_call(f,11,true,0,0);
    OC_CHECK(f->port.view(f->host)->revision==before_root+(MATTER_CSA_COMPAT_PENDING_ROOT?1u:0u));
    /* Core 11.18.6.13 suppresses the identical pending RCAC. The explicit
     * compatibility profile exposes it once, advancing its data version once. */
    Matter_Im_Value_T roots;
    OC_CHECK(matter_opcreds_read_fabric(f->o->core,4,1,false,&roots)==0);
    OC_CHECK(matter_tlv_init(&f->reader,roots.data,roots.size,2)==MATTER_TLV_OK &&
        matter_tlv_next(&f->reader,&f->e)==MATTER_TLV_OK && f->e.type==MATTER_TLV_ARRAY &&
        matter_tlv_next(&f->reader,&f->e)==MATTER_TLV_OK && f->e.type==MATTER_TLV_BYTES &&
        f->e.size==sizeof(fab_root) && !memcmp(f->e.data,fab_root,sizeof(fab_root)));
    if(MATTER_CSA_COMPAT_PENDING_ROOT)
        OC_CHECK(matter_tlv_next(&f->reader,&f->e)==MATTER_TLV_OK && f->e.type==MATTER_TLV_BYTES &&
            f->e.size==sizeof(fab_root) && !memcmp(f->e.data,fab_root,sizeof(fab_root)));
    OC_CHECK(matter_tlv_next(&f->reader,&f->e)==MATTER_TLV_OK && f->e.type==MATTER_TLV_END &&
        matter_tlv_next(&f->reader,&f->e)==MATTER_TLV_DONE);
    fab_request(f,6,FAB_CERT(fab_noc1),(Matter_Cert_Tlv_T){0},55);
    case_call(f,6,false,0xca,0); case_call(f,6,true,0,4); /* Missing CSR. */
    fab_scalar_value=11; oc_request(f->o,4,0,32,false);
    memcpy(f->args,f->o->request,f->o->request_size); f->args_size=f->o->request_size;
    case_call(f,4,true,0,0);
    memcpy(f->changed,fab_noc1,sizeof(fab_noc1)); f->changed[sizeof(fab_noc1)-2]^=1;
    fab_request(f,6,(Matter_Cert_Tlv_T){f->changed,sizeof(fab_noc1)},(Matter_Cert_Tlv_T){0},55);
    case_call(f,6,true,0,3); /* Signature validation is still mandatory. */
    OC_CHECK(f->port.view(f->host)->count==1);
    fab_request(f,6,FAB_CERT(fab_noc1),(Matter_Cert_Tlv_T){0},55); case_call(f,6,true,0,0);
    OC_CHECK(f->port.view(f->host)->count==2 && matter_opcreds_pending_fabric(f->o->core)==2);
    root_count(f,2); /* AddNOC consumed the staged root: no extra pending copy. */
    OC_CHECK(matter_opcreds_rollback(f->o->core)==MATTER_OK && f->port.view(f->host)->count==1);
    root_count(f,1);
    fab_free(f);
    puts("PASS generic CASE AddRoot/AddNOC: failsafe, malformed root, storage error, CSR, signature, addition and rollback");
}
typedef struct { uint64_t high; unsigned count,mask; } RemovalLog;
static Matter_Result_T removal_load(void* u,uint64_t* n) { *n=((RemovalLog*)u)->high; return MATTER_OK; }
static Matter_Result_T removal_store(void* u,uint64_t n) { ((RemovalLog*)u)->high=n; return MATTER_OK; }
static Matter_Result_T removal_admin(void* u,Matter_Exchange_Session_T s,Matter_Cluster_Request_T* q) {
    (void)u; (void)s; (void)q; return MATTER_INVALID_STATE;
}
static void removal_notice(void* u,uint8_t index) {
    RemovalLog* log=u; OC_CHECK(index>=1 && index<=5);
    OC_CHECK(!(log->mask&(1u<<index))); log->mask|=1u<<index; ++log->count;
}
static void management(FabFixture* f) {
    RemovalLog notices={0}; Matter_Events_Port_T ep={&notices,removal_load,removal_store};
    Matter_Events_T events=matter_events_new(&ep); OC_CHECK(events);
    Matter_Acl_Port_T acl_port=matter_fabric_host_acl_port(f->host); Matter_Acl_T acl=matter_acl_new(&acl_port); OC_CHECK(acl);
    Matter_Fabric_Host_Events_T hooks={acl,events,&notices,removal_admin,removal_notice};
    OC_CHECK(matter_fabric_host_bind_events(f->host,&hooks)==MATTER_OK);
    const Matter_Fabric_View_T* v=f->port.view(f->host); uint32_t version=v->revision;
    OC_CHECK(f->port.remove(f->host,0)==MATTER_INVALID_ARGUMENT && f->port.remove(f->host,255)==MATTER_INVALID_ARGUMENT);
    OC_CHECK(f->port.label(f->host,0,NULL,0)==MATTER_INVALID_ARGUMENT && f->port.label(f->host,1,NULL,1)==MATTER_INVALID_ARGUMENT && v->count==5);
    OC_CHECK(f->port.label(f->host,1,NULL,0)==MATTER_OK && v->revision==version);
    manage(f,1,9,"alpha",0,0,0); OC_CHECK(v->revision==version+1 && v->records[0].label_size==5);
    manage(f,1,9,"alpha",0,0,0); OC_CHECK(v->revision==version+1);
    manage(f,2,9,"alpha",0,0,10); OC_CHECK(!v->records[1].label_size && v->revision==version+1);
    manage(f,1,9,"",0,0,10); /* Other initial empty labels conflict, too. */
    manage(f,1,9,"12345678901234567890123456789012",0,0,0);
    manage(f,1,9,"123456789012345678901234567890123",0,MATTER_IM_CONSTRAINT_ERROR,0);
    manage(f,0,9,"none",0,MATTER_IM_INVALID_COMMAND,0);
    manage(f,1,10,NULL,0,MATTER_IM_CONSTRAINT_ERROR,0);
    manage(f,1,10,NULL,254,0,11); OC_CHECK(v->count==5);
    f->control.fail_store=true; matter_fabric_host_control(f->host,&f->control);
    version=v->revision;
    manage(f,1,9,"not stored",0,MATTER_IM_FAILURE,0);
    manage(f,1,10,NULL,2,MATTER_IM_FAILURE,0); OC_CHECK(v->count==5 && v->revision==version);
    OC_CHECK(!notices.count); /* Invalid indexes, label changes and failed removal. */
    f->control.fail_store=false; matter_fabric_host_control(f->host,&f->control);
    Matter_Case_Port_T cp=matter_fabric_host_case_port(f->host);
    Matter_Case_Fabric_T* snapshot=calloc(1,sizeof(*snapshot)); OC_CHECK(snapshot && cp.load(cp.user,2,snapshot)==MATTER_OK);
    manage(f,1,10,NULL,2,0,0); OC_CHECK(v->count==4 && !v->records[1].index);
    OC_CHECK(notices.count==1 && notices.mask==(1u<<2));
    OC_CHECK(cp.valid(cp.user,snapshot->index,snapshot->revision)==MATTER_OK); free(snapshot);
    Matter_Acl_Port_T ap=matter_fabric_host_acl_port(f->host); Matter_Groupkey_Port_T gp=matter_fabric_host_groupkey_port(f->host);
    OC_CHECK(!ap.view(ap.user)->fabrics[1].index && !gp.view(gp.user)->fabrics[1].index);
    OC_CHECK(matter_fabric_host_sign(f->host,2,f->ipk,16,f->signature)==MATTER_INVALID_STATE);
    OC_CHECK(matter_fabric_host_sign(f->host,3,f->ipk,16,f->signature)==MATTER_OK);
    manage(f,1,10,NULL,1,0,0); manage(f,3,10,NULL,3,0,0); manage(f,4,10,NULL,4,0,0);
    manage(f,5,9,"",0,0,0); manage(f,5,10,NULL,5,0,0); OC_CHECK(!v->count && !v->root_ready);
    OC_CHECK(notices.count==5 && notices.mask==0x3e);
    /* Drain the borrowing host while its event/notification ports are alive. */
    fab_free(f);
    OC_CHECK(matter_acl_delete(acl)==MATTER_OK && matter_events_delete(events)==MATTER_OK);
    puts("PASS fabric management: label bounds/idempotence/conflict, NOC statuses, failed store unchanged, selective keys/ACL/GKM/CASE invalidation, self/last removal");
}
static void vid_export(FabFixture* f,const char* prefix) {
    if(!prefix) return;
    size_t cap=strlen(prefix)+40; char* path=calloc(cap,1); OC_CHECK(path);
    for(unsigned mode=0;mode<2;++mode) {
        vid_request(f,2,0,mode?85:0,0); vid_call(f,2,12,0);
        vid_sign_request(f,2,32); vid_call(f,1,13,0); vid_verify(f,1);
        if(mode) f->wire[210]^=1; /* Undo the negative verification mutation. */
        const Matter_Fabric_Record_T* r=&f->port.view(f->host)->records[1];
        const char* names[]={"tbs","signature","public"};
        const uint8_t* data[]={f->wire,f->signature,r->operational_public};
        size_t sizes[]={mode?211u:126u,64,65};
        for(unsigned i=0;i<3;++i) {
            snprintf(path,cap,"%s-%s-%s.bin",prefix,mode?"statement":"plain",names[i]);
            FILE* out=fopen(path,"wb"); OC_CHECK(out);
            OC_CHECK(fwrite(data[i],1,sizes[i],out)==sizes[i] && fclose(out)==0);
        }
    }
    vid_request(f,2,0,0,0); vid_call(f,2,12,0); free(path);
}
int main(int argc,char** argv) {
    OC_CHECK(argc<=2);
    Matter_Crypto_Mbedtls_T backend=matter_crypto_mbedtls_new(NULL); OC_CHECK(backend);
    Matter_Crypto_Port_T crypto; Matter_Credentials_Port_T cp;
    OC_CHECK(matter_crypto_mbedtls_port(backend,&crypto)==MATTER_OK && matter_crypto_mbedtls_credentials(backend,&cp)==MATTER_OK);
    OcFixture* legacy=oc_new(&crypto,&cp); oc_free(legacy);
    FabFixture* f=fab_new(&crypto,&cp); read_count(f,0);
    profile_publication(f);
    case_addition(&crypto,&cp);
    f->o->session_user=f->o; f->o->session_challenge=two_sessions;
    /* No root in THIS fail-safe, malformed root and schema failures have no effects. */
    fab_csr(f,10); fab_request(f,6,FAB_CERT(fab_noc0),(Matter_Cert_Tlv_T){0},55); fab_call(f,1,6,true,0,3);
    OC_CHECK(matter_opcreds_rollback(f->o->core)==MATTER_OK);
    fab_request(f,11,(Matter_Cert_Tlv_T){fab_root,sizeof(fab_root)-1},(Matter_Cert_Tlv_T){0},0);
    fab_call(f,1,11,true,MATTER_IM_INVALID_COMMAND,0);
    /* A well-formed RCAC with a corrupted self-signature is rejected before
     * any fail-safe journal/root/revision change; a valid retry still works. */
    uint32_t root_revision=f->port.view(f->host)->revision;
    memcpy(f->changed,fab_root,sizeof(fab_root)); f->changed[sizeof(fab_root)-2]^=1;
    fab_request(f,11,(Matter_Cert_Tlv_T){f->changed,sizeof(fab_root)},(Matter_Cert_Tlv_T){0},0);
    fab_call(f,1,11,true,MATTER_IM_INVALID_COMMAND,0);
    OC_CHECK(!f->port.view(f->host)->root_ready && !f->port.view(f->host)->count &&
        f->port.view(f->host)->revision==root_revision);
    memset(f->wire,0,401); fab_request(f,11,(Matter_Cert_Tlv_T){f->wire,401},(Matter_Cert_Tlv_T){0},0);
    fab_call(f,1,11,true,MATTER_IM_INVALID_COMMAND,0);
    fab_request(f,6,FAB_CERT(fab_noc0),(Matter_Cert_Tlv_T){0},55);
    OC_CHECK(matter_tlv_init(&f->reader,f->args,f->args_size,3)==MATTER_TLV_OK);
    while(matter_tlv_next(&f->reader,&f->e)==MATTER_TLV_OK) if(f->e.type==MATTER_TLV_BYTES && f->e.tag.number==2) break;
    f->args[f->e.offset]=0x2c; /* IPK encoded as text. */ fab_call(f,1,6,true,MATTER_IM_INVALID_COMMAND,0);
    OC_CHECK(!f->port.view(f->host)->root_ready && !f->port.view(f->host)->count);
    fab_request(f,11,FAB_CERT(fab_root),(Matter_Cert_Tlv_T){0},0); fab_call(f,1,11,false,0xca,0);
    fab_call(f,1,11,true,0,0); uint32_t revision=matter_opcreds_version(f->o->core);
    fab_call(f,1,11,true,0,0); OC_CHECK(matter_opcreds_version(f->o->core)==revision);
    memcpy(f->changed,fab_root,sizeof(fab_root)); f->changed[10]^=1;
    fab_request(f,11,(Matter_Cert_Tlv_T){f->changed,sizeof(fab_root)},(Matter_Cert_Tlv_T){0},0); fab_call(f,1,11,true,MATTER_IM_CONSTRAINT_ERROR,0);
    fab_request(f,6,FAB_CERT(fab_noc0),(Matter_Cert_Tlv_T){0},55); fab_call(f,1,6,false,0xca,0); fab_call(f,1,6,true,0,4);
    fab_csr(f,10); fab_call(f,2,6,true,0,4); /* Same key cannot be claimed by another session. */
    f->o->challenge[0]^=1; fab_call(f,1,6,true,0,4); f->o->challenge[0]^=1; /* Reused token, different incarnation. */
    for(unsigned bad=0;bad<5;++bad) {
        Matter_Cert_Tlv_T cert=bad==0?FAB_CERT(fab_noc1):bad==1?FAB_CERT(fab_invalid_node):bad==2?FAB_CERT(fab_invalid_fabric):FAB_CERT(fab_noc0);
        if(bad==3) { memcpy(f->changed,fab_noc0,sizeof(fab_noc0)); f->changed[sizeof(fab_noc0)-2]^=1; cert=(Matter_Cert_Tlv_T){f->changed,sizeof(fab_noc0)}; }
        fab_request(f,6,cert,(Matter_Cert_Tlv_T){0},bad==4?0:55); fab_call(f,1,6,true,0,bad==0?1:bad==1?2:bad==4?6:3);
        read_count(f,0); OC_CHECK(matter_opcreds_host_candidate(f->o->host,f->o->candidate)==MATTER_OK);
    }
    for(unsigned fault=0;fault<3;++fault) {
        f->control=(Matter_Fabric_Host_Control_T){.fail_store=fault==0,.fail_acl=fault==1,.fail_discovery=fault==2}; matter_fabric_host_control(f->host,&f->control);
        fab_request(f,6,FAB_CERT(fab_noc0),(Matter_Cert_Tlv_T){0},55); fab_call(f,1,6,true,MATTER_IM_FAILURE,0); read_count(f,0);
    }
    f->control=(Matter_Fabric_Host_Control_T){0}; matter_fabric_host_control(f->host,&f->control);
#ifdef MATTER_TEST_ALLOC
    fail_at=calls+1; fab_call(f,1,6,true,0,3); fail_at=0; read_count(f,0);
#endif
    FabFixture* independent=fab_new(&crypto,&cp); read_count(independent,0);
    fab_call(f,1,6,true,0,0); read_count(f,1); read_count(independent,0); fab_free(independent);
    OC_CHECK(matter_opcreds_fabric_index(f->o->core,1)==1 && !matter_opcreds_fabric_index(f->o->core,2) && matter_opcreds_pending_fabric(f->o->core)==1);
    OC_CHECK(matter_opcreds_host_candidate(f->o->host,f->o->candidate)==MATTER_INVALID_STATE);
    Matter_Groupkey_Port_T gp=matter_fabric_host_groupkey_port(f->host);
    OC_CHECK(gp.view(gp.user)->fabrics[0].sets[0].count==1 && gp.view(gp.user)->fabrics[0].sets[0].times[0]==0);
    OC_CHECK(matter_fabric_host_case_authorize(f->host,1,55,NULL,0,MATTER_IM_ADMINISTER));
    OC_CHECK(!matter_fabric_host_case_authorize(f->host,1,56,NULL,0,MATTER_IM_ADMINISTER));
    const Matter_Fabric_View_T* view=f->port.view(f->host);
    /* Independent Python hashlib/HMAC HKDF: root scalar8, FabricID1, NodeID100. */
    OC_CHECK(!strcmp(view->records[0].discovery_instance,"A046E5722F80993D-0000000000000064"));
    OC_CHECK(matter_fabric_host_sign(f->host,1,f->ipk,16,f->signature)==MATTER_OK && crypto.ecdsa_verify(crypto.user,view->records[0].operational_public,f->ipk,16,f->signature)==MATTER_OK);
    fab_call(f,1,6,true,MATTER_IM_CONSTRAINT_ERROR,0); oc_request(f->o,4,0,32,false);
    OC_CHECK(oc_start(f->o,4,true)==MATTER_OK && f->o->result.status==MATTER_IM_CONSTRAINT_ERROR);
    f->control.fail_rollback=true; matter_fabric_host_control(f->host,&f->control);
    OC_CHECK(matter_opcreds_rollback(f->o->core)==MATTER_PORT_ERROR); read_count(f,1);
    f->control.fail_rollback=false; matter_fabric_host_control(f->host,&f->control);
    fab_restart(f); read_count(f,0); /* Journal recovery removes keys/IPK/ACL/discovery. */
    Matter_Acl_Port_T acl=matter_fabric_host_acl_port(f->host);
    for(unsigned j=0;j<MATTER_ACL_FABRICS;++j) OC_CHECK(!acl.view(acl.user)->fabrics[j].index);
    OC_CHECK(matter_fabric_host_sign(f->host,1,f->ipk,16,f->signature)==MATTER_INVALID_STATE);
    /* Commit is a local harness operation, NOT a successful wire commissioning. */
    const Matter_Cert_Tlv_T certs[]={FAB_CERT(fab_noc0),FAB_CERT(fab_noc1),FAB_CERT(fab_noc2),FAB_CERT(fab_noc3),FAB_CERT(fab_noc4)};
    for(unsigned j=0;j<5;++j) {
        fab_csr(f,10+j); fab_request(f,11,FAB_CERT(fab_root),(Matter_Cert_Tlv_T){0},0); fab_call(f,1,11,true,0,0);
        if(j==1) { fab_request(f,6,FAB_CERT(fab_conflict),(Matter_Cert_Tlv_T){0},55); fab_call(f,1,6,true,0,9); }
        fab_request(f,6,certs[j],(Matter_Cert_Tlv_T){0},UINT64_C(0xfffffffd00010002)); fab_call(f,1,6,true,0,0);
        OC_CHECK(matter_opcreds_fabric_index(f->o->core,1)==j+1 && matter_fabric_host_commit(f->host)==MATTER_OK); read_count(f,j+1);
    }
    /* Commit revokes the temporary PASE association. Trusted CASE identity supplies
     * the fabric index for operational reads (wire ACL is checked by its adapter). */
    Matter_Im_Value_T v; OC_CHECK(!matter_opcreds_fabric_index(f->o->core,1));
    /* Core 7.19.1.8.2: unfiltered reads include all entries even before a PASE
     * session has an accessing fabric; filtered reads then have no matches. */
    OC_CHECK(matter_opcreds_read_session(f->o->core,0,1,false,&v)==0 && v.size>1000);
    OC_CHECK(matter_opcreds_read_session(f->o->core,1,1,false,&v)==0 && v.size>200);
    for(unsigned attr=0;attr<2;++attr) {
        OC_CHECK(matter_opcreds_read_session(f->o->core,attr,1,true,&v)==0);
        OC_CHECK(v.type==MATTER_TLV_ARRAY && v.size==2 && v.data[0]==0x16 && v.data[1]==0x18);
    }
    OC_CHECK(matter_opcreds_read_fabric(f->o->core,0,5,false,&v)==0 && v.size>1000);
    OC_CHECK(matter_opcreds_read_fabric(f->o->core,1,5,true,&v)==0 && v.size<200);
    uint32_t cat=0x00010003; OC_CHECK(matter_fabric_host_case_authorize(f->host,5,99,&cat,1,MATTER_IM_ADMINISTER)); cat=0x00010001;
    OC_CHECK(!matter_fabric_host_case_authorize(f->host,5,99,&cat,1,MATTER_IM_ADMINISTER));
    fab_csr(f,15); fab_request(f,11,FAB_CERT(fab_root),(Matter_Cert_Tlv_T){0},0); fab_call(f,1,11,true,0,0);
    fab_request(f,6,FAB_CERT(fab_noc5),(Matter_Cert_Tlv_T){0},55); fab_call(f,1,6,true,0,5);
    OC_CHECK(matter_opcreds_rollback(f->o->core)==MATTER_OK); fab_restart(f); read_count(f,5);
    full_table_root(f);
    /* Installed-key collision fails CSR without changing the persistent store. */
    fab_scalar_value=10; oc_request(f->o,4,0,32,false); OC_CHECK(oc_start(f->o,4,true)==MATTER_PENDING); oc_finish(f->o); OC_CHECK(f->o->result.status==MATTER_IM_FAILURE);
    vid_checks(f); vid_export(f,argc==2?argv[1]:NULL); fabric_subscriptions(f); management(f); rollback_isolation(&crypto,&cp);
    f=fab_new(&crypto,&cp); fab_csr(f,16); fab_request(f,11,FAB_CERT(fab_root),(Matter_Cert_Tlv_T){0},0); fab_call(f,1,11,true,0,0);
    fab_request(f,6,FAB_CERT(fab_noc6),FAB_CERT(fab_icac),55); fab_call(f,1,6,true,0,0); read_count(f,1);
    vid_request(f,5,0x6a01,0,0); vid_call(f,1,12,MATTER_IM_INVALID_COMMAND);
    OC_CHECK(f->port.view(f->host)->records[0].vendor==0xfff1);
    fab_free(f);
    OC_CHECK(matter_crypto_mbedtls_delete(backend)==MATTER_OK);
#ifdef MATTER_TEST_ALLOC
    OC_CHECK(!live);
#endif
    puts("PASS fabrics: independent NOC chains, session/key matching, atomic IPK/ACL/discovery, gates, capacity, conflict, rollback and restart"); return 0;
}

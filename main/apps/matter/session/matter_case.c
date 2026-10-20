#include "matter_case.h"
#include "matter_handshake_buffer_internal.h"
#include "matter_secure_internal.h"
#include "../codec/matter_tlv_writer.h"
#include "../codec/matter_tlv_validate.h"
#include <stdlib.h>
#include <string.h>
enum { START, SIGMA1, SIGMA2, SIGMA3, FINISH, COMPLETE, FAILED };
enum { CASE_PAYLOAD=MATTER_CASE_MAX_PAYLOAD, CASE_TRANSCRIPT=3*MATTER_CASE_MAX_PAYLOAD };
typedef struct {
    Matter_Tlv_Reader_T reader; Matter_Tlv_Writer_T writer; Matter_Tlv_Element_T e,fields[8],inner[5],sub[10];
    Matter_Tlv_Validation_Workspace_T validation; Matter_Tlv_Tag_T tags[64];
    uint8_t mic[16];
} Matter_Case_Work;
typedef struct { uint8_t work[CASE_PAYLOAD],plain[CASE_PAYLOAD],cipher[CASE_PAYLOAD]; } Matter_Case_Sigma;
struct Matter_Case {
    Matter_Crypto_Port_T crypto; Matter_Credentials_Port_T credentials; Matter_Case_Port_T port;
    Matter_Case_Config_T config; Matter_Case_Fabric_T fabric; Matter_Case_Keys_T keys;
    Matter_Operational_Identity_T peer; Matter_Case_Resumption_T resumption;
    bool resume_attempt;
    unsigned phase, after_send; bool busy,queued,output,transferred,confirmed;
    uint64_t now,deadline; uint8_t in_opcode,out_opcode;
    size_t in_size,out_size,transcript_size,work_size,plain_size;
    uint8_t *in,*out,*transcript; size_t out_capacity,transcript_capacity;
    uint8_t status[8]; Matter_Case_Work* workspace; Matter_Case_Sigma* scratch;
    uint8_t secret[32],public_key[65],peer_key[65],shared[32],random[32],resume[16],signature[64];
    uint8_t salt[145],digest[32],derived[48],key[16];

};
static void erase(void* p,size_t n) { volatile uint8_t* b=p; while(n--) *b++=0; }
static Matter_Result_T check(Matter_Case_T s) { return !s?MATTER_INVALID_ARGUMENT:s->busy?MATTER_BUSY:MATTER_OK; }
Matter_Result_T matter_case_ipk(const Matter_Crypto_Port_T* p,const uint8_t epoch[16],const uint8_t compressed[8],uint8_t out[16]) {
    if(!p || !p->hkdf_sha256 || !epoch || !compressed || !out) return MATTER_INVALID_ARGUMENT;
    return p->hkdf_sha256(p->user,epoch,16,compressed,8,(const uint8_t*)"GroupKey v1.0",13,out,16);
}
Matter_Result_T matter_case_destination(const Matter_Crypto_Port_T* p,const uint8_t ipk[16],const uint8_t random[32],
    const uint8_t root[65],uint64_t fabric,uint64_t node,uint8_t out[32]) {
    if(!p || !p->hmac_sha256 || !ipk || !random || !root || !out || !fabric || !node || node>UINT64_C(0xffffffefffffffff)) return MATTER_INVALID_ARGUMENT;
    uint8_t message[113]; memcpy(message,random,32); memcpy(message+32,root,65);
    for(unsigned i=0;i<8;++i) { message[97+i]=(uint8_t)(fabric>>(8*i)); message[105+i]=(uint8_t)(node>>(8*i)); }
    Matter_Result_T r=p->hmac_sha256(p->user,ipk,16,message,sizeof(message),out); erase(message,sizeof(message)); return r;
}
static void secrets(Matter_Case_T s) {
    erase(s->secret,32); erase(s->shared,32); erase(s->fabric.ipk,16); erase(s->key,16); erase(s->derived,48);
    erase(s->salt,sizeof(s->salt));
    matter_handshake_clear(&s->transcript,&s->transcript_capacity); s->transcript_size=0;
    matter_handshake_delete(s->scratch,sizeof(*s->scratch)); s->scratch=NULL;
}
static void failure(Matter_Case_T s,unsigned code,bool report) {
    secrets(s); erase(&s->resumption,sizeof(s->resumption)); erase(&s->keys,sizeof(s->keys)); matter_handshake_clear(&s->in,&s->in_size);
    matter_handshake_clear(&s->out,&s->out_capacity);
    s->phase=FAILED; s->queued=false; s->output=report; s->out_size=0;
    if(report) { memset(s->status,0,8); s->status[0]=1; s->status[6]=(uint8_t)code; s->out_size=8; s->out_opcode=0x40; s->after_send=FAILED; }
}
Matter_Case_T matter_case_new(const Matter_Crypto_Port_T* p,const Matter_Credentials_Port_T* cp,
    const Matter_Case_Port_T* port,const Matter_Case_Config_T* c,uint64_t now) {
    if(!p || !cp || !cp->cert_verify_chain || !port || !port->load || !port->valid || !port->sign || !port->capacity ||
        (!!port->resume_find!=!!port->resume_save) ||
        !c || (c->resumption_profile!=MATTER_CASE_RESUMPTION_SPEC && c->resumption_profile!=MATTER_CASE_RESUMPTION_CHIP) || !c->local_session_id || !c->timeout_ms || c->time.mode!=MATTER_CERT_TIME_SUPPLIED ||
        (!c->responder && (!c->fabric_index || c->fabric_index==255 || !c->peer_node_id || c->peer_node_id>UINT64_C(0xffffffefffffffff))) ||
        !p->random || !p->sha256 || !p->hmac_sha256 || !p->hkdf_sha256 || !p->p256_scalar || !p->p256_base ||
        !p->ecdh || !p->ecdsa_verify || !p->ccm_encrypt || !p->ccm_decrypt || !p->equal) return NULL;
    Matter_Case_T s=calloc(1,sizeof(*s)); if(!s) return NULL;
    s->crypto=*p; s->credentials=*cp; s->port=*port; s->config=*c; s->phase=c->responder?SIGMA1:START;
    s->now=now; s->deadline=UINT64_MAX-now<c->timeout_ms?UINT64_MAX:now+c->timeout_ms;
    s->keys.traffic.local_session_id=c->local_session_id; s->keys.traffic.peer_intervals=(Matter_Pase_Intervals_T){500,300,4000}; return s;
}
static bool selected(Matter_Case_T s) { return !s->fabric.index || s->port.valid(s->port.user,s->fabric.index,s->fabric.revision)==MATTER_OK; }
uint8_t matter_case_fabric_index(Matter_Case_T s) { return s?s->fabric.index:0; }
static Matter_Result_T load(Matter_Case_T s,unsigned slot) {
    erase(&s->fabric,sizeof(s->fabric));
    Matter_Result_T r=s->port.load(s->port.user,slot,&s->fabric); if(r!=MATTER_OK) return r;
    return s->fabric.index && s->fabric.index!=255 && s->fabric.fabric_id && s->fabric.node_id &&
        s->fabric.noc_size && s->fabric.noc_size<=400 && s->fabric.icac_size<=400 && s->fabric.root_size && s->fabric.root_size<=400?MATTER_OK:MATTER_PORT_ERROR;
}
static bool fields(Matter_Case_T s,Matter_Tlv_Element_T* out,size_t n) {
    memset(out,0,n*sizeof(*out)); bool seen=false; uint32_t last=0;
    while(matter_tlv_next(&s->workspace->reader,&s->workspace->e)==MATTER_TLV_OK) {
        if(s->workspace->e.type==MATTER_TLV_END) return true;
        if(s->workspace->e.tag.control!=1 || (seen && s->workspace->e.tag.number<=last)) return false;
        seen=true; last=s->workspace->e.tag.number; if(last<n) out[last]=s->workspace->e;
        if((s->workspace->e.type==MATTER_TLV_STRUCTURE || s->workspace->e.type==MATTER_TLV_ARRAY || s->workspace->e.type==MATTER_TLV_LIST) &&
            matter_tlv_skip_container(&s->workspace->reader)!=MATTER_TLV_OK) return false;
    }
    return false;
}
static bool decode(Matter_Case_T s,const uint8_t* p,size_t n,Matter_Tlv_Element_T* out,size_t count) {
    const Matter_Tlv_Validation_Options_T opt={1200,128,2400,8,false,0,0}; Matter_Tlv_Validation_Report_T report;
    return matter_tlv_validate(p,n,&opt,&s->workspace->validation,s->workspace->tags,64,&report)==MATTER_TLV_OK &&
        matter_tlv_init(&s->workspace->reader,p,n,8)==MATTER_TLV_OK && matter_tlv_next(&s->workspace->reader,&s->workspace->e)==MATTER_TLV_OK &&
        s->workspace->e.type==MATTER_TLV_STRUCTURE && !s->workspace->e.tag.control && fields(s,out,count) && matter_tlv_next(&s->workspace->reader,&s->workspace->e)==MATTER_TLV_DONE;
}
static bool bytes(const Matter_Tlv_Element_T* e,size_t min,size_t max) { return e->tag.control && e->type==MATTER_TLV_BYTES && e->size>=min && e->size<=max; }
static bool number(const Matter_Tlv_Element_T* e,uint64_t max) { return e->tag.control && e->type==MATTER_TLV_UNSIGNED && e->unsigned_value<=max; }
static bool intervals(Matter_Case_T s,unsigned tag) {
    if(!s->workspace->fields[tag].tag.control) return true;
    if(s->workspace->fields[tag].type!=MATTER_TLV_STRUCTURE || matter_tlv_init(&s->workspace->reader,s->in,s->in_size,8)!=MATTER_TLV_OK) return false;
    do { if(matter_tlv_next(&s->workspace->reader,&s->workspace->e)!=MATTER_TLV_OK) return false; } while(s->workspace->e.offset!=s->workspace->fields[tag].offset);
    if(!fields(s,s->workspace->sub,10)) return false;
    for(unsigned i=1;i<10;++i) if(s->workspace->sub[i].tag.control && !number(&s->workspace->sub[i],i==1 || i==2 || i==6 || i==9?UINT32_MAX:UINT16_MAX)) return false;
    if(s->workspace->sub[1].tag.control) s->keys.traffic.peer_intervals.idle_ms=(uint32_t)s->workspace->sub[1].unsigned_value;
    if(s->workspace->sub[2].tag.control) s->keys.traffic.peer_intervals.active_ms=(uint32_t)s->workspace->sub[2].unsigned_value;
    if(s->workspace->sub[3].tag.control) s->keys.traffic.peer_intervals.active_threshold_ms=(uint16_t)s->workspace->sub[3].unsigned_value;
    return true;
}
static bool put(Matter_Case_T s,Matter_Tlv_Type_T t,unsigned tag,uint64_t v,const uint8_t* p,size_t n) {
    s->workspace->e=(Matter_Tlv_Element_T){.type=t,.tag={.control=tag?1:0,.number=tag},.unsigned_value=v,.data=p,.size=n};
    return matter_tlv_write(&s->workspace->writer,&s->workspace->e,0)==MATTER_TLV_OK;
}
#define B(tag,p,n) put(s,MATTER_TLV_BYTES,tag,0,p,n)
static bool begin(Matter_Case_T s,uint8_t* p,size_t n) { return matter_tlv_writer_init(&s->workspace->writer,p,n,2)==MATTER_TLV_OK && put(s,MATTER_TLV_STRUCTURE,0,0,NULL,0); }
static bool end(Matter_Case_T s,size_t* n) { return put(s,MATTER_TLV_END,0,0,NULL,0) && matter_tlv_writer_finish(&s->workspace->writer,n)==MATTER_TLV_OK; }
static bool append(Matter_Case_T s,const uint8_t* p,size_t n) {
    /* Keep only exact Sigma1 while resumption is still possible. Full CASE
     * reserves the unchanged transcript ceiling before allocating Sigma scratch. */
    if(n>CASE_TRANSCRIPT-s->transcript_size ||
        !matter_handshake_reserve(&s->transcript,&s->transcript_capacity,
            s->phase==START?s->transcript_size+n:CASE_TRANSCRIPT)) return false;
    memcpy(s->transcript+s->transcript_size,p,n); s->transcript_size+=n; return true;
}
static void session_keys(Matter_Case_T s) {
    memcpy(s->keys.traffic.send_key,s->derived+(s->config.responder?16:0),16);
    memcpy(s->keys.traffic.receive_key,s->derived+(s->config.responder?0:16),16);
    memcpy(s->keys.traffic.attestation_challenge,s->derived+32,16);
    s->keys.identity=(Matter_Secure_Identity_T){.fabric_index=s->fabric.index,.cat_count=s->peer.cat_count,
        .fabric_id=s->fabric.fabric_id,.local_node_id=s->fabric.node_id,.peer_node_id=s->peer.node_id};
    memcpy(s->keys.identity.cats,s->peer.cats,sizeof(s->peer.cats));
    if(s->port.resume_save) {
        s->resumption.identity=s->keys.identity; s->resumption.revision=s->fabric.revision;
        memcpy(s->resumption.shared_secret,s->shared,32); memcpy(s->resumption.id,s->resume,16);
    }
}
static bool derive(Matter_Case_T s,unsigned sigma) {
    if(s->crypto.sha256(s->crypto.user,s->transcript,s->transcript_size,s->digest)!=MATTER_OK) return false;
    memcpy(s->salt,s->fabric.ipk,16); size_t n=16;
    if(sigma==2) { memcpy(s->salt+n,s->random,32); n+=32; memcpy(s->salt+n,s->config.responder?s->public_key:s->peer_key,65); n+=65; }
    memcpy(s->salt+n,s->digest,32); n+=32;
    const char* info=sigma==2?"Sigma2":sigma==3?"Sigma3":"SessionKeys";
    if(s->crypto.hkdf_sha256(s->crypto.user,s->shared,32,s->salt,n,(const uint8_t*)info,strlen(info),s->derived,sigma?16:48)!=MATTER_OK) return false;
    if(sigma) memcpy(s->key,s->derived,16);
    else session_keys(s);
    erase(s->derived,48); erase(s->salt,sizeof(s->salt)); return true;
}
static bool ephemeral(Matter_Case_T s) {
    return s->crypto.p256_scalar(s->crypto.user,s->secret)==MATTER_OK && s->crypto.p256_base(s->crypto.user,s->secret,32,s->public_key)==MATTER_OK;
}
static bool sigma_work(Matter_Case_T s) {
    if(!s->scratch) s->scratch=calloc(1,sizeof(*s->scratch));
    return s->scratch!=NULL;
}
static bool begin_output(Matter_Case_T s) {
    return matter_handshake_reserve(&s->out,&s->out_capacity,CASE_PAYLOAD) && begin(s,s->out,CASE_PAYLOAD);
}
static bool tbs(Matter_Case_T s,const uint8_t* noc,size_t nn,const uint8_t* icac,size_t ni,bool own) {
    return sigma_work(s) && begin(s,s->scratch->work,sizeof(s->scratch->work)) && B(1,noc,nn) && (!ni || B(2,icac,ni)) &&
        B(3,own?s->public_key:s->peer_key,65) && B(4,own?s->peer_key:s->public_key,65) && end(s,&s->work_size);
}
static bool encrypted(Matter_Case_T s,unsigned sigma) {
    if(!tbs(s,s->fabric.noc,s->fabric.noc_size,s->fabric.icac,s->fabric.icac_size,true) ||
        s->port.sign(s->port.user,s->fabric.index,s->scratch->work,s->work_size,s->signature)!=MATTER_OK ||
        !begin(s,s->scratch->plain,sizeof(s->scratch->plain)) || !B(1,s->fabric.noc,s->fabric.noc_size) ||
        (s->fabric.icac_size && !B(2,s->fabric.icac,s->fabric.icac_size)) || !B(3,s->signature,64) ||
        (sigma==2 && !B(4,s->resume,16)) || !end(s,&s->plain_size) || s->plain_size>sizeof(s->scratch->cipher)-16 || !derive(s,sigma)) return false;
    return s->crypto.ccm_encrypt(s->crypto.user,s->key,(const uint8_t*)(sigma==2?"NCASE_Sigma2N":"NCASE_Sigma3N"),NULL,0,s->scratch->plain,s->plain_size,s->scratch->cipher)==MATTER_OK;
}
static bool verify(Matter_Case_T s,const Matter_Tlv_Element_T* encrypted,unsigned sigma) {
    if(!bytes(encrypted,17,CASE_PAYLOAD) || !sigma_work(s) || !derive(s,sigma) ||
        s->crypto.ccm_decrypt(s->crypto.user,s->key,(const uint8_t*)(sigma==2?"NCASE_Sigma2N":"NCASE_Sigma3N"),NULL,0,encrypted->data,encrypted->size-16,s->scratch->plain)!=MATTER_OK ||
        !decode(s,s->scratch->plain,encrypted->size-16,s->workspace->inner,5) || !bytes(&s->workspace->inner[1],1,400) ||
        (s->workspace->inner[2].tag.control && !bytes(&s->workspace->inner[2],1,400)) || !bytes(&s->workspace->inner[3],64,64) ||
        (sigma==2 && !bytes(&s->workspace->inner[4],16,16))) return false;
    Matter_Cert_Tlv_T noc={s->workspace->inner[1].data,s->workspace->inner[1].size},icac={s->workspace->inner[2].data,s->workspace->inner[2].size};
    if(matter_operational_cert_verify(&s->credentials,noc,icac,(Matter_Cert_Tlv_T){s->fabric.root,s->fabric.root_size},s->fabric.fabric_id,&s->config.time,&s->peer)!=MATTER_OK ||
        (sigma==2 && s->peer.node_id!=s->config.peer_node_id) ||
        !tbs(s,noc.data,noc.size,icac.data,icac.size,false) ||
        s->crypto.ecdsa_verify(s->crypto.user,s->peer.public_key,s->scratch->work,s->work_size,s->workspace->inner[3].data)!=MATTER_OK) return false;
    if(sigma==2) memcpy(s->resume,s->workspace->inner[4].data,16);
    return true;
}
#include "matter_case_resumption.h"
static bool start(Matter_Case_T s) {
    bool found=false;
    for(unsigned i=0;i<s->port.capacity;++i) {
        Matter_Result_T r=load(s,i); if(r==MATTER_INVALID_STATE) continue; if(r!=MATTER_OK) return false;
        if(s->fabric.index==s->config.fabric_index) { found=true; break; }
    }
    if(!found || s->crypto.random(s->crypto.user,s->random,32)!=MATTER_OK || !ephemeral(s) ||
        matter_case_destination(&s->crypto,s->fabric.ipk,s->random,s->fabric.root_public,s->fabric.fabric_id,s->config.peer_node_id,s->digest)!=MATTER_OK) return false;
    s->resume_attempt=resume_find(s,NULL);
    if(s->resume_attempt && !resume_mic(s,s->resumption.id,1,NULL)) return false;
    if(!begin_output(s) || !B(1,s->random,32) || !put(s,MATTER_TLV_UNSIGNED,2,s->config.local_session_id,NULL,0) ||
        !B(3,s->digest,32) || !B(4,s->public_key,65) ||
        (s->resume_attempt && (!B(6,s->resumption.id,16) || !B(7,s->workspace->mic,16))) || !end(s,&s->out_size) || !append(s,s->out,s->out_size)) return false;
    s->out_opcode=0x30; s->after_send=SIGMA2; s->output=true; return true;
}
static unsigned sigma1(Matter_Case_T s) {
    if(!decode(s,s->in,s->in_size,s->workspace->fields,8) || !bytes(&s->workspace->fields[1],32,32) || !number(&s->workspace->fields[2],65535) || !s->workspace->fields[2].unsigned_value ||
        !bytes(&s->workspace->fields[3],32,32) || !bytes(&s->workspace->fields[4],65,65) || !intervals(s,5) ||
        (!!s->workspace->fields[6].tag.control!=!!s->workspace->fields[7].tag.control) ||
        (s->workspace->fields[6].tag.control && (!bytes(&s->workspace->fields[6],16,16) || !bytes(&s->workspace->fields[7],16,16)))) return 2;
    s->keys.traffic.peer_session_id=(uint16_t)s->workspace->fields[2].unsigned_value;
    memcpy(s->random,s->workspace->fields[1].data,32);
    if(s->workspace->fields[6].tag.control && resume_find(s,s->workspace->fields[6].data) &&
        resume_mic(s,s->resumption.id,1,s->workspace->fields[7].data)) return resume_reply(s)?0:2;
    erase(&s->resumption,sizeof(s->resumption)); erase(s->shared,32);
    bool found=false;
    for(unsigned i=0;i<s->port.capacity;++i) {
        Matter_Result_T r=load(s,i); if(r==MATTER_INVALID_STATE) continue; if(r!=MATTER_OK) return 2;
        if(matter_case_destination(&s->crypto,s->fabric.ipk,s->workspace->fields[1].data,s->fabric.root_public,s->fabric.fabric_id,s->fabric.node_id,s->digest)!=MATTER_OK) return 2;
        if(s->crypto.equal(s->digest,s->workspace->fields[3].data,32)) { found=true; break; }
    }
    if(!found) return 1;
    s->keys.traffic.peer_session_id=(uint16_t)s->workspace->fields[2].unsigned_value; memcpy(s->peer_key,s->workspace->fields[4].data,65);
    if(!append(s,s->in,s->in_size) || !ephemeral(s) || s->crypto.ecdh(s->crypto.user,s->secret,s->peer_key,s->shared)!=MATTER_OK ||
        s->crypto.random(s->crypto.user,s->resume,16)!=MATTER_OK || s->crypto.random(s->crypto.user,s->random,32)!=MATTER_OK || !encrypted(s,2)) return 2;
    if(!begin_output(s) || !B(1,s->random,32) || !put(s,MATTER_TLV_UNSIGNED,2,s->config.local_session_id,NULL,0) ||
        !B(3,s->public_key,65) || !B(4,s->scratch->cipher,s->plain_size+16) || !end(s,&s->out_size) || !append(s,s->out,s->out_size)) return 2;
    s->out_opcode=0x31; s->after_send=SIGMA3; s->output=true; return 0;
}
static bool sigma2(Matter_Case_T s) {
    s->resume_attempt=false; erase(&s->resumption,sizeof(s->resumption));
    if(!decode(s,s->in,s->in_size,s->workspace->fields,8) || !bytes(&s->workspace->fields[1],32,32) || !number(&s->workspace->fields[2],65535) || !s->workspace->fields[2].unsigned_value ||
        !bytes(&s->workspace->fields[3],65,65) || !intervals(s,5)) return false;
    memcpy(s->random,s->workspace->fields[1].data,32); memcpy(s->peer_key,s->workspace->fields[3].data,65);
    s->keys.traffic.peer_session_id=(uint16_t)s->workspace->fields[2].unsigned_value;
    if(!matter_handshake_reserve(&s->transcript,&s->transcript_capacity,CASE_TRANSCRIPT) ||
        s->crypto.ecdh(s->crypto.user,s->secret,s->peer_key,s->shared)!=MATTER_OK || !verify(s,&s->workspace->fields[4],2) ||
        !append(s,s->in,s->in_size) || !encrypted(s,3) || !begin_output(s) ||
        !B(1,s->scratch->cipher,s->plain_size+16) || !end(s,&s->out_size) || !append(s,s->out,s->out_size) || !derive(s,0)) return false;
    secrets(s); s->out_opcode=0x32; s->after_send=FINISH; s->output=true; return true;
}
static bool sigma3(Matter_Case_T s) {
    if(!decode(s,s->in,s->in_size,s->workspace->fields,8) || !verify(s,&s->workspace->fields[1],3) || !append(s,s->in,s->in_size) || !derive(s,0)) return false;
    secrets(s); memset(s->status,0,8); s->out_size=8; s->out_opcode=0x40; s->after_send=COMPLETE; s->output=true; return true;
}
Matter_Result_T matter_case_receive(Matter_Case_T s,uint8_t op,const uint8_t* p,size_t n) {
    Matter_Result_T r=check(s); if(r!=MATTER_OK) return r;
    if(!p || !n) return MATTER_INVALID_ARGUMENT;
    if(n>CASE_PAYLOAD) return MATTER_LIMIT_REACHED;
    if(s->phase==START || s->phase==COMPLETE || s->phase==FAILED) return MATTER_INVALID_STATE;
    if(s->queued || s->output) return MATTER_WOULD_BLOCK;
    if(!matter_handshake_copy(&s->in,&s->in_size,p,n)) return MATTER_LIMIT_REACHED;
    s->in_opcode=op; s->queued=true; return MATTER_OK;
}
Matter_Result_T matter_case_process(Matter_Case_T s,uint64_t now) {
    Matter_Result_T r=check(s); if(r!=MATTER_OK) return r;
    if(now<s->now) return MATTER_INVALID_ARGUMENT;
    s->now=now;
    if(s->phase==FAILED) return MATTER_PORT_ERROR;
    if(s->phase==COMPLETE) return MATTER_OK;
    s->busy=true;
    if((s->phase==START && !s->output) || s->queued) s->workspace=calloc(1,sizeof(*s->workspace));
    if(now>=s->deadline || !selected(s)) failure(s,2,false);
    else if(((s->phase==START && !s->output) || s->queued) && !s->workspace) failure(s,2,s->queued && s->in_opcode!=0x40);
    else if(!s->output && s->phase==START) { if(!start(s)) failure(s,2,false); }
    else if(s->queued) {
        s->queued=false;
        if(s->in_opcode==0x40) {
            static const uint8_t success[8]={0};
            if(s->in_size==8 && !memcmp(s->in,success,8)) { if(s->phase==FINISH) s->phase=COMPLETE; } /* Unexpected success ignored. */
            else failure(s,2,false);
        } else if(s->phase==SIGMA1 && s->in_opcode==0x30) { unsigned code=sigma1(s); if(code) failure(s,code,true); }
        else if(s->phase==SIGMA2 && s->in_opcode==0x33) { if(!resume_response(s)) failure(s,2,true); }
        else if(s->phase==SIGMA2 && s->in_opcode==0x31) { if(!sigma2(s)) failure(s,2,true); }
        else if(s->phase==SIGMA3 && s->in_opcode==0x32) { if(!sigma3(s)) failure(s,2,true); }
        else failure(s,2,true);
        matter_handshake_clear(&s->in,&s->in_size);
    }
    matter_handshake_delete(s->scratch,sizeof(*s->scratch)); s->scratch=NULL;
    matter_handshake_delete(s->workspace,sizeof(*s->workspace)); s->workspace=NULL;
    s->busy=false; return s->phase==FAILED?MATTER_PORT_ERROR:s->phase==COMPLETE?MATTER_OK:MATTER_PENDING;
}
Matter_Result_T matter_case_output(Matter_Case_T s,Matter_Pase_Message_T* m) {
    Matter_Result_T r=check(s); if(r!=MATTER_OK) return r;
    if(!m) return MATTER_INVALID_ARGUMENT;
    if(!s->output) return MATTER_WOULD_BLOCK;
    *m=(Matter_Pase_Message_T){s->out_opcode,s->out_opcode==0x40?s->status:s->out,s->out_size}; return MATTER_OK;
}
Matter_Result_T matter_case_sent(Matter_Case_T s) {
    Matter_Result_T r=check(s); if(r!=MATTER_OK) return r;
    if(!s->output) return MATTER_INVALID_STATE;
    matter_handshake_clear(&s->out,&s->out_capacity);
    s->output=false; s->phase=s->after_send; return MATTER_OK;
}
Matter_Result_T matter_case_confirm_delivery(Matter_Case_T s,uint64_t now) {
    Matter_Result_T r=check(s); if(r!=MATTER_OK) return r;
    /* Optional MRP bookkeeping, not a second authentication/key gate. A late
     * ACK or MRP timeout cannot revoke a session already used by the peer. */
    if(s->phase!=COMPLETE || s->after_send!=COMPLETE || s->confirmed || now<s->now) return MATTER_INVALID_STATE;
    s->now=now; s->confirmed=true; return MATTER_OK;
}
static Matter_Result_T take(void* u,Matter_Pase_Keys_T* traffic,Matter_Secure_Identity_T* identity) {
    Matter_Case_T s=u; Matter_Result_T r=check(s); if(r!=MATTER_OK) return r;
    if(s->phase!=COMPLETE || s->transferred) return MATTER_INVALID_STATE;
    s->busy=true; if(!selected(s)) { failure(s,2,false); s->busy=false; return MATTER_INVALID_STATE; }
    if(s->port.resume_save) (void)s->port.resume_save(s->port.user,&s->resumption);
    erase(&s->resumption,sizeof(s->resumption));
    *traffic=s->keys.traffic; *identity=s->keys.identity; erase(&s->keys,sizeof(s->keys));
    /* Public MRP timing is still needed for the retained final packet. */
    s->keys.traffic.peer_intervals=traffic->peer_intervals;
    s->transferred=true; s->busy=false; return MATTER_OK;
}
Matter_Result_T matter_case_take_keys(Matter_Case_T s,Matter_Case_Keys_T* k) { if(!k) return MATTER_INVALID_ARGUMENT; return take(s,&k->traffic,&k->identity); }
Matter_Secure_T matter_secure_new_case(const Matter_Crypto_Port_T* p,Matter_Case_T s,uint64_t now) { return s && now>=s->now?matter_secure_from_case(p,s,take,now):NULL; }
Matter_Result_T matter_case_peer_intervals(Matter_Case_T s,Matter_Pase_Intervals_T* p) {
    Matter_Result_T r=check(s); if(r!=MATTER_OK) return r;
    if(!p) return MATTER_INVALID_ARGUMENT;
    if(s->phase==FAILED) return MATTER_INVALID_STATE;
    *p=s->keys.traffic.peer_intervals; return MATTER_OK;
}
Matter_Case_State_T matter_case_state(Matter_Case_T s) { return !s || s->phase==FAILED?MATTER_CASE_FAILED:s->output?MATTER_CASE_OUTPUT:s->phase==COMPLETE?MATTER_CASE_COMPLETE:MATTER_CASE_WAITING; }
Matter_Result_T matter_case_cancel(Matter_Case_T s) { Matter_Result_T r=check(s); if(r!=MATTER_OK) return r; failure(s,2,false); return MATTER_OK; }
Matter_Result_T matter_case_delete(Matter_Case_T s) { if(!s) return MATTER_OK; if(s->busy) return MATTER_BUSY; secrets(s); matter_handshake_clear(&s->in,&s->in_size); matter_handshake_clear(&s->out,&s->out_capacity);
    matter_handshake_delete(s->workspace,sizeof(*s->workspace)); erase(s,sizeof(*s)); free(s); return MATTER_OK; }

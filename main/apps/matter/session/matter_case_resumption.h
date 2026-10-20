/* Private CASE resumption computations. All secret workspaces belong to the
 * heap attempt; optional cache callbacks never own pointers into the attempt. */
static bool resume_identity(Matter_Case_T s) {
    const Matter_Secure_Identity_T* id=&s->resumption.identity;
    return id->fabric_index==s->fabric.index && id->fabric_id==s->fabric.fabric_id &&
        id->local_node_id==s->fabric.node_id && id->peer_node_id && id->peer_node_id<=UINT64_C(0xffffffefffffffff) &&
        id->cat_count<=3 && s->resumption.revision==s->fabric.revision && selected(s) &&
        (s->config.responder || id->peer_node_id==s->config.peer_node_id);
}
static bool resume_find(Matter_Case_T s,const uint8_t* id) {
    if(!s->port.resume_find || s->port.resume_find(s->port.user,s->config.fabric_index,s->config.peer_node_id,id,&s->resumption)!=MATTER_OK) {
        erase(&s->resumption,sizeof(s->resumption)); return false;
    }
    if(id) {
        bool found=false;
        if(!s->crypto.equal(id,s->resumption.id,16)) return false;
        for(unsigned i=0;i<s->port.capacity;++i) {
            Matter_Result_T r=load(s,i); if(r==MATTER_INVALID_STATE) continue; if(r!=MATTER_OK) return false;
            if(s->fabric.index==s->resumption.identity.fabric_index) { found=true; break; }
        }
        if(!found) return false;
    }
    if(!resume_identity(s)) { erase(&s->resumption,sizeof(s->resumption)); return false; }
    memcpy(s->shared,s->resumption.shared_secret,32);
    s->peer.node_id=s->resumption.identity.peer_node_id; s->peer.cat_count=s->resumption.identity.cat_count;
    memcpy(s->peer.cats,s->resumption.identity.cats,sizeof(s->peer.cats)); return true;
}
static bool resume_derive(Matter_Case_T s,const uint8_t id[16],const char* info,size_t n) {
    memcpy(s->salt,s->random,32); memcpy(s->salt+32,id,16);
    bool ok=s->crypto.hkdf_sha256(s->crypto.user,s->shared,32,s->salt,48,(const uint8_t*)info,strlen(info),s->derived,n)==MATTER_OK;
    erase(s->salt,sizeof(s->salt)); return ok;
}
static bool resume_mic(Matter_Case_T s,const uint8_t id[16],unsigned sigma,const uint8_t* received) {
    bool ok=resume_derive(s,id,sigma==1?"Sigma1_Resume":"Sigma2_Resume",16);
    const uint8_t* nonce=(const uint8_t*)(sigma==1?"NCASE_SigmaS1":"NCASE_SigmaS2");
    if(ok) ok=(received?s->crypto.ccm_decrypt(s->crypto.user,s->derived,nonce,NULL,0,received,0,s->workspace->mic):
        s->crypto.ccm_encrypt(s->crypto.user,s->derived,nonce,NULL,0,NULL,0,s->workspace->mic))==MATTER_OK;
    erase(s->derived,sizeof(s->derived)); return ok;
}
static bool resume_keys(Matter_Case_T s) {
    const uint8_t* id=s->config.resumption_profile==MATTER_CASE_RESUMPTION_CHIP?s->resumption.id:s->resume;
    if(!resume_derive(s,id,"SessionResumptionKeys",48)) return false;
    session_keys(s); secrets(s); return true;
}
static bool resume_reply(Matter_Case_T s) {
    if(s->crypto.random(s->crypto.user,s->resume,16)!=MATTER_OK || !resume_mic(s,s->resume,2,NULL) ||
        !begin_output(s) || !B(1,s->resume,16) || !B(2,s->workspace->mic,16) ||
        !put(s,MATTER_TLV_UNSIGNED,3,s->config.local_session_id,NULL,0) || !end(s,&s->out_size) || !resume_keys(s)) return false;
    s->out_opcode=0x33; s->after_send=FINISH; s->output=true; return true;
}
static bool resume_response(Matter_Case_T s) {
    if(!s->resume_attempt || !decode(s,s->in,s->in_size,s->workspace->fields,8) || !bytes(&s->workspace->fields[1],16,16) ||
        !bytes(&s->workspace->fields[2],16,16) || !number(&s->workspace->fields[3],65535) || !s->workspace->fields[3].unsigned_value || !intervals(s,4) ||
        !resume_mic(s,s->workspace->fields[1].data,2,s->workspace->fields[2].data)) return false;
    s->keys.traffic.peer_session_id=(uint16_t)s->workspace->fields[3].unsigned_value; memcpy(s->resume,s->workspace->fields[1].data,16);
    if(!resume_keys(s)) return false;
    memset(s->status,0,8); s->out_size=8; s->out_opcode=0x40; s->after_send=COMPLETE; s->output=true; return true;
}

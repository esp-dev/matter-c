/* Real crypto, optional application-owned cache and both handshake roles.
 * Workspaces stay in CaseFixture/heap; no secret material is logged. */
static Matter_Case_Port_T resume_original;
static unsigned resume_fault;
static Matter_Result_T resume_changed(void* u,uint8_t index,uint64_t peer,const uint8_t* id,Matter_Case_Resumption_T* out) {
    Matter_Result_T r=resume_original.resume_find(u,index,peer,id,out);
    if(r==MATTER_OK) {
        if(resume_fault==1) out->shared_secret[0]^=1;
        if(resume_fault==2) out->id[0]^=1;
        if(resume_fault==3) ++out->revision;
    }
    return r;
}
static Matter_Result_T resume_no_save(void* u,const Matter_Case_Resumption_T* r) { (void)u; (void)r; return MATTER_PORT_ERROR; }
static void resume_new(CaseFixture* f,const Matter_Credentials_Port_T* cp) {
    for(unsigned i=0;i<2;++i) {
        OC_CHECK(matter_case_delete(f->session[i])==MATTER_OK);
        f->config[i].local_session_id+=2;
        f->session[i]=matter_case_new(&f->crypto,cp,&f->ports[i],&f->config[i],0); OC_CHECK(f->session[i]);
    }
}
static void resume_take(CaseFixture* f) {
    for(unsigned i=0;i<2;++i) OC_CHECK(matter_case_take_keys(f->session[i],&f->keys[i])==MATTER_OK);
    OC_CHECK(!memcmp(f->keys[0].traffic.send_key,f->keys[1].traffic.receive_key,16) &&
        !memcmp(f->keys[1].traffic.send_key,f->keys[0].traffic.receive_key,16) &&
        !memcmp(f->keys[0].traffic.attestation_challenge,f->keys[1].traffic.attestation_challenge,16));
}
static void resume_exchange(CaseFixture* f,bool resumed) {
    Matter_Pase_Message_T m; OC_CHECK(matter_case_process(f->session[0],0)==MATTER_PENDING);
    case_step(f,0,1); OC_CHECK(matter_case_output(f->session[1],&m)==MATTER_OK && m.opcode==(resumed?0x33:0x31));
    case_step(f,1,2);
    if(resumed) {
        OC_CHECK(matter_case_take_keys(f->session[0],&f->keys[0])==MATTER_INVALID_STATE);
        OC_CHECK(matter_case_take_keys(f->session[1],&f->keys[1])==MATTER_INVALID_STATE);
        case_step(f,0,3); OC_CHECK(matter_case_state(f->session[1])==MATTER_CASE_COMPLETE);
        OC_CHECK(matter_case_state(f->session[0])==MATTER_CASE_COMPLETE);
        OC_CHECK(matter_case_confirm_delivery(f->session[0],4)==MATTER_OK);
    } else {
        case_step(f,0,3); case_step(f,1,4); OC_CHECK(matter_case_confirm_delivery(f->session[1],5)==MATTER_OK);
    }
}
static Matter_Result_T case_no_random(void* u,uint8_t* p,size_t n) { (void)u;(void)p;(void)n;return MATTER_PORT_ERROR; }
static void case_activation(const Matter_Crypto_Port_T* crypto,const Matter_Credentials_Port_T* cp) {
    for(unsigned profile=0;profile<2;++profile) for(unsigned resumed=0;resumed<2;++resumed) for(unsigned fault=0;fault<3;++fault) {
        CaseFixture* f=case_fixture(crypto,cp);
        for(unsigned i=0;i<2;++i) f->config[i].resumption_profile=(Matter_Case_Resumption_Profile_T)profile;
        if(resumed) { case_establish(f); resume_take(f); }
        resume_new(f,cp); OC_CHECK(matter_case_process(f->session[0],0)==MATTER_PENDING);
        case_step(f,0,1); case_step(f,1,2); if(!resumed) case_step(f,0,3);
        unsigned sender=resumed?0:1; Matter_Case_T s=f->session[sender];
        OC_CHECK(matter_case_state(s)==MATTER_CASE_OUTPUT && matter_case_take_keys(s,&f->keys[sender])==MATTER_INVALID_STATE);
        OC_CHECK(matter_case_confirm_delivery(s,4)==MATTER_INVALID_STATE);
        if(fault==1) { /* Cancel before enqueue never grants a session. */
            OC_CHECK(matter_case_cancel(s)==MATTER_OK && matter_case_take_keys(s,&f->keys[sender])==MATTER_INVALID_STATE);
        } else {
            case_step(f,sender,4); OC_CHECK(matter_case_state(s)==MATTER_CASE_COMPLETE);
            if(fault==2) {
                OC_CHECK(f->fabrics[sender]->port.remove(f->fabrics[sender]->host,1)==MATTER_OK);
                OC_CHECK(matter_case_take_keys(s,&f->keys[sender])==MATTER_INVALID_STATE);
            } else {
                Matter_Pase_Intervals_T before,after; OC_CHECK(matter_case_peer_intervals(s,&before)==MATTER_OK);
                Matter_Crypto_Port_T broken=*crypto; broken.random=case_no_random;
                OC_CHECK(!matter_secure_new_case(&broken,s,4) && matter_case_state(s)==MATTER_CASE_COMPLETE);
#ifdef MATTER_TEST_ALLOC
                fail_at=calls+1; OC_CHECK(!matter_secure_new_case(crypto,s,4)); fail_at=0;
#endif
                f->secure[sender]=matter_secure_new_case(crypto,s,4); OC_CHECK(f->secure[sender]);
                OC_CHECK(matter_case_take_keys(s,&f->keys[sender])==MATTER_INVALID_STATE);
                OC_CHECK(matter_case_peer_intervals(s,&after)==MATTER_OK && before.idle_ms==after.idle_ms && before.active_ms==after.active_ms && before.active_threshold_ms==after.active_threshold_ms);
                OC_CHECK(matter_case_process(s,30000)==MATTER_OK); /* Handshake timeout no longer applies. */
                OC_CHECK(matter_case_confirm_delivery(s,29999)==MATTER_INVALID_STATE);
                OC_CHECK(matter_case_confirm_delivery(s,30001)==MATTER_OK && matter_case_confirm_delivery(s,30001)==MATTER_INVALID_STATE);
                OC_CHECK(matter_case_confirm_delivery(f->session[1-sender],30001)==MATTER_INVALID_STATE);
            }
        }
        case_free(f);
    }
    puts("PASS CASE activation: both roles/profiles, no ACK gate, one-shot handoff, retained MRP timing, late ACK, cancel/revocation/RNG/OOM");
}
static void resume_tests(const Matter_Crypto_Port_T* crypto,const Matter_Credentials_Port_T* cp) {
    Matter_Case_Resumption_T* saved=calloc(3,sizeof(*saved)); OC_CHECK(saved);
    for(unsigned profile=0;profile<2;++profile) for(unsigned fault=0;fault<4;++fault) {
        CaseFixture* f=case_fixture(crypto,cp); case_establish(f); resume_take(f);
        for(unsigned i=0;i<2;++i) f->config[i].resumption_profile=(Matter_Case_Resumption_Profile_T)profile;
        OC_CHECK(f->ports[0].resume_find(f->ports[0].user,1,100,NULL,&saved[0])==MATTER_OK);
        OC_CHECK(f->ports[1].resume_find(f->ports[1].user,0,0,saved[0].id,&saved[1])==MATTER_OK);
        OC_CHECK(!memcmp(saved[0].shared_secret,saved[1].shared_secret,32));
        memcpy(saved[2].shared_secret,f->keys[0].traffic.send_key,16);
        if(fault) { resume_original=f->ports[0]; resume_fault=fault; f->ports[0].resume_find=resume_changed; }
        resume_new(f,cp); resume_exchange(f,!fault); resume_take(f);
        OC_CHECK(memcmp(saved[2].shared_secret,f->keys[0].traffic.send_key,16));
        if(fault) f->ports[0].resume_find=resume_original.resume_find; /* Original function, same per-fixture user. */
        if(!fault) {
            OC_CHECK(f->ports[1].resume_find(f->ports[1].user,0,0,saved[0].id,&saved[2])==MATTER_INVALID_STATE);
            OC_CHECK(f->ports[1].resume_find(f->ports[1].user,1,101,NULL,&saved[2])==MATTER_OK);
            OC_CHECK(memcmp(saved[0].id,saved[2].id,16) && !memcmp(saved[0].shared_secret,saved[2].shared_secret,32));
        }
        case_free(f);
    }
    /* Invalid Sigma2 MIC fails closed, no cache publication. Cancel, timeout
     * and revocation after Sigma2Resume cannot hand out keys or rotate the ID. */
    for(unsigned fault=0;fault<4;++fault) {
        CaseFixture* f=case_fixture(crypto,cp); case_establish(f); resume_take(f);
        OC_CHECK(f->ports[1].resume_find(f->ports[1].user,1,101,NULL,saved)==MATTER_OK);
        resume_new(f,cp); OC_CHECK(matter_case_process(f->session[0],0)==MATTER_PENDING); case_step(f,0,1);
        if(!fault) {
            Matter_Pase_Message_T m; OC_CHECK(matter_case_output(f->session[1],&m)==MATTER_OK && m.opcode==0x33);
            memcpy(f->bytes,m.data,m.size); f->bytes[24]^=1;
            OC_CHECK(matter_case_receive(f->session[0],m.opcode,f->bytes,m.size)==MATTER_OK);
            OC_CHECK(matter_case_process(f->session[0],2)==MATTER_PORT_ERROR);
        } else if(fault==1) OC_CHECK(matter_case_cancel(f->session[1])==MATTER_OK);
        else if(fault==2) OC_CHECK(matter_case_process(f->session[1],30000)==MATTER_PORT_ERROR);
        else {
            OC_CHECK(f->fabrics[1]->port.remove(f->fabrics[1]->host,1)==MATTER_OK);
            OC_CHECK(matter_case_process(f->session[1],2)==MATTER_PORT_ERROR);
        }
        for(unsigned i=0;i<2;++i) OC_CHECK(matter_case_take_keys(f->session[i],&f->keys[i])==MATTER_INVALID_STATE);
        OC_CHECK(f->ports[1].resume_find(f->ports[1].user,0,0,saved->id,&saved[1])==(fault==3?MATTER_INVALID_STATE:MATTER_OK));
        case_free(f);
    }
    /* Volatile cache loss is a full authenticated handshake, not an error. */
    CaseFixture* f=case_fixture(crypto,cp); case_establish(f); resume_take(f);
    OC_CHECK(matter_fabric_host_commit(f->fabrics[1]->host)==MATTER_OK);
    OC_CHECK(matter_case_delete(f->session[1])==MATTER_OK); f->session[1]=NULL;
    fab_restart(f->fabrics[1]); f->ports[1]=matter_fabric_host_case_port(f->fabrics[1]->host);
    resume_new(f,cp); resume_exchange(f,false); resume_take(f); case_free(f);
    /* Optional pair stays optional, partial ports and invalid profiles fail fast. */
    f=case_fixture(crypto,cp); f->ports[0].resume_save=NULL;
    OC_CHECK(!matter_case_new(crypto,cp,&f->ports[0],&f->config[0],0));
    f->ports[0].resume_find=NULL; resume_new(f,cp); resume_exchange(f,false); resume_take(f);
    f->config[0].resumption_profile=(Matter_Case_Resumption_Profile_T)2;
    OC_CHECK(!matter_case_new(crypto,cp,&f->ports[0],&f->config[0],0)); case_free(f);
#ifdef MATTER_TEST_ALLOC
    f=case_fixture(crypto,cp); case_establish(f); resume_take(f);
    OC_CHECK(f->ports[0].resume_find(f->ports[0].user,1,100,NULL,saved)==MATTER_OK);
    resume_new(f,cp); resume_exchange(f,true);
    fail_at=calls+1; OC_CHECK(!matter_secure_new_case(crypto,f->session[0],5)); fail_at=0;
    OC_CHECK(f->ports[0].resume_find(f->ports[0].user,0,0,saved->id,&saved[1])==MATTER_OK);
    f->secure[0]=matter_secure_new_case(crypto,f->session[0],5); OC_CHECK(f->secure[0]);
    OC_CHECK(f->ports[0].resume_find(f->ports[0].user,0,0,saved->id,&saved[1])==MATTER_INVALID_STATE);
    case_free(f);
#endif
    /* Cache write failure must not turn successful authentication into failure. */
    f=case_fixture(crypto,cp); f->ports[1].resume_save=resume_no_save; resume_new(f,cp);
    resume_exchange(f,false); resume_take(f);
    OC_CHECK(f->ports[1].resume_find(f->ports[1].user,1,101,NULL,saved)==MATTER_INVALID_STATE); case_free(f);
    memset(saved,0,3*sizeof(*saved)); free(saved);
    puts("PASS CASE resumption: both roles, fresh keys/IDs, MIC/unknown/revision fallback, final ACK gate, cancel/timeout/removal, volatile restart and save failure");
}
static void resume_cache_tests(const Matter_Crypto_Port_T* crypto,const Matter_Credentials_Port_T* cp) {
    CaseFixture* f=case_fixture(crypto,cp); case_establish(f); resume_take(f);
    Matter_Case_Resumption_T* saved=calloc(2,sizeof(*saved)); OC_CHECK(saved);
    Matter_Case_Port_T* p=&f->ports[1]; FabFixture* fab=f->fabrics[1];
    OC_CHECK(p->resume_find(p->user,1,101,NULL,saved)==MATTER_OK);
#ifdef MATTER_TEST_ALLOC
    saved[1]=saved[0]; saved[1].identity.peer_node_id=999; saved[1].id[0]^=0x80;
    size_t cache_live=live; fail_at=calls+1;
    OC_CHECK(p->resume_save(p->user,&saved[1])==MATTER_LIMIT_REACHED); fail_at=0;
    OC_CHECK(live==cache_live && p->resume_find(p->user,1,999,NULL,&saved[1])==MATTER_INVALID_STATE);
    OC_CHECK(p->resume_find(p->user,1,101,NULL,&saved[1])==MATTER_OK && !memcmp(saved,&saved[1],sizeof(*saved)));
    /* Same-peer update reuses its node, even with the next allocation failing. */
    size_t cache_calls=calls; fail_at=calls+1;
    OC_CHECK(p->resume_save(p->user,saved)==MATTER_OK && calls==cache_calls); fail_at=0;
#endif
    Matter_Case_Fabric_T* snapshot=calloc(1,sizeof(*snapshot)); OC_CHECK(snapshot);
    OC_CHECK(matter_fabric_host_commit(fab->host)==MATTER_OK);
    fab_csr(fab,11); fab_request(fab,11,FAB_CERT(fab_root),(Matter_Cert_Tlv_T){0},0); fab_call(fab,1,11,true,0,0);
    fab_request(fab,6,FAB_CERT(fab_noc1),(Matter_Cert_Tlv_T){0},55); fab_call(fab,1,6,true,0,0);
    OC_CHECK(matter_fabric_host_commit(fab->host)==MATTER_OK && p->load(p->user,1,snapshot)==MATTER_OK);
    OC_CHECK(p->resume_find(p->user,1,101,NULL,&saved[1])==MATTER_OK && !memcmp(saved,&saved[1],sizeof(*saved)));
    saved[1]=saved[0]; saved[1].identity.fabric_index=snapshot->index;
    saved[1].identity.fabric_id=snapshot->fabric_id; saved[1].identity.local_node_id=snapshot->node_id;
    saved[1].revision=snapshot->revision; saved[1].id[0]=0xfe;
    OC_CHECK(p->resume_save(p->user,&saved[1])==MATTER_OK);
    memset(snapshot,0,sizeof(*snapshot)); free(snapshot);
    /* Three peers per fabric, authenticated write order, oldest eviction. */
    for(unsigned i=0;i<4;++i) { saved->identity.peer_node_id=101+i; saved->id[0]=(uint8_t)i; OC_CHECK(p->resume_save(p->user,saved)==MATTER_OK); }
    OC_CHECK(p->resume_find(p->user,1,101,NULL,&saved[1])==MATTER_INVALID_STATE);
    for(unsigned i=1;i<4;++i) OC_CHECK(p->resume_find(p->user,1,101+i,NULL,&saved[1])==MATTER_OK);
#ifdef MATTER_TEST_ALLOC
    /* Full per-fabric replacement reuses the oldest node without allocation. */
    saved->identity.peer_node_id=105; saved->id[0]=4;
    cache_calls=calls; fail_at=calls+1;
    OC_CHECK(p->resume_save(p->user,saved)==MATTER_OK && calls==cache_calls); fail_at=0;
    OC_CHECK(p->resume_find(p->user,1,102,NULL,&saved[1])==MATTER_INVALID_STATE);
    OC_CHECK(p->resume_find(p->user,1,104,NULL,&saved[1])==MATTER_OK); *saved=saved[1];
#endif
    /* Colliding IDs for different peers rejected without changing existing key. */
    saved->identity.peer_node_id=999;
    OC_CHECK(p->resume_save(p->user,saved)==MATTER_INVALID_STATE);
    OC_CHECK(p->resume_find(p->user,1,104,NULL,&saved[1])==MATTER_OK);
    OC_CHECK(fab->port.label(fab->host,1,(const uint8_t*)"label",5)==MATTER_OK);
    OC_CHECK(p->resume_find(p->user,1,104,NULL,&saved[1])==MATTER_OK);
    /* IPK revision change invalidates cached identity; failed mutation doesn't. */
    Matter_Groupkey_Port_T group=matter_fabric_host_groupkey_port(fab->host);
    Matter_Groupkey_Set_T set=group.view(group.user)->fabrics[0].sets[0]; uint8_t keys[3][16]={{0}}; memset(keys[0],0x24,16);
    fab->control.fail_store=true; matter_fabric_host_control(fab->host,&fab->control);
    OC_CHECK(group.store(group.user,1,&set,keys)!=0);
    OC_CHECK(p->resume_find(p->user,1,104,NULL,&saved[1])==MATTER_OK);
    fab->control.fail_store=false; matter_fabric_host_control(fab->host,&fab->control);
    OC_CHECK(group.store(group.user,1,&set,keys)==0);
    OC_CHECK(p->resume_find(p->user,1,104,NULL,&saved[1])==MATTER_INVALID_STATE);
    OC_CHECK(p->resume_save(p->user,saved)==MATTER_INVALID_STATE);
    OC_CHECK(p->resume_find(p->user,2,101,NULL,&saved[1])==MATTER_OK);
    OC_CHECK(fab->port.remove(fab->host,1)==MATTER_OK);
    OC_CHECK(p->resume_find(p->user,2,101,NULL,&saved[1])==MATTER_OK);
    OC_CHECK(p->resume_save(p->user,saved)==MATTER_INVALID_STATE);
    memset(saved,0,2*sizeof(*saved)); free(saved); case_free(f);
    puts("PASS resumption cache: bounded per-fabric eviction, ID collision, labels retained, IPK/removal isolation and failed mutation");
}

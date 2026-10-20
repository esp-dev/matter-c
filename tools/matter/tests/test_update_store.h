/* Real crypto and generic cluster API, with durable file fault injection.
 * Large snapshots reuse the parent StoreTest heap workspace. */
static void update_call(FabFixture* f,uint32_t cmd,bool armed,uint8_t im,uint8_t noc) {
    Matter_Cluster_Request_T q={.session=1,.fabric=1,.is_case=true,.armed=armed};
    OC_CHECK(matter_tlv_writer_init(&f->writer,f->response,sizeof(f->response),3)==MATTER_TLV_OK);
    Matter_Result_T r=matter_cluster_start(f->o->core,cmd,&q,f->args,f->args_size,&f->writer,&f->result,&f->token);
    for(unsigned i=0;i<8 && r==MATTER_PENDING;++i) {
        Matter_Result_T step=matter_opcreds_process(f->o->core); OC_CHECK(step==MATTER_OK || step==MATTER_PENDING);
        r=matter_cluster_poll(f->o->core,f->token,&f->writer,&f->result);
    }
    if(r!=MATTER_OK || f->result.status!=im) fprintf(stderr,"Update cmd=%u result=%d IM=%u expected=%u\n",cmd,r,f->result.status,im);
    OC_CHECK(r==MATTER_OK && f->result.status==im);
    if(!im && cmd==7) {
        OC_CHECK(matter_tlv_writer_finish(&f->writer,&f->response_size)==MATTER_TLV_OK);
        OC_CHECK(matter_tlv_init(&f->reader,f->response,f->response_size,2)==MATTER_TLV_OK);
        OC_CHECK(matter_tlv_next(&f->reader,&f->e)==MATTER_TLV_OK && matter_tlv_next(&f->reader,&f->e)==MATTER_TLV_OK);
        if(f->e.unsigned_value!=noc) fprintf(stderr,"Update NOC=%llu expected=%u\n",(unsigned long long)f->e.unsigned_value,noc);
        OC_CHECK(f->e.unsigned_value==noc);
    }
}
static void update_csr(FabFixture* f,unsigned scalar,bool update) {
    fab_scalar_value=(uint8_t)scalar; oc_request(f->o,4,0,32,update);
    memcpy(f->args,f->o->request,f->o->request_size); f->args_size=f->o->request_size;
    update_call(f,4,true,0,0);
}
static void update_checks(StoreTest* t,FabFixture* f) {
    case_establish(t->cases);
    for(unsigned i=0;i<2;++i) OC_CHECK(matter_case_take_keys(t->cases->session[i],&t->cases->keys[i])==MATTER_OK);
    Matter_Case_Port_T resume=matter_fabric_host_case_port(f->host);
    OC_CHECK(resume.resume_find(f->host,1,101,NULL,&t->resumption[0])==MATTER_OK);
    read_file(t); OC_CHECK(matter_store_tlv_decode(t->bytes,t->size,&t->previous)==MATTER_OK);
    Matter_Exchange_Session_T invoker; uint64_t epoch=matter_fabric_host_credential_revision(f->host,1,&invoker);
    fab_request(f,7,FAB_CERT(fab_conflict),(Matter_Cert_Tlv_T){0},0);
    update_call(f,7,false,0xca,0); update_call(f,7,true,0,4);
    update_csr(f,11,false); fab_request(f,7,FAB_CERT(fab_conflict),(Matter_Cert_Tlv_T){0},0);
    update_call(f,7,true,MATTER_IM_CONSTRAINT_ERROR,0);
    OC_CHECK(matter_opcreds_rollback(f->o->core)==MATTER_OK);
    update_csr(f,11,true);
    fab_request(f,7,FAB_CERT(fab_noc1),(Matter_Cert_Tlv_T){0},0); update_call(f,7,true,0,3); /* Different fabric. */
    fab_request(f,7,FAB_CERT(fab_noc0),(Matter_Cert_Tlv_T){0},0); update_call(f,7,true,0,1); /* Wrong CSR key. */
    fab_request(f,7,FAB_CERT(fab_conflict),(Matter_Cert_Tlv_T){0},0);
    ++f->o->challenge[0]; update_call(f,7,true,0,4); --f->o->challenge[0]; /* Replaced secure incarnation. */
    read_file(t); memcpy(t->copy,t->bytes,t->size); t->copy_size=t->size;
    for(unsigned fault=1;fault<=4;++fault) {
        matter_store_file_fault(t->file,fault); update_call(f,7,true,MATTER_IM_FAILURE,0); same_file(t);
        OC_CHECK(f->port.view(f->host)->records[0].node_id==100 && matter_opcreds_host_candidate(f->o->host,f->o->candidate)==MATTER_OK);
        OC_CHECK(matter_fabric_host_credential_revision(f->host,1,&invoker)==epoch);
        OC_CHECK(resume.resume_find(f->host,0,0,t->resumption[0].id,&t->resumption[1])==MATTER_OK);
    }
    matter_store_file_fault(t->file,0);
#ifdef MATTER_TEST_ALLOC
    fail_at=calls+1; update_call(f,7,true,0,3); fail_at=0; same_file(t); /* Certificate validation OOM. */
#endif
    update_call(f,7,true,0,0);
    OC_CHECK(resume.resume_find(f->host,0,0,t->resumption[0].id,&t->resumption[1])==MATTER_INVALID_STATE);
    OC_CHECK(resume.resume_save(f->host,&t->resumption[0])==MATTER_INVALID_STATE);
    OC_CHECK(matter_fabric_host_credential_revision(f->host,1,&invoker)!=epoch && invoker==1);
    update_call(f,7,true,MATTER_IM_CONSTRAINT_ERROR,0);
    vid_request(f,7,0x6a02,85,400); vid_call(f,1,12,0);
    read_file(t); OC_CHECK(matter_store_tlv_decode(t->bytes,t->size,&t->data)==MATTER_OK);
    OC_CHECK(t->data.schema==7 && t->data.fabrics.previous.node_id==100 && t->data.fabrics.view.records[0].node_id==101);
    OC_CHECK(t->data.fabrics.view.count==1 && !memcmp(&t->data.fabrics.acl,&t->previous.fabrics.acl,sizeof(t->data.fabrics.acl)) &&
        !memcmp(&t->data.fabrics.groupkey,&t->previous.fabrics.groupkey,sizeof(t->data.fabrics.groupkey)) &&
        !memcmp(t->data.fabrics.groupkeys,t->previous.fabrics.groupkeys,sizeof(t->data.fabrics.groupkeys)));
    /* schema1/2 cannot silently discard an active credential rollback image. */
    size_t n=0; t->data.schema=2; OC_CHECK(encode_checked(&t->data,t->copy,sizeof(t->copy),&n)==MATTER_INVALID_ARGUMENT);
    matter_store_file_fault(t->file,4); OC_CHECK(matter_opcreds_rollback(f->o->core)==MATTER_PORT_ERROR);
    OC_CHECK(f->port.view(f->host)->records[0].node_id==101); matter_store_file_fault(t->file,0);
    OC_CHECK(f->port.label(f->host,1,(const uint8_t*)"new label",9)==MATTER_OK);
    OC_CHECK(matter_opcreds_rollback(f->o->core)==MATTER_OK && f->port.view(f->host)->records[0].node_id==100);
    OC_CHECK(f->port.view(f->host)->records[0].vendor==t->previous.fabrics.view.records[0].vendor && !f->port.view(f->host)->records[0].vvs_size && !f->port.view(f->host)->records[0].vvsc_size);
    OC_CHECK(!memcmp(f->port.view(f->host)->records[0].label,"new label",9));
    OC_CHECK(resume.resume_find(f->host,0,0,t->resumption[0].id,&t->resumption[1])==MATTER_INVALID_STATE);
    OC_CHECK(resume.resume_save(f->host,&t->resumption[0])==MATTER_INVALID_STATE);
    puts("PASS resumption UpdateNOC: failed publication keeps cache, success erases it, rollback rejects old revision");
    /* Successful commit keeps new identity and erases the old private key. */
    update_csr(f,11,true); fab_request(f,7,FAB_CERT(fab_conflict),(Matter_Cert_Tlv_T){0},0); update_call(f,7,true,0,0);
    vid_request(f,7,0x6a03,85,400); vid_call(f,1,12,0);
    matter_store_file_fault(t->file,4); OC_CHECK(matter_fabric_host_commit(f->host)==MATTER_PORT_ERROR);
    matter_store_file_fault(t->file,0); OC_CHECK(matter_fabric_host_commit(f->host)==MATTER_OK);
    read_file(t); OC_CHECK(matter_store_tlv_decode(t->bytes,t->size,&t->data)==MATTER_OK && !t->data.fabrics.journal && !t->data.fabrics.previous.index);
    OC_CHECK(t->data.fabrics.view.records[0].vendor==0x6a03 && t->data.fabrics.view.records[0].vvs_size==85);
    for(unsigned i=0;i<32;++i) OC_CHECK(!t->data.fabrics.previous_key[i]);
    /* Restore original identity through another real rotation for the later
     * independent-process CASE checks. Pending restart covered on real wire. */
    update_csr(f,10,true); fab_request(f,7,FAB_CERT(fab_noc0),(Matter_Cert_Tlv_T){0},0); update_call(f,7,true,0,0);
    OC_CHECK(matter_fabric_host_commit(f->host)==MATTER_OK);
    vid_request(f,7,0xfff1,0,0); vid_call(f,1,12,0);
    OC_CHECK(f->port.label(f->host,1,(const uint8_t*)"persisted",9)==MATTER_OK);
    puts("PASS UpdateNOC store: generic CASE/CSR purpose/incarnation, fabric/key rejection, retry/OOM/file faults, rollback, independent label/ACL/IPK, commit/key erasure");
}

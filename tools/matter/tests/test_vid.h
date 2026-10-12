/* Core 1.6.1 6.4.10, 11.18.6.14-16 / TC-OPCREDS-3.8.
 * Workspaces belong to the existing heap fixture. */
static inline void vid_request(FabFixture* f,unsigned fields,uint16_t vendor,size_t vvs,size_t vvsc) {
    memset(f->changed,0x5a,sizeof(f->changed));
    OC_CHECK(matter_tlv_writer_init(&f->writer,f->args,sizeof(f->args),3)==MATTER_TLV_OK);
    fab_put(f,MATTER_TLV_STRUCTURE,-1,0,NULL,0);
    if(fields&1) fab_put(f,MATTER_TLV_UNSIGNED,0,vendor,NULL,0);
    if(fields&2) fab_put(f,MATTER_TLV_BYTES,1,0,f->changed,vvs);
    if(fields&4) fab_put(f,MATTER_TLV_BYTES,2,0,f->changed,vvsc);
    fab_put(f,MATTER_TLV_END,-1,0,NULL,0);
    OC_CHECK(matter_tlv_writer_finish(&f->writer,&f->args_size)==MATTER_TLV_OK);
}
static inline void vid_sign_request(FabFixture* f,unsigned index,size_t size) {
    OC_CHECK(matter_tlv_writer_init(&f->writer,f->args,sizeof(f->args),2)==MATTER_TLV_OK);
    fab_put(f,MATTER_TLV_STRUCTURE,-1,0,NULL,0);
    fab_put(f,MATTER_TLV_UNSIGNED,0,index,NULL,0);
    fab_put(f,MATTER_TLV_BYTES,1,0,f->o->nonce,size);
    fab_put(f,MATTER_TLV_END,-1,0,NULL,0);
    OC_CHECK(matter_tlv_writer_finish(&f->writer,&f->args_size)==MATTER_TLV_OK);
}
static inline void vid_call(FabFixture* f,uint8_t accessing,uint32_t command,uint8_t expected) {
    Matter_Cluster_Request_T q={.session=1,.fabric=accessing,.is_case=true};
    OC_CHECK(matter_tlv_writer_init(&f->writer,f->response,sizeof(f->response),3)==MATTER_TLV_OK);
    Matter_Result_T r=matter_cluster_start(f->o->core,command,&q,f->args,f->args_size,&f->writer,&f->result,&f->token);
    for(unsigned i=0;i<8 && r==MATTER_PENDING;++i) {
        Matter_Result_T step=matter_opcreds_process(f->o->core); OC_CHECK(step==MATTER_OK || step==MATTER_PENDING);
        r=matter_cluster_poll(f->o->core,f->token,&f->writer,&f->result);
    }
    if(r!=MATTER_OK || f->result.status!=expected) fprintf(stderr,"VID cmd=%u result=%d status=%u expected=%u\n",command,r,f->result.status,expected);
    OC_CHECK(r==MATTER_OK && f->result.status==expected);
    if(!expected && command==13) OC_CHECK(matter_tlv_writer_finish(&f->writer,&f->response_size)==MATTER_TLV_OK);
}
static inline void vid_verify(FabFixture* f,unsigned slot) {
    const Matter_Fabric_Record_T* r=&f->port.view(f->host)->records[slot];
    OC_CHECK(matter_tlv_init(&f->reader,f->response,f->response_size,2)==MATTER_TLV_OK);
    OC_CHECK(matter_tlv_next(&f->reader,&f->e)==MATTER_TLV_OK && f->e.type==MATTER_TLV_STRUCTURE);
    OC_CHECK(matter_tlv_next(&f->reader,&f->e)==MATTER_TLV_OK && f->e.tag.number==0 && f->e.unsigned_value==r->index);
    OC_CHECK(matter_tlv_next(&f->reader,&f->e)==MATTER_TLV_OK && f->e.tag.number==1 && f->e.unsigned_value==1);
    OC_CHECK(matter_tlv_next(&f->reader,&f->e)==MATTER_TLV_OK && f->e.tag.number==2 && f->e.type==MATTER_TLV_BYTES && f->e.size==64);
    memcpy(f->signature,f->e.data,64);
    OC_CHECK(matter_tlv_next(&f->reader,&f->e)==MATTER_TLV_OK && f->e.type==MATTER_TLV_END && matter_tlv_next(&f->reader,&f->e)==MATTER_TLV_DONE);
    uint8_t* b=f->wire; size_t n=0;
    b[n++]=1; memcpy(b+n,f->o->nonce,32); n+=32; memcpy(b+n,f->o->challenge,16); n+=16;
    b[n++]=r->index; b[n++]=1; memcpy(b+n,r->root_public,65); n+=65;
    for(unsigned j=0;j<8;++j) b[n++]=(uint8_t)(r->fabric_id>>(8*(7-j)));
    b[n++]=(uint8_t)(r->vendor>>8); b[n++]=(uint8_t)r->vendor;
    memcpy(b+n,r->vvs,r->vvs_size); n+=r->vvs_size;
    OC_CHECK(n==126u+r->vvs_size);
    OC_CHECK(f->o->crypto.ecdsa_verify(f->o->crypto.user,r->operational_public,b,n,f->signature)==MATTER_OK);
    const unsigned offsets[]={0,1,33,49,50,51,116,124,125};
    for(unsigned j=0;j<sizeof(offsets)/sizeof(*offsets);++j) {
        b[offsets[j]]^=1;
        OC_CHECK(f->o->crypto.ecdsa_verify(f->o->crypto.user,r->operational_public,b,n,f->signature)!=MATTER_OK);
        b[offsets[j]]^=1;
    }
    if(r->vvs_size) { b[n-1]^=1; OC_CHECK(f->o->crypto.ecdsa_verify(f->o->crypto.user,r->operational_public,b,n,f->signature)!=MATTER_OK); }
}
static inline void vid_checks(FabFixture* f) {
    Matter_Im_Command_T c;
    OC_CHECK(!matter_cluster_command(f->o->core,12,&c) && c.privilege==MATTER_IM_ADMINISTER && c.fabric_scoped && !c.response);
    OC_CHECK(!matter_cluster_command(f->o->core,13,&c) && !c.fabric_scoped && c.response_command==14 && c.response_capacity==75);
    /* Caller fabric1 signs fabric2: legitimate cross-fabric transparency. */
    vid_sign_request(f,2,32); vid_call(f,1,13,0); vid_verify(f,1);
    vid_request(f,0,0,0,0); vid_call(f,1,12,MATTER_IM_INVALID_COMMAND);
    vid_request(f,1,0,0,0); vid_call(f,1,12,MATTER_IM_CONSTRAINT_ERROR);
    vid_request(f,1,0xfff5,0,0); vid_call(f,1,12,MATTER_IM_CONSTRAINT_ERROR);
    vid_request(f,2,0,84,0); vid_call(f,1,12,MATTER_IM_CONSTRAINT_ERROR);
    vid_request(f,2,0,86,0); vid_call(f,1,12,MATTER_IM_CONSTRAINT_ERROR);
    vid_request(f,7,0x6a01,85,400);
    size_t full=f->args_size;
    for(size_t n=0;n<full;++n) OC_CHECK(matter_opcreds_validate(f->o->core,12,f->args,n)!=0);
    uint32_t version=matter_opcreds_version(f->o->core);
    f->control.fail_store=true; matter_fabric_host_control(f->host,&f->control);
    vid_call(f,2,12,MATTER_IM_FAILURE); OC_CHECK(matter_opcreds_version(f->o->core)==version);
    f->control.fail_store=false; matter_fabric_host_control(f->host,&f->control);
    vid_call(f,2,12,0);
    const Matter_Fabric_View_T* v=f->port.view(f->host);
    OC_CHECK(v->records[1].vendor==0x6a01 && v->records[1].vvs_size==85 && v->records[1].vvsc_size==400);
    OC_CHECK(v->records[0].vendor==0xfff1 && !v->records[0].vvs_size && !v->records[0].vvsc_size);
    OC_CHECK(matter_opcreds_version(f->o->core)==version+1);
    vid_call(f,2,12,0); OC_CHECK(matter_opcreds_version(f->o->core)==version+1); /* no-op */
    Matter_Im_Value_T val;
    OC_CHECK(!matter_opcreds_read_fabric(f->o->core,0,2,true,&val) && val.size>400);
    OC_CHECK(!matter_opcreds_read_fabric(f->o->core,1,2,true,&val));
    OC_CHECK(matter_tlv_init(&f->reader,val.data,val.size,3)==MATTER_TLV_OK);
    unsigned statement=0;
    while(matter_tlv_next(&f->reader,&f->e)==MATTER_TLV_OK) if(f->e.tag.control==1 && f->e.tag.number==6) {
        OC_CHECK(f->e.type==MATTER_TLV_BYTES && f->e.size==85 && !memcmp(f->e.data,f->changed,85)); ++statement;
    }
    OC_CHECK(statement==1);
    vid_sign_request(f,2,32); vid_call(f,1,13,0); vid_verify(f,1);
    OC_CHECK(f->o->crypto.ecdsa_verify(f->o->crypto.user,v->records[0].operational_public,f->wire,211,f->signature)!=MATTER_OK);
    for(unsigned index=0;index<=255;index+=255) { vid_sign_request(f,index,32); vid_call(f,1,13,MATTER_IM_CONSTRAINT_ERROR); }
    vid_sign_request(f,254,32); vid_call(f,1,13,MATTER_IM_CONSTRAINT_ERROR);
    vid_sign_request(f,2,31); vid_call(f,1,13,MATTER_IM_CONSTRAINT_ERROR);
    vid_sign_request(f,2,32);
    Matter_Cluster_Request_T q={.session=1,.fabric=1,.is_case=true};
    OC_CHECK(matter_tlv_writer_init(&f->writer,f->response,sizeof(f->response),3)==MATTER_TLV_OK);
    OC_CHECK(matter_cluster_start(f->o->core,13,&q,f->args,f->args_size,&f->writer,&f->result,&f->token)==MATTER_PENDING);
    ++f->o->challenge[0];
    for(unsigned i=0;i<2;++i) (void)matter_opcreds_process(f->o->core);
    OC_CHECK(matter_cluster_poll(f->o->core,f->token,&f->writer,&f->result)==MATTER_OK && f->result.status==MATTER_IM_UNSUPPORTED_ACCESS);
    --f->o->challenge[0];
    OC_CHECK(matter_cluster_start(f->o->core,13,&q,f->args,f->args_size,&f->writer,&f->result,&f->token)==MATTER_PENDING);
    OC_CHECK(matter_opcreds_process(f->o->core)==MATTER_OK); ++f->o->challenge[0];
    OC_CHECK(matter_cluster_poll(f->o->core,f->token,&f->writer,&f->result)==MATTER_OK && f->result.status==MATTER_IM_UNSUPPORTED_ACCESS);
    --f->o->challenge[0];
    /* PASE also binds its challenge; after commit it cannot Set a fabric. */
    fab_call(f,1,13,false,0,0);
    vid_request(f,6,0,0,0); vid_call(f,2,12,0);
    OC_CHECK(!v->records[1].vvs_size && !v->records[1].vvsc_size);
    OC_CHECK(matter_opcreds_start(f->o->core,1,12,false,f->args,f->args_size,NULL,&f->result,&f->token)==MATTER_OK && f->result.status==MATTER_IM_UNSUPPORTED_ACCESS);
    puts("PASS VID: validation, metadata, two fabrics, NOC signatures/challenge binding, session revocation, atomic failure/no-op and erase");
}

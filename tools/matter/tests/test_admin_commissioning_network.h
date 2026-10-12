#ifdef MATTER_TEST_HOST_UDP
typedef struct {
    AclNetwork peers; AdminFixture wire; GcFixture* gc; Pair* pase;
    Matter_Root_Case_Invoke_Binding_T binding;
    bool deny,pase_fail_safe,revoked;
} AdminNetwork;
static uint8_t admin_access_network(void* u,Matter_Exchange_Session_T s,const Matter_Im_Path_T* p,Matter_Im_Privilege_T v) {
    AdminNetwork* n=u; return n->deny && v==MATTER_IM_ADMINISTER?MATTER_IM_UNSUPPORTED_ACCESS:acl_access(&n->peers,s,p,v);
}
static Matter_Result_T admin_vendor_network(void* u,uint8_t index,uint16_t* vendor) {
    AdminNetwork* n=u; FabFixture* f=n->peers.admin->fabrics[1]; const Matter_Fabric_View_T* v=f->port.view(f->host);
    for(unsigned i=0;i<v->count;++i) if(v->records[i].index==index) { *vendor=v->records[i].vendor; return MATTER_OK; }
    return MATTER_INVALID_STATE;
}
static Matter_Result_T admin_blocked_network(void* u,bool* blocked) {
    AdminNetwork* n=u; Matter_Root_Fail_Safe_State_T state;
    Matter_Result_T r=matter_root_fail_safe_state(n->peers.root->root,&state); *blocked=state!=MATTER_ROOT_FAIL_SAFE_IDLE; return r;
}
static Matter_Result_T admin_advertise_network(void* u,bool open,uint16_t discriminator) { return admin_advertise(&((AdminNetwork*)u)->wire,open,discriminator); }
static Matter_Result_T admin_retire_network(void* u) {
    AdminNetwork* n=u; n->revoked=true;
    if(!n->pase) return MATTER_OK;
    Peer* p=&n->pase->b;
    if(p->pase) {
        REQUIRE(matter_pase_cancel(p->pase)==MATTER_OK);
        if(p->tx_pins) { Matter_Result_T r=matter_retransmission_sender_cancel(p->tx,p->message_id); REQUIRE(r==MATTER_OK || r==MATTER_PENDING); }
        if(p->handle) { REQUIRE(matter_rx_close(p->rx,p->handle)==MATTER_OK); p->handle=0; }
        return p->tx_pins || p->ack_pins?MATTER_PENDING:MATTER_OK;
    }
    return matter_secure_channel_retire(p->channel,p->rx,p->tx);
}
static Matter_Result_T admin_revoke_network(void* u) {
    AdminNetwork* n=u; ++n->wire.revokes;
    if(n->pase_fail_safe) { Matter_Result_T r=matter_root_expire(n->peers.root->root); if(r!=MATTER_OK && r!=MATTER_PENDING) return r; }
    Matter_Result_T r=admin_retire_network(n); if(r!=MATTER_OK) return r;
    Matter_Root_Fail_Safe_State_T state; REQUIRE(matter_root_fail_safe_state(n->peers.root->root,&state)==MATTER_OK);
    return n->pase_fail_safe && state!=MATTER_ROOT_FAIL_SAFE_IDLE?MATTER_PENDING:MATTER_OK;
}
static void admin_service(AdminNetwork* n) {
    Matter_Result_T r=matter_cluster_process(n->wire.model,n->peers.now); REQUIRE(r==MATTER_OK || r==MATTER_PENDING);
    r=matter_root_process(n->peers.root->root,n->peers.now); REQUIRE(r==MATTER_OK || r==MATTER_PENDING);
}
static void admin_wire_request(AdminFixture* w,unsigned cmd,bool timed) {
    const uint8_t head[]={0x15,0x28,0,0x28,1,0x36,2,0x15,0x37,0,0x24,0,0,0x24,1,0x3c,0x24,2,0,0x18,0x35,1};
    const uint8_t tail[]={0x18,0x18,0x24,255,13,0x18};
    memcpy(w->request,head,sizeof(head)); w->request[3]=timed?0x29:0x28; w->request[18]=(uint8_t)cmd;
    memcpy(w->request+sizeof(head),w->args+1,w->n-1); memcpy(w->request+sizeof(head)+w->n-1,tail,sizeof(tail));
    w->request_size=sizeof(head)+w->n-1+sizeof(tail);
}
static bool admin_invoke_network(AdminNetwork* n,unsigned cmd,bool timed,uint8_t expected,int cluster,bool loss,bool drain) {
    bool ok=false; AclNetwork* h=&n->peers; PaseFixture* f=h->net; f->link=h->links[0];
    Peer* a=&f->link->a; Peer* b=&f->link->b; AdminFixture* w=&n->wire;
    CHECK(fab_exchange(f)); admin_wire_request(w,cmd,timed);
    Matter_Im_Invoke_Port_T port; Matter_Im_Invoke_Async_Port_T async; Matter_Im_Read_Fabric_Port_T resolver;
    CHECK(matter_root_case_invoke_port(h->root->root,b->secure_token,b->secure,&n->binding,&port,&async,&resolver)==MATTER_OK);
    Matter_Im_Invoke_Config_T config={{b->secure_token,a->key.exchange_id,false},30000,256,false};
    b->invoke=matter_im_invoke_new_case(&port,&async,&resolver,&config,++h->now); CHECK(b->invoke);
    if(timed) {
        const uint8_t request[]={0x15,0x25,0,0x88,0x13,0x24,255,13,0x18}; /* 5000 ms. */
        CHECK(im_host_send(f,a,10,request,sizeof(request),h->now) && tick(a,h->now)); network_poll(a);
        CHECK(network_take(a) && network_receive(b) && network_admit(b,h->now) && tick(b,h->now) && im_ack_transfer(b,a,h->now+=200));
        admin_service(n); CHECK(matter_im_invoke_process(b->invoke,h->now)==MATTER_PENDING);
        Matter_Im_Invoke_Message_T out; CHECK(matter_im_invoke_output(b->invoke,&out)==MATTER_OK && out.opcode==1 && !out.data[3]);
        CHECK(im_host_send(f,b,1,out.data,out.size,h->now) && tick(b,h->now)); network_poll(b);
        CHECK(network_take(b) && network_receive(a) && network_admit(a,h->now) && tick(a,h->now) && im_ack_transfer(a,b,h->now+=200));
    }
    CHECK(im_host_send(f,a,8,w->request,w->request_size,++h->now) && tick(a,h->now)); network_poll(a);
    CHECK(network_take(a) && network_receive(b)); f->link->delayed_data=b->inbox;
    CHECK(network_admit(b,h->now) && tick(b,h->now) && im_ack_transfer(b,a,h->now+=200));
    admin_service(n); CHECK(matter_im_invoke_process(b->invoke,h->now)==MATTER_PENDING);
    unsigned opens=w->opens,deliveries=b->deliveries;
    CHECK(receive_packet(b,&f->link->delayed_data,h->now)==MATTER_OK && tick(b,h->now) && deliveries==b->deliveries && im_ack_transfer(b,a,h->now));
    if(drain) {
        admin_service(n); CHECK(n->revoked && n->pase->b.tx_pins && n->gc->marker);
        Matter_Secure_Info_T info; CHECK(matter_secure_info(n->pase->b.secure,&info)==MATTER_OK && info.closing);
        CHECK(matter_im_invoke_state(b->invoke)==MATTER_IM_INVOKE_PENDING);
        network_poll(&n->pase->b); CHECK(network_take(&n->pase->b) && tick(&n->pase->b,h->now));
    }
    for(unsigned i=0;i<4 && matter_im_invoke_state(b->invoke)==MATTER_IM_INVOKE_PENDING;++i) {
        ++h->now; admin_service(n); CHECK(matter_im_invoke_process(b->invoke,h->now)==MATTER_PENDING);
    }
    Matter_Im_Invoke_Message_T out; CHECK(matter_im_invoke_output(b->invoke,&out)==MATTER_OK && out.opcode==9);
    const uint8_t status_head[]={0x15,0x29,0,0x36,1,0x15,0x35,1,0x37,0,0x24,0,0,0x24,1,0x3c,0x24,2,(uint8_t)cmd,0x18,0x35,1,0x24,0,expected};
    const uint8_t status_tail[]={0x18,0x18,0x18,0x18,0x24,255,13,0x18};
    CHECK(out.size==sizeof(status_head)+sizeof(status_tail)+(cluster>=0?3u:0u) && !memcmp(out.data,status_head,sizeof(status_head)));
    if(cluster>=0) CHECK(out.data[25]==0x24 && out.data[26]==1 && out.data[27]==cluster);
    CHECK(!memcmp(out.data+sizeof(status_head)+(cluster>=0?3:0),status_tail,sizeof(status_tail)));
    CHECK(im_host_send(f,b,out.opcode,out.data,out.size,h->now) && tick(b,h->now)); network_poll(b);
    CHECK(network_take(b) && network_receive(a));
    if(loss) {
        f->link->delayed_ack=a->inbox; a->inbox_full=false;
        CHECK(matter_retransmission_sender_deadline(b->tx,&h->now)==MATTER_OK && tick(b,h->now)); complete_resolver(b); network_poll(b);
        CHECK(network_take(b) && network_receive(a) && a->inbox.size==f->link->delayed_ack.size && !memcmp(a->inbox.data,f->link->delayed_ack.data,a->inbox.size) && w->opens==opens);
    }
    CHECK(network_admit(a,h->now) && tick(a,h->now) && im_ack_transfer(a,b,h->now+=200));
    CHECK(matter_im_invoke_state(b->invoke)==MATTER_IM_INVOKE_COMPLETE && matter_im_invoke_delete(b->invoke)==MATTER_OK);
    b->invoke=NULL; a->im_client=false; ok=true;
done: return ok;
}
static bool admin_read_network(AdminNetwork* g,uint32_t attr,bool null,uint64_t expected) {
    bool ok=false; AclNetwork* h=&g->peers; PaseFixture* f=h->net; f->link=h->links[0]; Peer* a=&f->link->a; Peer* b=&f->link->b;
    Matter_Root_Case_Read_Binding_T binding; Matter_Im_Read_Port_T port; Matter_Im_Read_Fabric_Port_T fabric;
    CHECK(fab_exchange(f) && matter_root_case_read_port(h->root->root,b->secure_token,b->secure,&binding,&port,&fabric)==MATTER_OK);
    Matter_Im_Read_Config_T config={{b->secure_token,a->key.exchange_id,false},30000,192,false};
    b->im=matter_im_read_new_case(&port,&fabric,&config,++h->now); CHECK(b->im);
    memcpy(g->wire.request,im_request,sizeof(im_request)); g->wire.request[9]=0x3c; g->wire.request[12]=(uint8_t)attr;
    CHECK(im_host_send(f,a,2,g->wire.request,sizeof(im_request),h->now) && tick(a,h->now)); network_poll(a);
    CHECK(network_take(a) && network_receive(b) && network_admit(b,h->now) && tick(b,h->now));
    CHECK(im_ack_transfer(b,a,h->now+=200) && matter_im_read_process(b->im,h->now)==MATTER_PENDING);
    Matter_Im_Read_Message_T out; CHECK(matter_im_read_output(b->im,&out)==MATTER_OK && out.opcode==5);
    CHECK(im_host_send(f,b,5,out.data,out.size,h->now) && matter_im_read_sent(b->im)==MATTER_OK && tick(b,h->now)); network_poll(b);
    CHECK(network_take(b) && network_receive(a) && network_admit(a,h->now) && tick(a,h->now));
    RootFixture* r=h->root; unsigned values=0;
    CHECK(matter_tlv_init(&r->reader,a->im_received.data,a->im_received.size,8)==MATTER_TLV_OK);
    while(matter_tlv_next(&r->reader,&r->token)==MATTER_TLV_OK) {
        if(r->token.type==MATTER_TLV_LIST) { CHECK(matter_tlv_skip_container(&r->reader)==MATTER_TLV_OK); continue; }
        if(r->token.tag.control!=1 || r->token.tag.number!=2) continue;
        if(r->token.type==(null?MATTER_TLV_NULL:MATTER_TLV_UNSIGNED) && (null || r->token.unsigned_value==expected)) ++values;
    }
    CHECK(values==1 && im_ack_transfer(a,b,h->now+=200) && matter_im_read_state(b->im)==MATTER_IM_READ_COMPLETE);
    CHECK(matter_im_read_delete(b->im)==MATTER_OK); b->im=NULL; a->im_client=false; ok=true;
done: return ok;
}
static bool admin_pase_network(AdminNetwork* n,bool expire) {
    bool ok=false; AclNetwork* h=&n->peers; PaseFixture* f=h->net;
    CHECK(!n->pase); f->link=n->pase=create_network(); CHECK(n->pase);
    if(expire) { CHECK(matter_cluster_deadline(n->wire.model,&h->now)==MATTER_OK); --h->now; }
    for(unsigned i=0;i<2;++i) { CHECK(matter_pase_delete(f->s[i])==MATTER_OK); f->s[i]=NULL; }
    f->s[0]=matter_pase_new(&f->port,&f->config[0],h->now);
    f->s[1]=matter_admin_commissioning_pase_new(n->wire.model,456,30000,h->now); CHECK(f->s[0] && f->s[1]);
    Peer* peers[]={&f->link->a,&f->link->b};
    for(unsigned i=0;i<2;++i) { peers[i]->pase=f->s[i]; CHECK(matter_rx_register(peers[i]->rx,0,0)==MATTER_OK); }
    for(unsigned i=0;i<6;++i) {
        admin_service(n); CHECK(matter_pase_process(peers[i%2]->pase,h->now)==MATTER_PENDING);
        CHECK(transport_message(f,peers[i%2],peers[1-i%2],&h->now,false,true));
    }
    CHECK(matter_pase_process(f->s[0],h->now)==MATTER_OK && same_keys(f));
    for(unsigned i=0;i<2;++i) {
        Peer* p=peers[i]; CHECK(matter_rx_close(p->rx,p->handle)==MATTER_OK); p->handle=0; p->pase=NULL;
        p->secure=matter_secure_new(&f->port,f->s[i],h->now); CHECK(p->secure);
        p->secure_token=40001+i; p->session=p->secure_token; p->channel=matter_secure_channel_new(p->secure,p->secure_token,&p->path); CHECK(p->channel);
        CHECK(matter_rx_register(p->rx,0,1)==MATTER_OK);
    }
    if(expire) {
        CHECK(!n->wire.published && !n->revoked && !matter_admin_commissioning_pase_new(n->wire.model,789,30000,h->now));
        Matter_Secure_Info_T info; CHECK(matter_secure_info(peers[1]->secure,&info)==MATTER_OK && !info.closing);
    }
    ok=true;
done: return ok;
}
static bool network_admin_commissioning(void) {
    bool ok=false; AdminNetwork* n=calloc(1,sizeof(*n)); REQUIRE(n); AclNetwork* h=&n->peers;
    h->net=setup(false,false); PaseFixture* f=h->net; Matter_Credentials_Port_T cp;
    CHECK(matter_crypto_mbedtls_credentials(f->crypto,&cp)==MATTER_OK); h->admin=case_fixture(&f->port,&cp);
    FabFixture* server=h->admin->fabrics[1]; Matter_Acl_Port_T acl=matter_fabric_host_acl_port(server->host); h->acl=matter_acl_new(&acl); CHECK(h->acl);
    n->gc=gc_fixture(); h->root=n->gc->f; n->gc->config.recommended_seconds=180; n->gc->config.cumulative_seconds=900;
    Matter_Root_Port_T root={n,acl_load,admin_access_network,acl_store_root};
    Matter_Root_Commissioning_Port_T gc={n->gc,gc_begin,gc_cleanup,gc_regulatory,NULL};
    h->root->root=matter_root_new_commissioning(&root,&n->gc->config,&gc,h->now); CHECK(h->root->root);
    CHECK(matter_root_attach_opcreds(h->root->root,server->o->core)==MATTER_OK && matter_root_attach_acl(h->root->root,h->acl)==MATTER_OK);
    Matter_Admin_Commissioning_Port_T port={n,admin_vendor_network,admin_blocked_network,admin_advertise_network,admin_revoke_network};
    n->wire.model=matter_admin_commissioning_new(&port,&f->port,17,0); CHECK(n->wire.model && matter_root_attach_cluster(h->root->root,n->wire.model)==MATTER_OK);
    CHECK(acl_handshake(h,0,h->admin->session));
    memcpy(n->wire.verifier,f->config[1].w0,32); memcpy(n->wire.verifier+32,f->config[1].L,65);
    admin_args(&n->wire,&f->config[1],180,1234,1000,16,97);
    CHECK(admin_invoke_network(n,0,false,MATTER_IM_NEEDS_TIMED_INTERACTION,-1,false,false) && !n->wire.opens);
    n->deny=true; CHECK(admin_invoke_network(n,0,true,MATTER_IM_UNSUPPORTED_ACCESS,-1,false,false) && !n->wire.opens); n->deny=false;
    CHECK(admin_invoke_network(n,0,true,0,-1,true,false) && n->wire.published && n->wire.opens==1);
    CHECK(admin_read_network(n,0,false,1) && admin_read_network(n,1,false,1) && admin_read_network(n,2,false,0xfff1));
    CHECK(admin_invoke_network(n,0,true,MATTER_IM_FAILURE,2,false,false));
    /* PASE started just before expiry completes after it; a new attempt fails. */
    CHECK(admin_pase_network(n,true));
    CHECK(admin_read_network(n,0,false,0) && admin_read_network(n,1,true,0) && admin_read_network(n,2,true,0));
    admin_empty(&n->wire); CHECK(admin_invoke_network(n,2,true,MATTER_IM_FAILURE,4,false,false) && n->revoked);
    cleanup(n->pase); n->pase=NULL; n->revoked=false;
    admin_args(&n->wire,&f->config[1],180,99,1000,16,97); CHECK(admin_invoke_network(n,0,true,0,-1,false,false));
    CHECK(admin_pase_network(n,false));
    /* Arm through the existing trusted PASE binding; mutate a transaction
     * participant and hold an encrypted TX while CASE Revoke arrives. */
    CHECK(matter_root_invoke_port(h->root->root,n->pase->b.secure_token,&n->gc->binding,&n->gc->invoke)==MATTER_OK);
    const uint8_t arm[]={0x15,0x25,0,0xb4,0,0x24,1,7,0x18}; Matter_Im_Command_Path_T path={0,0x30,0};
    CHECK(matter_tlv_writer_init(&h->root->writer,h->root->expected,sizeof(h->root->expected),2)==MATTER_TLV_OK);
    CHECK(!n->gc->invoke.invoke(n->gc->invoke.user,&path,arm,sizeof(arm),&h->root->writer).status && n->gc->marker);
    n->gc->network=9; n->pase_fail_safe=true; n->gc->cleanup_hook=admin_retire_network; n->gc->hook_user=n;
    f->link=n->pase;
    CHECK(matter_rx_initiate(n->pase->b.rx,n->pase->b.secure_token,&n->pase->b.handle)==MATTER_OK &&
        matter_rx_get(n->pase->b.rx,n->pase->b.handle,&n->pase->b.key)==MATTER_OK);
    const uint8_t success[]={0x15,0x24,0,0,0x24,255,13,0x18};
    CHECK(im_host_send(f,&n->pase->b,1,success,sizeof(success),h->now) && tick(&n->pase->b,h->now) && n->pase->b.tx_pins);
    admin_empty(&n->wire); CHECK(admin_invoke_network(n,2,true,0,-1,false,true));
    CHECK(!n->gc->marker && n->gc->network==3 && !n->wire.published && !n->pase->b.tx_pins);
    Matter_Secure_Identity_T identity; CHECK(matter_secure_identity(h->links[0]->b.secure,&identity)==MATTER_OK);
    admin_empty(&n->wire); CHECK(admin_invoke_network(n,2,true,MATTER_IM_FAILURE,4,false,false));
    puts("PASS Administrator Commissioning CASE/IPv6: timed/Administer, retry/duplicate, new PASE across window expiry, revoke closed/open, retained encrypted TX drain and fail-safe rollback; CASE survives"); ok=true;
done:
    if(n->gc) gc_release(n->gc,h->now);
    if(n->wire.model) { (void)matter_admin_commissioning_close(n->wire.model); REQUIRE(matter_cluster_process(n->wire.model,h->now)==MATTER_OK); REQUIRE(matter_cluster_delete(n->wire.model)==MATTER_OK); }
    if(n->pase) cleanup(n->pase);
    if(h->links[0]) cleanup(h->links[0]);
    if(h->acl) REQUIRE(matter_acl_delete(h->acl)==MATTER_OK);
    if(h->admin) case_free(h->admin);
    f->link=NULL; dispose(f); free(n); return ok;
}
#endif

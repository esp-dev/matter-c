#ifdef MATTER_TEST_HOST_UDP
#include "matter_commissioning_host.h"
#include "matter_store_host.h"
#include "matter_store_file.h"
typedef struct {
    PaseFixture* net; Pair* pase; Pair* operational; WifiFixture* w; FabFixture* server; FabFixture* client;
    Matter_Commissioning_Host_Image_T image; Matter_Commissioning_Host_T host;
    Matter_Case_T cases[2]; Matter_Root_Async_Invoke_Binding_T pase_binding;
    Matter_Root_Case_Invoke_Binding_T case_binding; Matter_Im_Invoke_Port_T invoke;
    Matter_Im_Invoke_Async_Port_T async; Matter_Im_Read_Fabric_Port_T resolver;
    Matter_Store_File_T file; Matter_Store_Host_T store; Matter_Diagnostics_Host_Image_T diagnostics;
    char* storage_path;
    uint64_t now; unsigned commits; bool closed,crash,deny;
} CompleteFixture;
static Matter_Result_T complete_load(void* u,Matter_Root_Config_T* c) { return root_load(((CompleteFixture*)u)->w->g->f,c); }
static Matter_Result_T complete_store(void* u,const Matter_Root_Settings_T* c) { CompleteFixture* f=u; return f->store?matter_store_host_root(f->store,c):root_store(f->w->g->f,c); }
static uint8_t complete_authorize(void* u,Matter_Exchange_Session_T token,const Matter_Im_Path_T* p,Matter_Im_Privilege_T v) {
    CompleteFixture* c=u; (void)p;
    if(c->deny) return MATTER_IM_UNSUPPORTED_ACCESS;
    if(!c->closed && token==c->pase->b.secure_token) return 0;
    if(c->operational && token==c->operational->b.secure_token) {
        Matter_Secure_Identity_T id;
        if(matter_secure_identity(c->operational->b.secure,&id)==MATTER_OK &&
            matter_fabric_host_case_authorize(c->server->host,id.fabric_index,id.peer_node_id,id.cats,id.cat_count,v)) return 0;
    }
    return MATTER_IM_UNSUPPORTED_ACCESS;
}
static Matter_Result_T complete_retire(void* u,bool success) {
    CompleteFixture* c=u; c->closed=true; /* Admission/window/grants closed BEFORE drain. */
    if(!success && c->operational) {
        Matter_Result_T r=matter_secure_channel_retire(c->operational->b.channel,c->operational->b.rx,c->operational->b.tx);
        if(r!=MATTER_OK) return r;
    }
    return matter_secure_channel_retire(c->pase->b.channel,c->pase->b.rx,c->pase->b.tx);
}
static Matter_Result_T complete_begin(void* u) { return matter_commissioning_host_begin(((CompleteFixture*)u)->host); }
static Matter_Result_T complete_cleanup(void* u) {
    CompleteFixture* c=u; return c->crash?MATTER_OK:matter_commissioning_host_cleanup(c->host);
}
static Matter_Result_T complete_regulatory(void* u,const Matter_Root_Settings_T* s,uint8_t v,bool* country) { return gc_regulatory(((CompleteFixture*)u)->w->g,s,v,country); }
static Matter_Result_T complete_commit(void* u,uint8_t index) {
    CompleteFixture* c=u; Matter_Result_T r=matter_commissioning_host_complete(c->host,index); if(r==MATTER_OK) ++c->commits; return r;
}
static void complete_root(CompleteFixture* c,bool recover) {
    GcFixture* g=c->w->g; Matter_Root_Port_T p={c,complete_load,complete_authorize,complete_store};
    Matter_Root_Commissioning_Port_T cp={c,complete_begin,complete_cleanup,complete_regulatory,NULL};
    g->config.recover_pending=recover; g->f->root=matter_root_new_commissioning(&p,&g->config,&cp,c->now); REQUIRE(g->f->root);
    if(!recover) {
        REQUIRE(matter_root_attach_wifi(g->f->root,c->w->wifi)==MATTER_OK && matter_root_attach_opcreds(g->f->root,c->server->o->core)==MATTER_OK);
        Matter_Root_Complete_Port_T complete={c,complete_commit}; REQUIRE(matter_root_attach_complete(g->f->root,&complete)==MATTER_OK);
    }
    REQUIRE(matter_root_ports(g->f->root,&g->f->read,&g->f->write)==MATTER_OK);
}
static bool complete_request(CompleteFixture* c,bool pase,uint8_t expected,bool status,bool pending_tx,bool loss) {
    bool ok=false; PaseFixture* f=c->net; Peer* a=&f->link->a; Peer* b=&f->link->b; GcFixture* g=c->w->g;
    CHECK(fab_exchange(f)); gc_request(g,4,0,NULL,0);
    Matter_Im_Invoke_Config_T config={{b->secure_token,a->key.exchange_id,false},10000,256,pase};
    Matter_Im_Read_Fabric_Port_T resolver={matter_root_invoke_fabric};
    b->invoke=pase?matter_im_invoke_new_fabric(&g->invoke,&c->w->async,&resolver,&config,++c->now):
        matter_im_invoke_new_case(&c->invoke,&c->async,&c->resolver,&config,++c->now); CHECK(b->invoke);
    CHECK(im_host_send(f,a,8,g->f->request,g->f->request_size,c->now) && tick(a,c->now)); network_poll(a);
    CHECK(network_take(a) && network_receive(b)); f->link->delayed_data=b->inbox;
    CHECK(network_admit(b,c->now) && tick(b,c->now));
    CHECK(receive_packet(b,&f->link->delayed_data,c->now)==MATTER_OK && tick(b,c->now)); /* No second command. */
    CHECK(im_ack_transfer(b,a,c->now+=200));
    CHECK(matter_im_invoke_process(b->invoke,c->now)==MATTER_PENDING);
    if(pending_tx) {
        CHECK(matter_root_process(g->f->root,c->now)==MATTER_PENDING && c->closed && matter_commissioning_host_pending(c->image));
        CHECK(c->server->port.view(c->server->host)->added && !c->commits);
        Matter_Secure_Info_T info; CHECK(matter_secure_info(c->pase->b.secure,&info)==MATTER_OK && info.closing);
        network_poll(&c->pase->b); CHECK(network_take(&c->pase->b) && tick(&c->pase->b,c->now));
    }
    for(unsigned i=0;i<5 && matter_im_invoke_state(b->invoke)!=MATTER_IM_INVOKE_OUTPUT;++i) {
        Matter_Result_T r=matter_root_process(g->f->root,++c->now); CHECK(r==MATTER_OK || r==MATTER_PENDING);
        CHECK(matter_im_invoke_process(b->invoke,c->now)==MATTER_PENDING);
    }
    Matter_Im_Invoke_Message_T out; CHECK(matter_im_invoke_output(b->invoke,&out)==MATTER_OK && out.opcode==9); gc_reply(out.data,out.size,4,expected,status);
    CHECK(im_host_send(f,b,9,out.data,out.size,c->now) && matter_im_invoke_sent_at(b->invoke,c->now)==MATTER_OK && tick(b,c->now)); network_poll(b);
    CHECK(network_take(b) && network_receive(a));
    if(loss) {
        f->link->delayed_ack=a->inbox; a->inbox_full=false; unsigned commits=c->commits;
        CHECK(matter_retransmission_sender_deadline(b->tx,&c->now)==MATTER_OK && tick(b,c->now)); complete_resolver(b); network_poll(b);
        CHECK(network_take(b) && network_receive(a) && a->inbox.size==f->link->delayed_ack.size && !memcmp(a->inbox.data,f->link->delayed_ack.data,a->inbox.size));
        CHECK(c->commits==commits);
    }
    CHECK(network_admit(a,c->now) && tick(a,c->now) && im_ack_transfer(a,b,c->now+=200));
    CHECK(matter_im_invoke_state(b->invoke)==MATTER_IM_INVOKE_COMPLETE && matter_im_invoke_delete(b->invoke)==MATTER_OK);
    b->invoke=NULL; a->im_client=false; ok=true;
done: return ok;
}
static bool complete_read(CompleteFixture* c) {
    bool ok=false; PaseFixture* f=c->net; Peer* a=&f->link->a; Peer* b=&f->link->b;
    Matter_Root_Case_Read_Binding_T binding; Matter_Im_Read_Port_T port; Matter_Im_Read_Fabric_Port_T fabric;
    CHECK(fab_exchange(f) && matter_root_case_read_port(c->w->g->f->root,b->secure_token,b->secure,&binding,&port,&fabric)==MATTER_OK);
    Matter_Im_Read_Config_T config={{b->secure_token,a->key.exchange_id,false},10000,256,false}; b->im=matter_im_read_new_case(&port,&fabric,&config,++c->now); CHECK(b->im);
    CHECK(im_host_send(f,a,2,im_request,sizeof(im_request),c->now) && tick(a,c->now)); network_poll(a);
    CHECK(network_take(a) && network_receive(b) && network_admit(b,c->now) && tick(b,c->now));
    CHECK(im_ack_transfer(b,a,c->now+=200) && matter_im_read_process(b->im,c->now)==MATTER_PENDING);
    Matter_Im_Read_Message_T out; CHECK(matter_im_read_output(b->im,&out)==MATTER_OK && out.opcode==5);
    CHECK(im_host_send(f,b,5,out.data,out.size,c->now) && matter_im_read_sent(b->im)==MATTER_OK && tick(b,c->now)); network_poll(b);
    CHECK(network_take(b) && network_receive(a) && network_admit(a,c->now) && tick(a,c->now) && im_ack_transfer(a,b,c->now+=200));
    CHECK(a->im_received.size && matter_im_read_state(b->im)==MATTER_IM_READ_COMPLETE);
    FabFixture* m=c->server; unsigned found=0;
    CHECK(matter_tlv_init(&m->reader,a->im_received.data,a->im_received.size,8)==MATTER_TLV_OK);
    while(matter_tlv_next(&m->reader,&m->e)==MATTER_TLV_OK)
        if(m->e.type==MATTER_TLV_UNSIGNED && m->e.tag.control==1 && m->e.tag.number==2 && m->e.unsigned_value==0xfff1) ++found;
    CHECK(found==1);
    CHECK(matter_im_read_delete(b->im)==MATTER_OK); b->im=NULL; a->im_client=false; ok=true;
done: return ok;
}
static bool network_complete(unsigned mode) {
    bool ok=false; CompleteFixture* c=calloc(1,sizeof(*c)); REQUIRE(c); PaseFixture* f=c->net=setup(false,false);
    c->pase=f->link=create_network(); CHECK(c->pase); Peer* a=&c->pase->a; Peer* b=&c->pase->b; Peer* peers[]={a,b};
    for(unsigned i=0;i<2;++i) { peers[i]->pase=f->s[i]; CHECK(matter_rx_register(peers[i]->rx,0,0)==MATTER_OK); }
    for(unsigned i=0;i<6;++i) { CHECK(matter_pase_process(peers[i%2]->pase,c->now)==MATTER_PENDING); CHECK(transport_message(f,peers[i%2],peers[1-i%2],&c->now,false,false)); }
    CHECK(matter_pase_process(f->s[0],c->now)==MATTER_OK);
    for(unsigned i=0;i<2;++i) {
        Peer* p=peers[i]; CHECK(matter_rx_close(p->rx,p->handle)==MATTER_OK); p->handle=0; p->pase=NULL;
        p->secure=matter_secure_new(&f->port,f->s[i],c->now); CHECK(p->secure); p->secure_token=10001+i; p->session=p->secure_token;
        p->channel=matter_secure_channel_new(p->secure,p->secure_token,&p->path); CHECK(p->channel); CHECK(matter_rx_register(p->rx,0,1)==MATTER_OK);
    }
    Matter_Credentials_Port_T credentials; CHECK(matter_crypto_mbedtls_credentials(f->crypto,&credentials)==MATTER_OK);
    c->server=fab_new(&f->port,&credentials); c->w=wf_new_product(c->now,b->secure_token,0x8000); GcFixture* g=c->w->g;
#ifdef MATTER_TEST_ALLOC
    fail_at=calls+1; CHECK(!matter_commissioning_host_image_new(&c->w->config.initial,&c->w->config.connected)); fail_at=0;
#endif
    c->image=matter_commissioning_host_image_new(&c->w->config.initial,&c->w->config.connected); CHECK(c->image);
    const char* directory=getenv("MATTER_TEST_STORE_DIR");
    if(directory) {
        size_t size=strlen(directory)+40; c->storage_path=calloc(size,1); CHECK(c->storage_path);
        snprintf(c->storage_path,size,"%s/complete-%u.tlv",directory,mode);
        c->file=matter_store_file_new(c->storage_path); CHECK(c->file);
        Matter_Store_Blob_Port_T blob=matter_store_file_port(c->file);
        c->store=matter_store_host_new(&blob,c->server->image,c->image,&g->f->durable.settings,&c->diagnostics,false); CHECK(c->store);
    }
    Matter_Commissioning_Host_Port_T hp={c,complete_retire};
#ifdef MATTER_TEST_ALLOC
    fail_at=calls+1; CHECK(!matter_commissioning_host_new(c->image,c->w->wifi,c->w->sim,c->server->o->core,c->server->host,&hp)); fail_at=0;
#endif
    c->host=matter_commissioning_host_new(c->image,c->w->wifi,c->w->sim,c->server->o->core,c->server->host,&hp); CHECK(c->host);
    CHECK(matter_root_delete(g->f->root)==MATTER_OK); complete_root(c,false);
    CHECK(matter_root_async_invoke_port(g->f->root,b->secure_token,&c->pase_binding,&g->invoke,&c->w->async)==MATTER_OK);
    wf_arm(c->w,60); CHECK(matter_commissioning_host_pending(c->image));
    wf_command(c->w,2,"new","password",0,17,0,false); wf_command(c->w,6,"new",NULL,0,18,0,false); c->now=c->w->now;
    c->server->o->session_user=b; c->server->o->session_challenge=oc_secure_challenge; CHECK(matter_secure_challenge(a->secure,c->server->o->challenge)==MATTER_OK);
    fab_scalar_value=10; oc_request(c->server->o,4,0,32,false); memcpy(c->server->args,c->server->o->request,c->server->o->request_size); c->server->args_size=c->server->o->request_size;
    CHECK(fab_invoke_network(f,c->server,c->w,&c->now,4,0,false));
    fab_request(c->server,11,FAB_CERT(fab_root),(Matter_Cert_Tlv_T){0},0); CHECK(fab_invoke_network(f,c->server,c->w,&c->now,11,0,false));
    fab_request(c->server,6,FAB_CERT(fab_noc0),(Matter_Cert_Tlv_T){0},101); CHECK(fab_invoke_network(f,c->server,c->w,&c->now,6,0,true));
    CHECK(complete_request(c,true,2,false,false,false)); /* PASE after AddNOC. */
    /* The legacy synchronous binding must give the same PASE refusal. */
    {
        Matter_Root_Invoke_Binding_T binding; Matter_Im_Invoke_Port_T port;
        const Matter_Im_Command_Path_T path={0,0x30,4}; const uint8_t args[]={0x15,0x18};
        CHECK(matter_root_invoke_port(g->f->root,c->pase->b.secure_token,&binding,&port)==MATTER_OK);
        CHECK(matter_tlv_writer_init(&c->server->writer,c->server->response,8,2)==MATTER_TLV_OK);
        CHECK(!port.invoke(port.user,&path,args,sizeof(args),&c->server->writer).status && c->server->response[3]==2);
        CHECK(!c->closed && !c->commits);
    }
    c->client=fab_new(&f->port,&credentials); fab_csr(c->client,11);
    fab_request(c->client,11,FAB_CERT(fab_root),(Matter_Cert_Tlv_T){0},0); fab_call(c->client,1,11,true,0,0);
    fab_request(c->client,6,FAB_CERT(fab_conflict),(Matter_Cert_Tlv_T){0},100); fab_call(c->client,1,6,true,0,0);
    c->operational=f->link=create_network(); CHECK(c->operational); a=&f->link->a; b=&f->link->b; peers[0]=a; peers[1]=b;
    for(unsigned i=0;i<2;++i) {
        Matter_Case_Config_T config={.responder=i!=0,.local_session_id=(uint16_t)(41+i),.timeout_ms=30000,.fabric_index=1,.peer_node_id=100,.time={MATTER_CERT_TIME_SUPPLIED,{2026,10,9,0,0,0}}};
        Matter_Case_Port_T port=matter_fabric_host_case_port(i?c->server->host:c->client->host);
        c->cases[i]=matter_case_new(&f->port,&credentials,&port,&config,c->now); CHECK(c->cases[i]); peers[i]->case_session=c->cases[i]; CHECK(matter_rx_register(peers[i]->rx,0,0)==MATTER_OK);
    }
    for(unsigned i=0;i<4;++i) { CHECK(matter_case_process(c->cases[i%2],c->now)==MATTER_PENDING); CHECK(transport_message(f,peers[i%2],peers[1-i%2],&c->now,true,true)); }
    CHECK(matter_case_process(c->cases[0],c->now)==MATTER_OK);
    for(unsigned i=0;i<2;++i) {
        Peer* p=peers[i]; CHECK(matter_rx_close(p->rx,p->handle)==MATTER_OK); p->handle=0; p->case_session=NULL;
        p->secure=matter_secure_new_case(&f->port,c->cases[i],c->now); CHECK(p->secure); p->secure_token=20001+i; p->session=p->secure_token;
        p->channel=matter_secure_channel_new(p->secure,p->secure_token,&p->path); CHECK(p->channel); CHECK(matter_rx_register(p->rx,0,1)==MATTER_OK);
    }
    CHECK(matter_root_case_invoke_port(g->f->root,b->secure_token,b->secure,&c->case_binding,&c->invoke,&c->async,&c->resolver)==MATTER_OK);
    /* Wrong authenticated fabric at trusted adapter boundary: no side effect. */
    uint64_t token; Matter_Im_Command_Result_T result;
    CHECK(matter_tlv_writer_init(&c->server->writer,c->server->response,8,2)==MATTER_TLV_OK);
    CHECK(matter_root_complete_start(g->f->root,b->secure_token,2,true,&c->server->writer,&result,&token)==MATTER_OK && !result.status && !token && c->server->response[3]==2);
    CHECK(matter_tlv_writer_init(&c->server->writer,c->server->response,7,2)==MATTER_TLV_OK);
    CHECK(matter_root_complete_start(g->f->root,b->secure_token,1,true,&c->server->writer,&result,&token)==MATTER_OK && result.status==MATTER_IM_RESOURCE_EXHAUSTED && !token);
    CHECK(matter_tlv_writer_init(&c->server->writer,c->server->response,8,2)==MATTER_TLV_OK);
    CHECK(matter_root_complete_start(g->f->root,b->secure_token,1,true,&c->server->writer,&result,&token)==MATTER_PENDING && token);
    matter_root_complete_cancel(g->f->root,token);
    CHECK(matter_root_process(g->f->root,c->now)==MATTER_PENDING && !c->closed && !c->commits);
    CHECK(matter_tlv_writer_init(&c->server->writer,c->server->response,8,2)==MATTER_TLV_OK);
    CHECK(matter_root_complete_start(g->f->root,b->secure_token,1,true,&c->server->writer,&result,&token)==MATTER_PENDING);
    c->deny=true;
    CHECK(matter_root_process(g->f->root,c->now)==MATTER_PENDING && !c->closed && !c->commits);
    CHECK(matter_root_complete_poll(g->f->root,token,&c->server->writer,&result)==MATTER_OK && result.status==MATTER_IM_UNSUPPORTED_ACCESS);
    c->deny=true; CHECK(complete_request(c,false,MATTER_IM_UNSUPPORTED_ACCESS,true,false,false)); c->deny=false;
    /* Keep PASE TX borrowed while CASE Complete starts. Commit cannot run yet. */
    f->link=c->pase; static const uint8_t status[]={0x15,0x24,0,0,0x24,255,13,0x18};
    CHECK(im_host_send(f,&c->pase->b,1,status,sizeof(status),++c->now) && tick(&c->pase->b,c->now) && c->pase->b.retained); f->link=c->operational;
    matter_commissioning_host_fail_commit(c->host,true);
    CHECK(complete_request(c,false,MATTER_IM_FAILURE,true,true,false));
    CHECK(matter_commissioning_host_pending(c->image) && c->server->port.view(c->server->host)->added && !c->commits);
    matter_commissioning_host_fail_commit(c->host,false);
    if(c->file) {
        matter_store_file_fault(c->file,4);
        CHECK(complete_request(c,false,MATTER_IM_FAILURE,true,false,false) && !c->commits && matter_commissioning_host_pending(c->image));
        matter_store_file_fault(c->file,0);
    }
    if(mode==1) {
        /* Expiry while CASE TX is borrowed: no fabric/key removal before drain. */
        CHECK(im_host_send(f,b,1,status,sizeof(status),++c->now) && tick(b,c->now) && b->retained);
        uint64_t deadline; CHECK(matter_root_deadline(g->f->root,&deadline)==MATTER_OK); c->now=deadline;
        CHECK(matter_root_process(g->f->root,c->now)==MATTER_PENDING && c->server->port.view(c->server->host)->count==1);
        network_poll(b); CHECK(network_take(b) && tick(b,c->now));
        c->w->control.fail_restore=true; matter_wifi_sim_control(c->w->sim,&c->w->control);
        CHECK(matter_root_process(g->f->root,c->now)==MATTER_PORT_ERROR && matter_commissioning_host_pending(c->image));
        c->w->control.fail_restore=false; matter_wifi_sim_control(c->w->sim,&c->w->control);
        CHECK(matter_root_process(g->f->root,c->now)==MATTER_OK && !matter_commissioning_host_pending(c->image));
        CHECK(!c->server->port.view(c->server->host)->count && matter_wifi_sim_settings(c->w->sim)->count==1);
        CHECK(!memcmp(matter_wifi_sim_connected(c->w->sim)->bytes,"old",3) && !c->commits);
        puts("PASS Complete expiry: CASE TX drain before key removal, failed Wi-Fi rollback retry and old network restored");
        goto restart;
    }
    if(mode==2) {
        /* Simulate abrupt runtime loss: discard volatile Root/Wi-Fi state only;
         * persistent images remain pending. This is NOT a production shutdown. */
        c->crash=true; CHECK(matter_root_expire(g->f->root)==MATTER_PENDING && matter_root_process(g->f->root,c->now)==MATTER_OK);
        CHECK(matter_wifi_commit(c->w->wifi)==MATTER_OK && matter_commissioning_host_pending(c->image));
        goto restart;
    }
    CHECK(complete_request(c,false,0,false,false,true) && c->commits==1 && c->closed && !matter_commissioning_host_pending(c->image));
    Matter_Root_Fail_Safe_State_T state; CHECK(matter_root_fail_safe_state(g->f->root,&state)==MATTER_OK && state==MATTER_ROOT_FAIL_SAFE_IDLE);
    CHECK(gc_scalar(g,0x30,0,NULL)==0 && !matter_opcreds_fabric_index(c->server->o->core,c->pase->b.secure_token));
    CHECK(matter_commissioning_host_settings(c->image)->count==2 && matter_commissioning_host_connected(c->image)->size==3);
    CHECK(complete_read(c) && complete_request(c,false,3,false,false,false) && c->commits==1);
    puts("PASS Complete IPv6: PASE/CSR/AddNOC -> CASE -> Complete -> Read; PASE/wrong fabric/ACL refusal, commit fault, retained PASE TX drain, duplicate/lost response and NoFailSafe"); ok=true;
restart:
    /* Destroy runtime and, with a file backend, discard both RAM images. */
    cleanup(c->operational); c->operational=NULL; f->link=c->pase;
    CHECK(matter_root_delete(g->f->root)==MATTER_OK); g->f->root=NULL;
    CHECK(matter_commissioning_host_delete(c->host)==MATTER_OK); c->host=NULL;
    CHECK(matter_wifi_delete(c->w->wifi)==MATTER_OK && matter_wifi_sim_delete(c->w->sim)==MATTER_OK);
    if(c->store) {
        FabFixture* server=c->server;
        CHECK(matter_opcreds_delete(server->o->core)==MATTER_OK && matter_fabric_delete(server->model)==MATTER_OK);
        CHECK(matter_fabric_host_delete(server->host)==MATTER_OK && matter_store_host_delete(c->store)==MATTER_OK); c->store=NULL;
        CHECK(matter_fabric_host_image_delete(server->image)==MATTER_OK && matter_commissioning_host_image_delete(c->image)==MATTER_OK);
        server->image=matter_fabric_host_image_new(); CHECK(server->image);
        c->image=matter_commissioning_host_image_new(&c->w->config.initial,&c->w->config.connected); CHECK(c->image);
        Matter_Store_Blob_Port_T blob=matter_store_file_port(c->file);
        c->store=matter_store_host_new(&blob,server->image,c->image,&g->f->durable.settings,&c->diagnostics,true); CHECK(c->store);
        server->o->core=matter_opcreds_new(&server->o->config.identity,&server->o->port); CHECK(server->o->core); fab_attach(server);
    }
    c->w->config.initial=*matter_commissioning_host_settings(c->image); c->w->config.connected=*matter_commissioning_host_connected(c->image);
    c->w->sim=matter_wifi_sim_new(&c->w->config,c->now); CHECK(c->w->sim);
    Matter_Wifi_Port_T wp=matter_wifi_sim_port(c->w->sim); Matter_Wifi_Config_T wc={3,2,3,5,17,100};
    c->w->wifi=matter_wifi_new(&wc,&wp,c->now); CHECK(c->w->wifi);
    if(!c->store) fab_restart(c->server);
    c->host=matter_commissioning_host_new(c->image,c->w->wifi,c->w->sim,c->server->o->core,c->server->host,&hp); CHECK(c->host);
    c->crash=false; complete_root(c,matter_commissioning_host_pending(c->image));
    CHECK(matter_root_process(g->f->root,c->now)==MATTER_OK && !matter_commissioning_host_pending(c->image));
    CHECK(c->server->port.view(c->server->host)->count==(mode?0u:1u));
    CHECK(matter_wifi_sim_settings(c->w->sim)->count==(mode?1u:2u) && !memcmp(matter_wifi_sim_connected(c->w->sim)->bytes,mode?"old":"new",3));
    CHECK(matter_fabric_host_sign(c->server->host,1,c->server->ipk,16,c->server->signature)==(mode?MATTER_INVALID_STATE:MATTER_OK));
    if(c->file) puts("PASS Complete IPv6: file reload into fresh images and atomic rename failure");
    puts(mode?"PASS Complete restart: pending/rolled-back journal restores old network and removes uncommitted fabric":"PASS Complete restart: committed network, fabric and operational key survive"); ok=true;

done:
    if(c->operational) { c->operational->a.case_session=c->operational->b.case_session=NULL; }
    if(c->w) { c->w->now=c->now; REQUIRE(matter_root_expire(c->w->g->f->root)==MATTER_OK); }
    if(c->host) REQUIRE(matter_commissioning_host_delete(c->host)==MATTER_OK);
    if(c->store) REQUIRE(matter_store_host_delete(c->store)==MATTER_OK);
    if(c->file) REQUIRE(matter_store_file_delete(c->file)==MATTER_OK);
    free(c->storage_path);
    if(c->w) wf_release(c->w);
    for(unsigned i=0;i<2;++i) REQUIRE(matter_case_delete(c->cases[i])==MATTER_OK);
    if(c->client) fab_free(c->client);
    if(c->server) fab_free(c->server);
    if(c->image) REQUIRE(matter_commissioning_host_image_delete(c->image)==MATTER_OK);
    if(c->operational) cleanup(c->operational);
    f->link=c->pase; dispose(f); free(c); return ok;
}
#endif

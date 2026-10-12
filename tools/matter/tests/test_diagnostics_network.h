#ifdef MATTER_TEST_HOST_UDP
#define DIAG_CHECK OC_CHECK
#include "test_diagnostics_fixture.h"
#undef DIAG_CHECK
typedef struct {
    AclNetwork peers; GkWire wire; GcFixture* gc; DiagFixture* diag;
    Matter_Groupkey_T groupkey; Matter_Root_Case_Invoke_Binding_T binding;
    uint32_t tx,rx;
} DiagNetwork;
/* The application counts an accepted IM message once, not MRP ACKs/retries. */
static void dn_message(DiagNetwork* g,bool tx) {
    matter_diagnostics_host_message(g->diag->host,tx);
    if(tx) ++g->tx; else ++g->rx;
}
static bool dn_invoke(DiagNetwork* g,unsigned peer,unsigned cluster,unsigned cmd,uint8_t expected,bool loss,size_t capacity) {
    bool ok=false; AclNetwork* h=&g->peers; PaseFixture* f=h->net; f->link=h->links[peer]; Peer* a=&f->link->a; Peer* b=&f->link->b;
    CHECK(fab_exchange(f)); gk_args(&g->wire,4,0,0,0);
    if(cluster==0x33 && !cmd) {
        g->wire.n=1; gk_byte(&g->wire,0x30); gk_byte(&g->wire,0); gk_byte(&g->wire,16);
        for(unsigned i=0;i<16;++i) gk_byte(&g->wire,0);
        gk_uint(&g->wire,1,1); gk_byte(&g->wire,0x18);
    }
    gk_request(&g->wire,cmd); g->wire.request[15]=(uint8_t)cluster;
    Matter_Im_Invoke_Port_T p; Matter_Im_Invoke_Async_Port_T async; Matter_Im_Read_Fabric_Port_T resolver;
    CHECK(matter_root_case_invoke_port(h->root->root,b->secure_token,b->secure,&g->binding,&p,&async,&resolver)==MATTER_OK);
    Matter_Im_Invoke_Config_T config={{b->secure_token,a->key.exchange_id,false},30000,capacity,false};
    b->invoke=matter_im_invoke_new_case(&p,&async,&resolver,&config,++h->now); CHECK(b->invoke);
    CHECK(im_host_send(f,a,8,g->wire.request,g->wire.request_size,h->now) && tick(a,h->now)); network_poll(a);
    CHECK(network_take(a) && network_receive(b)); f->link->delayed_data=b->inbox;
    CHECK(network_admit(b,h->now) && tick(b,h->now) && im_ack_transfer(b,a,h->now+=200)); dn_message(g,false);
    CHECK(matter_diagnostics_host_process(g->diag->host,h->now)==MATTER_OK);
    CHECK(matter_im_invoke_process(b->invoke,h->now)==MATTER_PENDING);
    unsigned deliveries=b->deliveries; uint32_t version;
    CHECK(matter_diagnostics_version(g->diag->model,0x36,&version)==MATTER_OK);
    CHECK(receive_packet(b,&f->link->delayed_data,h->now)==MATTER_OK && tick(b,h->now));
    CHECK(deliveries==b->deliveries && im_ack_transfer(b,a,h->now));
    Matter_Im_Invoke_Message_T out; CHECK(matter_im_invoke_output(b->invoke,&out)==MATTER_OK);
    if(capacity<32) CHECK(out.opcode==1 && out.data[3]==expected);
    else if(expected || !cmd) {
        const uint8_t status[]={0x15,0x29,0,0x36,1,0x15,0x35,1,0x37,0,0x24,0,0,0x24,1,(uint8_t)cluster,0x24,2,(uint8_t)cmd,
            0x18,0x35,1,0x24,0,expected,0x18,0x18,0x18,0x18,0x24,255,13,0x18};
        CHECK(out.opcode==9 && out.size==sizeof(status) && !memcmp(out.data,status,sizeof(status)));
    } else {
        CHECK(out.opcode==9 && out.data[15]==0x33 && out.data[18]==2);
        RootFixture* r=h->root; unsigned time=0,nulls=0;
        CHECK(matter_tlv_init(&r->reader,out.data,out.size,8)==MATTER_TLV_OK);
        while(matter_tlv_next(&r->reader,&r->token)==MATTER_TLV_OK) {
            if(r->token.type==MATTER_TLV_LIST) { CHECK(matter_tlv_skip_container(&r->reader)==MATTER_TLV_OK); continue; }
            if(r->token.type==MATTER_TLV_UNSIGNED && r->token.tag.number==0 && r->token.unsigned_value==h->now) ++time;
            if(r->token.type==MATTER_TLV_NULL && r->token.tag.number==1) ++nulls;
        }
        CHECK(time==1 && nulls==1);
    }
    CHECK(im_host_send(f,b,out.opcode,out.data,out.size,h->now) && matter_im_invoke_sent_at(b->invoke,h->now)==MATTER_OK && tick(b,h->now)); network_poll(b);
    CHECK(network_take(b) && network_receive(a)); dn_message(g,true);
    if(loss) {
        f->link->delayed_ack=a->inbox; a->inbox_full=false;
        CHECK(matter_retransmission_sender_deadline(b->tx,&h->now)==MATTER_OK && tick(b,h->now)); complete_resolver(b); network_poll(b);
        CHECK(network_take(b) && network_receive(a) && a->inbox.size==f->link->delayed_ack.size && !memcmp(a->inbox.data,f->link->delayed_ack.data,a->inbox.size));
    }
    uint32_t after; CHECK(matter_diagnostics_version(g->diag->model,0x36,&after)==MATTER_OK && version==after);
    CHECK(network_admit(a,h->now) && tick(a,h->now) && im_ack_transfer(a,b,h->now+=200));
    CHECK(matter_im_invoke_state(b->invoke)==MATTER_IM_INVOKE_COMPLETE && matter_im_invoke_delete(b->invoke)==MATTER_OK);
    b->invoke=NULL; a->im_client=false; ok=true;
done: return ok;
}
static bool dn_read(DiagNetwork* g,unsigned peer,unsigned cluster,unsigned attr,Matter_Tlv_Type_T type,int64_t expected,uint8_t error) {
    bool ok=false; AclNetwork* h=&g->peers; PaseFixture* f=h->net; f->link=h->links[peer]; Peer* a=&f->link->a; Peer* b=&f->link->b;
    Matter_Root_Case_Read_Binding_T binding; Matter_Im_Read_Port_T port; Matter_Im_Read_Fabric_Port_T fabric;
    CHECK(fab_exchange(f) && matter_root_case_read_port(h->root->root,b->secure_token,b->secure,&binding,&port,&fabric)==MATTER_OK);
    Matter_Im_Read_Config_T config={{b->secure_token,a->key.exchange_id,false},30000,192,false};
    b->im=matter_im_read_new_case(&port,&fabric,&config,++h->now); CHECK(b->im);
    memcpy(g->wire.request,im_request,sizeof(im_request)); g->wire.request[9]=(uint8_t)cluster; g->wire.request[12]=(uint8_t)attr;
    CHECK(im_host_send(f,a,2,g->wire.request,sizeof(im_request),h->now) && tick(a,h->now)); network_poll(a);
    CHECK(network_take(a) && network_receive(b) && network_admit(b,h->now) && tick(b,h->now)); dn_message(g,false);
    CHECK(im_ack_transfer(b,a,h->now+=200));
    CHECK(matter_diagnostics_host_process(g->diag->host,h->now)==MATTER_OK);
    Matter_Result_T refresh=matter_diagnostics_refresh(g->diag->model); CHECK(refresh==(error==MATTER_IM_FAILURE?MATTER_PORT_ERROR:MATTER_OK));
    CHECK(matter_im_read_process(b->im,h->now)==MATTER_PENDING);
    Matter_Im_Read_Message_T out; CHECK(matter_im_read_output(b->im,&out)==MATTER_OK && out.opcode==5);
    /* Literal DeviceLoadStatus, with fabric1 selected by live CASE identity. */
    if(cluster==0x33 && attr==10) {
        g->wire.n=0; gk_byte(&g->wire,0x15); gk_uint(&g->wire,0,3); gk_uint(&g->wire,1,1); gk_uint(&g->wire,2,3);
        gk_uint(&g->wire,3,g->tx); gk_uint(&g->wire,4,g->rx); gk_byte(&g->wire,0x18);
    }
    CHECK(im_host_send(f,b,5,out.data,out.size,h->now) && matter_im_read_sent(b->im)==MATTER_OK && tick(b,h->now)); network_poll(b);
    CHECK(network_take(b) && network_receive(a) && network_admit(a,h->now) && tick(a,h->now)); dn_message(g,true);
    RootFixture* r=h->root; unsigned values=0,errors=0;
    CHECK(matter_tlv_init(&r->reader,a->im_received.data,a->im_received.size,8)==MATTER_TLV_OK);
    while(matter_tlv_next(&r->reader,&r->token)==MATTER_TLV_OK) {
        if(r->token.type==MATTER_TLV_LIST) { CHECK(matter_tlv_skip_container(&r->reader)==MATTER_TLV_OK); continue; }
        if(error && r->token.type==MATTER_TLV_UNSIGNED && r->token.tag.number==0 && r->token.unsigned_value==error) ++errors;
        if(r->token.tag.control!=1 || r->token.tag.number!=2) continue;
        CHECK(r->token.type==type); ++values;
        if(type==MATTER_TLV_UNSIGNED) CHECK(r->token.unsigned_value==(uint64_t)expected);
        if(type==MATTER_TLV_SIGNED) CHECK(r->token.signed_value==expected);
        if(type==MATTER_TLV_BYTES) CHECK(r->token.size==6 && !memcmp(r->token.data,g->diag->config.aps[0].ap.bssid,6));
        if(type==MATTER_TLV_STRUCTURE) {
            size_t start=r->token.offset; CHECK(matter_tlv_skip_container(&r->reader)==MATTER_TLV_OK);
            CHECK(r->reader.offset-start==g->wire.n+1 && !memcmp(a->im_received.data+start+2,g->wire.data+1,g->wire.n-1));
        }
        if(type==MATTER_TLV_ARRAY) { CHECK(matter_tlv_skip_container(&r->reader)==MATTER_TLV_OK); }
    }
    CHECK(values==(error?0u:1u) && errors==(error?1u:0u));
    CHECK(im_ack_transfer(a,b,h->now+=200) && matter_im_read_state(b->im)==MATTER_IM_READ_COMPLETE);
    CHECK(matter_im_read_delete(b->im)==MATTER_OK); b->im=NULL; a->im_client=false; ok=true;
done: return ok;
}
static bool network_diagnostics(void) {
    bool ok=false; DiagNetwork* g=calloc(1,sizeof(*g)); REQUIRE(g); AclNetwork* h=&g->peers;
    h->net=setup(false,false); PaseFixture* f=h->net; Matter_Credentials_Port_T cp;
    CHECK(matter_crypto_mbedtls_credentials(f->crypto,&cp)==MATTER_OK);
    h->admin=case_fixture(&f->port,&cp); FabFixture* server=h->admin->fabrics[1];
    Matter_Acl_Port_T ap=matter_fabric_host_acl_port(server->host); h->acl=matter_acl_new(&ap); CHECK(h->acl);
    Matter_Groupkey_Port_T gp=matter_fabric_host_groupkey_port(server->host); g->groupkey=matter_groupkey_new(&gp); CHECK(g->groupkey);
    g->gc=gc_fixture(); h->root=g->gc->f; g->diag=diag_fixture();
    Matter_Root_Port_T rp={h,acl_load,acl_access,acl_store_root}; Matter_Root_Commissioning_Port_T gc={g->gc,gc_begin,gc_cleanup,gc_regulatory,NULL};
    h->root->root=matter_root_new_commissioning(&rp,&g->gc->config,&gc,h->now); CHECK(h->root->root);
    CHECK(matter_root_attach_opcreds(h->root->root,server->o->core)==MATTER_OK);
    CHECK(matter_root_attach_acl(h->root->root,h->acl)==MATTER_OK && matter_root_attach_groupkey(h->root->root,g->groupkey)==MATTER_OK);
    CHECK(matter_root_attach_wifi(h->root->root,g->diag->wifi)==MATTER_OK && matter_root_attach_diagnostics(h->root->root,g->diag->model)==MATTER_OK);
    CHECK(acl_handshake(h,0,h->admin->session));
    h->guest=fab_new(&f->port,&cp); fab_csr(h->guest,12); fab_request(h->guest,11,FAB_CERT(fab_root),(Matter_Cert_Tlv_T){0},0); fab_call(h->guest,1,11,true,0,0);
    fab_request(h->guest,6,FAB_CERT(acl_peer_noc),(Matter_Cert_Tlv_T){0},100); fab_call(h->guest,1,6,true,0,0);
    for(unsigned i=0;i<2;++i) {
        Matter_Case_Port_T p=matter_fabric_host_case_port(i?server->host:h->guest->host);
        Matter_Case_Config_T c={.responder=i!=0,.local_session_id=(uint16_t)(51+i),.timeout_ms=30000,.fabric_index=1,.peer_node_id=100,.time={MATTER_CERT_TIME_SUPPLIED,{2026,10,9,0,0,0}}};
        h->guest_cases[i]=matter_case_new(&f->port,&cp,&p,&c,h->now); CHECK(h->guest_cases[i]);
    }
    CHECK(acl_handshake(h,1,h->guest_cases));
    CHECK(dn_read(g,0,0x33,0,MATTER_TLV_ARRAY,0,0) && dn_read(g,0,0x33,1,MATTER_TLV_UNSIGNED,1,0));
    CHECK(dn_read(g,0,0x36,0,MATTER_TLV_BYTES,0,0) && dn_read(g,0,0x36,4,MATTER_TLV_SIGNED,-42,0));
    CHECK(dn_read(g,1,0x36,4,MATTER_TLV_SIGNED,0,MATTER_IM_UNSUPPORTED_ACCESS));
    CHECK(dn_invoke(g,0,0x33,1,0,true,256) && dn_invoke(g,0,0x33,0,MATTER_IM_CONSTRAINT_ERROR,false,256));
    matter_diagnostics_host_packets(g->diag->host,0,17); matter_diagnostics_host_overruns(g->diag->host,9); diag_tick(g->diag,h->now);
    CHECK(dn_invoke(g,1,0x36,0,MATTER_IM_UNSUPPORTED_ACCESS,false,256));
    CHECK(dn_invoke(g,0,0x36,0,MATTER_IM_RESOURCE_EXHAUSTED,false,8));
    CHECK(diag_read(g->diag,0x36,5,0).unsigned_value==17);
    matter_diagnostics_host_control(g->diag->host,false,true);
    CHECK(dn_invoke(g,0,0x36,0,MATTER_IM_FAILURE,false,256) && diag_read(g->diag,0x36,5,0).unsigned_value==17);
    matter_diagnostics_host_control(g->diag->host,false,false);
    CHECK(dn_invoke(g,0,0x36,0,0,true,256));
    CHECK(dn_read(g,0,0x36,5,MATTER_TLV_UNSIGNED,0,0) && dn_read(g,0,0x36,12,MATTER_TLV_UNSIGNED,9,0));
    CHECK(matter_diagnostics_host_subscription(g->diag->host,1,true)==MATTER_OK);
    CHECK(matter_diagnostics_host_subscription(g->diag->host,2,true)==MATTER_OK && matter_diagnostics_host_subscription(g->diag->host,2,true)==MATTER_OK);
    CHECK(dn_read(g,0,0x33,10,MATTER_TLV_STRUCTURE,0,0));
    matter_diagnostics_host_control(g->diag->host,true,false);
    CHECK(dn_read(g,0,0x36,4,MATTER_TLV_NULL,0,MATTER_IM_FAILURE));
    matter_diagnostics_host_control(g->diag->host,false,false);
    CHECK(!matter_wifi_write(g->diag->wifi,(const uint8_t[]){0x08},1));
    CHECK(dn_read(g,0,0x36,4,MATTER_TLV_NULL,0,0));
    /* All attached Root modules, monotonically ordered wildcard enumeration. */
    Matter_Im_Read_Port_T read; Matter_Im_Write_Port_T write; CHECK(matter_root_ports(h->root->root,&read,&write)==MATTER_OK);
    Matter_Im_Selector_T all={0}; Matter_Im_Path_T path={0}; bool found; unsigned count=0; uint32_t last=0;
    while(read.enumerate(read.user,&all,count?&path:NULL,&path,&found)==MATTER_OK && found) { CHECK(path.cluster>=last); last=path.cluster; ++count; }
    CHECK(count==116);
    puts("PASS diagnostics CASE IPv6: Read/TimeSnapshot/ResetCounts, disabled triggers, live ACL, backend/preflight failures, duplicate/loss, IM counters and full Root topology"); ok=true;
done:
    if(g->gc) gc_release(g->gc,h->now);
    if(g->diag) diag_release(g->diag);
    if(g->groupkey) REQUIRE(matter_groupkey_delete(g->groupkey)==MATTER_OK);
    if(h->acl) REQUIRE(matter_acl_delete(h->acl)==MATTER_OK);
    for(unsigned i=0;i<2;++i) { if(h->links[i]) cleanup(h->links[i]); if(h->guest_cases[i]) REQUIRE(matter_case_delete(h->guest_cases[i])==MATTER_OK); }
    if(h->guest) fab_free(h->guest);
    if(h->admin) case_free(h->admin);
    f->link=NULL; dispose(f); free(g); return ok;
}
#endif

#ifdef MATTER_TEST_HOST_UDP
#include "test_groupkey_wire.h"
typedef struct {
    AclNetwork peers; GkWire wire; Matter_Groupkey_T model;
    Matter_Root_Case_Invoke_Binding_T binding; GcFixture* gc;
} GkNetwork;
static bool gk_invoke_network(GkNetwork* g,unsigned peer,unsigned cmd,uint8_t expected,bool loss,size_t capacity) {
    bool ok=false; AclNetwork* h=&g->peers; PaseFixture* f=h->net; f->link=h->links[peer]; Peer* a=&f->link->a; Peer* b=&f->link->b;
    CHECK(fab_exchange(f)); gk_request(&g->wire,cmd);
    Matter_Im_Invoke_Port_T p; Matter_Im_Invoke_Async_Port_T async; Matter_Im_Read_Fabric_Port_T resolver;
    CHECK(matter_root_case_invoke_port(h->root->root,b->secure_token,b->secure,&g->binding,&p,&async,&resolver)==MATTER_OK);
    Matter_Im_Invoke_Config_T config={{b->secure_token,a->key.exchange_id,false},30000,capacity,false};
    b->invoke=matter_im_invoke_new_case(&p,&async,&resolver,&config,++h->now); CHECK(b->invoke);
    CHECK(im_host_send(f,a,8,g->wire.request,g->wire.request_size,h->now) && tick(a,h->now)); network_poll(a);
    CHECK(network_take(a) && network_receive(b)); f->link->delayed_data=b->inbox;
    CHECK(network_admit(b,h->now) && tick(b,h->now) && im_ack_transfer(b,a,h->now+=200));
    CHECK(matter_im_invoke_process(b->invoke,h->now)==MATTER_PENDING);
    uint32_t version=matter_groupkey_version(g->model); unsigned deliveries=b->deliveries;
    CHECK(receive_packet(b,&f->link->delayed_data,h->now)==MATTER_OK && tick(b,h->now));
    CHECK(deliveries==b->deliveries && version==matter_groupkey_version(g->model) && im_ack_transfer(b,a,h->now));
    Matter_Im_Invoke_Message_T out; CHECK(matter_im_invoke_output(b->invoke,&out)==MATTER_OK);
    if(capacity<32) CHECK(out.opcode==1 && out.data[3]==expected);
    else if(expected || cmd==0 || cmd==3) {
        const uint8_t status[]={0x15,0x29,0,0x36,1,0x15,0x35,1,0x37,0,0x24,0,0,0x24,1,0x3f,0x24,2,(uint8_t)cmd,
            0x18,0x35,1,0x24,0,expected,0x18,0x18,0x18,0x18,0x24,255,13,0x18};
        CHECK(out.opcode==9 && out.size==sizeof(status) && !memcmp(out.data,status,sizeof(status)));
    } else {
        CHECK(out.opcode==9 && out.size>25 && out.data[15]==0x3f && out.data[18]==cmd+1);
        RootFixture* r=h->root; unsigned nulls=0;
        CHECK(matter_tlv_init(&r->reader,out.data,out.size,8)==MATTER_TLV_OK);
        while(matter_tlv_next(&r->reader,&r->token)==MATTER_TLV_OK) {
            CHECK(r->token.type!=MATTER_TLV_BYTES);
            if(r->token.type==MATTER_TLV_NULL && (r->token.tag.number==2 || r->token.tag.number==4 || r->token.tag.number==6)) ++nulls;
        }
        CHECK(cmd!=1 || nulls==3);
    }
    CHECK(im_host_send(f,b,out.opcode,out.data,out.size,h->now) && matter_im_invoke_sent_at(b->invoke,h->now)==MATTER_OK && tick(b,h->now)); network_poll(b);
    CHECK(network_take(b) && network_receive(a));
    if(loss) {
        f->link->delayed_ack=a->inbox; a->inbox_full=false;
        CHECK(matter_retransmission_sender_deadline(b->tx,&h->now)==MATTER_OK && tick(b,h->now)); complete_resolver(b); network_poll(b);
        CHECK(network_take(b) && network_receive(a) && a->inbox.size==f->link->delayed_ack.size && !memcmp(a->inbox.data,f->link->delayed_ack.data,a->inbox.size));
        CHECK(version==matter_groupkey_version(g->model));
    }
    CHECK(network_admit(a,h->now) && tick(a,h->now) && im_ack_transfer(a,b,h->now+=200));
    CHECK(matter_im_invoke_state(b->invoke)==MATTER_IM_INVOKE_COMPLETE && matter_im_invoke_delete(b->invoke)==MATTER_OK);
    b->invoke=NULL; a->im_client=false; ok=true;
done: return ok;
}
static bool gk_read_network(GkNetwork* g,uint32_t attr,uint64_t expected) {
    bool ok=false; AclNetwork* h=&g->peers; PaseFixture* f=h->net; f->link=h->links[0]; Peer* a=&f->link->a; Peer* b=&f->link->b;
    Matter_Root_Case_Read_Binding_T binding; Matter_Im_Read_Port_T port; Matter_Im_Read_Fabric_Port_T fabric;
    CHECK(fab_exchange(f) && matter_root_case_read_port(h->root->root,b->secure_token,b->secure,&binding,&port,&fabric)==MATTER_OK);
    Matter_Im_Read_Config_T config={{b->secure_token,a->key.exchange_id,false},30000,192,false};
    b->im=matter_im_read_new_case(&port,&fabric,&config,++h->now); CHECK(b->im);
    memcpy(g->wire.request,im_request,sizeof(im_request)); g->wire.request[9]=0x3f; g->wire.request[12]=(uint8_t)attr;
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
        if(attr<2 && r->token.type==MATTER_TLV_ARRAY) { ++values; CHECK(matter_tlv_next(&r->reader,&r->token)==MATTER_TLV_OK && r->token.type==MATTER_TLV_END); }
        if(attr>=2 && r->token.type==MATTER_TLV_UNSIGNED && r->token.unsigned_value==expected) ++values;
    }
    if(values!=1) { fprintf(stderr,"GKM attr=%u values=%u:",(unsigned)attr,values); for(size_t i=0;i<a->im_received.size;++i) fprintf(stderr," %02x",a->im_received.data[i]); fprintf(stderr,"\n"); }
    CHECK(values==1 && im_ack_transfer(a,b,h->now+=200) && matter_im_read_state(b->im)==MATTER_IM_READ_COMPLETE);
    CHECK(matter_im_read_delete(b->im)==MATTER_OK); b->im=NULL; a->im_client=false; ok=true;
done: return ok;
}
static bool gk_map_network(GkNetwork* g,unsigned peer,bool add,uint8_t expected) {
    bool ok=false; AclNetwork* h=&g->peers; PaseFixture* f=h->net; f->link=h->links[peer]; Peer* a=&f->link->a; Peer* b=&f->link->b;
    CHECK(fab_exchange(f)); h->wire.size=0;
    if(add) { aw_open(&h->wire,0x15,-1); aw_uint(&h->wire,1,1); aw_uint(&h->wire,2,7); }
    else aw_open(&h->wire,0x16,-1);
    aw_byte(&h->wire,0x18); aw_request(&h->wire,add,false,-1); h->wire.request[13]=0x3f;
    Matter_Im_Write_Port_T port; Matter_Im_Read_Fabric_Port_T resolver;
    CHECK(matter_root_case_write_port(h->root->root,b->secure_token,b->secure,&h->bindings[peer],&port,&resolver)==MATTER_OK);
    Matter_Im_Write_Config_T config={{b->secure_token,a->key.exchange_id,false},30000,128,false};
    b->write=matter_im_write_new_case(&port,&resolver,&config,++h->now); CHECK(b->write);
    CHECK(im_host_send(f,a,6,h->wire.request,h->wire.request_size,h->now) && tick(a,h->now)); network_poll(a);
    CHECK(network_take(a) && network_receive(b) && network_admit(b,h->now) && tick(b,h->now) && im_ack_transfer(b,a,h->now+=200));
    CHECK(matter_im_write_process(b->write,h->now)==MATTER_PENDING);
    Matter_Im_Write_Message_T out; CHECK(matter_im_write_output(b->write,&out)==MATTER_OK);
    memcpy(h->root->expected,write_response,sizeof(write_response)); h->root->expected[11]=0x3f; h->root->expected[14]=0; h->root->expected[20]=expected;
    CHECK(out.opcode==7 && out.size==sizeof(write_response) && !memcmp(out.data,h->root->expected,out.size));
    CHECK(im_host_send(f,b,out.opcode,out.data,out.size,h->now) && tick(b,h->now)); network_poll(b);
    CHECK(network_take(b) && network_receive(a) && network_admit(a,h->now) && tick(a,h->now) && im_ack_transfer(a,b,h->now+=200));
    CHECK(matter_im_write_state(b->write)==MATTER_IM_WRITE_COMPLETE && matter_im_write_delete(b->write)==MATTER_OK); b->write=NULL; a->im_client=false; ok=true;
done: return ok;
}
static bool network_groupkey(void) {
    bool ok=false; GkNetwork* g=calloc(1,sizeof(*g)); REQUIRE(g); AclNetwork* h=&g->peers;
    h->net=setup(false,false); PaseFixture* f=h->net; Matter_Credentials_Port_T cp;
    CHECK(matter_crypto_mbedtls_credentials(f->crypto,&cp)==MATTER_OK);
    h->admin=case_fixture(&f->port,&cp); FabFixture* server=h->admin->fabrics[1];
    Matter_Acl_Port_T ap=matter_fabric_host_acl_port(server->host); h->acl=matter_acl_new(&ap); CHECK(h->acl);
    Matter_Groupkey_Port_T gp=matter_fabric_host_groupkey_port(server->host); g->model=matter_groupkey_new(&gp); CHECK(g->model);
    g->gc=gc_fixture(); h->root=g->gc->f;
    Matter_Root_Port_T rp={h,acl_load,acl_access,acl_store_root}; Matter_Root_Commissioning_Port_T gc={g->gc,gc_begin,gc_cleanup,gc_regulatory,NULL};
    h->root->root=matter_root_new_commissioning(&rp,&g->gc->config,&gc,h->now); CHECK(h->root->root);
    CHECK(matter_root_attach_opcreds(h->root->root,server->o->core)==MATTER_OK);
    CHECK(matter_root_attach_acl(h->root->root,h->acl)==MATTER_OK && matter_root_attach_groupkey(h->root->root,g->model)==MATTER_OK);
    CHECK(acl_handshake(h,0,h->admin->session));
    h->guest=fab_new(&f->port,&cp); fab_csr(h->guest,12); fab_request(h->guest,11,FAB_CERT(fab_root),(Matter_Cert_Tlv_T){0},0); fab_call(h->guest,1,11,true,0,0);
    fab_request(h->guest,6,FAB_CERT(acl_peer_noc),(Matter_Cert_Tlv_T){0},100); fab_call(h->guest,1,6,true,0,0);
    for(unsigned i=0;i<2;++i) {
        Matter_Case_Port_T p=matter_fabric_host_case_port(i?server->host:h->guest->host);
        Matter_Case_Config_T c={.responder=i!=0,.local_session_id=(uint16_t)(51+i),.timeout_ms=30000,.fabric_index=1,.peer_node_id=100,.time={MATTER_CERT_TIME_SUPPLIED,{2026,10,9,0,0,0}}};
        h->guest_cases[i]=matter_case_new(&f->port,&cp,&p,&c,h->now); CHECK(h->guest_cases[i]);
    }
    CHECK(acl_handshake(h,1,h->guest_cases));
    for(unsigned attr=0;attr<4;++attr) CHECK(gk_read_network(g,attr,attr==3?4:0));
    CHECK(gk_map_network(g,0,false,0) && gk_map_network(g,0,true,MATTER_IM_RESOURCE_EXHAUSTED) && gk_map_network(g,1,false,MATTER_IM_UNSUPPORTED_ACCESS));
    gk_args(&g->wire,1,0,0,0); CHECK(gk_invoke_network(g,0,1,0,false,256));
    CHECK(gk_invoke_network(g,1,1,MATTER_IM_UNSUPPORTED_ACCESS,false,256));
    gk_args(&g->wire,0,7,3,100); uint32_t version=matter_groupkey_version(g->model);
    CHECK(gk_invoke_network(g,1,0,MATTER_IM_UNSUPPORTED_ACCESS,false,256) && matter_groupkey_version(g->model)==version);
    CHECK(gk_invoke_network(g,0,0,MATTER_IM_RESOURCE_EXHAUSTED,false,8) && matter_groupkey_version(g->model)==version);
    Matter_Fabric_Host_Control_T fault={.fail_store=true}; matter_fabric_host_control(server->host,&fault);
    CHECK(gk_invoke_network(g,0,0,MATTER_IM_FAILURE,false,256) && matter_groupkey_version(g->model)==version);
    fault.fail_store=false; matter_fabric_host_control(server->host,&fault);
    CHECK(gk_invoke_network(g,0,0,0,true,256) && matter_groupkey_version(g->model)==version+1);
    gk_args(&g->wire,1,7,0,0); CHECK(gk_invoke_network(g,0,1,0,false,256));
    gk_args(&g->wire,4,0,0,0); CHECK(gk_invoke_network(g,0,4,0,false,256));
    gk_args(&g->wire,3,0,0,0); CHECK(gk_invoke_network(g,0,3,MATTER_IM_INVALID_COMMAND,false,256));
    gk_args(&g->wire,3,7,0,0); CHECK(gk_invoke_network(g,0,3,0,true,256));
    CHECK(gk_invoke_network(g,0,3,MATTER_GROUPKEY_NOT_FOUND,false,256));
    /* Metadata and topology include the attached cluster. No Groups server. */
    Matter_Im_Read_Port_T read; Matter_Im_Write_Port_T write; CHECK(matter_root_ports(h->root->root,&read,&write)==MATTER_OK);
    Matter_Im_Selector_T all={0}; Matter_Im_Path_T path={0}; bool found; unsigned count=0;
    while(read.enumerate(read.user,&all,count?&path:NULL,&path,&found)==MATTER_OK && found) ++count;
    CHECK(count==69);
    puts("PASS Group Key Management CASE IPv6: four commands, redacted read, four attributes/map writes, ACL denial, atomic failures, duplicate/loss and topology"); ok=true;
done:
    if(g->gc) gc_release(g->gc,h->now);
    if(g->model) REQUIRE(matter_groupkey_delete(g->model)==MATTER_OK);
    if(h->acl) REQUIRE(matter_acl_delete(h->acl)==MATTER_OK);
    for(unsigned i=0;i<2;++i) { if(h->links[i]) cleanup(h->links[i]); if(h->guest_cases[i]) REQUIRE(matter_case_delete(h->guest_cases[i])==MATTER_OK); }
    if(h->guest) fab_free(h->guest);
    if(h->admin) case_free(h->admin);
    f->link=NULL; dispose(f); free(g); return ok;
}
#endif

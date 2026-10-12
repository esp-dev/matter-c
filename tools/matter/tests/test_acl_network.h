#ifdef MATTER_TEST_HOST_UDP
#include "test_acl_wire.h"
#include "../fixtures/acl_peer_vectors.h"
typedef struct {
    PaseFixture* net; CaseFixture* admin; FabFixture* guest;
    Pair* links[2]; Matter_Case_T guest_cases[2]; RootFixture* root; Matter_Acl_T acl;
    Matter_Root_Case_Write_Binding_T bindings[2]; AclWire wire; uint64_t now;
} AclNetwork;
static bool acl_types(void* u,uint16_t ep,uint32_t type) { (void)u; return ep==0 && type==0x16; }
static Matter_Result_T acl_load(void* u,Matter_Root_Config_T* c) { return root_load(((AclNetwork*)u)->root,c); }
static Matter_Result_T acl_store_root(void* u,const Matter_Root_Settings_T* s) { return root_store(((AclNetwork*)u)->root,s); }
static uint8_t acl_access(void* u,Matter_Exchange_Session_T token,const Matter_Im_Path_T* p,Matter_Im_Privilege_T v) {
    AclNetwork* h=u; Matter_Acl_Device_Port_T device={NULL,acl_types};
    for(unsigned i=0;i<2;++i) if(h->links[i] && h->links[i]->b.secure_token==token) {
        Matter_Secure_Identity_T id;
        if(matter_secure_identity(h->links[i]->b.secure,&id)==MATTER_OK &&
            matter_acl_authorize(h->acl,id.fabric_index,id.peer_node_id,id.cats,id.cat_count,p,v,&device)) return 0;
    }
    return MATTER_IM_UNSUPPORTED_ACCESS;
}
static bool acl_handshake(AclNetwork* h,unsigned link,Matter_Case_T* sessions) {
    bool ok=false; PaseFixture* f=h->net; f->link=h->links[link]=create_network(); CHECK(f->link);
    Peer* peers[]={&f->link->a,&f->link->b};
    for(unsigned i=0;i<2;++i) { peers[i]->case_session=sessions[i]; CHECK(matter_rx_register(peers[i]->rx,0,0)==MATTER_OK); }
    for(unsigned i=0;i<4;++i) {
        CHECK(matter_case_process(sessions[i%2],h->now)==MATTER_PENDING);
        CHECK(transport_message(f,peers[i%2],peers[1-i%2],&h->now,false,false));
    }
    CHECK(matter_case_process(sessions[0],h->now)==MATTER_OK);
    for(unsigned i=0;i<2;++i) {
        Peer* p=peers[i]; CHECK(matter_rx_close(p->rx,p->handle)==MATTER_OK); p->handle=0; p->case_session=NULL;
        p->secure=matter_secure_new_case(&f->port,sessions[i],h->now); CHECK(p->secure);
        p->secure_token=30001+link*10+i; p->session=p->secure_token;
        p->channel=matter_secure_channel_new(p->secure,p->secure_token,&p->path); CHECK(p->channel);
        CHECK(matter_rx_register(p->rx,0,1)==MATTER_OK);
    }
    ok=true;
done: return ok;
}
static bool acl_write_network(AclNetwork* h,unsigned peer,bool add,bool more,int64_t version,uint8_t expected,bool loss,size_t capacity) {
    bool ok=false; PaseFixture* f=h->net; f->link=h->links[peer]; Peer* a=&f->link->a; Peer* b=&f->link->b;
    if(!b->write) {
        CHECK(fab_exchange(f)); Matter_Im_Write_Port_T p; Matter_Im_Read_Fabric_Port_T resolver;
        CHECK(matter_root_case_write_port(h->root->root,b->secure_token,b->secure,&h->bindings[peer],&p,&resolver)==MATTER_OK);
        Matter_Im_Write_Config_T config={{b->secure_token,a->key.exchange_id,false},30000,capacity,false};
        b->write=matter_im_write_new_case(&p,&resolver,&config,++h->now); CHECK(b->write);
    }
    aw_request(&h->wire,add,more,version);
    CHECK(im_host_send(f,a,6,h->wire.request,h->wire.request_size,++h->now) && tick(a,h->now)); network_poll(a);
    CHECK(network_take(a) && network_receive(b)); f->link->delayed_data=b->inbox;
    CHECK(network_admit(b,h->now) && tick(b,h->now) && im_ack_transfer(b,a,h->now+=200));
    CHECK(matter_im_write_process(b->write,h->now)==MATTER_PENDING);
    uint32_t after=matter_acl_version(h->acl); unsigned delivered=b->deliveries;
    CHECK(receive_packet(b,&f->link->delayed_data,h->now)==MATTER_OK && tick(b,h->now));
    CHECK(b->deliveries==delivered && matter_acl_version(h->acl)==after && im_ack_transfer(b,a,h->now));
    Matter_Im_Write_Message_T out; CHECK(matter_im_write_output(b->write,&out)==MATTER_OK);
    if(capacity>=sizeof(write_response)) {
        CHECK(out.opcode==7 && out.size==sizeof(write_response));
        memcpy(h->root->expected,write_response,sizeof(write_response)); h->root->expected[11]=0x1f; h->root->expected[14]=0; h->root->expected[20]=expected;
        CHECK(!memcmp(out.data,h->root->expected,out.size));
    } else CHECK(out.opcode==1 && out.data[3]==expected);
    CHECK(im_host_send(f,b,out.opcode,out.data,out.size,h->now) && tick(b,h->now)); network_poll(b);
    CHECK(network_take(b) && network_receive(a));
    if(loss) {
        f->link->delayed_ack=a->inbox; a->inbox_full=false;
        CHECK(matter_retransmission_sender_deadline(b->tx,&h->now)==MATTER_OK && tick(b,h->now)); complete_resolver(b); network_poll(b);
        CHECK(network_take(b) && network_receive(a) && a->inbox.size==f->link->delayed_ack.size && !memcmp(a->inbox.data,f->link->delayed_ack.data,a->inbox.size));
        CHECK(matter_acl_version(h->acl)==after);
    }
    CHECK(network_admit(a,h->now) && tick(a,h->now) && im_ack_transfer(a,b,h->now+=200));
    if(!more) { CHECK(matter_im_write_state(b->write)==MATTER_IM_WRITE_COMPLETE && matter_im_write_delete(b->write)==MATTER_OK); b->write=NULL; a->im_client=false; }
    else CHECK(matter_im_write_state(b->write)==MATTER_IM_WRITE_WAIT_CHUNK);
    ok=true;
done: return ok;
}
static bool acl_read_network(AclNetwork* h,unsigned peer,bool list,unsigned expected,bool denied) {
    bool ok=false; PaseFixture* f=h->net; f->link=h->links[peer]; Peer* a=&f->link->a; Peer* b=&f->link->b;
    Matter_Root_Case_Read_Binding_T binding; Matter_Im_Read_Port_T port; Matter_Im_Read_Fabric_Port_T fabric;
    CHECK(fab_exchange(f) && matter_root_case_read_port(h->root->root,b->secure_token,b->secure,&binding,&port,&fabric)==MATTER_OK);
    Matter_Im_Read_Config_T config={{b->secure_token,a->key.exchange_id,false},30000,192,false};
    b->im=matter_im_read_new_case(&port,&fabric,&config,++h->now); CHECK(b->im);
    memcpy(h->wire.request,im_request,sizeof(im_request)); if(list) { h->wire.request[9]=0x1f; h->wire.request[12]=0; }
    CHECK(im_host_send(f,a,2,h->wire.request,sizeof(im_request),h->now) && tick(a,h->now)); network_poll(a);
    CHECK(network_take(a) && network_receive(b) && network_admit(b,h->now) && tick(b,h->now));
    CHECK(im_ack_transfer(b,a,h->now+=200) && matter_im_read_process(b->im,h->now)==MATTER_PENDING);
    unsigned found=0,errors=0,chunks=0;
    for(;chunks<10;++chunks) {
        Matter_Im_Read_Message_T out; CHECK(matter_im_read_output(b->im,&out)==MATTER_OK && out.opcode==5);
        CHECK(im_host_send(f,b,5,out.data,out.size,h->now) && matter_im_read_sent(b->im)==MATTER_OK && tick(b,h->now)); network_poll(b);
        CHECK(network_take(b) && network_receive(a) && network_admit(a,h->now) && tick(a,h->now));
        RootFixture* r=h->root; bool more=false;
        CHECK(matter_tlv_init(&r->reader,a->im_received.data,a->im_received.size,8)==MATTER_TLV_OK);
        while(matter_tlv_next(&r->reader,&r->token)==MATTER_TLV_OK) {
            if(r->token.type==MATTER_TLV_BOOL && r->token.tag.number==3) more=r->token.unsigned_value!=0;
            if(r->token.type==MATTER_TLV_UNSIGNED && r->token.tag.control==1) {
                if(r->token.tag.number==254) { CHECK(r->token.unsigned_value==1); if(list) ++found; }
                if(!list && r->token.tag.number==2 && r->token.unsigned_value==0xfff1) ++found;
                if(r->token.tag.number==0 && r->token.unsigned_value==MATTER_IM_UNSUPPORTED_ACCESS) ++errors;
            }
        }
        CHECK(im_ack_transfer(a,b,h->now+=200));
        if(!more) break;
        static const uint8_t success[]={0x15,0x24,0,0,0x24,255,13,0x18};
        CHECK(im_host_send(f,a,1,success,sizeof(success),h->now) && tick(a,h->now)); network_poll(a);
        CHECK(network_take(a) && network_receive(b) && network_admit(b,h->now) && tick(b,h->now));
        CHECK(im_ack_transfer(b,a,h->now+=200) && matter_im_read_process(b->im,h->now)==MATTER_PENDING);
    }
    CHECK(found==expected && errors==(denied?1u:0u) && matter_im_read_state(b->im)==MATTER_IM_READ_COMPLETE);
    if(list && expected==4) CHECK(chunks>0);
    CHECK(matter_im_read_delete(b->im)==MATTER_OK); b->im=NULL; a->im_client=false; ok=true;
done: return ok;
}
static bool network_acl(void) {
    bool ok=false; AclNetwork* h=calloc(1,sizeof(*h)); REQUIRE(h); h->net=setup(false,false); PaseFixture* f=h->net;
    Matter_Credentials_Port_T cp; CHECK(matter_crypto_mbedtls_credentials(f->crypto,&cp)==MATTER_OK);
    h->admin=case_fixture(&f->port,&cp); FabFixture* server=h->admin->fabrics[1];
    Matter_Acl_Port_T port=matter_fabric_host_acl_port(server->host); h->acl=matter_acl_new(&port); CHECK(h->acl);
    h->root=root_fixture(); Matter_Root_Port_T rp={h,acl_load,acl_access,acl_store_root}; h->root->root=matter_root_new(&rp); CHECK(h->root->root);
    CHECK(matter_root_attach_acl(h->root->root,h->acl)==MATTER_OK);
    CHECK(acl_handshake(h,0,h->admin->session));
    h->guest=fab_new(&f->port,&cp); fab_csr(h->guest,12); fab_request(h->guest,11,FAB_CERT(fab_root),(Matter_Cert_Tlv_T){0},0); fab_call(h->guest,1,11,true,0,0);
    fab_request(h->guest,6,FAB_CERT(acl_peer_noc),(Matter_Cert_Tlv_T){0},100); fab_call(h->guest,1,6,true,0,0);
    for(unsigned i=0;i<2;++i) {
        Matter_Case_Port_T p=matter_fabric_host_case_port(i?server->host:h->guest->host);
        Matter_Case_Config_T c={.responder=i!=0,.local_session_id=(uint16_t)(51+i),.timeout_ms=30000,.fabric_index=1,.peer_node_id=100,.time={MATTER_CERT_TIME_SUPPLIED,{2026,10,9,0,0,0}}};
        h->guest_cases[i]=matter_case_new(&f->port,&cp,&p,&c,h->now); CHECK(h->guest_cases[i]);
    }
    CHECK(acl_handshake(h,1,h->guest_cases));
    CHECK(acl_read_network(h,0,true,1,false) && acl_read_network(h,1,false,0,true));
    aw_list(&h->wire,true); uint32_t initial=matter_acl_version(h->acl);
    CHECK(acl_write_network(h,1,false,false,-1,MATTER_IM_UNSUPPORTED_ACCESS,false,128) && matter_acl_version(h->acl)==initial);
    CHECK(acl_write_network(h,0,false,false,initial+1,MATTER_IM_DATA_VERSION_MISMATCH,false,128) && matter_acl_version(h->acl)==initial);
    CHECK(acl_write_network(h,0,false,false,-1,MATTER_IM_RESOURCE_EXHAUSTED,false,8) && matter_acl_version(h->acl)==initial);
    Matter_Fabric_Host_Control_T fault={.fail_acl=true}; matter_fabric_host_control(server->host,&fault);
    CHECK(acl_write_network(h,0,false,false,-1,MATTER_IM_FAILURE,false,128) && matter_acl_version(h->acl)==initial);
    fault.fail_acl=false; matter_fabric_host_control(server->host,&fault);
    CHECK(acl_write_network(h,0,false,false,initial,0,true,128) && matter_acl_version(h->acl)==initial+1);
    CHECK(acl_read_network(h,0,true,2,false) && acl_read_network(h,1,false,1,false) && acl_read_network(h,1,true,0,true));
    aw_list(&h->wire,false); CHECK(acl_write_network(h,0,false,false,-1,0,false,128));
    CHECK(acl_read_network(h,1,false,0,true)); /* SAME CASE session loses access. */
    /* Nonempty REPLACE prefix, ADD continuation, then chunked Read. */
    aw_list(&h->wire,false); CHECK(acl_write_network(h,0,false,true,-1,0,false,128));
    for(unsigned i=0;i<3;++i) {
        h->wire.size=0; aw_entry_ex(&h->wire,102+i*4,1,2,4,3,1);
        CHECK(acl_write_network(h,0,true,i<2,-1,0,i==1,128));
    }
    CHECK(acl_read_network(h,0,true,4,false));
    /* Admin is allowed to remove its own rights; next chunk is denied. */
    h->wire.size=0; aw_open(&h->wire,0x16,-1); aw_entry(&h->wire,102,1,1); aw_byte(&h->wire,0x18);
    CHECK(acl_write_network(h,0,false,true,-1,0,false,128));
    h->wire.size=0; aw_entry(&h->wire,101,5,0);
    CHECK(acl_write_network(h,0,true,false,-1,MATTER_IM_UNSUPPORTED_ACCESS,false,128));
    CHECK(!matter_fabric_host_case_authorize(server->host,1,101,NULL,0,MATTER_IM_ADMINISTER));
    /* ACL shares the persisted fabric image. Complete commit doesn't recreate bootstrap. */
    CHECK(matter_fabric_host_commit(server->host)==MATTER_OK);
    for(unsigned i=0;i<2;++i) { cleanup(h->links[i]); h->links[i]=NULL; }
    f->link=NULL; root_release(h->root); h->root=NULL; CHECK(matter_acl_delete(h->acl)==MATTER_OK); h->acl=NULL;
    fab_restart(server); port=matter_fabric_host_acl_port(server->host); h->acl=matter_acl_new(&port); CHECK(h->acl);
    Matter_Im_Path_T basic={0,0x28,2};
    CHECK(!matter_acl_authorize(h->acl,1,101,NULL,0,&basic,MATTER_IM_ADMINISTER,NULL));
    CHECK(matter_acl_authorize(h->acl,1,102,NULL,0,&basic,MATTER_IM_VIEW,NULL));
    puts("PASS ACL CASE IPv6: two authenticated peers, bootstrap/read/replace/add/chunks, grant/revoke on live session, version/capacity/store failure, self-lockout, duplicate/loss and persisted policy"); ok=true;
done:
    if(h->root) root_release(h->root);
    if(h->acl) REQUIRE(matter_acl_delete(h->acl)==MATTER_OK);
    for(unsigned i=0;i<2;++i) { if(h->links[i]) cleanup(h->links[i]); if(h->guest_cases[i]) REQUIRE(matter_case_delete(h->guest_cases[i])==MATTER_OK); }
    if(h->guest) fab_free(h->guest);
    if(h->admin) case_free(h->admin);
    f->link=NULL; dispose(f); free(h); return ok;
}
#endif

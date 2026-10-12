#ifdef MATTER_TEST_HOST_UDP
#include "test_case_fixture.h"
typedef struct { RootFixture* model; FabFixture* fabric; Peer* peer; bool deny; } CaseRoot;
static Matter_Result_T case_root_load(void* u,Matter_Root_Config_T* c) { return root_load(((CaseRoot*)u)->model,c); }
static Matter_Result_T case_root_store(void* u,const Matter_Root_Settings_T* s) { return root_store(((CaseRoot*)u)->model,s); }
static uint8_t case_root_authorize(void* u,Matter_Exchange_Session_T token,const Matter_Im_Path_T* p,Matter_Im_Privilege_T privilege) {
    CaseRoot* h=u; Matter_Secure_Identity_T id; (void)p;
    if(h->deny || token!=h->peer->secure_token || matter_secure_identity(h->peer->secure,&id)!=MATTER_OK ||
        !matter_fabric_host_case_authorize(h->fabric->host,id.fabric_index,id.peer_node_id,id.cats,id.cat_count,privilege)) return MATTER_IM_UNSUPPORTED_ACCESS;
    return 0;
}
static bool network_case(void) {
    bool ok=false; uint64_t now=0; PaseFixture* f=setup(false,false); f->link=create_network(); REQUIRE(f->link);
    Matter_Credentials_Port_T cp; REQUIRE(matter_crypto_mbedtls_credentials(f->crypto,&cp)==MATTER_OK);
    CaseFixture* c=case_fixture(&f->port,&cp); Peer* peers[]={&f->link->a,&f->link->b}; Peer* a=peers[0]; Peer* b=peers[1];
    GcFixture* g=gc_fixture(); CaseRoot host={g->f,c->fabrics[1],b,false};
    Matter_Root_Port_T root_port={&host,case_root_load,case_root_authorize,case_root_store};
    Matter_Root_Commissioning_Port_T gc_port={g,gc_begin,gc_cleanup,gc_regulatory,NULL};
    g->f->root=matter_root_new_commissioning(&root_port,&g->config,&gc_port,0); CHECK(g->f->root);
    CHECK(matter_root_attach_opcreds(g->f->root,c->fabrics[1]->o->core)==MATTER_OK);
    for(unsigned i=0;i<2;++i) { peers[i]->case_session=c->session[i]; CHECK(matter_rx_register(peers[i]->rx,0,0)==MATTER_OK); }
    for(unsigned i=0;i<4;++i) {
        unsigned from=i%2; CHECK(matter_case_process(c->session[from],now)==MATTER_PENDING);
        CHECK(matter_case_take_keys(c->session[from],&c->keys[from])==MATTER_INVALID_STATE);
        CHECK(transport_message(f,peers[from],peers[1-from],&now,true,true));
    }
    CHECK(matter_case_process(c->session[0],now)==MATTER_OK && matter_case_state(c->session[1])==MATTER_CASE_COMPLETE);
    for(unsigned i=0;i<2;++i) {
        Peer* p=peers[i]; CHECK(matter_rx_close(p->rx,p->handle)==MATTER_OK); p->handle=0; p->case_session=NULL;
        p->secure=matter_secure_new_case(&f->port,c->session[i],now); CHECK(p->secure);
        p->secure_token=20001+i; p->session=p->secure_token;
        p->channel=matter_secure_channel_new(p->secure,p->secure_token,&p->path); CHECK(p->channel);
        CHECK(matter_rx_register(p->rx,0,1)==MATTER_OK);
    }
    for(unsigned mode=0;mode<4;++mode) {
        CHECK(fab_exchange(f)); memcpy(c->bytes,im_request,sizeof(im_request));
        if(mode==1 || mode==2) { c->bytes[9]=0x3e; c->bytes[12]=mode==1?5:0; }
        host.deny=mode==3;
        Matter_Root_Case_Read_Binding_T binding; Matter_Im_Read_Port_T port; Matter_Im_Read_Fabric_Port_T fabric;
        CHECK(matter_root_case_read_port(g->f->root,b->secure_token,b->secure,&binding,&port,&fabric)==MATTER_OK);
        Matter_Im_Read_Config_T config={{b->secure_token,a->key.exchange_id,false},10000,512,false};
        b->im=matter_im_read_new_case(&port,&fabric,&config,++now); CHECK(b->im);
        CHECK(im_host_send(f,a,2,c->bytes,sizeof(im_request),now) && tick(a,now)); network_poll(a);
        CHECK(network_take(a) && network_receive(b) && network_admit(b,now) && tick(b,now));
        CHECK(im_ack_transfer(b,a,now+=200) && matter_im_read_process(b->im,now)==MATTER_PENDING);
        Matter_Im_Read_Message_T out; CHECK(matter_im_read_output(b->im,&out)==MATTER_OK && out.opcode==5);
        CHECK(im_host_send(f,b,5,out.data,out.size,now) && matter_im_read_sent(b->im)==MATTER_OK && tick(b,now)); network_poll(b);
        CHECK(network_take(b) && network_receive(a));
        if(mode==0) {
            f->link->delayed_ack=a->inbox; a->inbox_full=false;
            CHECK(matter_retransmission_sender_deadline(b->tx,&now)==MATTER_OK && tick(b,now)); complete_resolver(b);
            network_poll(b); CHECK(network_take(b) && network_receive(a));
            CHECK(a->inbox.size==f->link->delayed_ack.size && !memcmp(a->inbox.data,f->link->delayed_ack.data,a->inbox.size));
        }
        CHECK(network_admit(a,now) && tick(a,now));
        FabFixture* m=c->fabrics[1]; CHECK(matter_tlv_init(&m->reader,a->im_received.data,a->im_received.size,8)==MATTER_TLV_OK); unsigned found=0;
        while(matter_tlv_next(&m->reader,&m->e)==MATTER_TLV_OK) {
            if(mode<2 && m->e.type==MATTER_TLV_UNSIGNED && m->e.tag.number==2 && m->e.unsigned_value==(mode?1:0xfff1)) ++found;
            if(mode==2 && m->e.type==MATTER_TLV_BYTES && m->e.tag.number==1) { CHECK(m->e.size==sizeof(fab_noc0) && !memcmp(m->e.data,fab_noc0,m->e.size)); ++found; }
            if(mode==3 && m->e.type==MATTER_TLV_UNSIGNED && m->e.unsigned_value==MATTER_IM_UNSUPPORTED_ACCESS) ++found;
        }
        CHECK(found==1 && im_ack_transfer(a,b,now+=200) && matter_im_read_state(b->im)==MATTER_IM_READ_COMPLETE);
        CHECK(matter_im_read_delete(b->im)==MATTER_OK); b->im=NULL; a->im_client=false;
    }
    /* Session close with borrowed TX must drain before fabric rollback. */
    static const uint8_t status[]={0x15,0x24,0,0,0x24,255,13,0x18};
    CHECK(im_host_send(f,b,1,status,sizeof(status),++now) && tick(b,now) && b->retained);
    CHECK(matter_secure_channel_retire(b->channel,b->rx,b->tx)==MATTER_PENDING);
    Matter_Secure_Identity_T identity; CHECK(matter_secure_identity(b->secure,&identity)==MATTER_INVALID_STATE);
    network_poll(b); CHECK(network_take(b) && tick(b,now));
    CHECK(matter_secure_channel_retire(b->channel,b->rx,b->tx)==MATTER_OK && !b->tx_pins && !b->rx_pins && !b->ack_pins);
    CHECK(matter_opcreds_rollback(c->fabrics[1]->o->core)==MATTER_OK);
    puts("PASS CASE IPv6: four messages with loss/duplicates, authenticated secure handoff, Root/CurrentFabricIndex/NOCs Read, ACL denial, immutable retry and TX drain"); ok=true;
done:
    a->case_session=b->case_session=NULL;
    if(b->im) { REQUIRE(matter_im_read_cancel(b->im)==MATTER_OK && matter_im_read_delete(b->im)==MATTER_OK); b->im=NULL; }
    gc_release(g,now); /* Handlers/Root before fabrics. */
    cleanup(f->link); f->link=NULL; case_free(c); dispose(f); return ok;
}
#endif

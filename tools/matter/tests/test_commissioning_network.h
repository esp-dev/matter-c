#ifdef MATTER_TEST_HOST_UDP
#include "test_commissioning_fixture.h"
static Matter_Result_T gc_retire(void* user) {
    Peer* b=user; return matter_secure_channel_retire(b->channel,b->rx,b->tx);
}
static bool gc_read_network(PaseFixture* f,GcFixture* g,uint64_t* clock,uint32_t cluster,uint32_t attr,
    uint64_t value,const char* text,uint32_t version) {
    bool ok=false; uint64_t now=++*clock; Peer* a=&f->link->a; Peer* b=&f->link->b;
    memcpy(g->f->request,im_request,sizeof(im_request)); g->f->request[9]=(uint8_t)cluster; g->f->request[12]=(uint8_t)attr;
    CHECK(im_host_begin_port(f,now,256,g->f->request,sizeof(im_request),&g->f->read) && tick(a,now)); network_poll(a);
    CHECK(network_take(a) && network_receive(b) && network_admit(b,now) && tick(b,now));
    CHECK(im_ack_transfer(b,a,now+=200));
    Matter_Result_T r=matter_root_process(g->f->root,now); CHECK(r==MATTER_OK || r==MATTER_PENDING);
    CHECK(matter_im_read_process(b->im,now)==MATTER_PENDING);
    Matter_Im_Read_Message_T out; CHECK(matter_im_read_output(b->im,&out)==MATTER_OK && out.opcode==5);
    CHECK(im_host_send(f,b,5,out.data,out.size,now) && matter_im_read_sent(b->im)==MATTER_OK && tick(b,now)); network_poll(b);
    CHECK(network_take(b) && network_receive(a) && network_admit(a,now) && tick(a,now));
    ROOT_CHECK(matter_tlv_init(&g->f->reader,a->im_received.data,a->im_received.size,8)==MATTER_TLV_OK);
    unsigned depth=0,values=0; bool saw_version=false; Matter_Tlv_Result_T tr;
    while((tr=matter_tlv_next(&g->f->reader,&g->f->token))==MATTER_TLV_OK) {
        Matter_Tlv_Element_T* e=&g->f->token;
        if(e->type==MATTER_TLV_END) { CHECK(depth); --depth; continue; }
        if(depth==4 && e->tag.number==0) { CHECK(e->unsigned_value==version); saw_version=true; }
        if(depth==4 && e->tag.number==2) {
            ++values;
            if(text) CHECK(e->type==MATTER_TLV_UTF8 && e->size==strlen(text) && !memcmp(e->data,text,e->size));
            else CHECK(e->type==MATTER_TLV_UNSIGNED && e->unsigned_value==value);
        }
        if(e->type==MATTER_TLV_STRUCTURE || e->type==MATTER_TLV_ARRAY || e->type==MATTER_TLV_LIST) ++depth;
    }
    CHECK(tr==MATTER_TLV_DONE && !depth && values==1 && saw_version);
    CHECK(im_ack_transfer(a,b,now+=200) && matter_im_read_state(b->im)==MATTER_IM_READ_COMPLETE);
    CHECK(matter_im_read_delete(b->im)==MATTER_OK); b->im=NULL; a->im_client=false; *clock=now; ok=true;
done: return ok;
}
static bool commissioning_network(PaseFixture* f,uint64_t now) {
    bool ok=false; Peer* a=&f->link->a; Peer* b=&f->link->b;
    GcFixture* g=gc_fixture(); g->f->session=b->secure_token;
    g->config.recommended_seconds=30; g->config.cumulative_seconds=60; gc_open(g,now);
    CHECK(gc_read_network(f,g,&now,0x30,0,0,NULL,13));
    uint64_t initial_deadline=0;
    for(unsigned mode=0;mode<6;++mode) {
        if(a->handle) CHECK(matter_rx_close(a->rx,a->handle)==MATTER_OK);
        if(b->handle) CHECK(matter_rx_close(b->rx,b->handle)==MATTER_OK);
        a->handle=b->handle=0; a->im_client=true; a->im_received.size=0;
        CHECK(matter_rx_initiate(a->rx,a->secure_token,&a->handle)==MATTER_OK && matter_rx_get(a->rx,a->handle,&a->key)==MATTER_OK);
        Matter_Im_Invoke_Config_T c={{b->secure_token,a->key.exchange_id,false},5000,256,true};
        b->invoke=matter_im_invoke_new(&g->invoke,&c,++now); CHECK(b->invoke);
        uint32_t cmd=mode<2?0:mode==5?4:2;
        gc_request(g,cmd,mode<2?30:0,mode==3?"ZZ":"pl",mode+41);
        g->fail_regulatory=mode==4;
        CHECK(im_host_send(f,a,8,g->f->request,g->f->request_size,now) && tick(a,now)); network_poll(a);
        CHECK(network_take(a) && network_receive(b) && network_admit(b,now) && tick(b,now));
        CHECK(im_ack_transfer(b,a,now+=200));
        Matter_Result_T r=matter_root_process(g->f->root,now); CHECK(r==MATTER_OK || r==MATTER_PENDING);
        CHECK(matter_im_invoke_process(b->invoke,now)==MATTER_PENDING);
        uint64_t deadline; CHECK(matter_root_deadline(g->f->root,&deadline)==MATTER_OK);
        if(mode==0) initial_deadline=deadline;
        if(mode==1) CHECK(deadline>initial_deadline && g->begins==1);
        Matter_Im_Invoke_Message_T out; CHECK(matter_im_invoke_output(b->invoke,&out)==MATTER_OK && out.opcode==9);
        CHECK(im_host_send(f,b,9,out.data,out.size,now) && matter_im_invoke_sent_at(b->invoke,now)==MATTER_OK && tick(b,now)); network_poll(b);
        CHECK(network_take(b) && network_receive(a));
        if(!mode) {
            f->link->delayed_ack=a->inbox; a->inbox_full=false;
            CHECK(matter_retransmission_sender_deadline(b->tx,&now)==MATTER_OK && tick(b,now)); complete_resolver(b);
            network_poll(b); CHECK(network_take(b) && network_receive(a));
            CHECK(a->inbox.size==f->link->delayed_ack.size && !memcmp(a->inbox.data,f->link->delayed_ack.data,a->inbox.size));
        }
        CHECK(network_admit(a,now) && tick(a,now));
        gc_reply(a->im_received.data,a->im_received.size,cmd,mode==3?1:mode==4?MATTER_IM_FAILURE:mode==5?MATTER_IM_UNSUPPORTED_ACCESS:0,mode>=4);
        CHECK(im_ack_transfer(a,b,now+=200) && matter_im_invoke_state(b->invoke)==MATTER_IM_INVOKE_COMPLETE);
        CHECK(matter_im_invoke_delete(b->invoke)==MATTER_OK); b->invoke=NULL; a->im_client=false;
    }
    CHECK(g->begins==1 && g->regulations==3);
    CHECK(gc_read_network(f,g,&now,0x30,0,43,NULL,16));
    CHECK(gc_read_network(f,g,&now,0x28,6,0,"ZZ",9));
    /* Expire with real outgoing I/O retained; cleanup cannot release early. */
    static const uint8_t status[]={0x15,0x24,0,0,0x24,255,13,0x18};
    CHECK(im_host_send(f,b,1,status,sizeof(status),++now) && tick(b,now) && b->retained);
    g->cleanup_hook=gc_retire; g->hook_user=b; g->network=99;
    CHECK(matter_root_deadline(g->f->root,&now)==MATTER_OK);
    CHECK(matter_root_process(g->f->root,now)==MATTER_PENDING && g->marker && g->revoked);
    CHECK(matter_root_delete(g->f->root)==MATTER_INVALID_STATE);
    network_poll(b); CHECK(network_take(b) && tick(b,now));
    CHECK(matter_root_process(g->f->root,now)==MATTER_OK && !g->marker && g->network==3 && gc_scalar(g,0x30,0,NULL)==0);
    bool closed=false; CHECK(matter_secure_channel_is_closed(b->channel,&closed)==MATTER_OK && closed);
    CHECK(!b->tx_pins && !b->ack_pins && !b->rx_pins);
    puts("PASS commissioning IPv6: Arm/rearm/regulatory/readback, fabric gate, immutable retry, expiry revokes PASE and drains TX before rollback"); ok=true;
done:
    if(b->invoke) { REQUIRE(matter_im_invoke_cancel(b->invoke)==MATTER_OK && matter_im_invoke_delete(b->invoke)==MATTER_OK); b->invoke=NULL; }
    if(b->im) { REQUIRE(matter_im_read_cancel(b->im)==MATTER_OK && matter_im_read_delete(b->im)==MATTER_OK); b->im=NULL; }
    gc_release(g,now); return ok;
}
#endif

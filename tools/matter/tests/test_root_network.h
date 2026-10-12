#ifdef MATTER_TEST_HOST_UDP
#include "test_root_fixture.h"
static bool root_read_network(PaseFixture* f,RootFixture* model,uint64_t* clock,bool filter,unsigned expected,uint32_t version) {
    bool ok=false; Peer* a=&f->link->a; Peer* b=&f->link->b; uint64_t now=*clock;
    root_read_request(model,filter); model->seen=0; model->received=0;
    CHECK(im_host_begin_port(f,++now,256,model->request,model->request_size,&model->read) && tick(a,now));
    network_poll(a); CHECK(network_take(a) && network_receive(b) && network_admit(b,now) && tick(b,now));
    CHECK(im_ack_transfer(b,a,now+=200));
    for(unsigned step=0;step<40;++step) {
        CHECK(matter_im_read_process(b->im,now)==MATTER_PENDING);
        Matter_Im_Read_Message_T out;
        if(matter_im_read_output(b->im,&out)!=MATTER_OK) continue;
        CHECK(out.opcode==5 && im_host_send(f,b,5,out.data,out.size,now) && matter_im_read_sent(b->im)==MATTER_OK && tick(b,now));
        network_poll(b); CHECK(network_take(b) && network_receive(a) && network_admit(a,now) && tick(a,now));
        CHECK(a->im_opcode==5); bool more=root_report(model,a->im_received.data,a->im_received.size,version);
        CHECK(im_ack_transfer(a,b,now+=200));
        if(!more) break;
        static const uint8_t success[]={0x15,0x24,0,0,0x24,255,13,0x18};
        CHECK(im_host_send(f,a,1,success,sizeof(success),now) && tick(a,now)); network_poll(a);
        CHECK(network_take(a) && network_receive(b) && network_admit(b,now) && tick(b,now));
        CHECK(im_ack_transfer(b,a,now+=200));
    }
    CHECK(matter_im_read_state(b->im)==MATTER_IM_READ_COMPLETE && model->received==expected);
    CHECK(!a->tx_pins && !b->tx_pins && !a->ack_pins && !b->ack_pins);
    CHECK(matter_im_read_delete(b->im)==MATTER_OK); b->im=NULL; a->im_client=false; *clock=now; ok=true;
done: return ok;
}
static bool root_network(PaseFixture* f,uint64_t* clock) {
    bool ok=false; Peer* a=&f->link->a; Peer* b=&f->link->b; uint64_t now=*clock;
    RootFixture* model=root_fixture(); model->session=b->secure_token; root_open(model); model->reenter=true;
    CHECK(root_read_network(f,model,&now,false,30,7));
    CHECK(root_read_network(f,model,&now,true,0,7));
    for(unsigned mode=0;mode<5;++mode) {
        if(a->handle) CHECK(matter_rx_close(a->rx,a->handle)==MATTER_OK);
        if(b->handle) CHECK(matter_rx_close(b->rx,b->handle)==MATTER_OK);
        a->handle=b->handle=0; a->im_client=true; a->im_received.size=0;
        CHECK(matter_rx_initiate(a->rx,a->secure_token,&a->handle)==MATTER_OK && matter_rx_get(a->rx,a->handle,&a->key)==MATTER_OK);
        Matter_Im_Write_Config_T c={{b->secure_token,a->key.exchange_id,false},5000,256,true};
        b->write=matter_im_write_new(&model->write,&c,++now); CHECK(b->write);
        uint32_t attr=mode==1?6:5;
        root_write_request(model,attr,(const uint8_t*)(mode==1?"pl":"meter"),mode==1?2:5,mode==0?7:mode==1?8:9);
        model->fail_store=mode==2; model->denied=mode==3?MATTER_IM_UNSUPPORTED_ACCESS:0;
        if(mode==2) root_write_request(model,5,(const uint8_t*)"changed",7,9);
        if(mode==4) root_write_request(model,5,(const uint8_t*)"stale",5,7);
        CHECK(im_host_send(f,a,6,model->request,model->request_size,now) && tick(a,now)); network_poll(a);
        CHECK(network_take(a) && network_receive(b) && network_admit(b,now) && tick(b,now));
        CHECK(im_ack_transfer(b,a,now+=200) && matter_im_write_process(b->write,now)==MATTER_PENDING);
        Matter_Im_Write_Message_T out; CHECK(matter_im_write_output(b->write,&out)==MATTER_OK && out.opcode==7);
        CHECK(im_host_send(f,b,out.opcode,out.data,out.size,now) && tick(b,now)); network_poll(b);
        CHECK(network_take(b) && network_receive(a));
        if(mode==0) {
            f->link->delayed_ack=a->inbox; a->inbox_full=false; /* Lose response; retry must not write again. */
            CHECK(matter_retransmission_sender_deadline(b->tx,&now)==MATTER_OK && tick(b,now)); complete_resolver(b);
            network_poll(b); CHECK(network_take(b) && network_receive(a));
            CHECK(a->inbox.size==f->link->delayed_ack.size && !memcmp(a->inbox.data,f->link->delayed_ack.data,a->inbox.size));
        }
        CHECK(network_admit(a,now) && tick(a,now));
        const uint8_t code=mode==2?MATTER_IM_FAILURE:mode==3?MATTER_IM_UNSUPPORTED_ACCESS:mode==4?MATTER_IM_DATA_VERSION_MISMATCH:0;
        const uint8_t reply[]={0x15,0x36,0,0x15,0x37,0,0x24,2,0,0x24,3,0x28,0x24,4,(uint8_t)attr,
            0x18,0x35,1,0x24,0,code,0x18,0x18,0x18,0x24,255,13,0x18};
        CHECK(a->im_opcode==7 && a->im_received.size==sizeof(reply) && !memcmp(a->im_received.data,reply,sizeof(reply)));
        CHECK(im_ack_transfer(a,b,now+=200) && matter_im_write_state(b->write)==MATTER_IM_WRITE_COMPLETE);
        CHECK(model->stores==(mode<2?mode+1:3));
        CHECK(matter_im_write_delete(b->write)==MATTER_OK); b->write=NULL; a->im_client=false;
    }
    model->fail_store=false; model->denied=0;
    CHECK(root_read_network(f,model,&now,false,30,9));
    CHECK(root_read_network(f,model,&now,true,21,9));
    CHECK(matter_root_delete(model->root)==MATTER_OK); model->root=NULL; root_open(model);
    CHECK(root_read_network(f,model,&now,false,30,7)); /* Durable settings, new publication seed. */
    *clock=now; ok=true;
    puts("PASS root IPv6: PASE, 30 real attributes/chunks/filters, NodeLabel/Location, persistent restart, retry and access/store/version failures");
done:
    if(b->im) { REQUIRE(matter_im_read_cancel(b->im)==MATTER_OK && matter_im_read_delete(b->im)==MATTER_OK); b->im=NULL; }
    if(b->write) { REQUIRE(matter_im_write_cancel(b->write)==MATTER_OK && matter_im_write_delete(b->write)==MATTER_OK); b->write=NULL; }
    root_release(model); return ok;
}
#endif

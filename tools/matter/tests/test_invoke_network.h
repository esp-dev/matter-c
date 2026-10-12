#ifdef MATTER_TEST_HOST_UDP
#include "test_invoke_model.h"
static bool invoke_begin_opcode(PaseFixture* f,InvokeModel* m,uint64_t now,size_t capacity,const uint8_t* request,size_t size,uint8_t opcode) {
    Peer* a=&f->link->a; Peer* b=&f->link->b;
    if(a->handle) REQUIRE(matter_rx_close(a->rx,a->handle)==MATTER_OK);
    if(b->handle) REQUIRE(matter_rx_close(b->rx,b->handle)==MATTER_OK);
    a->handle=b->handle=0; a->im_client=true; a->im_received.size=0;
    REQUIRE(matter_rx_initiate(a->rx,a->secure_token,&a->handle)==MATTER_OK);
    REQUIRE(matter_rx_get(a->rx,a->handle,&a->key)==MATTER_OK);
    Matter_Im_Invoke_Port_T port=invoke_port(m);
    Matter_Im_Invoke_Config_T c={{b->secure_token,a->key.exchange_id,false},5000,capacity,true};
    REQUIRE(!b->im && !b->invoke); m->active=b->invoke=matter_im_invoke_new(&port,&c,now); REQUIRE(b->invoke);
    return im_host_send(f,a,opcode,request,size,now);
}
static bool invoke_begin(PaseFixture* f,InvokeModel* m,uint64_t now,size_t capacity,const uint8_t* request,size_t size) {
    return invoke_begin_opcode(f,m,now,capacity,request,size,8);
}
static bool invoke_network(PaseFixture* f,uint64_t* clock) {
    bool ok=false; Peer* a=&f->link->a; Peer* b=&f->link->b; uint64_t now=*clock;
    InvokeModel* m=calloc(1,sizeof(*m)); REQUIRE(m);
    for(unsigned mode=0;mode<5;++mode) {
        memset(m,0,sizeof(*m)); memcpy(m->input,invoke_request,sizeof(invoke_request));
        if(mode==2) m->input[1]=0x29;
        CHECK(invoke_begin(f,m,++now,mode==4 ? 8 : 1024,m->input,sizeof(invoke_request)));
        if(mode==1) m->deny=MATTER_IM_UNSUPPORTED_ACCESS;
        if(mode==2) m->metadata.response=false;
        CHECK(tick(a,now)); network_poll(a); CHECK(network_take(a) && network_receive(b));
        f->link->delayed_data=b->inbox;
        CHECK(network_admit(b,now) && tick(b,now) && !m->executions);
        CHECK(im_ack_transfer(b,a,now+=200));
        if(mode==3) { now+=5000; CHECK(matter_im_invoke_process(b->invoke,now)==MATTER_PORT_ERROR && !m->executions); }
        else {
            CHECK(matter_im_invoke_process(b->invoke,now)==(mode==2 ? MATTER_OK : MATTER_PENDING));
            unsigned delivered=b->deliveries;
            /* Same encrypted request after execution is ACKed by RX without
             * reaching the handler, including when the response is suppressed. */
            Matter_Udp_Datagram_T duplicate={.path=b->received_path,.data=f->link->delayed_data.data,.size=f->link->delayed_data.size};
            CHECK(matter_secure_channel_receive(b->channel,b->rx,&duplicate,now,now)==MATTER_OK && tick(b,now));
            CHECK(b->deliveries==delivered && im_ack_transfer(b,a,now));
            if(mode==2) CHECK(matter_im_invoke_state(b->invoke)==MATTER_IM_INVOKE_COMPLETE && m->executions==1);
            else {
                Matter_Im_Invoke_Message_T response;
                CHECK(matter_im_invoke_output(b->invoke,&response)==MATTER_OK);
                CHECK(im_host_send(f,b,response.opcode,response.data,response.size,now) && matter_im_invoke_sent(b->invoke)==MATTER_OK && tick(b,now));
                network_poll(b); CHECK(network_take(b) && network_receive(a));
                if(!mode) {
                    f->link->delayed_ack=a->inbox; a->inbox_full=false;
                    CHECK(matter_retransmission_sender_deadline(b->tx,&now)==MATTER_OK && tick(b,now));
                    complete_resolver(b); network_poll(b); CHECK(network_take(b) && network_receive(a));
                    CHECK(a->inbox.size==f->link->delayed_ack.size && !memcmp(a->inbox.data,f->link->delayed_ack.data,a->inbox.size));
                }
                CHECK(network_admit(a,now) && tick(a,now));
                if(!mode) CHECK(a->im_opcode==9 && a->im_received.size==sizeof(invoke_response) && !memcmp(a->im_received.data,invoke_response,sizeof(invoke_response)));
                if(mode==1) CHECK(a->im_opcode==9 && a->im_received.data[24]==MATTER_IM_UNSUPPORTED_ACCESS);
                if(mode==4) CHECK(a->im_opcode==1 && a->im_received.data[3]==MATTER_IM_RESOURCE_EXHAUSTED);
                CHECK(im_ack_transfer(a,b,now+=200) && matter_im_invoke_state(b->invoke)==MATTER_IM_INVOKE_COMPLETE);
                CHECK(m->executions==(!mode ? 1u : 0u));
            }
        }
        CHECK(!a->tx_pins && !b->tx_pins && !a->ack_pins && !b->ack_pins);
        CHECK(matter_im_invoke_delete(b->invoke)==MATTER_OK); b->invoke=NULL; a->im_client=false;
    }
    *clock=now; puts("PASS Invoke IPv6: PASE, one execution on duplicate request/lost response, identical retry, suppression/access/capacity and timeout"); ok=true;
done:
    if(b->invoke) { REQUIRE(matter_im_invoke_cancel(b->invoke)==MATTER_OK && matter_im_invoke_delete(b->invoke)==MATTER_OK); b->invoke=NULL; }
    free(m); return ok;
}
static bool invoke_close_network(PaseFixture* f,uint64_t now) {
    bool ok=false; Peer* a=&f->link->a; Peer* b=&f->link->b;
    InvokeModel* m=calloc(1,sizeof(*m)); REQUIRE(m);
    CHECK(invoke_begin(f,m,now,1024,invoke_request,sizeof(invoke_request)) && tick(a,now));
    network_poll(a); CHECK(network_take(a) && network_receive(b) && network_admit(b,now) && tick(b,now));
    CHECK(im_ack_transfer(b,a,now+=200) && matter_im_invoke_process(b->invoke,now)==MATTER_PENDING && m->executions==1);
    CHECK(matter_secure_channel_send_close(a->channel,a->rx,a->udp,now,&a->udp_request)==MATTER_PENDING);
    CHECK(matter_secure_channel_retire(a->channel,a->rx,a->tx)==MATTER_PENDING);
    CHECK(network_receive(b) && network_admit(b,now));
    CHECK(matter_secure_channel_retire(b->channel,b->rx,b->tx)==MATTER_OK && matter_im_invoke_cancel(b->invoke)==MATTER_OK);
    network_poll(a); CHECK(network_take(a) && tick(a,now));
    CHECK(matter_secure_channel_retire(a->channel,a->rx,a->tx)==MATTER_OK);
    CHECK(matter_im_invoke_process(b->invoke,now)==MATTER_INVALID_STATE && m->executions==1 && m->value==7);
    CHECK(matter_im_invoke_confirm(b->invoke,now)==MATTER_INVALID_STATE);
    CHECK(matter_im_invoke_delete(b->invoke)==MATTER_OK); b->invoke=NULL; a->im_client=false;
    CHECK(!a->tx_pins && !b->tx_pins && !a->rx_pins && !b->rx_pins);
    puts("PASS Invoke CloseSession IPv6: executed command, discarded unsent response, no rollback/reexecution, session retire/drain"); ok=true;
done:
    if(b->invoke) { REQUIRE(matter_im_invoke_cancel(b->invoke)==MATTER_OK && matter_im_invoke_delete(b->invoke)==MATTER_OK); b->invoke=NULL; }
    free(m); return ok;
}
#endif

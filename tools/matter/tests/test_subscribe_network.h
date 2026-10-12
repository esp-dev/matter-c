#ifdef MATTER_TEST_HOST_UDP
#include "test_subscribe_model.h"
static bool sub_host_packet(PaseFixture* f,Peer* from,Peer* to,uint8_t opcode,const uint8_t* data,size_t size,uint64_t now) {
    if(!im_host_send(f,from,opcode,data,size,now) || !tick(from,now)) return false;
    network_poll(from);
    return network_take(from) && network_receive(to) && network_admit(to,now) && tick(to,now);
}
static bool sub_host_output(PaseFixture* f,uint64_t* clock,bool lose) {
    bool ok=false; Peer* a=&f->link->a; Peer* b=&f->link->b; uint64_t now=*clock;
    Matter_Im_Subscribe_Message_T out; CHECK(matter_im_subscribe_output(b->sub,&out)==MATTER_OK);
    CHECK(im_host_send(f,b,out.opcode,out.data,out.size,now) && tick(b,now)); network_poll(b);
    CHECK(network_take(b) && network_receive(a));
    if(lose) {
        f->link->delayed_data=a->inbox; a->inbox_full=false;
        CHECK(matter_retransmission_sender_deadline(b->tx,&now)==MATTER_OK && tick(b,now)); complete_resolver(b);
        network_poll(b); CHECK(network_take(b) && network_receive(a));
        CHECK(a->inbox.size==f->link->delayed_data.size && !memcmp(a->inbox.data,f->link->delayed_data.data,a->inbox.size));
    }
    CHECK(network_admit(a,now) && tick(a,now) && a->im_opcode==out.opcode);
    CHECK(a->im_received.size==out.size && !memcmp(a->im_received.data,out.data,out.size));
    *clock=now; ok=true;
done: return ok;
}
static bool sub_host_exchange(PaseFixture* f,uint64_t now) {
    Peer* a=&f->link->a; Peer* b=&f->link->b; uint16_t previous=b->key.exchange_id;
    REQUIRE(!a->tx_pins && !b->tx_pins && !a->ack_pins && !b->ack_pins);
    REQUIRE(matter_rx_close(a->rx,a->handle)==MATTER_OK && matter_rx_close(b->rx,b->handle)==MATTER_OK);
    a->handle=b->handle=0;
    REQUIRE(matter_rx_initiate(b->rx,b->secure_token,&b->handle)==MATTER_OK && matter_rx_get(b->rx,b->handle,&b->key)==MATTER_OK);
    REQUIRE(b->key.initiator && b->key.exchange_id!=previous);
    return matter_im_subscribe_bind_report(b->sub,&b->key,now)==MATTER_OK;
}
static bool subscribe_network(PaseFixture* f,uint64_t* clock,bool close) {
    bool ok=false; Peer* a=&f->link->a; Peer* b=&f->link->b; uint64_t now=*clock+1;
    SubModel* m=calloc(1,sizeof(*m)); REQUIRE(m);
    if(a->handle) CHECK(matter_rx_close(a->rx,a->handle)==MATTER_OK);
    if(b->handle) CHECK(matter_rx_close(b->rx,b->handle)==MATTER_OK);
    a->handle=b->handle=0; a->im_client=true;
    CHECK(matter_rx_initiate(a->rx,a->secure_token,&a->handle)==MATTER_OK && matter_rx_get(a->rx,a->handle,&a->key)==MATTER_OK);
    Matter_Im_Subscribe_Port_T port=sub_port(m);
    Matter_Im_Subscribe_Config_T c={{b->secure_token,a->key.exchange_id,false},10000,128,true};
    CHECK(!b->im && !b->invoke && !b->write && !b->sub);
    m->active=b->sub=matter_im_subscribe_new(&port,&c,now); CHECK(b->sub);
    CHECK(sub_host_packet(f,a,b,3,sub_request,sizeof(sub_request),now));
    CHECK(!m->reads && !m->reserves); /* RX only copies. */
    CHECK(im_ack_transfer(b,a,now+=200) && matter_im_subscribe_process(b->sub,now)==MATTER_PENDING);
    uint64_t sent=now;
    CHECK(sub_host_output(f,&now,false) && a->im_received.size==sizeof(sub_report) && !memcmp(a->im_received.data,sub_report,sizeof(sub_report)));
    /* IM SUCCESS arrives before the standalone MRP ACK for the report. */
    CHECK(sub_host_packet(f,a,b,1,sub_success,sizeof(sub_success),++now));
    CHECK(matter_im_subscribe_process(b->sub,now)==MATTER_PENDING && matter_im_subscribe_state(b->sub)==MATTER_IM_SUB_IN_FLIGHT);
    CHECK(im_ack_transfer(a,b,now+=200) && im_ack_transfer(b,a,now));
    CHECK(matter_im_subscribe_process(b->sub,now)==MATTER_PENDING && sub_host_output(f,&now,false));
    CHECK(a->im_received.size==sizeof(sub_response) && !memcmp(a->im_received.data,sub_response,sizeof(sub_response)));
    CHECK(im_ack_transfer(a,b,now+=200) && matter_im_subscribe_state(b->sub)==MATTER_IM_SUB_IDLE);
    m->value=10; ++m->version; CHECK(matter_im_subscribe_changed(b->sub)==MATTER_OK);
    now=sent+1999; CHECK(matter_im_subscribe_process(b->sub,now)==MATTER_PENDING && matter_im_subscribe_state(b->sub)==MATTER_IM_SUB_IDLE);
    ++now; CHECK(matter_im_subscribe_process(b->sub,now)==MATTER_PENDING && sub_host_exchange(f,now));
    CHECK(matter_im_subscribe_process(b->sub,now)==MATTER_PENDING); sent=now;
    CHECK(sub_host_output(f,&now,true) && m->reads==2 && a->im_received.data[11]==8 && a->im_received.data[26]==10);
    CHECK(!a->key.initiator && b->key.initiator);
    CHECK(sub_host_packet(f,a,b,1,sub_success,sizeof(sub_success),++now));
    f->link->delayed_ack=b->inbox;
    unsigned delivered=b->deliveries;
    Matter_Udp_Datagram_T duplicate={.path=b->received_path,.data=f->link->delayed_ack.data,.size=f->link->delayed_ack.size};
    CHECK(matter_secure_channel_receive(b->channel,b->rx,&duplicate,now,now)==MATTER_OK && tick(b,now));
    CHECK(b->deliveries==delivered && m->reads==2);
    if(close) {
        /* Queued IM SUCCESS and both MRP messages still live when CloseSession arrives. */
        CHECK(matter_secure_channel_send_close(a->channel,a->rx,a->udp,now,&a->udp_request)==MATTER_PENDING);
        CHECK(matter_secure_channel_retire(a->channel,a->rx,a->tx)==MATTER_PENDING);
        CHECK(network_receive(b) && network_admit(b,now) && matter_im_subscribe_cancel(b->sub)==MATTER_OK);
        CHECK(matter_secure_channel_retire(b->channel,b->rx,b->tx)==MATTER_PENDING);
        network_poll(a); CHECK(network_take(a));
        network_poll(b); CHECK(network_take(b)); /* Duplicate's ACK was submitted before close. */
        CHECK(tick(a,now) && tick(b,now) && tick(a,now) && tick(b,now));
        CHECK(matter_secure_channel_retire(a->channel,a->rx,a->tx)==MATTER_OK && matter_secure_channel_retire(b->channel,b->rx,b->tx)==MATTER_OK);
        CHECK(matter_im_subscribe_process(b->sub,now)==MATTER_INVALID_STATE && matter_im_subscribe_confirm(b->sub,now)==MATTER_INVALID_STATE);
    } else {
        /* Duplicate forces an immediate ACK for the subscriber's StatusResponse. */
        CHECK(im_ack_transfer(b,a,now) && im_ack_transfer(a,b,now+=200));
        CHECK(matter_im_subscribe_process(b->sub,now)==MATTER_PENDING && matter_im_subscribe_state(b->sub)==MATTER_IM_SUB_IDLE);
        now=sent+5000; CHECK(matter_im_subscribe_process(b->sub,now)==MATTER_PENDING && sub_host_exchange(f,now));
        CHECK(matter_im_subscribe_process(b->sub,now)==MATTER_PENDING && sub_host_output(f,&now,false));
        CHECK(m->reads==2 && a->im_received.size==sizeof(sub_empty) && !memcmp(a->im_received.data,sub_empty,sizeof(sub_empty)));
        CHECK(im_ack_transfer(a,b,now+=200) && matter_im_subscribe_state(b->sub)==MATTER_IM_SUB_WAIT_STATUS);
        now+=10000; CHECK(matter_im_subscribe_process(b->sub,now)==MATTER_PORT_ERROR); /* MRP ACK does not replace IM SUCCESS. */
    }
    CHECK(m->releases==1 && !a->tx_pins && !b->tx_pins && !a->ack_pins && !b->ack_pins);
    CHECK(matter_im_subscribe_delete(b->sub)==MATTER_OK); b->sub=NULL; a->im_client=false;
    *clock=now; puts(close ? "PASS Subscribe CloseSession IPv6: queued status discarded, MRP drained, ID released once" :
        "PASS Subscribe IPv6: prime/status/response, min/change/new exchange, exact encrypted retry, duplicate status, heartbeat and missing IM status timeout"); ok=true;
done:
    if(b->sub) { REQUIRE(matter_im_subscribe_cancel(b->sub)==MATTER_OK && matter_im_subscribe_delete(b->sub)==MATTER_OK); b->sub=NULL; }
    free(m); return ok;
}
#endif

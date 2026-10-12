/* Included by PASE fixture: direct crypto smoke for fake transport, production
 * secure channel with existing RX/MRP/ACK executors on real host UDP. */
#include "session/matter_secure.h"
#ifndef MATTER_TEST_HOST_UDP
typedef struct {
    Matter_Secure_T s[2];
    unsigned fresh, duplicates;
    uint32_t counter;
} SecureTraffic;
static Matter_Result_T secure_admit(void* u, const Matter_Secure_Received_T* m) {
    SecureTraffic* t=u;
    if (m->duplicate) { REQUIRE(!m->payload && !m->size); ++t->duplicates; }
    else {
        if (m->protocol.opcode==0x10) { /* Secure-channel standalone ACK. */
            REQUIRE(m->protocol.acknowledged_message_counter==t->counter && !m->size);
        } else { REQUIRE(m->size==3 && !memcmp(m->payload,"\xa1\xb2\xc3",3)); t->counter=m->message.message_counter; }
        ++t->fresh;
    }
    return MATTER_OK;
}
static bool secure_transfer(Peer* from, Peer* to, Matter_Secure_T sender, Matter_Secure_T receiver,
    SecureTraffic* traffic, uint64_t now, bool close_pending) {
    bool ok=false;
    (void)to; /* Only real UDP needs the destination fixture. */
    REQUIRE(matter_secure_retain(sender)==MATTER_OK);
#ifdef MATTER_TEST_HOST_UDP
    if (from->host) {
        Matter_Udp_Datagram_T d={.path=from->path,.data=from->outbound.data,.size=from->outbound.size};
        REQUIRE(matter_udp_send(from->udp,&d,&from->secure_request)==MATTER_PENDING);
        if (close_pending) {
            REQUIRE(matter_secure_close(sender)==MATTER_OK);
            REQUIRE(matter_secure_delete(sender)==MATTER_INVALID_STATE);
            /* Cancel the transport while it still borrows ciphertext. */
            REQUIRE(matter_udp_stop(from->udp)==MATTER_PENDING);
        }
        network_poll(from);
        CHECK(!from->secure_request);
        if (!close_pending) CHECK(from->secure_outcome==MATTER_OPERATION_SUCCEEDED);
        CHECK(network_receive(to));
        CHECK(to->inbox.size==from->outbound.size && !memcmp(to->inbox.data,from->outbound.data,to->inbox.size));
        to->inbox_full=false;
        CHECK(matter_secure_receive(receiver,to->inbox.data,to->inbox.size,now,secure_admit,traffic)==MATTER_OK);
    } else
#endif
    {
        if (close_pending) {
            REQUIRE(matter_secure_close(sender)==MATTER_OK);
            REQUIRE(matter_secure_delete(sender)==MATTER_INVALID_STATE);
        }
        CHECK(matter_secure_receive(receiver,from->outbound.data,from->outbound.size,now,secure_admit,traffic)==MATTER_OK);
    }
    ok=true;
done:
    REQUIRE(matter_secure_release(sender)==MATTER_OK); return ok;
}
static bool secure_traffic(PaseFixture* f, uint64_t now) {
    bool ok=false;
    SecureTraffic* t=calloc(1,sizeof(*t)); REQUIRE(t);
    Peer* a=&f->link->a; Peer* b=&f->link->b;
    static const uint8_t data[]={5,1,0x34,0x12,4,0,0xa1,0xb2,0xc3};
    for (unsigned i=0;i<2;++i) {
        t->s[i]=matter_secure_new(&f->port,f->s[i],now); CHECK(t->s[i]);
        CHECK(matter_pase_keys(f->s[i],&f->keys[i])==MATTER_INVALID_STATE);
        CHECK(!matter_secure_new(&f->port,f->s[i],now));
    }
    f->port.clear((uint8_t*)f->keys,sizeof(f->keys));
    CHECK(matter_secure_seal(t->s[0],data,sizeof(data),now,a->outbound.data,sizeof(a->outbound.data),&a->outbound.size)==MATTER_OK);
    CHECK(secure_transfer(a,b,t->s[0],t->s[1],t,now,false) && t->fresh==1);
    /* Lost ACK: resend the SAME encrypted bytes, only MRP control is admitted. */
    CHECK(secure_transfer(a,b,t->s[0],t->s[1],t,++now,false) && t->fresh==1 && t->duplicates==1);
    Matter_Protocol_Header_T ack={.exchange_flags=MATTER_PROTOCOL_ACK,.opcode=0x10,
        .exchange_id=0x1234,.acknowledged_message_counter=t->counter};
    size_t n;
    CHECK(matter_protocol_header_write(&ack,f->buffer,sizeof(f->buffer),&n)==MATTER_MESSAGE_OK);
    CHECK(matter_secure_seal(t->s[1],f->buffer,n,now,b->outbound.data,sizeof(b->outbound.data),&b->outbound.size)==MATTER_OK);
    CHECK(secure_transfer(b,a,t->s[1],t->s[0],t,now,false) && t->fresh==2);
    CHECK(matter_secure_seal(t->s[0],data,sizeof(data),++now,a->outbound.data,sizeof(a->outbound.data),&a->outbound.size)==MATTER_OK);
    CHECK(secure_transfer(a,b,t->s[0],t->s[1],t,now,true) && t->fresh==3);
    ok=true;
done:
    for (unsigned i=0;i<2;++i) if (t->s[i]) {
        REQUIRE(matter_secure_close(t->s[i])==MATTER_OK && matter_secure_delete(t->s[i])==MATTER_OK);
    }
    free(t); return ok;
}
#else
static Matter_Result_T inspect_close(void* user, const Matter_Secure_Received_T* m) {
    const Matter_Exchange_Info_T* old=user;
    static const uint8_t body[]={0,0,0,0,0,0,3,0};
    REQUIRE(!m->duplicate && m->protocol.exchange_flags==MATTER_PROTOCOL_INITIATOR);
    REQUIRE(m->protocol.opcode==0x40 && !m->protocol.protocol_id && !m->protocol.vendor_id);
    REQUIRE(m->protocol.exchange_id!=old->exchange_id && m->size==8 && !memcmp(m->payload,body,8));
    return MATTER_WOULD_BLOCK; /* Independent inspection without committing replay. */
}
static bool secure_traffic(PaseFixture* f, uint64_t now) {
    bool ok=false;
    Peer* a=&f->link->a; Peer* b=&f->link->b;
    Peer* peers[]={a,b};
    for (unsigned i=0;i<2;++i) {
        Peer* p=peers[i];
        CHECK(matter_rx_close(p->rx,p->handle)==MATTER_OK);
        p->handle=0;
        Matter_Pase_Intervals_T intervals;
        CHECK(matter_pase_peer_intervals(f->s[i],&intervals)==MATTER_OK);
        p->secure=matter_secure_new(&f->port,f->s[i],now); CHECK(p->secure);
        CHECK(!matter_secure_new(&f->port,f->s[i],now));
        CHECK(matter_pase_keys(f->s[i],&f->keys[i])==MATTER_INVALID_STATE);
        p->secure_token=10001+i; p->session=p->secure_token; p->pase=NULL;
#ifdef MATTER_TEST_ALLOC
        size_t baseline=live; fail_at=calls+1;
        CHECK(!matter_secure_channel_new(p->secure,p->secure_token,&p->path)); fail_at=0;
        CHECK(live==baseline && !session_pins(p,p->secure_token));
#endif
        CHECK(!matter_secure_channel_new(p->secure,0,&p->path));
        p->channel=matter_secure_channel_new(p->secure,p->secure_token,&p->path); CHECK(p->channel);
        CHECK(session_pins(p,p->secure_token)==1);
        Matter_Retransmission_Parameters_T parameters;
        CHECK(matter_secure_channel_parameters(p->channel,now,&parameters)==MATTER_OK && parameters.peer_active);
        CHECK(parameters.idle_interval_ms==intervals.idle_ms && parameters.active_interval_ms==intervals.active_ms);
        CHECK(matter_secure_channel_parameters(p->channel,now+intervals.active_threshold_ms,&parameters)==MATTER_OK && !parameters.peer_active);
        CHECK(matter_secure_channel_parameters(p->channel,now-1,&parameters)==MATTER_INVALID_ARGUMENT);
    }
    f->port.clear((uint8_t*)f->keys,sizeof(f->keys));
    CHECK(queue_data(a,0xa1) && tick(a,now) && a->retained);
    uint64_t rejected=99;
    CHECK(matter_secure_channel_send(a->channel,a->udp,a->outbound.data,a->outbound.size,&rejected)==MATTER_BUSY && rejected==99);
    Matter_Secure_Channel_Result_T pending={99,MATTER_OPERATION_FAILED};
    CHECK(matter_secure_channel_take(a->channel,&pending)==MATTER_PENDING && pending.request==99);
    CHECK(matter_secure_channel_complete(a->channel,a->udp_request+1,MATTER_OPERATION_SUCCEEDED)==MATTER_INVALID_STATE);
    CHECK(matter_secure_channel_complete(a->channel,a->udp_request,(Matter_Operation_Result_T)99)==MATTER_INVALID_ARGUMENT);
    network_poll(a); CHECK(network_take(a) && network_receive(b));
    f->link->delayed_data=b->inbox;
    Matter_Udp_Datagram_T d={.path=b->received_path,.data=b->inbox.data,.size=b->inbox.size};
    ++d.path.peer.port;
    CHECK(matter_secure_channel_receive(b->channel,b->rx,&d,now,now)==MATTER_INVALID_ARGUMENT);
    --d.path.peer.port; ++d.path.interface_id;
    CHECK(matter_secure_channel_receive(b->channel,b->rx,&d,now,now)==MATTER_INVALID_ARGUMENT);
    --d.path.interface_id; b->inbox.data[b->inbox.size-1]^=1;
    CHECK(matter_secure_channel_receive(b->channel,b->rx,&d,now,now)==MATTER_PORT_ERROR);
    b->inbox.data[b->inbox.size-1]^=1;
    b->pin_error=MATTER_OFFLINE;
    CHECK(matter_secure_channel_receive(b->channel,b->rx,&d,now,now)==MATTER_OFFLINE);
    b->pin_error=MATTER_OK;
    CHECK(matter_secure_channel_receive(b->channel,b->rx,&d,now,now)==MATTER_OK); b->inbox_full=false;
    /* A second authenticated, non-reliable packet cannot consume RX history
     * while the one-slot executor is full. Retain its original receive time. */
    Matter_Protocol_Header_T ph={.exchange_flags=MATTER_PROTOCOL_INITIATOR,.opcode=1,.protocol_id=4,.exchange_id=a->key.exchange_id};
    size_t n; Matter_Secure_Prepared_T prepared;
    CHECK(matter_protocol_header_write(&ph,f->buffer,sizeof(f->buffer),&n)==MATTER_MESSAGE_OK);
    f->buffer[n++]=0xb2;
    CHECK(matter_secure_channel_prepare(a->channel,f->buffer,n,now,f->link->delayed_ack.data,sizeof(f->link->delayed_ack.data),&prepared)==MATTER_OK);
    f->link->delayed_ack.size=prepared.size; d.data=f->link->delayed_ack.data; d.size=prepared.size;
    CHECK(matter_secure_channel_receive(b->channel,b->rx,&d,now,now)==MATTER_WOULD_BLOCK);
    unsigned delivered=b->deliveries;
    CHECK(tick(b,now) && b->deliveries==delivered+1);
    CHECK(matter_secure_channel_receive(b->channel,b->rx,&d,now,now+1)==MATTER_OK);
    CHECK(tick(b,++now) && b->deliveries==delivered+2 && b->last_payload==0xb2);
    now+=200; CHECK(tick(b,now) && b->retained_ack);
    network_poll(b); CHECK(network_take(b) && network_receive(a) && network_admit(a,now));
    CHECK(tick(a,now) && a->outcome==MATTER_RETRANSMISSION_ACKNOWLEDGED && !a->tx_pins);

    /* Authenticated standalone ACK with application data is invalid and must
     * not reach the MRP callback, even though its MIC is correct. */
    ph=(Matter_Protocol_Header_T){.exchange_flags=MATTER_PROTOCOL_INITIATOR|MATTER_PROTOCOL_ACK,
        .opcode=0x10,.exchange_id=a->key.exchange_id,.acknowledged_message_counter=1};
    CHECK(matter_protocol_header_write(&ph,f->buffer,sizeof(f->buffer),&n)==MATTER_MESSAGE_OK);
    f->buffer[n++]=0xcc;
    CHECK(matter_secure_channel_prepare(a->channel,f->buffer,n,now,f->link->delayed_ack.data,sizeof(f->link->delayed_ack.data),&prepared)==MATTER_OK);
    d.data=f->link->delayed_ack.data; d.size=prepared.size;
    unsigned processed_acks=b->ack_calls;
    CHECK(matter_secure_channel_receive(b->channel,b->rx,&d,now,now)==MATTER_INVALID_ARGUMENT && b->ack_calls==processed_acks);

    /* Lost data, then lost ACK. All ACK encoding/encryption is done by the
     * existing ACK executor and secure channel, never synthesized by this test. */
    for (unsigned loss=0;loss<2;++loss) {
        ++now; a->pase_now=now;
        CHECK(queue_data(a,0xc3) && tick(a,now) && a->retained);
        f->link->delayed_data=a->wire;
        network_poll(a); CHECK(network_take(a) && network_receive(b));
        delivered=b->deliveries;
        if (loss) {
            CHECK(network_admit(b,now) && tick(b,now) && b->deliveries==delivered+1);
            now+=200; CHECK(tick(b,now) && b->retained_ack);
            network_poll(b); CHECK(network_take(b) && network_receive(a)); a->inbox_full=false;
        } else b->inbox_full=false;
        CHECK(matter_retransmission_sender_deadline(a->tx,&now)==MATTER_OK);
        CHECK(tick(a,now) && a->retained);
        CHECK(a->wire.size==f->link->delayed_data.size && !memcmp(a->wire.data,f->link->delayed_data.data,a->wire.size));
        complete_resolver(a);
        network_poll(a); CHECK(network_take(a) && network_receive(b) && network_admit(b,now));
        CHECK(tick(b,now) && b->deliveries==delivered+1);
        if (!loss) { now+=200; CHECK(tick(b,now)); }
        CHECK(b->retained_ack);
        network_poll(b); CHECK(network_take(b) && network_receive(a) && network_admit(a,now));
        CHECK(tick(a,now) && a->outcome==MATTER_RETRANSMISSION_ACKNOWLEDGED && a->attempts==2 && !a->tx_pins);
    }
    CHECK(im_network(f,&now));
    CHECK(invoke_network(f,&now));
    CHECK(timed_network(f,&now));
    CHECK(write_network(f,&now));
    CHECK(write_lists_network(f,&now));
    CHECK(subscribe_network(f,&now,false));
    CHECK(root_network(f,&now));
    /* Authenticated malformed CloseSession must not retire a live session. */
    bool closed=true;
    for (unsigned bad=0;bad<4;++bad) {
        static const uint8_t close_plain[]={1,0x40,0xcd,0xab,0,0,0,0,0,0,0,0,3,0,0};
        memcpy(f->buffer,close_plain,sizeof(close_plain)); n=14;
        if (bad==0) f->buffer[0]|=MATTER_PROTOCOL_RELIABLE;
        if (bad==1) f->buffer[6]=1; /* GeneralCode FAILURE. */
        if (bad==2) n=15; /* Unexpected protocol data. */
        if (bad==3) n=13;
        CHECK(matter_secure_channel_prepare(a->channel,f->buffer,n,now,f->link->delayed_ack.data,sizeof(f->link->delayed_ack.data),&prepared)==MATTER_OK);
        d.data=f->link->delayed_ack.data; d.size=prepared.size;
        CHECK(matter_secure_channel_receive(b->channel,b->rx,&d,now,now)==MATTER_INVALID_ARGUMENT);
        CHECK(matter_secure_channel_is_closed(b->channel,&closed)==MATTER_OK && !closed);
    }
    if(f->im_close_wait) { CHECK(im_close_wait_network(f,now+1)); ok=true; goto done; }
    if(f->invoke_close) { CHECK(invoke_close_network(f,now+1)); ok=true; goto done; }
    if(f->write_close) { CHECK(write_close_network(f,now+1,f->write_close==2)); ok=true; goto done; }
    if(f->write_list_close) { CHECK(write_lists_close_network(f,now+1)); ok=true; goto done; }
    if(f->subscribe_close) { CHECK(subscribe_network(f,&now,true)); ok=true; goto done; }
    if(f->timed_close) { CHECK(timed_close_network(f,now+1)); ok=true; goto done; }
    if(f->fabric_commissioning) { CHECK(fabric_network(f,now+1)); ok=true; goto done; }
    if(f->opcreds_commissioning) { CHECK(opcreds_network(f,now+1)); ok=true; goto done; }
    if(f->wifi_commissioning) { CHECK(wifi_network(f,now+1)); ok=true; goto done; }
    if(f->commissioning_expiry) { CHECK(commissioning_network(f,now+1)); ok=true; goto done; }
    /* Pending data and ACK at once, or a CloseSession overtaking queued RX. */
    ++now; a->pase_now=now;
    size_t im_size=im_many_request(f->link->delayed_data.data);
    CHECK(im_host_begin(f,now,34,f->link->delayed_data.data,im_size) && tick(a,now) && a->retained);
    CHECK(network_receive(b) && network_admit(b,now));
    if (f->config[0].has_parameters) {
        CHECK(tick(b,now));
        CHECK(matter_im_read_process(b->im,now)==MATTER_PENDING && matter_im_read_state(b->im)==MATTER_IM_READ_OUTPUT);
#ifdef MATTER_TEST_SECURE_EXHAUSTION
        b->secure->tx.next=UINT32_MAX;
        CHECK(matter_secure_channel_prepare(b->channel,f->buffer,14,now,f->link->delayed_ack.data,sizeof(f->link->delayed_ack.data),&prepared)==MATTER_OK);
#endif
        now+=200; CHECK(tick(b,now));
#ifdef MATTER_TEST_SECURE_EXHAUSTION
        Matter_Secure_Info_T info;
        CHECK(!b->retained_ack && b->rx_result==MATTER_PORT_ERROR); /* ACK cannot encrypt. */
        CHECK(matter_secure_info(b->secure,&info)==MATTER_OK && info.exhausted);
        CHECK(matter_secure_channel_prepare(b->channel,f->buffer,14,now,f->link->delayed_ack.data,sizeof(f->link->delayed_ack.data),&prepared)==MATTER_LIMIT_REACHED);
        CHECK(matter_secure_channel_send_close(b->channel,b->rx,b->udp,now,&rejected)==MATTER_LIMIT_REACHED);
#else
        CHECK(b->retained_ack);
#endif
        CHECK(matter_secure_channel_retire(a->channel,a->rx,a->tx)==MATTER_PENDING);
#ifdef MATTER_TEST_SECURE_EXHAUSTION
        CHECK(matter_secure_channel_retire(b->channel,b->rx,b->tx)==MATTER_OK && !b->rx_pins);
#else
        CHECK(matter_secure_channel_retire(b->channel,b->rx,b->tx)==MATTER_PENDING);
#endif
        CHECK(a->retained && a->cancels==1);
        CHECK(matter_secure_channel_retire(a->channel,a->rx,a->tx)==MATTER_PENDING && a->cancels==1);
    } else {
        CHECK(matter_secure_channel_send_close(a->channel,a->rx,a->udp,now,&rejected)==MATTER_BUSY);
        network_poll(a); CHECK(network_take(a));
#ifdef MATTER_TEST_ALLOC
        size_t baseline=live; fail_at=calls+1; /* CCM backend allocation failure. */
        CHECK(matter_secure_channel_send_close(a->channel,a->rx,a->udp,now,&rejected)==MATTER_PORT_ERROR);
        fail_at=0; CHECK(live==baseline && !a->udp_request);
        CHECK(matter_secure_channel_is_closed(a->channel,&closed)==MATTER_OK && !closed);
#endif
        CHECK(matter_secure_channel_send_close(a->channel,a->rx,a->udp,now,&a->udp_request)==MATTER_PENDING);
        CHECK(matter_secure_channel_is_closed(a->channel,&closed)==MATTER_OK && closed);
        CHECK(matter_secure_channel_retire(a->channel,a->rx,a->tx)==MATTER_PENDING);
        CHECK(network_receive(b));
        CHECK(matter_secure_receive(b->secure,b->inbox.data,b->inbox.size,now,inspect_close,&a->key)==MATTER_WOULD_BLOCK);
        b->inbox.data[b->inbox.size-1]^=1;
        d=(Matter_Udp_Datagram_T){.path=b->received_path,.data=b->inbox.data,.size=b->inbox.size};
        CHECK(matter_secure_channel_receive(b->channel,b->rx,&d,now,now)==MATTER_PORT_ERROR);
        CHECK(matter_secure_channel_is_closed(b->channel,&closed)==MATTER_OK && !closed);
        b->inbox.data[b->inbox.size-1]^=1;
        delivered=b->deliveries; unsigned acks=b->ack_sends;
        CHECK(network_admit(b,now)); /* B still has the prior data queued. */
        CHECK(matter_secure_channel_is_closed(b->channel,&closed)==MATTER_OK && closed);
        CHECK(matter_secure_channel_delete(b->channel)==MATTER_INVALID_STATE); /* retire required */
        CHECK(matter_secure_channel_retire(b->channel,b->rx,b->tx)==MATTER_OK);
        CHECK(tick(b,now) && b->deliveries==delivered && b->ack_sends==acks && !b->rx_pins);
        CHECK(matter_secure_channel_receive(b->channel,b->rx,&d,now,now)==MATTER_INVALID_STATE);
    }
    CHECK(matter_secure_channel_delete(a->channel)==MATTER_INVALID_STATE);
    CHECK(matter_secure_delete(a->secure)==MATTER_INVALID_STATE);
    network_poll(a); CHECK(network_take(a));
    network_poll(b); CHECK(network_take(b));
#ifndef MATTER_TEST_SECURE_EXHAUSTION
    if (f->config[0].has_parameters) {
        CHECK(network_receive(a));
        CHECK(!network_admit(a,now)); /* Closed channel cannot resurrect the exchange. */
    }
#endif
    CHECK(tick(a,now) && tick(b,now) && a->outcome==MATTER_RETRANSMISSION_CANCELLED && !a->tx_pins && !b->ack_pins);
    CHECK(tick(a,now)); /* RX closes after MRP notification releases its pin. */
    for (unsigned i=0;i<2;++i) {
        Peer* p=peers[i];
        CHECK(matter_secure_channel_retire(p->channel,p->rx,p->tx)==MATTER_OK);
        CHECK(!p->rx_pins && session_pins(p,p->secure_token)==1 && !p->dependencies && matter_udp_is_active(p->udp));
        Matter_Exchange_Info_T stale;
        if (p->handle) CHECK(matter_rx_get(p->rx,p->handle,&stale)==MATTER_INVALID_STATE);
        CHECK(matter_secure_retain(p->secure)==MATTER_INVALID_STATE);
    }
    CHECK(matter_secure_channel_complete(a->channel,99,MATTER_OPERATION_SUCCEEDED)==MATTER_INVALID_STATE);
    CHECK(matter_secure_channel_prepare(a->channel,f->buffer,n,now,f->link->delayed_ack.data,sizeof(f->link->delayed_ack.data),&prepared)==MATTER_INVALID_STATE);
    CHECK(matter_im_read_cancel(b->im)==MATTER_OK && matter_im_read_state(b->im)==MATTER_IM_READ_FAILED);
    Matter_Im_Read_Message_T cancelled;
    CHECK(matter_im_read_output(b->im,&cancelled)==MATTER_INVALID_STATE);
    CHECK(matter_im_read_delete(b->im)==MATTER_OK); b->im=NULL; a->im_client=false;
    /* The previous unsecured session can still exchange data over the SAME
     * sockets and RX/MRP executors after the secure incarnation is retired. */
    Matter_Secure_Channel_T channels[]={a->channel,b->channel};
    a->channel=b->channel=NULL;
    a->session=a->first_session; a->handle=b->handle=0;
    bool shared_ok=queue_data(a,0xe5) && tick(a,++now) && a->retained;
    if (shared_ok) { network_poll(a); shared_ok=network_take(a) && network_receive(b) && network_admit(b,now) && tick(b,now); }
    if (shared_ok) { now+=200; shared_ok=tick(b,now) && b->retained_ack; }
    if (shared_ok) { network_poll(b); shared_ok=network_take(b) && network_receive(a) && network_admit(a,now) && tick(a,now); }
    a->channel=channels[0]; b->channel=channels[1];
    CHECK(shared_ok && b->last_payload==0xe5 && a->outcome==MATTER_RETRANSMISSION_ACKNOWLEDGED);
    CHECK(!a->dependencies && !b->dependencies);
    puts("PASS secure MRP IPv6: loss/retry, replay, encrypted CloseSession, terminal TX/ACK drain, queued RX discard and stale events");
    ok=true;
done:
#ifdef MATTER_TEST_ALLOC
    fail_at=0;
#endif
    /* fixture cleanup drains RX/MRP, deletes channel, then clears the session. */
    return ok;
}
#endif

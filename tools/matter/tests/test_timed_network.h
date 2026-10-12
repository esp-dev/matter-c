#ifdef MATTER_TEST_HOST_UDP
static bool timed_network(PaseFixture* f,uint64_t* clock) {
    bool ok=false; Peer* a=&f->link->a; Peer* b=&f->link->b; uint64_t now=*clock;
    InvokeModel* m=calloc(1,sizeof(*m)); REQUIRE(m);
    for(unsigned mode=0;mode<7;++mode) {
        memset(m,0,sizeof(*m)); memcpy(m->input,timed_request,sizeof(timed_request)); m->input[3]=100; m->input[4]=0;
        CHECK(invoke_begin_opcode(f,m,++now,1024,m->input,sizeof(timed_request),10));
        m->metadata.timed=mode!=4; if(mode==6) m->metadata.response=false;
        CHECK(tick(a,now)); network_poll(a); CHECK(network_take(a) && network_receive(b)); f->link->delayed_data=b->inbox;
        CHECK(network_admit(b,now) && tick(b,now) && im_ack_transfer(b,a,now+=200));
        CHECK(matter_im_invoke_process(b->invoke,now)==MATTER_PENDING);
        Matter_Im_Invoke_Message_T response; CHECK(matter_im_invoke_output(b->invoke,&response)==MATTER_OK);
        CHECK(response.opcode==1 && response.size==8 && !response.data[3] && !m->auths);
        CHECK(im_host_send(f,b,1,response.data,response.size,now));
        b->online=false; CHECK(tick(b,now) && !b->retained && matter_im_invoke_state(b->invoke)==MATTER_IM_INVOKE_OUTPUT);
        now+=150; b->online=true; CHECK(tick(b,now) && b->retained && matter_im_invoke_state(b->invoke)==MATTER_IM_INVOKE_IN_FLIGHT);
        network_poll(b); CHECK(network_take(b) && network_receive(a));
        if(mode==1) {
            f->link->delayed_ack=a->inbox; a->inbox_full=false;
            CHECK(matter_retransmission_sender_deadline(b->tx,&now)==MATTER_OK && tick(b,now));
            complete_resolver(b); network_poll(b); CHECK(network_take(b) && network_receive(a));
            CHECK(a->inbox.size==f->link->delayed_ack.size && !memcmp(a->inbox.data,f->link->delayed_ack.data,a->inbox.size));
        }
        CHECK(network_admit(a,now) && tick(a,now));
        if(!mode) { /* Retransmitted TimedRequest cannot create another window. */
            unsigned delivered=b->deliveries;
            Matter_Udp_Datagram_T dup={.path=b->received_path,.data=f->link->delayed_data.data,.size=f->link->delayed_data.size};
            CHECK(matter_secure_channel_receive(b->channel,b->rx,&dup,now,now)==MATTER_OK && tick(b,now));
            CHECK(b->deliveries==delivered && im_ack_transfer(b,a,now));
        }
        if(mode==3) now+=100; else ++now;
        memcpy(m->input,invoke_request,sizeof(invoke_request)); m->input[3]=mode==2 ? 0x28 : 0x29;
        if(mode==6) m->input[1]=0x29;
        CHECK(im_host_send(f,a,mode==5 ? 10 : 8,mode==5 ? timed_request : m->input,
            mode==5 ? sizeof(timed_request) : sizeof(invoke_request),now) && tick(a,now));
        network_poll(a); CHECK(network_take(a) && network_receive(b) && network_admit(b,now) && tick(b,now));
        CHECK(matter_im_invoke_process(b->invoke,now)==MATTER_PENDING && !m->auths);
        CHECK(matter_im_invoke_state(b->invoke)==MATTER_IM_INVOKE_IN_FLIGHT);
        CHECK(im_ack_transfer(a,b,now+=200)); /* Window is already expired: RX time decides. */
        CHECK(matter_im_invoke_state(b->invoke)==MATTER_IM_INVOKE_WAIT_INVOKE);
        CHECK(im_ack_transfer(b,a,now+=200));
        CHECK(matter_im_invoke_process(b->invoke,now)==(mode==6 ? MATTER_OK : MATTER_PENDING));
        if(mode==6) CHECK(matter_im_invoke_state(b->invoke)==MATTER_IM_INVOKE_COMPLETE && m->executions==1);
        else {
            CHECK(matter_im_invoke_output(b->invoke,&response)==MATTER_OK);
            if(!mode || mode==4) CHECK(response.opcode==9 && m->executions==1 && response.size==sizeof(invoke_response) && !memcmp(response.data,invoke_response,response.size));
            else CHECK(!m->auths && response.opcode==1 && response.size==8 && response.data[3]==
                (mode==1 || mode==3 ? MATTER_IM_TIMEOUT : mode==2 ? MATTER_IM_TIMED_REQUEST_MISMATCH : MATTER_IM_INVALID_ACTION));
            CHECK(im_host_send(f,b,response.opcode,response.data,response.size,now) && tick(b,now));
            network_poll(b); CHECK(network_take(b) && network_receive(a) && network_admit(a,now) && tick(a,now));
            CHECK(im_ack_transfer(a,b,now+=200) && matter_im_invoke_state(b->invoke)==MATTER_IM_INVOKE_COMPLETE);
        }
        CHECK(!a->tx_pins && !b->tx_pins && !a->ack_pins && !b->ack_pins);
        CHECK(matter_im_invoke_delete(b->invoke)==MATTER_OK); b->invoke=NULL; a->im_client=false;
    }
    *clock=now; puts("PASS Timed Invoke IPv6: delayed first send, RX before ACK/drain, status loss/retry never renews window, timeout/mismatch/order and suppress"); ok=true;
done:
    if(b->invoke) { REQUIRE(matter_im_invoke_cancel(b->invoke)==MATTER_OK && matter_im_invoke_delete(b->invoke)==MATTER_OK); b->invoke=NULL; }
    free(m); return ok;
}
static bool timed_close_network(PaseFixture* f,uint64_t now) {
    bool ok=false; Peer* a=&f->link->a; Peer* b=&f->link->b;
    InvokeModel* m=calloc(1,sizeof(*m)); REQUIRE(m);
    CHECK(invoke_begin_opcode(f,m,now,1024,timed_request,sizeof(timed_request),10) && tick(a,now));
    network_poll(a); CHECK(network_take(a) && network_receive(b) && network_admit(b,now) && tick(b,now));
    CHECK(im_ack_transfer(b,a,now+=200) && matter_im_invoke_process(b->invoke,now)==MATTER_PENDING);
    Matter_Im_Invoke_Message_T response; CHECK(matter_im_invoke_output(b->invoke,&response)==MATTER_OK);
    CHECK(im_host_send(f,b,1,response.data,response.size,now) && tick(b,now)); network_poll(b);
    CHECK(network_take(b) && network_receive(a) && network_admit(a,now) && tick(a,now));
    memcpy(m->input,invoke_request,sizeof(invoke_request)); m->input[3]=0x29;
    CHECK(im_host_send(f,a,8,m->input,sizeof(invoke_request),++now) && tick(a,now)); network_poll(a);
    CHECK(network_take(a) && network_receive(b) && network_admit(b,now) && tick(b,now));
    CHECK(matter_im_invoke_process(b->invoke,now)==MATTER_PENDING && !m->executions);
    CHECK(matter_im_invoke_state(b->invoke)==MATTER_IM_INVOKE_IN_FLIGHT); /* Queued, status not ACKed. */
    CHECK(matter_secure_channel_send_close(a->channel,a->rx,a->udp,now,&a->udp_request)==MATTER_PENDING);
    CHECK(matter_secure_channel_retire(a->channel,a->rx,a->tx)==MATTER_PENDING);
    CHECK(network_receive(b) && network_admit(b,now));
    CHECK(matter_im_invoke_cancel(b->invoke)==MATTER_OK);
    CHECK(matter_secure_channel_retire(b->channel,b->rx,b->tx)==MATTER_PENDING);
    network_poll(a); CHECK(network_take(a) && tick(a,now) && tick(b,now));
    CHECK(matter_secure_channel_retire(a->channel,a->rx,a->tx)==MATTER_OK && matter_secure_channel_retire(b->channel,b->rx,b->tx)==MATTER_OK);
    CHECK(matter_im_invoke_process(b->invoke,now)==MATTER_INVALID_STATE && !m->executions);
    CHECK(matter_im_invoke_delete(b->invoke)==MATTER_OK); b->invoke=NULL; a->im_client=false;
    CHECK(!a->tx_pins && !b->tx_pins && !a->rx_pins && !b->rx_pins);
    puts("PASS Timed Invoke CloseSession IPv6: queued command before status ACK, pending MRP cancelled/drained, zero effects"); ok=true;
done:
    if(b->invoke) { REQUIRE(matter_im_invoke_cancel(b->invoke)==MATTER_OK && matter_im_invoke_delete(b->invoke)==MATTER_OK); b->invoke=NULL; }
    free(m); return ok;
}
#endif

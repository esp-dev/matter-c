#ifdef MATTER_TEST_HOST_UDP
#include "test_im_vectors.h"
#include "test_im_model.h"
#include "test_im_values.h"
static Matter_Im_Status_T im_host_authorize(void* u,Matter_Exchange_Session_T token,
    const Matter_Im_Path_T* path,Matter_Im_Privilege_T privilege) {
    PaseFixture* f=u; (void)path;
    REQUIRE(token==f->link->b.secure_token && privilege==MATTER_IM_VIEW);
    return f->im_denied ? MATTER_IM_UNSUPPORTED_ACCESS : MATTER_IM_SUCCESS;
}
static Matter_Im_Status_T im_host_describe(void* u,const Matter_Im_Path_T* p,Matter_Im_Attribute_T* a) {
    (void)u;
    if(p->endpoint) return MATTER_IM_UNSUPPORTED_ENDPOINT;
    if(p->cluster!=0x28) return MATTER_IM_UNSUPPORTED_CLUSTER;
    if(p->attribute!=2 && p->attribute!=4) return MATTER_IM_UNSUPPORTED_ATTRIBUTE;
    *a=(Matter_Im_Attribute_T){MATTER_IM_VIEW,false}; return MATTER_IM_SUCCESS;
}
static Matter_Im_Status_T im_host_read(void* u,const Matter_Im_Path_T* p,bool filtered,Matter_Im_Value_T* v) {
    PaseFixture* f=u; REQUIRE(filtered && (p->attribute==2 || p->attribute==4)); ++f->im_reads;
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.unsigned_value=p->attribute==2 ? 0xfff1 : 0x8001,.data_version=7}; return MATTER_IM_SUCCESS;
}
static bool im_host_send(PaseFixture* f,Peer* p,uint8_t opcode,const uint8_t* payload,size_t size,uint64_t now) {
    Matter_Protocol_Header_T h={.exchange_id=p->key.exchange_id,.protocol_id=1,.opcode=opcode,
        .exchange_flags=MATTER_PROTOCOL_RELIABLE | (p->key.initiator ? MATTER_PROTOCOL_INITIATOR : 0)};
    size_t n;
    REQUIRE(size+6<=sizeof(f->buffer));
    REQUIRE(matter_protocol_header_write(&h,f->buffer,sizeof(f->buffer),&n)==MATTER_MESSAGE_OK);
    memcpy(f->buffer+n,payload,size);
    Matter_Secure_Prepared_T prepared;
    if(matter_secure_channel_prepare(p->channel,f->buffer,n+size,now,p->outbound.data,sizeof(p->outbound.data),&prepared)!=MATTER_OK) return false;
    p->outbound.size=prepared.size;
    return matter_retransmission_sender_add(p->tx,&p->key,prepared.counter,p->outbound.data,p->outbound.size,&p->message_id)==MATTER_OK;
}
static bool im_host_begin_port(PaseFixture* f,uint64_t now,size_t capacity,const uint8_t* data,size_t size,const Matter_Im_Read_Port_T* port) {
    Peer* a=&f->link->a; Peer* b=&f->link->b;
    if(a->handle) REQUIRE(matter_rx_close(a->rx,a->handle)==MATTER_OK);
    if(b->handle) REQUIRE(matter_rx_close(b->rx,b->handle)==MATTER_OK);
    a->handle=b->handle=0; a->im_client=true; a->im_received.size=0;
    REQUIRE(matter_rx_initiate(a->rx,a->secure_token,&a->handle)==MATTER_OK);
    REQUIRE(matter_rx_get(a->rx,a->handle,&a->key)==MATTER_OK);
    Matter_Im_Read_Config_T c={{b->secure_token,a->key.exchange_id,false},5000,capacity,true};
    REQUIRE(!b->im); b->im=matter_im_read_new(port,&c,now); REQUIRE(b->im);
    return im_host_send(f,a,2,data,size,now);
}
static bool im_host_begin(PaseFixture* f,uint64_t now,size_t capacity,const uint8_t* data,size_t size) {
    Matter_Im_Read_Port_T p={f,im_host_authorize,im_host_describe,im_host_read,NULL,NULL};
    return im_host_begin_port(f,now,capacity,data,size,&p);
}
static size_t im_many_request(uint8_t* out) {
    memcpy(out,im_request,3); size_t n=3;
    for(unsigned i=0;i<9;++i) { memcpy(out+n,im_request+3,11); out[n+9]=(uint8_t)(2+i%3); n+=11; }
    memcpy(out+n,im_request+14,7); return n+7;
}
static bool im_ack_transfer(Peer* from,Peer* to,uint64_t now) {
    REQUIRE(tick(from,now) && from->retained_ack); network_poll(from);
    return network_take(from) && network_receive(to) && network_admit(to,now) && tick(to,now);
}
static bool im_values_network(PaseFixture* f,uint64_t* clock) {
    bool ok=false; Peer* a=&f->link->a; Peer* b=&f->link->b; uint64_t now=*clock;
    ImValues* m=calloc(1,sizeof(*m)); REQUIRE(m);
    const Matter_Tlv_Type_T types[]={MATTER_TLV_UTF8,MATTER_TLV_BYTES,MATTER_TLV_STRUCTURE,MATTER_TLV_ARRAY,MATTER_TLV_ARRAY};
    for(unsigned mode=0;mode<5;++mode) {
        memset(m,0,sizeof(*m)); values_build(m,types[mode],40);
        Matter_Im_Read_Port_T port=values_port(m);
        CHECK(im_host_begin_port(f,++now,256,im_request,sizeof(im_request),&port) && tick(a,now)); m->active=b->im;
        network_poll(a); CHECK(network_take(a) && network_receive(b) && network_admit(b,now) && tick(b,now));
        CHECK(im_ack_transfer(b,a,now+=200) && matter_im_read_process(b->im,now)==MATTER_PENDING);
        memset(m->data,0xff,sizeof(m->data));
        for(unsigned chunk=0;chunk<16;++chunk) {
            Matter_Im_Read_Message_T response;
            CHECK(matter_im_read_output(b->im,&response)==MATTER_OK && response.opcode==5);
            CHECK(im_host_send(f,b,5,response.data,response.size,now) && matter_im_read_sent(b->im)==MATTER_OK && tick(b,now));
            network_poll(b); CHECK(network_take(b) && network_receive(a));
            if(mode==3 && chunk==1) {
                f->link->delayed_ack=a->inbox; a->inbox_full=false;
                CHECK(matter_retransmission_sender_deadline(b->tx,&now)==MATTER_OK && tick(b,now));
                complete_resolver(b); network_poll(b); CHECK(network_take(b) && network_receive(a));
                CHECK(a->inbox.size==f->link->delayed_ack.size && !memcmp(a->inbox.data,f->link->delayed_ack.data,a->inbox.size));
            }
            CHECK(network_admit(a,now) && tick(a,now) && a->im_opcode==5);
            bool more=values_report(m,a->im_received.data,a->im_received.size);
            CHECK(im_ack_transfer(a,b,now+=200));
            if(mode==4) { CHECK(more); now+=5000; CHECK(matter_im_read_process(b->im,now)==MATTER_PORT_ERROR); break; }
            if(!more) { CHECK(matter_im_read_state(b->im)==MATTER_IM_READ_COMPLETE); break; }
            const uint8_t success[]={0x15,0x24,0,0,0x24,0xff,13,0x18};
            CHECK(im_host_send(f,a,1,success,sizeof(success),now) && tick(a,now)); network_poll(a);
            CHECK(network_take(a) && network_receive(b) && network_admit(b,now) && tick(b,now));
            CHECK(im_ack_transfer(b,a,now+=200) && matter_im_read_process(b->im,now)==MATTER_PENDING);
        }
        CHECK(m->reads==1);
        if(mode==3) CHECK(m->received==40 && m->replacements==1 && m->appends && matter_im_read_state(b->im)==MATTER_IM_READ_COMPLETE);
        CHECK(!a->tx_pins && !b->tx_pins && !a->ack_pins && !b->ack_pins);
        CHECK(matter_im_read_delete(b->im)==MATTER_OK); b->im=NULL; a->im_client=false;
    }
    *clock=now; puts("PASS IM composite IPv6: UTF8/bytes/structure, list reconstruction, immutable ciphertext retry and partial-list timeout"); ok=true;
done:
    if(b->im) { REQUIRE(matter_im_read_cancel(b->im)==MATTER_OK && matter_im_read_delete(b->im)==MATTER_OK); b->im=NULL; }
    free(m); return ok;
}
static bool im_close_wait_network(PaseFixture* f,uint64_t now) {
    bool ok=false; Peer* a=&f->link->a; Peer* b=&f->link->b;
    ImValues* m=calloc(1,sizeof(*m)); REQUIRE(m); values_build(m,MATTER_TLV_ARRAY,40);
    Matter_Im_Read_Port_T port=values_port(m);
    CHECK(im_host_begin_port(f,now,128,im_request,sizeof(im_request),&port) && tick(a,now)); m->active=b->im;
    network_poll(a); CHECK(network_take(a) && network_receive(b) && network_admit(b,now) && tick(b,now));
    CHECK(im_ack_transfer(b,a,now+=200) && matter_im_read_process(b->im,now)==MATTER_PENDING);
    Matter_Im_Read_Message_T response;
    CHECK(matter_im_read_output(b->im,&response)==MATTER_OK && im_host_send(f,b,5,response.data,response.size,now));
    CHECK(matter_im_read_sent(b->im)==MATTER_OK && tick(b,now)); network_poll(b);
    CHECK(network_take(b) && network_receive(a) && network_admit(a,now) && tick(a,now));
    CHECK(im_ack_transfer(a,b,now+=200) && matter_im_read_state(b->im)==MATTER_IM_READ_WAIT_STATUS);
    CHECK(matter_secure_channel_send_close(a->channel,a->rx,a->udp,now,&a->udp_request)==MATTER_PENDING);
    CHECK(matter_secure_channel_retire(a->channel,a->rx,a->tx)==MATTER_PENDING);
    CHECK(network_receive(b) && network_admit(b,now));
    CHECK(matter_secure_channel_retire(b->channel,b->rx,b->tx)==MATTER_OK);
    CHECK(matter_im_read_cancel(b->im)==MATTER_OK && matter_im_read_output(b->im,&response)==MATTER_INVALID_STATE);
    network_poll(a); CHECK(network_take(a) && tick(a,now));
    CHECK(matter_secure_channel_retire(a->channel,a->rx,a->tx)==MATTER_OK);
    CHECK(matter_im_read_process(b->im,now)==MATTER_INVALID_STATE && matter_im_read_confirm(b->im,now)==MATTER_INVALID_STATE);
    CHECK(matter_im_read_delete(b->im)==MATTER_OK); b->im=NULL; a->im_client=false;
    CHECK(!a->tx_pins && !b->tx_pins && !a->rx_pins && !b->rx_pins);
    puts("PASS IM list CloseSession IPv6: first prefix delivered, status pending, session retire and handler cancel/drain");
    ok=true;
done:
    if(b->im) { REQUIRE(matter_im_read_cancel(b->im)==MATTER_OK && matter_im_read_delete(b->im)==MATTER_OK); b->im=NULL; }
    free(m); return ok;
}
static bool im_wildcard_network(PaseFixture* f,uint64_t* clock) {
    bool ok=false; Peer* a=&f->link->a; Peer* b=&f->link->b; uint64_t now=*clock;
    ImTestModel* m=calloc(1,sizeof(*m)); REQUIRE(m);
    for(unsigned mode=0;mode<5;++mode) {
        memset(m,0,sizeof(*m)); m->size=24; unsigned nf=0, want=24;
        if(mode==1 || mode==2) {
            nf=mode==1 ? 1 : 4; want=mode==1 ? 18 : 0;
            for(unsigned i=0;i<nf;++i) { m->filters[i].endpoint=(uint16_t)(i/2); m->filters[i].cluster=0x28+i%2; m->filters[i].version=7+i; }
        }
        if(mode==3) { m->deny=true; m->unreadable=true; want=16; }
        Matter_Im_Read_Port_T port=model_port(m,true);
        size_t size=model_request(m,0,(Matter_Im_Path_T){0},nf);
        CHECK(im_host_begin_port(f,++now,128,m->input,size,&port) && tick(a,now)); m->active=b->im;
        network_poll(a); CHECK(network_take(a) && network_receive(b) && network_admit(b,now) && tick(b,now));
        CHECK(im_ack_transfer(b,a,now+=200));
        if(mode==4) {
            CHECK(matter_im_read_process(b->im,now)==MATTER_PENDING && matter_im_read_state(b->im)==MATTER_IM_READ_EXPANDING);
            now+=5000; CHECK(matter_im_read_process(b->im,now)==MATTER_PORT_ERROR && !m->reads);
        } else {
            model_process(m,now); unsigned total=0;
            for(unsigned chunk=0;chunk<16;++chunk) {
                Matter_Im_Read_Message_T response;
                CHECK(matter_im_read_output(b->im,&response)==MATTER_OK && response.opcode==5);
                CHECK(im_host_send(f,b,5,response.data,response.size,now) && matter_im_read_sent(b->im)==MATTER_OK && tick(b,now));
                network_poll(b); CHECK(network_take(b) && network_receive(a));
                if(!mode && chunk==1) {
                    f->link->delayed_ack=a->inbox; a->inbox_full=false;
                    CHECK(matter_retransmission_sender_deadline(b->tx,&now)==MATTER_OK && tick(b,now));
                    complete_resolver(b); network_poll(b); CHECK(network_take(b) && network_receive(a));
                    CHECK(a->inbox.size==f->link->delayed_ack.size && !memcmp(a->inbox.data,f->link->delayed_ack.data,a->inbox.size));
                }
                CHECK(network_admit(a,now) && tick(a,now));
                bool more; unsigned errors;
                CHECK(a->im_opcode==5); total+=model_report(m,a->im_received.data,a->im_received.size,&more,&errors); CHECK(!errors);
                CHECK(im_ack_transfer(a,b,now+=200));
                if(!more) { CHECK(matter_im_read_state(b->im)==MATTER_IM_READ_COMPLETE); break; }
                const uint8_t success[]={0x15,0x24,0,0,0x24,0xff,13,0x18};
                CHECK(im_host_send(f,a,1,success,sizeof(success),now) && tick(a,now)); network_poll(a);
                CHECK(network_take(a) && network_receive(b) && network_admit(b,now) && tick(b,now));
                CHECK(im_ack_transfer(b,a,now+=200)); model_process(m,now);
            }
            CHECK(total==want && m->reads==want && matter_im_read_state(b->im)==MATTER_IM_READ_COMPLETE);
        }
        CHECK(!a->tx_pins && !b->tx_pins && !a->ack_pins && !b->ack_pins);
        CHECK(matter_im_read_delete(b->im)==MATTER_OK); b->im=NULL; m->active=NULL; a->im_client=false;
    }
    *clock=now; puts("PASS IM wildcard IPv6: 24 results, cluster filters/empty report, access omission, chunk loss and expansion timeout"); ok=true;
done:
    if(b->im) { REQUIRE(matter_im_read_cancel(b->im)==MATTER_OK && matter_im_read_delete(b->im)==MATTER_OK); b->im=NULL; }
    free(m); return ok;
}
static bool im_chunks_network(PaseFixture* f,uint64_t* clock) {
    bool ok=false; Peer* a=&f->link->a; Peer* b=&f->link->b; uint64_t now=*clock;
    for(unsigned mode=0;mode<4;++mode) {
        unsigned reads=f->im_reads;
        size_t n=im_many_request(f->link->delayed_data.data);
        CHECK(im_host_begin(f,++now,34,f->link->delayed_data.data,n));
        CHECK(tick(a,now) && a->retained); network_poll(a);
        CHECK(network_take(a) && network_receive(b) && network_admit(b,now) && tick(b,now));
        CHECK(im_ack_transfer(b,a,now+=200)); /* ReadRequest done, exchange remains. */
        CHECK(matter_im_read_process(b->im,now)==MATTER_PENDING);
        for(unsigned chunk=0;chunk<(mode ? 1u : 9u);++chunk) {
            Matter_Im_Read_Message_T response;
            CHECK(matter_im_read_output(b->im,&response)==MATTER_OK && response.opcode==5);
            CHECK(im_host_send(f,b,5,response.data,response.size,now) && matter_im_read_sent(b->im)==MATTER_OK);
            CHECK(tick(b,now) && b->retained); network_poll(b); CHECK(network_take(b) && network_receive(a));
            if(!mode && !chunk) { /* Drop one report, preserve exact ciphertext on retry. */
                f->link->delayed_ack=a->inbox; a->inbox_full=false;
                CHECK(matter_retransmission_sender_deadline(b->tx,&now)==MATTER_OK && tick(b,now));
                complete_resolver(b); network_poll(b); CHECK(network_take(b) && network_receive(a));
                CHECK(a->inbox.size==f->link->delayed_ack.size && !memcmp(a->inbox.data,f->link->delayed_ack.data,a->inbox.size));
            }
            CHECK(network_admit(a,now) && tick(a,now));
            CHECK(a->im_opcode==5 && matter_im_read_state(b->im)==MATTER_IM_READ_IN_FLIGHT);
            if(chunk%3==1) {
                const uint8_t expected[]={0x15,0x36,1,0x15,0x35,0,0x37,0,0x24,2,0,0x24,3,0x28,0x24,4,3,0x18,
                    0x35,1,0x24,0,0x86,0x18,0x18,0x18,0x18,0x29,3,0x24,0xff,13,0x18};
                CHECK(a->im_received.size==sizeof(expected) && !memcmp(a->im_received.data,expected,sizeof(expected)));
            } else {
                memcpy(f->buffer,im_report,sizeof(im_report));
                if(chunk<8) f->buffer[29]=3; /* MoreChunkedMessages, no SuppressResponse. */
                if(chunk%3==2) { f->buffer[19]=4; f->buffer[23]=1; f->buffer[24]=0x80; }
                CHECK(a->im_received.size==sizeof(im_report) && !memcmp(a->im_received.data,f->buffer,sizeof(im_report)));
            }
            if(chunk==8 || mode==3) {
                CHECK(im_ack_transfer(a,b,now+=200));
                if(mode==3) { now+=5000; CHECK(matter_im_read_process(b->im,now)==MATTER_PORT_ERROR); }
                break;
            }
            const uint8_t reply[]={0x15,mode==2 ? 0x29 : 0x24,0,mode==1 ? 1 : 0,0x24,0xff,13,0x18};
            CHECK(im_host_send(f,a,1,reply,sizeof(reply),now) && tick(a,now) && a->retained);
            network_poll(a); CHECK(network_take(a) && network_receive(b));
            if(!mode && chunk==1) { /* Lost IM SUCCESS cannot be replaced by MRP ACK. */
                b->inbox_full=false;
                CHECK(im_ack_transfer(a,b,now+=200));
                CHECK(matter_im_read_process(b->im,now)==MATTER_PENDING && matter_im_read_state(b->im)==MATTER_IM_READ_WAIT_STATUS);
                CHECK(matter_retransmission_sender_deadline(a->tx,&now)==MATTER_OK && tick(a,now));
                complete_resolver(a); network_poll(a); CHECK(network_take(a) && network_receive(b));
                CHECK(network_admit(b,now) && tick(b,now) && matter_im_read_process(b->im,now)==MATTER_PENDING);
            } else {
                CHECK(network_admit(b,now) && tick(b,now));
                CHECK(matter_im_read_process(b->im,now)==(mode==1 ? MATTER_PORT_ERROR : MATTER_PENDING));
                CHECK(matter_im_read_state(b->im)==(mode==1 ? MATTER_IM_READ_FAILED : MATTER_IM_READ_IN_FLIGHT));
                CHECK(im_ack_transfer(a,b,now+=200));
            }
            /* ACK the client's IM response. Dropping this ACK forces a duplicate
             * StatusResponse after the server has prepared the next chunk. */
            CHECK(tick(b,now+=200) && b->retained_ack); network_poll(b);
            CHECK(network_take(b) && network_receive(a));
            if(!mode && chunk==2) {
                a->inbox_full=false;
                CHECK(matter_im_read_process(b->im,now)==MATTER_PENDING);
                unsigned delivered=b->deliveries;
                uint64_t retry_at;
                CHECK(matter_retransmission_sender_deadline(a->tx,&retry_at)==MATTER_OK);
                if(retry_at>now) now=retry_at;
                CHECK(tick(a,now)); complete_resolver(a); network_poll(a);
                CHECK(network_take(a)); CHECK(network_receive(b)); CHECK(network_admit(b,now)); CHECK(tick(b,now));
                CHECK(b->deliveries==delivered && matter_im_read_state(b->im)==MATTER_IM_READ_OUTPUT);
                CHECK(im_ack_transfer(b,a,now)); /* Duplicate -> immediate ACK. */
            } else CHECK(network_admit(a,now) && tick(a,now));
            if(mode==1) { uint8_t code=0; CHECK(matter_im_read_peer_status(b->im,&code)==MATTER_OK && code==1); break; }
            CHECK(matter_im_read_process(b->im,now)==MATTER_PENDING);
            if(mode==2) {
                CHECK(matter_im_read_output(b->im,&response)==MATTER_OK && response.opcode==1 && response.data[3]==0x80);
                CHECK(im_host_send(f,b,1,response.data,response.size,now) && matter_im_read_sent(b->im)==MATTER_OK && tick(b,now));
                network_poll(b); CHECK(network_take(b) && network_receive(a) && network_admit(a,now) && tick(a,now));
                CHECK(im_ack_transfer(a,b,now+=200)); break;
            }
        }
        CHECK(f->im_reads==reads+6 && matter_im_read_state(b->im)==(mode==1 || mode==3 ? MATTER_IM_READ_FAILED : MATTER_IM_READ_COMPLETE));
        CHECK(!a->tx_pins && !b->tx_pins && !a->ack_pins && !b->ack_pins);
        CHECK(matter_im_read_delete(b->im)==MATTER_OK); b->im=NULL; a->im_client=false;
    }
    *clock=now; puts("PASS IM chunk IPv6: 9 mixed paths, report/status loss, duplicate status, independent IM/MRP gates, peer error, malformed status and timeout");
    ok=true;
done: return ok;
}
static bool im_network(PaseFixture* f,uint64_t* clock) {
    bool ok=false; Peer* a=&f->link->a; Peer* b=&f->link->b; uint64_t now=*clock;
    REQUIRE(matter_rx_register(a->rx,0,1)==MATTER_OK && matter_rx_register(b->rx,0,1)==MATTER_OK);
    for(unsigned mode=0;mode<6;++mode) {
        unsigned reads=f->im_reads; f->im_denied=mode==2;
        /* Request bytes stay independent of the production encoder. */
        memcpy(f->link->delayed_data.data,im_request,sizeof(im_request));
        if(mode==1) f->link->delayed_data.data[12]=3;
        if(mode==3) f->link->delayed_data.data[3]=0x15;
        CHECK(im_host_begin(f,++now,mode==4 ? 8 : 1024,f->link->delayed_data.data,sizeof(im_request)));
        CHECK(tick(a,now) && a->retained); network_poll(a);
        CHECK(network_take(a) && network_receive(b) && network_admit(b,now) && tick(b,now));
        CHECK(matter_im_read_process(b->im,now)==MATTER_PENDING);
        Matter_Im_Read_Message_T response;
        CHECK(matter_im_read_output(b->im,&response)==MATTER_OK);
        CHECK(im_host_send(f,b,response.opcode,response.data,response.size,now));
        CHECK(matter_im_read_sent(b->im)==MATTER_OK && tick(b,now) && b->retained);
        if(mode==5) {
            /* Deadline expires with an actual borrowed UDP/MRP packet. The IM
             * snapshot can be invalidated without freeing the transport bytes. */
            now+=5000;
            CHECK(matter_im_read_process(b->im,now)==MATTER_PORT_ERROR);
            CHECK(matter_retransmission_sender_cancel(b->tx,b->message_id)==MATTER_PENDING && b->retained);
            network_poll(b); CHECK(network_take(b) && network_receive(a));
            f->link->delayed_ack=a->inbox; a->inbox_full=false;
            CHECK(tick(b,now) && b->retained_ack && !b->tx_pins && b->outcome==MATTER_RETRANSMISSION_CANCELLED);
            network_poll(b); CHECK(network_take(b) && network_receive(a) && network_admit(a,now) && tick(a,now));
            /* Deliver the already-sent report late, then its real ACK. No
             * callback may resurrect the expired server transaction. */
            Matter_Udp_Datagram_T late={.path=a->received_path,.data=f->link->delayed_ack.data,.size=f->link->delayed_ack.size};
            CHECK(matter_secure_channel_receive(a->channel,a->rx,&late,now,now)==MATTER_OK && tick(a,now));
            now+=200; CHECK(tick(a,now) && a->retained_ack); network_poll(a);
            CHECK(network_take(a) && network_receive(b) && network_admit(b,now) && tick(b,now));
            CHECK(matter_im_read_state(b->im)==MATTER_IM_READ_FAILED && f->im_reads==reads+1);
            CHECK(matter_im_read_delete(b->im)==MATTER_OK); b->im=NULL; a->im_client=false;
            continue;
        }
        network_poll(b); CHECK(network_take(b) && network_receive(a));
        if(mode==0) { /* Drop report, then MRP retries the identical snapshot. */
            f->link->delayed_ack=a->inbox; a->inbox_full=false;
            now+=200; CHECK(tick(b,now) && b->retained_ack); network_poll(b);
            CHECK(network_take(b) && network_receive(a) && network_admit(a,now) && tick(a,now));
            CHECK(matter_retransmission_sender_deadline(b->tx,&now)==MATTER_OK && tick(b,now));
            complete_resolver(b); network_poll(b); CHECK(network_take(b) && network_receive(a));
            CHECK(a->inbox.size==f->link->delayed_ack.size && !memcmp(a->inbox.data,f->link->delayed_ack.data,a->inbox.size));
        }
        CHECK(network_admit(a,now) && tick(a,now));
        CHECK(matter_im_read_state(b->im)==MATTER_IM_READ_IN_FLIGHT); /* UDP success is not MRP ACK. */
        if(mode==0) CHECK(a->im_opcode==5 && a->im_received.size==sizeof(im_report) && !memcmp(a->im_received.data,im_report,sizeof(im_report)));
        else if(mode<3) {
            CHECK(a->im_opcode==5 && a->im_received.size==33 && a->im_received.data[22]==(mode==1 ? 0x86 : 0x7e));
        } else {
            const uint8_t expected[]={0x15,0x24,0,mode==3 ? 0x80 : 0x89,0x24,0xff,13,0x18};
            CHECK(a->im_opcode==1 && a->im_received.size==8 && !memcmp(a->im_received.data,expected,8));
        }
        now+=200; CHECK(tick(a,now) && a->retained_ack); network_poll(a); CHECK(network_take(a));
        CHECK(network_receive(b) && network_admit(b,now) && tick(b,now));
        if(mode) { CHECK(b->retained_ack); network_poll(b); CHECK(network_take(b) && network_receive(a) && network_admit(a,now) && tick(a,now)); }
        CHECK(matter_im_read_state(b->im)==MATTER_IM_READ_COMPLETE && b->outcome==MATTER_RETRANSMISSION_ACKNOWLEDGED);
        CHECK(f->im_reads==reads+(mode==0 || mode==4 ? 1u : 0u));
        CHECK(matter_im_read_delete(b->im)==MATTER_OK); b->im=NULL; a->im_client=false;
    }
    f->im_denied=false; CHECK(im_chunks_network(f,&now)); CHECK(im_wildcard_network(f,&now));
    CHECK(im_values_network(f,&now)); *clock=now;
    puts("PASS IM IPv6: PASE -> ReadRequest -> ReportData/status -> MRP ACK; snapshot/retry, access/schema/capacity, timeout with TX and late ACK");
    ok=true;
done: return ok;
}
#endif

#ifdef MATTER_TEST_HOST_UDP
#include "test_write_model.h"
static bool write_begin(PaseFixture* f,WriteModel* m,uint64_t now,size_t capacity,const uint8_t* request,size_t size,uint8_t opcode) {
    Peer* a=&f->link->a; Peer* b=&f->link->b;
    if(a->handle) REQUIRE(matter_rx_close(a->rx,a->handle)==MATTER_OK);
    if(b->handle) REQUIRE(matter_rx_close(b->rx,b->handle)==MATTER_OK);
    a->handle=b->handle=0; a->im_client=true; a->im_received.size=0;
    REQUIRE(matter_rx_initiate(a->rx,a->secure_token,&a->handle)==MATTER_OK);
    REQUIRE(matter_rx_get(a->rx,a->handle,&a->key)==MATTER_OK);
    Matter_Im_Write_Port_T port=write_port(m);
    Matter_Im_Write_Config_T c={{b->secure_token,a->key.exchange_id,false},5000,capacity,true};
    REQUIRE(!b->im && !b->invoke && !b->write); m->active=b->write=matter_im_write_new(&port,&c,now); REQUIRE(b->write);
    return im_host_send(f,a,opcode,request,size,now);
}
static Matter_Im_Status_T write_read_allow(void* u,Matter_Exchange_Session_T token,const Matter_Im_Path_T* p,Matter_Im_Privilege_T privilege) {
    (void)u; (void)p; REQUIRE(token && privilege==MATTER_IM_VIEW); return MATTER_IM_SUCCESS;
}
static Matter_Im_Status_T write_read_value(void* u,const Matter_Im_Path_T* p,bool filtered,Matter_Im_Value_T* out) {
    WriteModel* m=u; REQUIRE(!p->endpoint && p->cluster==0x28 && p->attribute==2 && filtered);
    REQUIRE(m->stored_size==2 && m->stored[0]==4); ++m->reads;
    *out=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.unsigned_value=m->stored[1],.data_version=m->version}; return MATTER_IM_SUCCESS;
}
static bool write_readback(PaseFixture* f,WriteModel* m,uint64_t* clock) {
    bool ok=false; Peer* a=&f->link->a; Peer* b=&f->link->b; uint64_t now=*clock;
    Matter_Im_Read_Port_T port={m,write_read_allow,im_host_describe,write_read_value,NULL,NULL};
    CHECK(im_host_begin_port(f,++now,1024,im_request,sizeof(im_request),&port) && tick(a,now));
    network_poll(a); CHECK(network_take(a) && network_receive(b) && network_admit(b,now) && tick(b,now));
    CHECK(im_ack_transfer(b,a,now+=200) && matter_im_read_process(b->im,now)==MATTER_PENDING);
    Matter_Im_Read_Message_T out; CHECK(matter_im_read_output(b->im,&out)==MATTER_OK);
    CHECK(im_host_send(f,b,out.opcode,out.data,out.size,now) && matter_im_read_sent(b->im)==MATTER_OK && tick(b,now));
    network_poll(b); CHECK(network_take(b) && network_receive(a) && network_admit(a,now) && tick(a,now));
    static const uint8_t expected[]={0x15,0x36,1,0x15,0x35,1,0x24,0,8,0x37,1,0x24,2,0,0x24,3,0x28,
        0x24,4,2,0x18,0x24,2,42,0x18,0x18,0x18,0x29,4,0x24,0xff,13,0x18};
    CHECK(a->im_opcode==5 && a->im_received.size==sizeof(expected) && !memcmp(a->im_received.data,expected,sizeof(expected)) && m->reads==1);
    CHECK(im_ack_transfer(a,b,now+=200) && matter_im_read_state(b->im)==MATTER_IM_READ_COMPLETE);
    CHECK(matter_im_read_delete(b->im)==MATTER_OK); b->im=NULL; a->im_client=false; *clock=now; ok=true;
done:
    return ok;
}
static bool write_network(PaseFixture* f,uint64_t* clock) {
    bool ok=false; Peer* a=&f->link->a; Peer* b=&f->link->b; uint64_t now=*clock;
    WriteModel* m=calloc(1,sizeof(*m)); REQUIRE(m);
    for(unsigned mode=0;mode<10;++mode) {
        memset(m,0,sizeof(*m)); memcpy(m->input,write_request,sizeof(write_request)); size_t n=sizeof(write_request);
        if(mode==3) m->input[23]=101;
        if(mode==6) { memmove(m->input+3,m->input+1,n-1); m->input[1]=0x29; m->input[2]=0; n+=2; }
        if(mode==9) --n;
        bool timed=mode==7 || mode==8;
        CHECK(write_begin(f,m,++now,mode==4 ? 8 : 1024,timed ? write_timed : m->input,timed ? sizeof(write_timed) : n,timed ? 10 : 6));
        if(mode==1) m->deny=MATTER_IM_UNSUPPORTED_ACCESS;
        if(mode==2) m->version=8;
        if(timed) m->metadata.timed=true;
        CHECK(tick(a,now)); network_poll(a); CHECK(network_take(a) && network_receive(b)); f->link->delayed_data=b->inbox;
        CHECK(network_admit(b,now) && tick(b,now) && !m->writes);
        CHECK(im_ack_transfer(b,a,now+=200));
        if(timed) {
            CHECK(matter_im_write_process(b->write,now)==MATTER_PENDING);
            Matter_Im_Write_Message_T status; CHECK(matter_im_write_output(b->write,&status)==MATTER_OK && status.opcode==1 && !status.data[3]);
            CHECK(im_host_send(f,b,status.opcode,status.data,status.size,now));
            b->online=false; CHECK(tick(b,now) && matter_im_write_state(b->write)==MATTER_IM_WRITE_OUTPUT);
            b->online=true; now+=150; CHECK(tick(b,now) && matter_im_write_state(b->write)==MATTER_IM_WRITE_IN_FLIGHT);
            network_poll(b); CHECK(network_take(b) && network_receive(a) && network_admit(a,now) && tick(a,now));
            m->input[1]=0x29; now+=mode==8 ? 100 : 1;
            CHECK(im_host_send(f,a,6,m->input,n,now) && tick(a,now)); network_poll(a);
            CHECK(network_take(a) && network_receive(b)); f->link->delayed_data=b->inbox;
            CHECK(network_admit(b,now) && tick(b,now) && matter_im_write_process(b->write,now)==MATTER_PENDING && !m->auths);
            CHECK(im_ack_transfer(a,b,now+=200) && matter_im_write_state(b->write)==MATTER_IM_WRITE_WAIT_WRITE);
            CHECK(im_ack_transfer(b,a,now+=200));
        }
        if(mode==5) { now+=5000; CHECK(matter_im_write_process(b->write,now)==MATTER_PORT_ERROR && !m->writes); }
        else {
            CHECK(matter_im_write_process(b->write,now)==(mode==6 ? MATTER_OK : MATTER_PENDING));
            unsigned deliveries=b->deliveries;
            Matter_Udp_Datagram_T dup={.path=b->received_path,.data=f->link->delayed_data.data,.size=f->link->delayed_data.size};
            CHECK(matter_secure_channel_receive(b->channel,b->rx,&dup,now,now)==MATTER_OK && tick(b,now));
            CHECK(b->deliveries==deliveries && im_ack_transfer(b,a,now));
            if(mode==6) CHECK(matter_im_write_state(b->write)==MATTER_IM_WRITE_COMPLETE && m->writes==1);
            else {
                Matter_Im_Write_Message_T out; CHECK(matter_im_write_output(b->write,&out)==MATTER_OK);
                CHECK(im_host_send(f,b,out.opcode,out.data,out.size,now) && tick(b,now));
                network_poll(b); CHECK(network_take(b) && network_receive(a));
                if(!mode) {
                    f->link->delayed_ack=a->inbox; a->inbox_full=false;
                    CHECK(matter_retransmission_sender_deadline(b->tx,&now)==MATTER_OK && tick(b,now)); complete_resolver(b);
                    network_poll(b); CHECK(network_take(b) && network_receive(a));
                    CHECK(a->inbox.size==f->link->delayed_ack.size && !memcmp(a->inbox.data,f->link->delayed_ack.data,a->inbox.size));
                }
                CHECK(network_admit(a,now) && tick(a,now));
                if(!mode || mode==7) CHECK(a->im_opcode==7 && a->im_received.size==sizeof(write_response) && !memcmp(a->im_received.data,write_response,sizeof(write_response)));
                if(mode==1 || mode==2 || mode==3) CHECK(a->im_opcode==7 && a->im_received.data[20]==
                    (mode==1 ? MATTER_IM_UNSUPPORTED_ACCESS : mode==2 ? MATTER_IM_DATA_VERSION_MISMATCH : MATTER_IM_CONSTRAINT_ERROR));
                if(mode==4 || mode==8 || mode==9) CHECK(a->im_opcode==1 && a->im_received.data[3]==
                    (mode==4 ? MATTER_IM_RESOURCE_EXHAUSTED : mode==8 ? MATTER_IM_TIMEOUT : MATTER_IM_INVALID_ACTION));
                CHECK(im_ack_transfer(a,b,now+=200) && matter_im_write_state(b->write)==MATTER_IM_WRITE_COMPLETE);
                CHECK(m->writes==(!mode || mode==7 ? 1u : 0u));
            }
        }
        CHECK(!a->tx_pins && !b->tx_pins && !a->ack_pins && !b->ack_pins);
        CHECK(matter_im_write_delete(b->write)==MATTER_OK); b->write=NULL; m->active=NULL; a->im_client=false;
        if(!mode || mode==7) CHECK(write_readback(f,m,&now));
    }
    *clock=now; puts("PASS Write IPv6: PASE write/readback and version, identical retry/duplicates, access/schema/version/capacity, suppress, timeout and timed RX before ACK"); ok=true;
done:
    if(b->write) { REQUIRE(matter_im_write_cancel(b->write)==MATTER_OK && matter_im_write_delete(b->write)==MATTER_OK); b->write=NULL; }
    free(m); return ok;
}
static bool write_close_network(PaseFixture* f,uint64_t now,bool executed) {
    bool ok=false; Peer* a=&f->link->a; Peer* b=&f->link->b;
    WriteModel* m=calloc(1,sizeof(*m)); REQUIRE(m);
    CHECK(write_begin(f,m,now,1024,write_request,sizeof(write_request),6) && tick(a,now));
    network_poll(a); CHECK(network_take(a) && network_receive(b) && network_admit(b,now) && tick(b,now));
    CHECK(im_ack_transfer(b,a,now+=200));
    if(executed) {
        CHECK(matter_im_write_process(b->write,now)==MATTER_PENDING && m->writes==1);
        Matter_Im_Write_Message_T out; CHECK(matter_im_write_output(b->write,&out)==MATTER_OK);
        CHECK(im_host_send(f,b,out.opcode,out.data,out.size,now) && tick(b,now)); /* Borrowed TX pending. */
    }
    CHECK(matter_secure_channel_send_close(a->channel,a->rx,a->udp,now,&a->udp_request)==MATTER_PENDING);
    CHECK(matter_secure_channel_retire(a->channel,a->rx,a->tx)==MATTER_PENDING);
    CHECK(network_receive(b) && network_admit(b,now) && matter_im_write_cancel(b->write)==MATTER_OK);
    CHECK(matter_secure_channel_retire(b->channel,b->rx,b->tx)==(executed ? MATTER_PENDING : MATTER_OK));
    network_poll(a); CHECK(network_take(a) && tick(a,now));
    if(executed) { network_poll(b); CHECK(network_take(b) && tick(b,now)); }
    CHECK(matter_secure_channel_retire(a->channel,a->rx,a->tx)==MATTER_OK && matter_secure_channel_retire(b->channel,b->rx,b->tx)==MATTER_OK);
    CHECK(matter_im_write_process(b->write,now)==MATTER_INVALID_STATE && m->writes==(executed ? 1u : 0u) && m->version==(executed ? 8u : 7u));
    CHECK(matter_im_write_confirm(b->write,now)==MATTER_INVALID_STATE);
    CHECK(matter_im_write_delete(b->write)==MATTER_OK); b->write=NULL; a->im_client=false;
    CHECK(!a->tx_pins && !b->tx_pins && !a->rx_pins && !b->rx_pins);
    puts("PASS Write CloseSession IPv6: before/after effect, pending response drain, no revival or rollback"); ok=true;
done:
    if(b->write) { REQUIRE(matter_im_write_cancel(b->write)==MATTER_OK && matter_im_write_delete(b->write)==MATTER_OK); b->write=NULL; }
    free(m); return ok;
}
#endif

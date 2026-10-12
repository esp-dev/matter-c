#ifdef MATTER_TEST_HOST_UDP
#include "test_write_list_model.h"
typedef struct {
    WriteListModel model;
    uint8_t encoded[4096], item[32];
    Matter_Tlv_Writer_T writer;
    Matter_Tlv_Reader_T reader;
    Matter_Tlv_Element_T token;
    size_t size;
    unsigned received, replacements;
} WriteListHost;
static bool wlh_begin(PaseFixture* f,WriteListHost* h,uint64_t now) {
    Peer* a=&f->link->a; Peer* b=&f->link->b;
    if(a->handle) REQUIRE(matter_rx_close(a->rx,a->handle)==MATTER_OK);
    if(b->handle) REQUIRE(matter_rx_close(b->rx,b->handle)==MATTER_OK);
    a->handle=b->handle=0; a->im_client=true; a->im_received.size=0;
    REQUIRE(matter_rx_initiate(a->rx,a->secure_token,&a->handle)==MATTER_OK && matter_rx_get(a->rx,a->handle,&a->key)==MATTER_OK);
    Matter_Im_Write_Port_T port=wl_port(&h->model);
    Matter_Im_Write_Config_T c={{b->secure_token,a->key.exchange_id,false},60000,128,true};
    h->model.version=7; REQUIRE(!b->write && !b->im && !b->invoke);
    h->model.active=b->write=matter_im_write_new(&port,&c,now); return b->write!=NULL;
}
static bool wlh_request(PaseFixture* f,WriteListHost* h,uint64_t now) {
    Peer* a=&f->link->a; Peer* b=&f->link->b;
    if(!im_host_send(f,a,6,h->model.input,h->model.input_size,now) || !tick(a,now)) return false;
    network_poll(a);
    if(!network_take(a) || !network_receive(b)) return false;
    f->link->delayed_data=b->inbox;
    return network_admit(b,now) && tick(b,now);
}
static bool wlh_response(PaseFixture* f,uint64_t* clock,bool lose) {
    bool ok=false; Peer* a=&f->link->a; Peer* b=&f->link->b; uint64_t now=*clock;
    Matter_Im_Write_Message_T out; CHECK(matter_im_write_output(b->write,&out)==MATTER_OK && out.opcode==7);
    CHECK(im_host_send(f,b,7,out.data,out.size,now) && tick(b,now)); network_poll(b);
    CHECK(network_take(b) && network_receive(a));
    if(lose) {
        f->link->delayed_ack=a->inbox; a->inbox_full=false;
        CHECK(matter_retransmission_sender_deadline(b->tx,&now)==MATTER_OK && tick(b,now)); complete_resolver(b);
        network_poll(b); CHECK(network_take(b) && network_receive(a));
        CHECK(a->inbox.size==f->link->delayed_ack.size && !memcmp(a->inbox.data,f->link->delayed_ack.data,a->inbox.size));
    }
    CHECK(network_admit(a,now) && tick(a,now) && a->im_opcode==7);
    CHECK(a->im_received.size==out.size && !memcmp(a->im_received.data,out.data,out.size));
    *clock=now; ok=true;
done: return ok;
}
static Matter_Im_Status_T wlh_read(void* u,const Matter_Im_Path_T* p,bool filtered,Matter_Im_Value_T* v) {
    WriteListHost* h=u; (void)p; REQUIRE(filtered);
    REQUIRE(matter_tlv_writer_init(&h->writer,h->encoded,sizeof(h->encoded),4)==MATTER_TLV_OK);
    h->token=(Matter_Tlv_Element_T){.type=MATTER_TLV_ARRAY}; REQUIRE(matter_tlv_write(&h->writer,&h->token,0)==MATTER_TLV_OK);
    for(unsigned i=0;i<h->model.count;++i) {
        memset(h->item,h->model.items[i],32);
        h->token=(Matter_Tlv_Element_T){.type=MATTER_TLV_BYTES,.data=h->item,.size=32};
        REQUIRE(matter_tlv_write(&h->writer,&h->token,0)==MATTER_TLV_OK);
    }
    h->token=(Matter_Tlv_Element_T){.type=MATTER_TLV_END}; REQUIRE(matter_tlv_write(&h->writer,&h->token,0)==MATTER_TLV_OK);
    REQUIRE(matter_tlv_writer_finish(&h->writer,&h->size)==MATTER_TLV_OK);
    *v=(Matter_Im_Value_T){.type=MATTER_TLV_ARRAY,.data=h->encoded,.size=h->size,.data_version=h->model.version}; return MATTER_IM_SUCCESS;
}
static bool wlh_report(WriteListHost* h,const uint8_t* data,size_t size) {
    REQUIRE(matter_tlv_init(&h->reader,data,size,8)==MATTER_TLV_OK);
    unsigned depth=0; bool more=false,append=false,version=false;
    Matter_Tlv_Result_T r;
    while((r=matter_tlv_next(&h->reader,&h->token))==MATTER_TLV_OK) {
        Matter_Tlv_Element_T* e=&h->token;
        if(e->type==MATTER_TLV_END) { REQUIRE(depth); --depth; continue; }
        if(depth==2) { append=false; version=false; }
        if(depth==4 && e->tag.control==1 && e->tag.number==0) { REQUIRE(e->type==MATTER_TLV_UNSIGNED && e->unsigned_value==h->model.version); version=true; }
        if(depth==5 && e->tag.control==1 && e->tag.number==5) { REQUIRE(e->type==MATTER_TLV_NULL); append=true; }
        if(depth==4 && e->type==MATTER_TLV_ARRAY && e->tag.number==2) { REQUIRE(version && !h->replacements++ && !h->received); }
        if((depth==4 || depth==5) && e->type==MATTER_TLV_BYTES) {
            REQUIRE(version && (depth==5 || append) && e->size==32 && h->received<h->model.count);
            for(size_t j=0;j<32;++j) REQUIRE(e->data[j]==h->model.items[h->received]);
            ++h->received;
        }
        if(depth==1 && e->tag.number==3) { REQUIRE(e->type==MATTER_TLV_BOOL); more=e->unsigned_value!=0; }
        if(e->type==MATTER_TLV_ARRAY || e->type==MATTER_TLV_STRUCTURE || e->type==MATTER_TLV_LIST) ++depth;
    }
    REQUIRE(r==MATTER_TLV_DONE); return more;
}
static bool wlh_readback(PaseFixture* f,WriteListHost* h,uint64_t* clock) {
    bool ok=false; Peer* a=&f->link->a; Peer* b=&f->link->b; uint64_t now=*clock;
    Matter_Im_Read_Port_T port={h,write_read_allow,im_host_describe,wlh_read,NULL,NULL};
    CHECK(im_host_begin_port(f,++now,512,im_request,sizeof(im_request),&port) && tick(a,now));
    network_poll(a); CHECK(network_take(a) && network_receive(b) && network_admit(b,now) && tick(b,now));
    CHECK(im_ack_transfer(b,a,now+=200) && matter_im_read_process(b->im,now)==MATTER_PENDING);
    for(unsigned chunk=0;chunk<64;++chunk) {
        Matter_Im_Read_Message_T out; CHECK(matter_im_read_output(b->im,&out)==MATTER_OK);
        CHECK(im_host_send(f,b,5,out.data,out.size,now) && matter_im_read_sent(b->im)==MATTER_OK && tick(b,now));
        network_poll(b); CHECK(network_take(b) && network_receive(a) && network_admit(a,now) && tick(a,now));
        bool more=wlh_report(h,a->im_received.data,a->im_received.size);
        CHECK(im_ack_transfer(a,b,now+=200));
        if(!more) break;
        static const uint8_t success[]={0x15,0x24,0,0,0x24,0xff,13,0x18};
        CHECK(im_host_send(f,a,1,success,sizeof(success),now) && tick(a,now)); network_poll(a);
        CHECK(network_take(a) && network_receive(b) && network_admit(b,now) && tick(b,now));
        CHECK(im_ack_transfer(b,a,now+=200) && matter_im_read_process(b->im,now)==MATTER_PENDING);
    }
    CHECK(h->received==h->model.count && h->replacements==1 && matter_im_read_state(b->im)==MATTER_IM_READ_COMPLETE);
    CHECK(matter_im_read_delete(b->im)==MATTER_OK); b->im=NULL; a->im_client=false; *clock=now; ok=true;
done: return ok;
}
static bool write_lists_network(PaseFixture* f,uint64_t* clock) {
    bool ok=false; Peer* a=&f->link->a; Peer* b=&f->link->b; uint64_t now=*clock;
    WriteListHost* h=calloc(1,sizeof(*h)); REQUIRE(h); CHECK(wlh_begin(f,h,++now));
    for(unsigned chunk=0;chunk<=40;++chunk) {
        wl_request(&h->model,chunk!=0,chunk!=40,(int)h->model.version,(uint8_t)(chunk ? chunk-1 : 0));
        CHECK(wlh_request(f,h,++now));
        if(chunk) {
            /* Previous response delivered but not ACKed; preserve it and defer ADD. */
            CHECK(matter_im_write_process(b->write,now)==MATTER_PENDING && h->model.writes==chunk);
            CHECK(im_ack_transfer(a,b,now+=200) && matter_im_write_state(b->write)==MATTER_IM_WRITE_WAIT_CHUNK);
        }
        CHECK(im_ack_transfer(b,a,now+=200) && matter_im_write_process(b->write,now)==MATTER_PENDING);
        CHECK(h->model.writes==chunk+1 && h->model.count==chunk);
        if(chunk==3) {
            unsigned delivered=b->deliveries;
            Matter_Udp_Datagram_T dup={.path=b->received_path,.data=f->link->delayed_data.data,.size=f->link->delayed_data.size};
            CHECK(matter_secure_channel_receive(b->channel,b->rx,&dup,now,now)==MATTER_OK && tick(b,now));
            CHECK(b->deliveries==delivered && h->model.writes==chunk+1 && im_ack_transfer(b,a,now));
        }
        CHECK(wlh_response(f,&now,chunk==3));
    }
    CHECK(im_ack_transfer(a,b,now+=200) && matter_im_write_state(b->write)==MATTER_IM_WRITE_COMPLETE && h->model.version==48);
    CHECK(matter_im_write_delete(b->write)==MATTER_OK); b->write=NULL; h->model.active=NULL;
    CHECK(wlh_readback(f,h,&now));
    CHECK(!a->tx_pins && !b->tx_pins && !a->ack_pins && !b->ack_pins);
    *clock=now; puts("PASS Write list IPv6: 40 items over 41 messages, RX before ACK, ADD duplicate/lost response, exact retry, version and chunked Read reconstruction"); ok=true;
done:
    if(b->write) { REQUIRE(matter_im_write_cancel(b->write)==MATTER_OK && matter_im_write_delete(b->write)==MATTER_OK); b->write=NULL; }
    free(h); return ok;
}
static bool write_lists_close_network(PaseFixture* f,uint64_t now) {
    bool ok=false; Peer* a=&f->link->a; Peer* b=&f->link->b;
    WriteListHost* h=calloc(1,sizeof(*h)); REQUIRE(h); CHECK(wlh_begin(f,h,now));
    wl_request(&h->model,true,true,7,9); CHECK(wlh_request(f,h,now));
    CHECK(im_ack_transfer(b,a,now+=200) && matter_im_write_process(b->write,now)==MATTER_PENDING && wlh_response(f,&now,false));
    wl_request(&h->model,true,false,8,10); CHECK(wlh_request(f,h,++now));
    CHECK(matter_im_write_process(b->write,now)==MATTER_PENDING && h->model.count==1);
    CHECK(matter_secure_channel_send_close(a->channel,a->rx,a->udp,now,&a->udp_request)==MATTER_PENDING);
    CHECK(matter_secure_channel_retire(a->channel,a->rx,a->tx)==MATTER_PENDING);
    CHECK(network_receive(b) && network_admit(b,now) && matter_im_write_cancel(b->write)==MATTER_OK);
    CHECK(matter_secure_channel_retire(b->channel,b->rx,b->tx)==MATTER_PENDING);
    network_poll(a); CHECK(network_take(a) && tick(a,now) && tick(b,now));
    CHECK(matter_secure_channel_retire(a->channel,a->rx,a->tx)==MATTER_OK && matter_secure_channel_retire(b->channel,b->rx,b->tx)==MATTER_OK);
    CHECK(h->model.count==1 && h->model.items[0]==9 && h->model.version==8 && h->model.writes==1);
    CHECK(matter_im_write_process(b->write,now)==MATTER_INVALID_STATE && matter_im_write_confirm(b->write,now)==MATTER_INVALID_STATE);
    CHECK(matter_im_write_delete(b->write)==MATTER_OK); b->write=NULL; a->im_client=false;
    CHECK(!a->tx_pins && !b->tx_pins && !a->rx_pins && !b->rx_pins);
    puts("PASS Write list CloseSession IPv6: committed prefix retained, queued ADD discarded, pending MRP drained"); ok=true;
done:
    if(b->write) { REQUIRE(matter_im_write_cancel(b->write)==MATTER_OK && matter_im_write_delete(b->write)==MATTER_OK); b->write=NULL; }
    free(h); return ok;
}
#endif

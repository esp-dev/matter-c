#ifdef MATTER_TEST_HOST_UDP
#include "test_fabric_fixture.h"
static void fab_wire(FabFixture* m,uint32_t cmd) {
    OC_CHECK(matter_tlv_writer_init(&m->writer,m->wire,sizeof(m->wire),8)==MATTER_TLV_OK);
    fab_put(m,MATTER_TLV_STRUCTURE,-1,0,NULL,0); fab_put(m,MATTER_TLV_BOOL,0,0,NULL,0); fab_put(m,MATTER_TLV_BOOL,1,0,NULL,0);
    fab_put(m,MATTER_TLV_ARRAY,2,0,NULL,0); fab_put(m,MATTER_TLV_STRUCTURE,-1,0,NULL,0); fab_put(m,MATTER_TLV_LIST,0,0,NULL,0);
    fab_put(m,MATTER_TLV_UNSIGNED,0,0,NULL,0); fab_put(m,MATTER_TLV_UNSIGNED,1,0x3e,NULL,0); fab_put(m,MATTER_TLV_UNSIGNED,2,cmd,NULL,0);
    fab_put(m,MATTER_TLV_END,-1,0,NULL,0);
    OC_CHECK(matter_tlv_init(&m->reader,m->args,m->args_size,4)==MATTER_TLV_OK);
    bool first=true; Matter_Tlv_Result_T r;
    while((r=matter_tlv_next(&m->reader,&m->e))==MATTER_TLV_OK) {
        if(first) { m->e.tag.control=1; m->e.tag.number=1; first=false; }
        OC_CHECK(matter_tlv_write(&m->writer,&m->e,0)==MATTER_TLV_OK);
    }
    OC_CHECK(r==MATTER_TLV_DONE);
    fab_put(m,MATTER_TLV_END,-1,0,NULL,0); fab_put(m,MATTER_TLV_END,-1,0,NULL,0);
    fab_put(m,MATTER_TLV_UNSIGNED,255,13,NULL,0); fab_put(m,MATTER_TLV_END,-1,0,NULL,0);
    OC_CHECK(matter_tlv_writer_finish(&m->writer,&m->wire_size)==MATTER_TLV_OK);
}
static bool fab_exchange(PaseFixture* f) {
    Peer* a=&f->link->a; Peer* b=&f->link->b;
    if(a->handle) REQUIRE(matter_rx_close(a->rx,a->handle)==MATTER_OK);
    if(b->handle) REQUIRE(matter_rx_close(b->rx,b->handle)==MATTER_OK);
    a->handle=b->handle=0; a->im_client=true; a->im_received.size=0;
    return matter_rx_initiate(a->rx,a->secure_token,&a->handle)==MATTER_OK && matter_rx_get(a->rx,a->handle,&a->key)==MATTER_OK;
}
static bool fab_invoke_network(PaseFixture* f,FabFixture* m,WifiFixture* w,uint64_t* clock,uint32_t cmd,uint8_t status,bool retry) {
    bool ok=false; uint64_t now=*clock; Peer* a=&f->link->a; Peer* b=&f->link->b;
    CHECK(fab_exchange(f)); fab_wire(m,cmd);
    Matter_Im_Invoke_Config_T config={{b->secure_token,a->key.exchange_id,false},10000,1018,true};
    b->invoke=matter_im_invoke_new_async(&w->g->invoke,&w->async,&config,++now); CHECK(b->invoke);
    CHECK(im_host_send(f,a,8,m->wire,m->wire_size,now) && tick(a,now)); network_poll(a);
    CHECK(network_take(a) && network_receive(b) && network_admit(b,now) && tick(b,now));
    CHECK(im_ack_transfer(b,a,now+=200));
    for(unsigned step=0;step<8 && matter_im_invoke_state(b->invoke)!=MATTER_IM_INVOKE_OUTPUT;++step) {
        wf_tick(w,++now); CHECK(matter_im_invoke_process(b->invoke,now)==MATTER_PENDING);
    }
    Matter_Im_Invoke_Message_T out; CHECK(matter_im_invoke_output(b->invoke,&out)==MATTER_OK && out.opcode==9);
    CHECK(im_host_send(f,b,9,out.data,out.size,now) && matter_im_invoke_sent_at(b->invoke,now)==MATTER_OK && tick(b,now)); network_poll(b);
    CHECK(network_take(b) && network_receive(a));
    if(retry) {
        unsigned count=m->port.view(m->host)->count; uint32_t version=matter_opcreds_version(m->o->core);
        f->link->delayed_ack=a->inbox; a->inbox_full=false;
        CHECK(matter_retransmission_sender_deadline(b->tx,&now)==MATTER_OK && tick(b,now)); complete_resolver(b);
        network_poll(b); CHECK(network_take(b) && network_receive(a));
        CHECK(a->inbox.size==f->link->delayed_ack.size && !memcmp(a->inbox.data,f->link->delayed_ack.data,a->inbox.size));
        CHECK(m->port.view(m->host)->count==count && matter_opcreds_version(m->o->core)==version);
    }
    CHECK(network_admit(a,now) && tick(a,now));
    if(cmd==4) oc_verify(m->o,4,a->im_received.data,a->im_received.size);
    else {
        CHECK(matter_tlv_init(&m->reader,a->im_received.data,a->im_received.size,8)==MATTER_TLV_OK);
        unsigned depth=0,got=0; bool path=false; Matter_Tlv_Result_T r;
        while((r=matter_tlv_next(&m->reader,&m->e))==MATTER_TLV_OK) {
            Matter_Tlv_Element_T* e=&m->e;
            if(e->type==MATTER_TLV_END) { CHECK(depth); --depth; continue; }
            if(depth==3) CHECK(e->tag.number==(cmd==11?1u:0u));
            if(depth==4) path=e->tag.number==0;
            if(depth==5 && path && e->tag.number==1) CHECK(e->unsigned_value==0x3e);
            if(depth==5 && path && e->tag.number==2) CHECK(e->unsigned_value==(cmd==11?11:8));
            if(depth==5 && !path && e->tag.number==0) { CHECK(e->unsigned_value==status); ++got; }
            if(depth==5 && !path && e->tag.number==1) CHECK(cmd==6 && !status && e->unsigned_value==1);
            if(e->type==MATTER_TLV_STRUCTURE || e->type==MATTER_TLV_ARRAY || e->type==MATTER_TLV_LIST) ++depth;
        }
        CHECK(r==MATTER_TLV_DONE && got==1);
    }
    CHECK(im_ack_transfer(a,b,now+=200) && matter_im_invoke_state(b->invoke)==MATTER_IM_INVOKE_COMPLETE);
    CHECK(matter_im_invoke_delete(b->invoke)==MATTER_OK); b->invoke=NULL; a->im_client=false; *clock=now; ok=true;
done: return ok;
}
static bool fab_read_network(PaseFixture* f,FabFixture* m,WifiFixture* w,uint64_t* clock) {
    bool ok=false; uint64_t now=*clock; Peer* a=&f->link->a; Peer* b=&f->link->b;
    Matter_Root_Invoke_Binding_T binding; Matter_Im_Read_Port_T port; Matter_Im_Read_Fabric_Port_T fabric;
    CHECK(matter_root_fabric_read_port(w->g->f->root,b->secure_token,&binding,&port,&fabric)==MATTER_OK);
    CHECK(fab_exchange(f)); root_read_request(w->g->f,false);
    Matter_Im_Read_Config_T config={{b->secure_token,a->key.exchange_id,false},20000,512,true};
    b->im=matter_im_read_new_fabric(&port,&fabric,&config,++now); CHECK(b->im);
    CHECK(im_host_send(f,a,2,w->g->f->request,w->g->f->request_size,now) && tick(a,now)); network_poll(a);
    CHECK(network_take(a) && network_receive(b) && network_admit(b,now) && tick(b,now));
    CHECK(im_ack_transfer(b,a,now+=200)); unsigned received=0,opattrs=0,chunks=0;
    for(;chunks<32;++chunks) {
        for(unsigned step=0;step<32 && matter_im_read_state(b->im)!=MATTER_IM_READ_OUTPUT;++step)
            CHECK(matter_im_read_process(b->im,now)==MATTER_PENDING);
        Matter_Im_Read_Message_T out; CHECK(matter_im_read_output(b->im,&out)==MATTER_OK && out.opcode==5);
        CHECK(im_host_send(f,b,5,out.data,out.size,now) && matter_im_read_sent(b->im)==MATTER_OK && tick(b,now)); network_poll(b);
        CHECK(network_take(b) && network_receive(a) && network_admit(a,now) && tick(a,now));
        CHECK(matter_tlv_init(&m->reader,a->im_received.data,a->im_received.size,8)==MATTER_TLV_OK);
        unsigned depth=0; uint32_t cluster=0,attr=0; bool more=false; Matter_Tlv_Result_T r;
        while((r=matter_tlv_next(&m->reader,&m->e))==MATTER_TLV_OK) {
            Matter_Tlv_Element_T* e=&m->e;
            if(e->type==MATTER_TLV_END) { CHECK(depth); --depth; continue; }
            CHECK(!(depth==3 && e->tag.number==0));
            if(depth==5 && e->tag.number==3) cluster=(uint32_t)e->unsigned_value;
            if(depth==5 && e->tag.number==4) attr=(uint32_t)e->unsigned_value;
            if(depth==4 && e->tag.number==2) {
                ++received;
                if(cluster==0x3e && attr<6) {
                    opattrs|=1u<<attr;
                    if(attr==2 || attr==3 || attr==5) CHECK(e->unsigned_value==(attr==2?5:1));
                    if(attr==0 || attr==1 || attr==4) CHECK(e->type==MATTER_TLV_ARRAY);
                }
            }
            if(cluster==0x3e && attr==0 && e->type==MATTER_TLV_BYTES && e->tag.number==1)
                CHECK(e->size==sizeof(fab_noc0) && !memcmp(e->data,fab_noc0,e->size));
            if(cluster==0x3e && (attr==0 || attr==1) && e->type==MATTER_TLV_UNSIGNED && e->tag.number==254) CHECK(e->unsigned_value==1);
            if(depth==1 && e->tag.number==3) more=e->unsigned_value!=0;
            if(e->type==MATTER_TLV_STRUCTURE || e->type==MATTER_TLV_ARRAY || e->type==MATTER_TLV_LIST) ++depth;
        }
        CHECK(r==MATTER_TLV_DONE && !depth && im_ack_transfer(a,b,now+=200));
        if(!more) break;
        static const uint8_t success[]={0x15,0x24,0,0,0x24,255,13,0x18};
        CHECK(im_host_send(f,a,1,success,sizeof(success),now) && tick(a,now)); network_poll(a);
        CHECK(network_take(a) && network_receive(b) && network_admit(b,now) && tick(b,now));
        CHECK(im_ack_transfer(b,a,now+=200));
    }
    CHECK(chunks>0 && chunks<32 && received==65 && opattrs==63 && matter_im_read_state(b->im)==MATTER_IM_READ_COMPLETE);
    CHECK(matter_im_read_delete(b->im)==MATTER_OK); b->im=NULL; a->im_client=false; *clock=now; ok=true;
done: return ok;
}
static bool fabric_network(PaseFixture* f,uint64_t now) {
    bool ok=false; Peer* a=&f->link->a; Peer* b=&f->link->b;
    Matter_Credentials_Port_T cp; REQUIRE(matter_crypto_mbedtls_credentials(f->crypto,&cp)==MATTER_OK);
    FabFixture* m=fab_new(&f->port,&cp); WifiFixture* w=wf_new_product(now,b->secure_token,0x8000); GcFixture* g=w->g;
    Matter_Root_Async_Invoke_Binding_T binding;
    m->o->session_user=b; m->o->session_challenge=oc_secure_challenge; CHECK(matter_secure_challenge(a->secure,m->o->challenge)==MATTER_OK);
    CHECK(matter_root_attach_opcreds(g->f->root,m->o->core)==MATTER_OK && matter_root_async_invoke_port(g->f->root,b->secure_token,&binding,&g->invoke,&w->async)==MATTER_OK);
    wf_arm(w,60); fab_scalar_value=10; oc_request(m->o,4,0,32,false); memcpy(m->args,m->o->request,m->o->request_size); m->args_size=m->o->request_size;
    CHECK(fab_invoke_network(f,m,w,&now,4,0,false));
    fab_request(m,11,FAB_CERT(fab_root),(Matter_Cert_Tlv_T){0},0); CHECK(fab_invoke_network(f,m,w,&now,11,0,false));
    fab_request(m,6,FAB_CERT(fab_noc1),(Matter_Cert_Tlv_T){0},55); CHECK(fab_invoke_network(f,m,w,&now,6,1,false));
    fab_request(m,6,FAB_CERT(fab_noc0),(Matter_Cert_Tlv_T){0},55); CHECK(fab_invoke_network(f,m,w,&now,6,0,true));
    uint8_t index; CHECK(matter_root_fail_safe_fabric(g->f->root,&index)==MATTER_OK && index==1);
    /* Even another application-authorized session cannot rearm/expire this fabric's fail-safe. */
    Matter_Im_Invoke_Port_T saved=g->invoke; Matter_Im_Invoke_Async_Port_T saved_async=w->async;
    Matter_Root_Async_Invoke_Binding_T other; uint64_t deadline,after;
    CHECK(matter_root_deadline(g->f->root,&deadline)==MATTER_OK);
    g->f->session=b->secure_token+1;
    CHECK(matter_root_async_invoke_port(g->f->root,g->f->session,&other,&g->invoke,&w->async)==MATTER_OK);
    for(unsigned j=0;j<2;++j) {
        gc_request(g,0,j?30:0,NULL,99); Matter_Im_Invoke_T denied=wf_start(w,256,1000);
        Matter_Im_Invoke_Message_T reply; CHECK(matter_im_invoke_output(denied,&reply)==MATTER_OK);
        gc_reply(reply.data,reply.size,0,4,false); CHECK(matter_im_invoke_delete(denied)==MATTER_OK);
        CHECK(matter_root_deadline(g->f->root,&after)==MATTER_OK && after==deadline);
    }
    g->f->session=b->secure_token; g->invoke=saved; w->async=saved_async;
    CHECK(fab_read_network(f,m,w,&now));
    static const uint8_t status[]={0x15,0x24,0,0,0x24,255,13,0x18};
    CHECK(im_host_send(f,b,1,status,sizeof(status),++now) && tick(b,now) && b->retained);
    OcCleanup cleanup={b,m->o}; g->cleanup_hook=oc_retire; g->hook_user=&cleanup;
    CHECK(matter_root_expire(g->f->root)==MATTER_PENDING && matter_root_process(g->f->root,now)==MATTER_PENDING && g->marker);
    CHECK(m->port.view(m->host)->count==1);
    network_poll(b); CHECK(network_take(b) && tick(b,now));
    CHECK(matter_root_process(g->f->root,now)==MATTER_OK && !g->marker && !m->port.view(m->host)->count);
    CHECK(matter_fabric_host_sign(m->host,1,m->ipk,16,m->signature)==MATTER_INVALID_STATE && !matter_opcreds_fabric_index(m->o->core,b->secure_token));
    puts("PASS fabrics IPv6/PASE: CSR/root/AddNOC, immutable retry, 65 Root attributes/chunks, PASE FabricIndex, secure drain before atomic rollback"); ok=true;
done:
    if(b->invoke) { REQUIRE(matter_im_invoke_cancel(b->invoke)==MATTER_OK && matter_im_invoke_delete(b->invoke)==MATTER_OK); b->invoke=NULL; }
    if(b->im) { REQUIRE(matter_im_read_cancel(b->im)==MATTER_OK && matter_im_read_delete(b->im)==MATTER_OK); b->im=NULL; }
    w->now=now; wf_release(w); fab_free(m); return ok;
}
#endif

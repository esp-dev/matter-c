#ifdef MATTER_TEST_HOST_UDP
#include "test_opcreds_fixture.h"
typedef struct { Peer* peer; OcFixture* oc; } OcCleanup;
static Matter_Result_T oc_secure_challenge(void* u,Matter_Exchange_Session_T session,uint8_t out[16]) {
    Peer* b=u;
    if(session!=b->secure_token) return MATTER_INVALID_STATE;
    return matter_secure_challenge(b->secure,out);
}
static Matter_Result_T oc_retire(void* u) {
    OcCleanup* c=u; Matter_Result_T r=gc_retire(c->peer);
    if(r!=MATTER_OK) return r;
    c->oc->revoked=true; return matter_opcreds_rollback(c->oc->core);
}
static void oc_network_request(RootFixture* f,OcFixture* o,uint32_t cmd,unsigned cert,bool bad) {
    OC_CHECK(matter_tlv_writer_init(&f->writer,f->request,sizeof(f->request),6)==MATTER_TLV_OK);
    root_put(f,MATTER_TLV_STRUCTURE,-1,0,NULL,0); root_put(f,MATTER_TLV_BOOL,0,0,NULL,0); root_put(f,MATTER_TLV_BOOL,1,0,NULL,0);
    root_put(f,MATTER_TLV_ARRAY,2,0,NULL,0); root_put(f,MATTER_TLV_STRUCTURE,-1,0,NULL,0); root_put(f,MATTER_TLV_LIST,0,0,NULL,0);
    root_put(f,MATTER_TLV_UNSIGNED,0,0,NULL,0); root_put(f,MATTER_TLV_UNSIGNED,1,0x3e,NULL,0); root_put(f,MATTER_TLV_UNSIGNED,2,cmd,NULL,0);
    root_put(f,MATTER_TLV_END,-1,0,NULL,0); root_put(f,MATTER_TLV_STRUCTURE,1,0,NULL,0);
    if(cmd==2) root_put(f,MATTER_TLV_UNSIGNED,0,cert,NULL,0);
    else root_put(f,MATTER_TLV_BYTES,0,0,o->nonce,bad?31:32);
    root_put(f,MATTER_TLV_END,-1,0,NULL,0); root_put(f,MATTER_TLV_END,-1,0,NULL,0); root_put(f,MATTER_TLV_END,-1,0,NULL,0);
    root_put(f,MATTER_TLV_UNSIGNED,255,13,NULL,0); root_put(f,MATTER_TLV_END,-1,0,NULL,0);
    OC_CHECK(matter_tlv_writer_finish(&f->writer,&f->request_size)==MATTER_TLV_OK);
}
static bool opcreds_network(PaseFixture* f,uint64_t now) {
    bool ok=false; Peer* a=&f->link->a; Peer* b=&f->link->b;
    Matter_Credentials_Port_T cp; REQUIRE(matter_crypto_mbedtls_credentials(f->crypto,&cp)==MATTER_OK);
    OcFixture* o=oc_new(&f->port,&cp); WifiFixture* w=wf_new_product(now,b->secure_token,0x8000); GcFixture* g=w->g;
    Matter_Root_Async_Invoke_Binding_T binding;
    oc_request(o,4,0,32,false); CHECK(oc_start(o,4,false)==MATTER_OK && o->result.status==0xca);
    o->session_user=b; o->session_challenge=oc_secure_challenge;
    CHECK(matter_secure_challenge(a->secure,o->challenge)==MATTER_OK);
    CHECK(matter_root_attach_opcreds(g->f->root,o->core)==MATTER_OK);
    CHECK(matter_root_async_invoke_port(g->f->root,b->secure_token,&binding,&g->invoke,&w->async)==MATTER_OK);
    CHECK(gc_scalar(g,0x3e,0xfffd,NULL)==2 && gc_scalar(g,0x28,2,NULL)==0xfff1 && gc_scalar(g,0x28,4,NULL)==0x8000);
    wf_arm(w,30);
    Matter_Im_Selector_T q={0}; Matter_Im_Path_T last,next; bool found; unsigned count=0;
    do { CHECK(g->f->read.enumerate(g->f->root,&q,count?&last:NULL,&next,&found)==MATTER_OK); if(found) {last=next; ++count;} } while(found);
    CHECK(count==59);
    /* Two pending handlers have overlapping backend token values (both 1).
     * Routing belongs to each handler, never to a shared Root cache. */
    wf_request(w,0,NULL,NULL,0,7); Matter_Im_Invoke_T scan=wf_start(w,1024,10000);
    Matter_Root_Async_Invoke_Binding_T second;
    Matter_Im_Invoke_Port_T saved=g->invoke; Matter_Im_Invoke_Async_Port_T saved_async=w->async;
    CHECK(matter_root_async_invoke_port(g->f->root,b->secure_token,&second,&g->invoke,&w->async)==MATTER_OK);
    oc_network_request(g->f,o,0,0,false); Matter_Im_Invoke_T attest=wf_start(w,1024,10000);
    g->invoke=saved; w->async=saved_async;
    CHECK(binding.pending_cluster==0x31 && second.pending_cluster==0x3e);
    for(unsigned i=0;i<3;++i) wf_tick(w,w->now+200);
    CHECK(matter_im_invoke_process(attest,w->now)==MATTER_PENDING);
    Matter_Im_Invoke_Message_T ready; CHECK(matter_im_invoke_output(attest,&ready)==MATTER_OK);
    oc_verify(o,0,ready.data,ready.size); CHECK(matter_im_invoke_delete(attest)==MATTER_OK);
    CHECK(matter_im_invoke_process(scan,w->now)==MATTER_PENDING); wf_finish(w,scan,0,0,false);
    /* Denied or capacity-rejected commands cannot start key generation. */
    for(unsigned gate=0;gate<2;++gate) {
        unsigned prepares=o->prepares;
        oc_network_request(g->f,o,4,0,false); g->f->denied=gate?MATTER_IM_UNSUPPORTED_ACCESS:0;
        Matter_Im_Invoke_T rejected=wf_start(w,gate?1024:256,1000);
        CHECK(matter_im_invoke_output(rejected,&ready)==MATTER_OK && o->prepares==prepares);
        CHECK(matter_tlv_init(&o->reader,ready.data,ready.size,8)==MATTER_TLV_OK); unsigned errors=0;
        while(matter_tlv_next(&o->reader,&o->e)==MATTER_TLV_OK)
            if(o->e.type==MATTER_TLV_UNSIGNED && o->e.unsigned_value==(unsigned)(gate?MATTER_IM_UNSUPPORTED_ACCESS:MATTER_IM_RESOURCE_EXHAUSTED)) ++errors;
        CHECK(errors==1 && matter_im_invoke_delete(rejected)==MATTER_OK);
    }
    g->f->denied=0;
    /* IM timeout cancels staged CSR before publish, then owner drains it. */
    oc_network_request(g->f,o,4,0,false); Matter_Im_Invoke_T timeout=wf_start(w,1024,2);
    wf_tick(w,w->now+1); CHECK(matter_opcreds_host_delete(o->host)==MATTER_INVALID_STATE);
    CHECK(matter_im_invoke_process(timeout,w->now+1)==MATTER_PORT_ERROR && matter_im_invoke_delete(timeout)==MATTER_OK);
    wf_tick(w,w->now+1); CHECK(matter_opcreds_host_candidate(o->host,o->candidate)==MATTER_INVALID_STATE);
    now=w->now;
    for(unsigned mode=0;mode<6;++mode) {
        if(a->handle) CHECK(matter_rx_close(a->rx,a->handle)==MATTER_OK);
        if(b->handle) CHECK(matter_rx_close(b->rx,b->handle)==MATTER_OK);
        a->handle=b->handle=0; a->im_client=true; a->im_received.size=0;
        CHECK(matter_rx_initiate(a->rx,a->secure_token,&a->handle)==MATTER_OK && matter_rx_get(a->rx,a->handle,&a->key)==MATTER_OK);
        uint32_t cmd=mode<2?2:mode==2?0:4;
        wf_tick(w,++now); oc_network_request(g->f,o,cmd,mode+1,mode==5);
        Matter_Im_Invoke_Config_T c={{b->secure_token,a->key.exchange_id,false},10000,1024,true};
        b->invoke=matter_im_invoke_new_async(&g->invoke,&w->async,&c,now); CHECK(b->invoke);
        CHECK(im_host_send(f,a,8,g->f->request,g->f->request_size,now) && tick(a,now)); network_poll(a);
        CHECK(network_take(a) && network_receive(b) && network_admit(b,now) && tick(b,now));
        CHECK(im_ack_transfer(b,a,now+=200)); wf_tick(w,now);
        CHECK(matter_im_invoke_process(b->invoke,now)==MATTER_PENDING);
        for(unsigned step=0;step<5 && matter_im_invoke_state(b->invoke)==MATTER_IM_INVOKE_PENDING;++step) {
            wf_tick(w,++now); CHECK(matter_im_invoke_process(b->invoke,now)==MATTER_PENDING);
        }
        Matter_Im_Invoke_Message_T out; CHECK(matter_im_invoke_output(b->invoke,&out)==MATTER_OK && out.opcode==9);
        CHECK(g->f->last_privilege==MATTER_IM_ADMINISTER);
        CHECK(im_host_send(f,b,9,out.data,out.size,now) && matter_im_invoke_sent_at(b->invoke,now)==MATTER_OK && tick(b,now)); network_poll(b);
        CHECK(network_take(b) && network_receive(a));
        if(mode==3) {
            unsigned signs=o->signs,prepares=o->prepares;
            f->link->delayed_ack=a->inbox; a->inbox_full=false;
            CHECK(matter_retransmission_sender_deadline(b->tx,&now)==MATTER_OK && tick(b,now)); complete_resolver(b);
            network_poll(b); CHECK(network_take(b) && network_receive(a));
            CHECK(a->inbox.size==f->link->delayed_ack.size && !memcmp(a->inbox.data,f->link->delayed_ack.data,a->inbox.size));
            CHECK(o->signs==signs && o->prepares==prepares);
        }
        CHECK(network_admit(a,now) && tick(a,now));
        if(mode>=2 && mode<5) {
            oc_verify(o,cmd,a->im_received.data,a->im_received.size);
            if(mode==3) memcpy(o->previous,o->candidate,65);
            if(mode==4) CHECK(memcmp(o->previous,o->candidate,65));
        } else {
            CHECK(matter_tlv_init(&o->reader,a->im_received.data,a->im_received.size,8)==MATTER_TLV_OK);
            unsigned found=0;
            while(matter_tlv_next(&o->reader,&o->e)==MATTER_TLV_OK) {
                if(mode<2 && o->e.type==MATTER_TLV_BYTES) {
                    CHECK(o->e.size==(mode?sizeof(oc_pai):sizeof(oc_dac)) && !memcmp(o->e.data,mode?oc_pai:oc_dac,o->e.size)); ++found;
                }
                if(mode==5 && o->e.type==MATTER_TLV_UNSIGNED && o->e.unsigned_value==MATTER_IM_INVALID_COMMAND) ++found;
            }
            CHECK(found==1);
        }
        CHECK(im_ack_transfer(a,b,now+=200) && matter_im_invoke_state(b->invoke)==MATTER_IM_INVOKE_COMPLETE);
        CHECK(matter_im_invoke_delete(b->invoke)==MATTER_OK); b->invoke=NULL; a->im_client=false;
    }
    /* Retained encrypted TX must drain BEFORE the temporary operational key. */
    static const uint8_t status[]={0x15,0x24,0,0,0x24,255,13,0x18};
    CHECK(im_host_send(f,b,1,status,sizeof(status),++now) && tick(b,now) && b->retained);
    OcCleanup cleanup={b,o}; g->cleanup_hook=oc_retire; g->hook_user=&cleanup;
    CHECK(matter_root_expire(g->f->root)==MATTER_PENDING && matter_root_process(g->f->root,now)==MATTER_PENDING && g->marker);
    CHECK(matter_opcreds_host_candidate(o->host,o->candidate)==MATTER_OK);
    network_poll(b); CHECK(network_take(b) && tick(b,now));
    CHECK(matter_root_process(g->f->root,now)==MATTER_OK && !g->marker);
    CHECK(matter_opcreds_host_candidate(o->host,o->candidate)==MATTER_INVALID_STATE);
    CHECK(!b->tx_pins && !b->ack_pins && !b->rx_pins);
    puts("PASS Operational Credentials IPv6/PASE: DAC/PAI, attestation, CSR, Wi-Fi routing, immutable retry, secure drain before key rollback"); ok=true;
done:
    if(b->invoke) { REQUIRE(matter_im_invoke_cancel(b->invoke)==MATTER_OK && matter_im_invoke_delete(b->invoke)==MATTER_OK); b->invoke=NULL; }
    w->now=now; wf_release(w); oc_free(o); return ok;
}
#endif

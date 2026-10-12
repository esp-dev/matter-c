#ifdef MATTER_TEST_HOST_UDP
#include "test_wifi_fixture.h"
static bool wifi_network(PaseFixture* f,uint64_t now) {
    bool ok=false; Peer* a=&f->link->a; Peer* b=&f->link->b;
    WifiFixture* w=wf_new(now,b->secure_token); GcFixture* g=w->g;
    wf_command(w,2,"new","password",0,2,MATTER_WIFI_FAILSAFE_REQUIRED,true); wf_arm(w,30);
    for(unsigned mode=0;mode<7;++mode) {
        if(a->handle) CHECK(matter_rx_close(a->rx,a->handle)==MATTER_OK);
        if(b->handle) CHECK(matter_rx_close(b->rx,b->handle)==MATTER_OK);
        a->handle=b->handle=0; a->im_client=true; a->im_received.size=0;
        CHECK(matter_rx_initiate(a->rx,a->secure_token,&a->handle)==MATTER_OK && matter_rx_get(a->rx,a->handle,&a->key)==MATTER_OK);
        uint32_t cmd=mode==0 || mode==3?2:mode==1?0:mode==2 || mode==6?6:mode==4?8:4;
        const char* id=mode==6?"absent":mode>=3?"guest":"new";
        wf_tick(w,++now); wf_request(w,cmd,id,"password",0,mode+10);
        Matter_Im_Invoke_Config_T c={{b->secure_token,a->key.exchange_id,false},10000,1024,true};
        b->invoke=matter_im_invoke_new_async(&g->invoke,&w->async,&c,now); CHECK(b->invoke);
        CHECK(im_host_send(f,a,8,g->f->request,g->f->request_size,now) && tick(a,now)); network_poll(a);
        CHECK(network_take(a) && network_receive(b) && network_admit(b,now) && tick(b,now));
        CHECK(im_ack_transfer(b,a,now+=200)); wf_tick(w,now);
        CHECK(matter_im_invoke_process(b->invoke,now)==MATTER_PENDING);
        if(mode==1 || mode==2) {
            CHECK(matter_im_invoke_state(b->invoke)==MATTER_IM_INVOKE_PENDING);
            Matter_Im_Invoke_Message_T unavailable; CHECK(matter_im_invoke_output(b->invoke,&unavailable)==MATTER_INVALID_STATE);
            wf_tick(w,now+=499); CHECK(matter_im_invoke_process(b->invoke,now)==MATTER_PENDING && matter_im_invoke_state(b->invoke)==MATTER_IM_INVOKE_PENDING);
            wf_tick(w,++now); CHECK(matter_im_invoke_process(b->invoke,now)==MATTER_PENDING);
        }
        Matter_Im_Invoke_Message_T out; CHECK(matter_im_invoke_output(b->invoke,&out)==MATTER_OK && out.opcode==9);
        CHECK(im_host_send(f,b,9,out.data,out.size,now) && matter_im_invoke_sent_at(b->invoke,now)==MATTER_OK && tick(b,now)); network_poll(b);
        CHECK(network_take(b) && network_receive(a));
        if(mode==1) {
            f->link->delayed_ack=a->inbox; a->inbox_full=false;
            CHECK(matter_retransmission_sender_deadline(b->tx,&now)==MATTER_OK && tick(b,now)); complete_resolver(b);
            network_poll(b); CHECK(network_take(b) && network_receive(a));
            CHECK(a->inbox.size==f->link->delayed_ack.size && !memcmp(a->inbox.data,f->link->delayed_ack.data,a->inbox.size));
        }
        CHECK(network_admit(a,now) && tick(a,now)); wf_reply(w,a->im_received.data,a->im_received.size,cmd,mode==6?3:0,false);
        CHECK(im_ack_transfer(a,b,now+=200) && matter_im_invoke_state(b->invoke)==MATTER_IM_INVOKE_COMPLETE);
        CHECK(matter_im_invoke_delete(b->invoke)==MATTER_OK); b->invoke=NULL; a->im_client=false;
    }
    CHECK(matter_wifi_sim_starts(w->sim)==2 && matter_wifi_sim_settings(w->sim)->count==2);
    CHECK(gc_read_network(f,g,&now,0x31,5,3,NULL,24));
    CHECK(gc_read_network(f,g,&now,0x30,0,15,NULL,20));
    /* Expire while scan AND a real encrypted TX are pending. PASE drains first;
     * Wi-Fi cancellation must drain before snapshot restore/marker removal. */
    wf_tick(w,++now); wf_request(w,0,NULL,NULL,0,99);
    b->invoke=wf_start(w,1024,60000); CHECK(matter_im_invoke_state(b->invoke)==MATTER_IM_INVOKE_PENDING);
    uint64_t old_token=matter_wifi_sim_token(w->sim);
    w->control.hold=w->control.hold_cancel=true; matter_wifi_sim_control(w->sim,&w->control);
    static const uint8_t status[]={0x15,0x24,0,0,0x24,255,13,0x18};
    CHECK(im_host_send(f,b,1,status,sizeof(status),now) && tick(b,now) && b->retained);
    g->cleanup_hook=gc_retire; g->hook_user=b;
    CHECK(matter_root_expire(g->f->root)==MATTER_PENDING && matter_root_process(g->f->root,now)==MATTER_PENDING && g->marker);
    network_poll(b); CHECK(network_take(b) && tick(b,now));
    CHECK(matter_root_process(g->f->root,now)==MATTER_PENDING && g->marker);
    CHECK(matter_im_invoke_cancel(b->invoke)==MATTER_OK && matter_im_invoke_delete(b->invoke)==MATTER_OK); b->invoke=NULL;
    CHECK(matter_wifi_complete(w->wifi,old_token,&w->completion)==MATTER_INVALID_STATE);
    w->control.hold_cancel=false; matter_wifi_sim_control(w->sim,&w->control);
    CHECK(matter_root_process(g->f->root,now)==MATTER_OK && !g->marker && matter_wifi_sim_settings(w->sim)->count==1);
    CHECK(!b->tx_pins && !b->ack_pins && !b->rx_pins);
    puts("PASS Wi-Fi IPv6/PASE: configuration, delayed scan/connect, readback, byte-identical retry, PASE+radio drain before rollback"); ok=true;
done:
    if(b->invoke) { REQUIRE(matter_im_invoke_cancel(b->invoke)==MATTER_OK && matter_im_invoke_delete(b->invoke)==MATTER_OK); b->invoke=NULL; }
    if(b->im) { REQUIRE(matter_im_read_cancel(b->im)==MATTER_OK && matter_im_read_delete(b->im)==MATTER_OK); b->im=NULL; }
    w->now=now; wf_release(w); return ok;
}
#endif

#include "test_wifi_fixture.h"
static void wifi_tests(void) {
    WifiFixture* w=wf_new(0,1); GcFixture* g=w->g; Matter_Im_Value_T v;
    Matter_Im_Selector_T q={0}; Matter_Im_Path_T last,next; bool found; unsigned count=0;
    do { ROOT_CHECK(g->f->read.enumerate(g->f->root,&q,count?&last:NULL,&next,&found)==MATTER_OK); if(found) {last=next; ++count;} } while(found);
    ROOT_CHECK(count==54 && gc_scalar(g,0x31,0xfffd,NULL)==2 && gc_scalar(g,0x31,0xfffc,NULL)==1);
    Matter_Im_Attribute_T a; ROOT_CHECK(matter_wifi_describe(w->wifi,1,&a)==0 && a.privilege==MATTER_IM_ADMINISTER);
    ROOT_CHECK(matter_wifi_read(w->wifi,5,&v)==0 && v.type==MATTER_TLV_UNSIGNED && v.unsigned_value==0);
    const uint8_t accepted[]={0x16,4,0,4,2,4,4,4,6,4,8,0x18};
    ROOT_CHECK(matter_wifi_read(w->wifi,0xfff9,&v)==0 && v.size==sizeof(accepted) && !memcmp(v.data,accepted,v.size));
    wf_command(w,2,"new","password",0,2,MATTER_WIFI_FAILSAFE_REQUIRED,true);
    ROOT_CHECK(matter_wifi_sim_settings(w->sim)->count==1);
    wf_arm(w,30);
    wf_command(w,2,"invalid","tiny",0,2,1,false); /* Invalid credential length, unchanged list/crumb. */
    wf_command(w,2,"new","password",0,2,0,false);
    wf_command(w,2,"guest","password",0,3,0,false);
    wf_command(w,2,"overflow","password",0,4,2,false);
    ROOT_CHECK(gc_scalar(g,0x30,0,NULL)==3 && matter_wifi_sim_settings(w->sim)->count==3);
    wf_command(w,8,"guest",NULL,0,5,0,false);
    ROOT_CHECK(!memcmp(matter_wifi_sim_settings(w->sim)->networks[0].id.bytes,"guest",5));
    wf_command(w,8,"guest",NULL,3,6,1,false); wf_command(w,4,"absent",NULL,0,7,3,false);
    wf_command(w,2,"new","password",0,8,0,false);
    wf_command(w,0,"new",NULL,0,9,0,false);
    ROOT_CHECK(gc_scalar(g,0x30,0,NULL)==9 && matter_wifi_sim_starts(w->sim)==1);
    wf_command(w,6,"new",NULL,0,10,0,false);
    ROOT_CHECK(gc_scalar(g,0x31,5,NULL)==0 && gc_scalar(g,0x30,0,NULL)==10);
    ROOT_CHECK(matter_wifi_read(w->wifi,1,&v)==0); /* Actual binary array, no credentials. */
    const uint8_t networks[]={0x16,0x15,0x30,0,5,'g','u','e','s','t',0x28,1,0x18,
        0x15,0x30,0,3,'o','l','d',0x28,1,0x18,0x15,0x30,0,3,'n','e','w',0x29,1,0x18,0x18};
    ROOT_CHECK(v.size==sizeof(networks) && !memcmp(v.data,networks,v.size));
    uint32_t observed_version=matter_wifi_version(w->wifi);Matter_Wifi_Id_T disconnected={0},actual=wf_id("new"),unknown=wf_id("unknown");
    ROOT_CHECK(matter_wifi_observe_connection(w->wifi,&disconnected)==MATTER_OK&&matter_wifi_version(w->wifi)==observed_version+1);
    ROOT_CHECK(v.size==sizeof(networks)&&!memcmp(v.data,networks,v.size)); /* Existing provider span has not been rewritten. */
    ROOT_CHECK(matter_wifi_observe_connection(w->wifi,&disconnected)==MATTER_OK&&matter_wifi_version(w->wifi)==observed_version+1);
    ROOT_CHECK(matter_wifi_observe_connection(w->wifi,&unknown)==MATTER_INVALID_ARGUMENT&&matter_wifi_version(w->wifi)==observed_version+1);
    ROOT_CHECK(matter_wifi_observe_connection(w->wifi,&actual)==MATTER_OK&&matter_wifi_version(w->wifi)==observed_version+2);
    ROOT_CHECK(gc_scalar(g,0x31,5,NULL)==0); /* Passive observations do not rewrite the last command result. */
    wf_command(w,2,"new","bad-pass",0,11,0,false);
    wf_command(w,6,"new",NULL,0,12,7,false);
    ROOT_CHECK(gc_scalar(g,0x30,0,NULL)==11 && matter_wifi_read(w->wifi,7,&v)==0 && v.type==MATTER_TLV_SIGNED && v.signed_value==13);
    w->control.fail_configure=true; matter_wifi_sim_control(w->sim,&w->control);
    wf_command(w,4,"guest",NULL,0,13,12,false); ROOT_CHECK(matter_wifi_sim_settings(w->sim)->count==3);
    w->control.fail_configure=false; matter_wifi_sim_control(w->sim,&w->control);
    wf_command(w,4,"guest",NULL,0,14,0,false);
    /* Pending operation cannot be overwritten by a second handler or validation. */
    wf_request(w,0,NULL,NULL,0,15); Matter_Im_Invoke_T im=wf_start(w,1024,10000);
    uint64_t token=matter_wifi_sim_token(w->sim); unsigned starts=matter_wifi_sim_starts(w->sim);
    ROOT_CHECK(token && matter_im_invoke_state(im)==MATTER_IM_INVOKE_PENDING);
    w->completion.count=MATTER_WIFI_SCAN_RESULTS+1;
    ROOT_CHECK(matter_wifi_complete(w->wifi,token,&w->completion)==MATTER_INVALID_ARGUMENT);
    w->completion.count=1; w->completion.aps[0].band=5;
    ROOT_CHECK(matter_wifi_complete(w->wifi,token,&w->completion)==MATTER_INVALID_ARGUMENT);
    memset(&w->completion,0,sizeof(w->completion));
    wf_command(w,6,"old",NULL,0,16,MATTER_WIFI_BUSY,true);
    ROOT_CHECK(matter_wifi_sim_starts(w->sim)==starts);
    wf_tick(w,w->now+500); ROOT_CHECK(matter_im_invoke_process(im,w->now)==MATTER_PENDING); wf_finish(w,im,0,0,false);
    ROOT_CHECK(gc_scalar(g,0x30,0,NULL)==15);
    /* Capacity preflight must prevent scan even when async is configured. */
    wf_request(w,0,NULL,NULL,0,17); im=wf_start(w,256,1000); wf_finish(w,im,0,MATTER_IM_RESOURCE_EXHAUSTED,true);
    ROOT_CHECK(matter_wifi_sim_starts(w->sim)==starts);
    /* IM timeout detaches; backend drain blocks reuse and late token delivery. */
    w->control.hold=w->control.hold_cancel=true; matter_wifi_sim_control(w->sim,&w->control);
    wf_request(w,0,NULL,NULL,0,18); im=wf_start(w,1024,100); token=matter_wifi_sim_token(w->sim);
    wf_tick(w,w->now+100); ROOT_CHECK(matter_im_invoke_process(im,w->now)==MATTER_PORT_ERROR);
    ROOT_CHECK(matter_im_invoke_delete(im)==MATTER_OK && matter_wifi_process(w->wifi,w->now)==MATTER_PENDING);
    ROOT_CHECK(matter_wifi_delete(w->wifi)==MATTER_INVALID_STATE);
    ROOT_CHECK(matter_wifi_complete(w->wifi,token,&w->completion)==MATTER_INVALID_STATE);
    w->control.hold_cancel=false; matter_wifi_sim_control(w->sim,&w->control); wf_tick(w,w->now);
    /* Backend timeout, distinct from IM timeout, produces cluster UnknownError. */
    wf_request(w,6,"old",NULL,0,19); im=wf_start(w,1024,10000);
    uint64_t due; ROOT_CHECK(matter_wifi_deadline(w->wifi,&due)==MATTER_OK); wf_tick(w,due);
    ROOT_CHECK(matter_im_invoke_process(im,w->now)==MATTER_PENDING); wf_finish(w,im,6,12,false);
    ROOT_CHECK(gc_scalar(g,0x30,0,NULL)==15);
    /* Cancel/delete and revocation cause no callback into a freed IM handler. */
    for(unsigned mode=0;mode<2;++mode) {
        wf_request(w,0,NULL,NULL,0,20); im=wf_start(w,1024,10000);
        if(mode) { g->f->denied=MATTER_IM_UNSUPPORTED_ACCESS; ROOT_CHECK(matter_im_invoke_process(im,w->now)==MATTER_PENDING); wf_finish(w,im,0,MATTER_IM_UNSUPPORTED_ACCESS,true); g->f->denied=0; }
        else ROOT_CHECK(matter_im_invoke_delete(im)==MATTER_OK);
        wf_tick(w,w->now); ROOT_CHECK(!matter_wifi_sim_token(w->sim));
    }
    /* InterfaceEnabled Write uses existing IM schema and atomic port contract. */
    const uint8_t no[]={0x08}, yes[]={0x09}, bad[]={4,1}; Matter_Im_Path_T ep={0,0x31,4};
    ROOT_CHECK(g->f->write.validate(g->f->root,&ep,bad,sizeof(bad))==MATTER_IM_INVALID_DATA_TYPE);
    ROOT_CHECK(g->f->write.write(g->f->root,&ep,no,sizeof(no)).status==0 && !gc_scalar(g,0x31,4,NULL));
    wf_command(w,0,NULL,NULL,0,21,MATTER_WIFI_BUSY,true);
    ROOT_CHECK(g->f->write.write(g->f->root,&ep,yes,sizeof(yes)).status==0);
    /* Expiry keeps cleanup blocked on restore error, then restores old config. */
    w->control.fail_restore=true; matter_wifi_sim_control(w->sim,&w->control);
    ROOT_CHECK(matter_root_expire(g->f->root)==MATTER_PENDING);
    ROOT_CHECK(matter_root_process(g->f->root,w->now)==MATTER_PORT_ERROR && g->marker);
    w->control.fail_restore=false; matter_wifi_sim_control(w->sim,&w->control);
    ROOT_CHECK(matter_root_process(g->f->root,w->now)==MATTER_OK && !g->marker);
    ROOT_CHECK(matter_wifi_sim_settings(w->sim)->count==1 && !memcmp(matter_wifi_sim_settings(w->sim)->networks[0].id.bytes,"old",3));
    ROOT_CHECK(matter_wifi_read(w->wifi,6,&v)==0 && v.type==MATTER_TLV_BYTES && v.size==3 && !memcmp(v.data,"old",3));
    ROOT_CHECK(matter_wifi_read(w->wifi,5,&v)==0 && v.type==MATTER_TLV_UNSIGNED && !v.unsigned_value);
    ROOT_CHECK(matter_wifi_read(w->wifi,7,&v)==0 && v.type==MATTER_TLV_NULL);
    wf_release(w);
    /* Malformed/truncated input, nullable scan SSID and binary SSID support. */
    w=wf_new(0,1); const uint8_t request[]={0x15,0x30,0,3,0,0xff,1,0x30,1,0,0x18};
    for(size_t n=0;n<sizeof(request);++n) ROOT_CHECK(matter_wifi_validate(w->wifi,2,request,n)!=0);
    ROOT_CHECK(matter_wifi_validate(w->wifi,2,request,sizeof(request))==0);
    const uint8_t nullable[]={0x15,0x34,0,0x18}; ROOT_CHECK(matter_wifi_validate(w->wifi,0,nullable,sizeof(nullable))==0);
    const uint8_t missing[]={0x15,0x18}; ROOT_CHECK(matter_wifi_validate(w->wifi,2,missing,sizeof(missing))==MATTER_IM_INVALID_COMMAND);
    wf_release(w);
#ifdef MATTER_TEST_ALLOC
    ROOT_CHECK(!live); w=wf_new(0,1); Matter_Wifi_Port_T p=matter_wifi_sim_port(w->sim); Matter_Wifi_Config_T c={1,1,1,1,1,200};
    for(unsigned i=1;i<=2;++i) { size_t before=live; fail_at=calls+i; ROOT_CHECK(!matter_wifi_new(&c,&p,0) && live==before); fail_at=0; } wf_release(w); ROOT_CHECK(!live);
#endif
    puts("PASS Wi-Fi: 54 Root attributes, async scan/connect, priority/configuration, credentials, errors, capacity, timeout/drain, revocation and fail-safe rollback");
}

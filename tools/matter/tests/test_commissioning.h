#include "test_commissioning_fixture.h"
#include "clusters/matter_root_internal.h"
static void gc_command(GcFixture* g,uint64_t now,uint32_t command,uint64_t value,const char* country,uint64_t breadcrumb,uint8_t code,bool status) {
    gc_request(g,command,value,country,breadcrumb);
    Matter_Result_T r=matter_root_process(g->f->root,now); ROOT_CHECK(r==MATTER_OK || r==MATTER_PENDING);
    Matter_Im_Invoke_Config_T c={{g->f->session,0x4321,false},1000,256,true};
    Matter_Im_Invoke_T im=matter_im_invoke_new(&g->invoke,&c,now); ROOT_CHECK(im);
    Matter_Rx_Decision_T d={.action=MATTER_RX_NEW_RESPONDER,.session=g->f->session,
        .header={.protocol_id=1,.opcode=8,.exchange_id=0x4321,.exchange_flags=5},.payload=g->f->request,.payload_size=g->f->request_size};
    ROOT_CHECK(matter_im_invoke_receive_at(im,&d,now)==MATTER_OK && matter_im_invoke_process(im,now)==MATTER_PENDING);
    Matter_Im_Invoke_Message_T out; ROOT_CHECK(matter_im_invoke_output(im,&out)==MATTER_OK && out.opcode==9);
    gc_reply(out.data,out.size,command,code,status);
    ROOT_CHECK(matter_im_invoke_sent_at(im,now)==MATTER_OK && matter_im_invoke_confirm(im,now)==MATTER_OK && matter_im_invoke_delete(im)==MATTER_OK);
}
static void commissioning_tests(void) {
    for(unsigned mode=0;mode<5;++mode) {
        GcFixture* bad=gc_fixture(); Matter_Root_Port_T rp=root_port(bad->f);
        Matter_Root_Commissioning_Port_T cp={bad,gc_begin,gc_cleanup,gc_regulatory,NULL};
        if(mode==0) cp.begin=NULL;
        if(mode==1) cp.cleanup=NULL;
        if(mode==2) bad->config.cumulative_seconds=1;
        if(mode==3) bad->config.regulatory_config=3;
        if(mode==4) bad->config.location_capability=0;
        ROOT_CHECK(!matter_root_new_commissioning(&rp,&bad->config,&cp,0)); gc_release(bad,0);
    }
    GcFixture* g=gc_fixture(); gc_open(g,100); uint32_t version; uint64_t deadline;
    Matter_Root_Fail_Safe_State_T state;
    ROOT_CHECK(gc_scalar(g,0x30,0,&version)==0 && version==13 && gc_scalar(g,0x30,0xfffd,NULL)==2);
    ROOT_CHECK(gc_scalar(g,0x30,0xfffc,NULL)==0 && gc_scalar(g,0x30,4,NULL)==1);
    Matter_Im_Path_T p={0,0x1d,1}; Matter_Im_Value_T v;
    ROOT_CHECK(g->f->read.read(g->f->root,&p,true,&v)==0);
    const uint8_t servers[]={0x16,4,0x1d,4,0x28,4,0x30,0x18}; ROOT_CHECK(v.size==sizeof(servers) && !memcmp(v.data,servers,v.size));
    p=(Matter_Im_Path_T){0,0x30,0xfff9}; ROOT_CHECK(g->f->read.read(g->f->root,&p,true,&v)==0);
    const uint8_t accepted[]={0x16,4,0,4,2,4,4,0x18}; ROOT_CHECK(v.size==sizeof(accepted) && !memcmp(v.data,accepted,v.size));
    Matter_Im_Selector_T q={0}; Matter_Im_Path_T last,next; bool found; unsigned count=0;
    do { ROOT_CHECK(g->f->read.enumerate(g->f->root,&q,count?&last:NULL,&next,&found)==MATTER_OK); if(found) { last=next; ++count; } } while(found);
    ROOT_CHECK(count==40);
    const uint8_t arm[]={0x15,0x24,0,1,0x24,1,1,0x18};
    const Matter_Im_Command_Path_T path={0,0x30,0};
    for(size_t n=0;n<sizeof(arm);++n) ROOT_CHECK(g->invoke.validate(g->invoke.user,&path,arm,n)==MATTER_IM_INVALID_COMMAND);
    ROOT_CHECK(g->invoke.validate(g->invoke.user,&path,arm,sizeof(arm))==0);
    memcpy(g->f->expected,arm,sizeof(arm)); g->f->expected[2]=1; /* Duplicate/missing. */
    ROOT_CHECK(g->invoke.validate(g->invoke.user,&path,g->f->expected,sizeof(arm))==MATTER_IM_INVALID_COMMAND);
    ROOT_CHECK(g->invoke.authorize(g->invoke.user,999,&path,MATTER_IM_ADMINISTER)==MATTER_IM_UNSUPPORTED_ACCESS);
    ROOT_CHECK(matter_tlv_writer_init(&g->f->writer,g->f->expected,7,4)==MATTER_TLV_OK);
    ROOT_CHECK(g->invoke.invoke(g->invoke.user,&path,arm,sizeof(arm),&g->f->writer).status==MATTER_IM_RESOURCE_EXHAUSTED && !g->begins);
    gc_command(g,100,4,0,NULL,0,MATTER_IM_UNSUPPORTED_ACCESS,true);
    g->fail_begin=true; gc_command(g,100,0,2,NULL,11,MATTER_IM_FAILURE,true); ROOT_CHECK(!g->marker);
    g->fail_begin=false; gc_command(g,100,0,2,NULL,UINT64_MAX,0,false);
    ROOT_CHECK(g->begins==2 && g->marker && gc_scalar(g,0x30,0,&version)==UINT64_MAX && version==14);
    ROOT_CHECK(matter_root_deadline(g->f->root,&deadline)==MATTER_OK && deadline==2100);
    ROOT_CHECK(matter_root_delete(g->f->root)==MATTER_INVALID_STATE);
    gc_command(g,2000,0,UINT16_MAX,NULL,12,0,false);
    ROOT_CHECK(g->begins==2 && matter_root_deadline(g->f->root,&deadline)==MATTER_OK && deadline==5100);
    gc_command(g,2000,0,65536,NULL,33,MATTER_IM_CONSTRAINT_ERROR,true);
    gc_command(g,2000,2,0,"pl",20,0,false);
    ROOT_CHECK(g->radio==0 && !memcmp(g->f->durable.settings.location,"PL",2) && gc_scalar(g,0x30,0,NULL)==20);
    ROOT_CHECK(gc_scalar(g,0x28,0,&version)==21 && version==8);
    gc_command(g,2000,2,1,"ZZ",30,1,false);
    ROOT_CHECK(!memcmp(g->f->durable.settings.location,"ZZ",2) && gc_scalar(g,0x30,0,NULL)==20 && g->radio==1);
    g->fail_regulatory=true; gc_command(g,2000,2,2,"DE",31,MATTER_IM_FAILURE,true);
    ROOT_CHECK(!memcmp(g->f->durable.settings.location,"ZZ",2) && g->radio==1); g->fail_regulatory=false;
    gc_command(g,2000,2,3,"PL",0,1,false);
    ROOT_CHECK(g->radio==1 && !memcmp(g->f->durable.settings.location,"ZZ",2) && gc_scalar(g,0x30,0,NULL)==20);
    gc_command(g,2000,2,256,"PL",0,MATTER_IM_CONSTRAINT_ERROR,true);
    gc_command(g,2000,2,0,"P",0,MATTER_IM_CONSTRAINT_ERROR,true);
    gc_command(g,2000,2,0,"1X",0,MATTER_IM_CONSTRAINT_ERROR,true);
    g->f->session=2; ROOT_CHECK(matter_root_invoke_port(g->f->root,2,&g->binding,&g->invoke)==MATTER_OK);
    gc_command(g,4000,0,10,NULL,40,0,false);
    ROOT_CHECK(matter_root_deadline(g->f->root,&deadline)==MATTER_OK && deadline==5100);
    g->network=99; g->pending_cleanup=true;
    ROOT_CHECK(matter_root_process(g->f->root,5099)==MATTER_PENDING && !g->cleanups);
    ROOT_CHECK(matter_root_process(g->f->root,5100)==MATTER_PENDING && g->cleanups==1 && g->revoked && g->marker);
    ROOT_CHECK(matter_root_fail_safe_state(g->f->root,&state)==MATTER_OK && state==MATTER_ROOT_FAIL_SAFE_CLEANUP);
    ROOT_CHECK(g->f->read.authorize(g->f->root,2,&p,MATTER_IM_VIEW)==MATTER_IM_UNSUPPORTED_ACCESS);
    g->pending_cleanup=false; g->fail_cleanup=true;
    ROOT_CHECK(matter_root_process(g->f->root,5101)==MATTER_PORT_ERROR && matter_root_delete(g->f->root)==MATTER_INVALID_STATE);
    g->fail_cleanup=false; ROOT_CHECK(matter_root_process(g->f->root,5102)==MATTER_OK && !g->marker && g->network==3);
    ROOT_CHECK(gc_scalar(g,0x30,0,NULL)==0 && matter_root_deadline(g->f->root,&deadline)==MATTER_INVALID_STATE);
    ROOT_CHECK(matter_root_process(g->f->root,5101)==MATTER_INVALID_ARGUMENT);
    g->f->denied=0; /* New application commissioning grant, not cleanup restoring it. */
    gc_command(g,5102,0,0,NULL,55,0,false); ROOT_CHECK(g->begins==2 && gc_scalar(g,0x30,0,NULL)==55);
    gc_command(g,5102,0,1,NULL,1,0,false); gc_command(g,5102,0,0,NULL,2,0,false);
    ROOT_CHECK(matter_root_fail_safe_state(g->f->root,&state)==MATTER_OK && state==MATTER_ROOT_FAIL_SAFE_CLEANUP);
    ROOT_CHECK(matter_root_process(g->f->root,5102)==MATTER_OK && gc_scalar(g,0x30,0,NULL)==0);
    gc_release(g,5102);
    g=gc_fixture(); g->config.location_capability=g->config.regulatory_config=0; gc_open(g,0);
    gc_command(g,0,2,1,"DE",99,1,false);
    ROOT_CHECK(g->radio==0 && !memcmp(g->f->durable.settings.location,"DE",2) && gc_scalar(g,0x30,0,NULL)==0);
    ROOT_CHECK(matter_root_delete(g->f->root)==MATTER_OK); g->f->root=NULL;
    g->config.recover_pending=true; g->marker=true; g->saved_network=7; g->network=8; gc_open(g,10);
    ROOT_CHECK(matter_root_delete(g->f->root)==MATTER_INVALID_STATE && matter_root_process(g->f->root,10)==MATTER_OK && g->network==7);
    g->f->denied=0;
    gc_command(g,UINT64_MAX-500,0,1,NULL,9,0,false);
    ROOT_CHECK(matter_root_deadline(g->f->root,&deadline)==MATTER_OK && deadline==UINT64_MAX);
    ROOT_CHECK(matter_root_process(g->f->root,UINT64_MAX)==MATTER_OK); gc_release(g,UINT64_MAX);
    /* Breadcrumb is a volatile uint64 Write requiring Administer. */
    g=gc_fixture(); gc_open(g,0);
    static const uint8_t write[]={0x15,0x28,1,0x36,2,0x15,0x24,0,13,0x37,1,0x24,2,0,0x24,3,0x30,0x24,4,0,
        0x18,0x27,2,255,255,255,255,255,255,255,255,0x18,0x18,0x24,255,13,0x18};
    Matter_Im_Write_Config_T wc={{1,1,false},1000,128,true};
    Matter_Im_Write_T w=matter_im_write_new(&g->f->write,&wc,0); ROOT_CHECK(w);
    Matter_Rx_Decision_T d={.action=MATTER_RX_NEW_RESPONDER,.session=1,.header={.protocol_id=1,.opcode=6,.exchange_id=1,.exchange_flags=5},.payload=write,.payload_size=sizeof(write)};
    ROOT_CHECK(matter_im_write_receive_at(w,&d,0)==MATTER_OK && matter_im_write_process(w,0)==MATTER_PENDING);
    ROOT_CHECK(gc_scalar(g,0x30,0,&version)==UINT64_MAX && version==14 && g->f->last_privilege==MATTER_IM_ADMINISTER && !g->f->stores);
    ROOT_CHECK(matter_im_write_cancel(w)==MATTER_OK && matter_im_write_delete(w)==MATTER_OK);
    gc_release(g,0);
    /* Core 11.10.7.2: an open window reserves an idle fail-safe for PASE.
     * Use generic cluster dispatch with explicit authenticated CASE identity. */
    g=gc_fixture(); gc_open(g,0); g->window=true;
    Matter_Cluster_Request_T request={.session=1,.fabric=1,.is_case=true};
    uint8_t body[8]; Matter_Tlv_Writer_T writer; Matter_Im_Command_Result_T result; uint64_t token;
    const uint8_t args[]={0x15,0x24,0,60,0x24,1,77,0x18};
    for(unsigned i=0;i<3;++i) {
        g->fail_window=i==1; g->window=i!=2;
        ROOT_CHECK(matter_tlv_writer_init(&writer,body,sizeof(body),2)==MATTER_TLV_OK);
        ROOT_CHECK(matter_root_cluster_start(g->f->root,&path,&request,args,sizeof(args),&writer,&result,&token)==MATTER_OK);
        ROOT_CHECK(result.status==(i==1?MATTER_IM_FAILURE:0));
        if(i!=1) ROOT_CHECK(writer.size>=4 && body[3]==(i==0?4:0));
        ROOT_CHECK(g->begins==(i==2?1u:0u) && gc_scalar(g,0x30,0,NULL)==(i==2?77u:0u));
    }
    g->window=true; /* Existing owning CASE can rearm despite a later window. */
    ROOT_CHECK(matter_tlv_writer_init(&writer,body,sizeof(body),2)==MATTER_TLV_OK);
    ROOT_CHECK(matter_root_cluster_start(g->f->root,&path,&request,args,sizeof(args),&writer,&result,&token)==MATTER_OK && !result.status && body[3]==0 && g->begins==1);
    const uint8_t regulatory_args[]={0x15,0x24,0,3,0x2c,1,2,'P','L',0x24,2,99,0x18};
    const Matter_Im_Command_Path_T regulatory_path={0,0x30,2};
    ROOT_CHECK(matter_root_cluster_validate_command(g->f->root,&regulatory_path,&request,regulatory_args,sizeof(regulatory_args))==0);
    ROOT_CHECK(matter_tlv_writer_init(&writer,body,sizeof(body),2)==MATTER_TLV_OK);
    ROOT_CHECK(matter_root_cluster_start(g->f->root,&regulatory_path,&request,regulatory_args,sizeof(regulatory_args),&writer,&result,&token)==MATTER_OK && !result.status && body[3]==1);
    ROOT_CHECK(g->regulations==0 && gc_scalar(g,0x30,0,NULL)==77);
    /* CASE-only fail-safe has an owner even without AddNOC. Wrong fabric is
     * rejected; the owner reaches the complete backend (absent in this fake). */
    uint8_t owner=0;
    ROOT_CHECK(matter_root_fail_safe_fabric(g->f->root,&owner)==MATTER_OK && owner==1);
    ROOT_CHECK(matter_tlv_writer_init(&writer,body,sizeof(body),2)==MATTER_TLV_OK);
    ROOT_CHECK(matter_root_complete_start(g->f->root,1,2,true,&writer,&result,&token)==MATTER_OK && !result.status && body[3]==2);
    ROOT_CHECK(matter_tlv_writer_init(&writer,body,sizeof(body),2)==MATTER_TLV_OK);
    ROOT_CHECK(matter_root_complete_start(g->f->root,1,1,true,&writer,&result,&token)==MATTER_OK && result.status==MATTER_IM_FAILURE);
    gc_release(g,0);
#ifdef MATTER_TEST_ALLOC
    ROOT_CHECK(!live); g=gc_fixture(); Matter_Root_Port_T rp=root_port(g->f);
    Matter_Root_Commissioning_Port_T cp={g,gc_begin,gc_cleanup,gc_regulatory,NULL};
    calls=0; fail_at=1; ROOT_CHECK(!matter_root_new_commissioning(&rp,&g->config,&cp,0) && !g->f->loads && !live);
    fail_at=0; gc_open(g,0); gc_release(g,0); ROOT_CHECK(!live);
#endif
    puts("PASS commissioning: metadata, schema, fabric gate, regulatory atomicity, rearm/cumulative/zero/overflow, cleanup error/drain/recovery");
}

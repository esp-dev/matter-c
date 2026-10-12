#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "test_root_fixture.h"
#ifdef MATTER_TEST_ALLOC
static size_t live,calls,fail_at;
void* matter_test_calloc(size_t n,size_t z) { if(++calls==fail_at) return NULL; void* p=calloc(n,z); if(p) ++live; return p; }
void matter_test_free(void* p) { if(p) { ROOT_CHECK(live); --live; } free(p); }
#endif
#include "test_commissioning.h"
#include "test_wifi.h"
#include "test_power_topology.h"
#include "test_epm.h"
#include "test_eem.h"
#include "test_boot_events.h"
static void write_im(RootFixture* f,uint32_t attr,const uint8_t* text,size_t size,uint32_t version,uint8_t expected) {
    root_write_request(f,attr,text,size,version);
    Matter_Im_Write_Config_T c={{f->session,0x1234,false},1000,256,true};
    Matter_Im_Write_T w=matter_im_write_new(&f->write,&c,0); ROOT_CHECK(w);
    Matter_Rx_Decision_T rx={.action=MATTER_RX_NEW_RESPONDER,.session=f->session,
        .header={.protocol_id=1,.opcode=6,.exchange_id=0x1234,.exchange_flags=5},.payload=f->request,.payload_size=f->request_size};
    ROOT_CHECK(matter_im_write_receive_at(w,&rx,0)==MATTER_OK && matter_im_write_process(w,0)==MATTER_PENDING);
    Matter_Im_Write_Message_T out; ROOT_CHECK(matter_im_write_output(w,&out)==MATTER_OK);
    const uint8_t reply[]={0x15,0x36,0,0x15,0x37,0,0x24,2,0,0x24,3,0x28,0x24,4,(uint8_t)attr,
        0x18,0x35,1,0x24,0,expected,0x18,0x18,0x18,0x24,0xff,13,0x18};
    ROOT_CHECK(out.opcode==7 && out.size==sizeof(reply) && !memcmp(out.data,reply,sizeof(reply)));
    ROOT_CHECK(matter_im_write_sent_at(w,1)==MATTER_OK && matter_im_write_confirm(w,2)==MATTER_OK && matter_im_write_delete(w)==MATTER_OK);
}
static void read_im(RootFixture* f,bool filter,unsigned expected,uint32_t basic_version) {
    root_read_request(f,filter); f->seen=0; f->received=0;
    Matter_Im_Read_Config_T c={{f->session,0x4321,false},1000,256,true};
    Matter_Im_Read_T r=matter_im_read_new(&f->read,&c,0); ROOT_CHECK(r);
    Matter_Rx_Decision_T rx={.action=MATTER_RX_NEW_RESPONDER,.session=f->session,
        .header={.protocol_id=1,.opcode=2,.exchange_id=0x4321,.exchange_flags=5},.payload=f->request,.payload_size=f->request_size};
    ROOT_CHECK(matter_im_read_receive(r,&rx)==MATTER_OK);
    for(unsigned work=0;work<50;++work) {
        Matter_Result_T result=matter_im_read_process(r,work); ROOT_CHECK(result==MATTER_PENDING);
        Matter_Im_Read_Message_T out;
        if(matter_im_read_output(r,&out)!=MATTER_OK) continue;
        ROOT_CHECK(out.opcode==5); bool more=root_report(f,out.data,out.size,basic_version);
        ROOT_CHECK(matter_im_read_sent(r)==MATTER_OK && matter_im_read_confirm(r,work)==MATTER_OK);
        if(!more) break;
        static const uint8_t success[]={0x15,0x24,0,0,0x24,255,13,0x18};
        rx.header.opcode=1; rx.payload=success; rx.payload_size=sizeof(success);
        ROOT_CHECK(matter_im_read_receive(r,&rx)==MATTER_OK);
    }
    ROOT_CHECK(matter_im_read_state(r)==MATTER_IM_READ_COMPLETE && f->received==expected);
    if(expected==30) ROOT_CHECK(f->seen==((UINT64_C(1)<<30)-1));
    ROOT_CHECK(matter_im_read_delete(r)==MATTER_OK);
}
static void utility_types(void) {
    RootFixture* f=root_fixture(); root_open(f);
    ROOT_CHECK(matter_root_add_device_type(NULL,0x12,1)==MATTER_INVALID_ARGUMENT);
    ROOT_CHECK(matter_root_add_device_type(f->root,0x16,4)==MATTER_INVALID_ARGUMENT);
    ROOT_CHECK(matter_root_add_device_type(f->root,0x12,0)==MATTER_INVALID_ARGUMENT);
    ROOT_CHECK(matter_root_add_device_type(f->root,0x16,5)==MATTER_OK);
    for(unsigned i=0;i<4;++i) ROOT_CHECK(matter_root_add_device_type(f->root,0x12+i,1)==MATTER_OK);
    ROOT_CHECK(matter_root_add_device_type(f->root,0x12,1)==MATTER_OK);
    ROOT_CHECK(matter_root_add_device_type(f->root,0x12,2)==MATTER_INVALID_ARGUMENT);
    ROOT_CHECK(matter_root_add_device_type(f->root,0x17,1)==MATTER_LIMIT_REACHED);
    Matter_Im_Path_T path={0,0x1d,0}; Matter_Im_Value_T v;
    ROOT_CHECK(!f->read.read(f->root,&path,true,&v));
    Matter_Tlv_Reader_T r; Matter_Tlv_Element_T e; unsigned count=0;
    ROOT_CHECK(matter_tlv_init(&r,v.data,v.size,3)==MATTER_TLV_OK);
    while(matter_tlv_next(&r,&e)==MATTER_TLV_OK) if(e.type==MATTER_TLV_UNSIGNED && e.tag.control==1 && !e.tag.number) {
        ROOT_CHECK(e.unsigned_value==(count?0x11+count:0x16)); ++count;
    }
    ROOT_CHECK(count==5); root_release(f); puts("PASS Root utility device types: preserve Root, bounded list, revisions, idempotence");
}
int main(void) {
    utility_types();
    power_tests();
    epm_tests();
    eem_tests();
    /* Constructor validation before publication, failed loads never expose ports. */
    for(unsigned mode=0;mode<17;++mode) {
        RootFixture* f=root_fixture(); Matter_Root_Port_T port=root_port(f);
        switch(mode) {
        case 0: port.load=NULL; break; case 1: port.authorize=NULL; break; case 2: port.store=NULL; break;
        case 3: f->fail_load=true; break; case 4: f->durable.vendor_name.size=33; break;
        case 5: f->durable.hardware_string.size=0; break; case 6: f->durable.software_string.size=65; break;
        case 7: f->durable.unique_id.data[0]=0xc0; break; case 8: f->durable.unique_id.size=33; break;
        case 9: f->durable.settings.node_label_size=33; break; case 10: f->durable.settings.location[1]='1'; break;
        case 11: f->durable.configuration_version=0; break; case 12: f->durable.vendor_id=0; break;
        case 13: f->durable.product_id=0; break; case 14: f->durable.capabilities.case_sessions=2; break;
        case 15: f->durable.capabilities.read_paths=8; break; case 16: f->durable.capabilities.subscribe_paths=10001; break;
        }
        ROOT_CHECK(!matter_root_new(&port)); root_release(f);
    }
    RootFixture* f=root_fixture(); RootFixture* other=root_fixture(); root_open(f); root_open(other);
    Matter_Cluster_T descriptor=matter_root_cluster(f->root,0x1d),basic=matter_root_cluster(f->root,0x28);
    ROOT_CHECK(descriptor && basic && matter_cluster_attribute_count(descriptor)==9 && matter_cluster_attribute_count(basic)==21);
    ROOT_CHECK(matter_cluster_delete(basic)==MATTER_BUSY && matter_cluster_retain(descriptor)==MATTER_OK);
    ROOT_CHECK(matter_root_delete(f->root)==MATTER_BUSY && matter_cluster_release(descriptor)==MATTER_OK);
    ROOT_CHECK(f->loads==1 && matter_root_ports(NULL,&f->read,&f->write)==MATTER_INVALID_ARGUMENT);
    ROOT_CHECK(matter_root_ports(f->root,NULL,&f->write)==MATTER_INVALID_ARGUMENT);
    Matter_Im_Path_T path={0,0x28,5}; Matter_Im_Attribute_T attr; Matter_Im_Write_Attribute_T writable;
    for(unsigned mode=0;mode<3;++mode) {
        path=(Matter_Im_Path_T){mode==0?1:0,mode==1?0x29:0x28,mode==2?0xfffa:5};
        uint8_t expected=mode==0?0x7f:mode==1?0xc3:0x86;
        ROOT_CHECK(f->read.describe(f->root,&path,&attr)==expected && f->write.describe(f->root,&path,&writable)==expected);
    }
    read_im(f,false,30,7); read_im(f,true,0,7);
    path=(Matter_Im_Path_T){0,0x28,2}; ROOT_CHECK(f->write.describe(f->root,&path,&writable)==MATTER_IM_UNSUPPORTED_WRITE);
    path.attribute=5; ROOT_CHECK(f->write.describe(f->root,&path,&writable)==0 && writable.privilege==MATTER_IM_MANAGE);
    path.attribute=6; ROOT_CHECK(f->write.describe(f->root,&path,&writable)==0 && writable.privilege==MATTER_IM_ADMINISTER);
    f->reenter=true;
    const uint8_t label[]={'G','o',' ',0xc5,0xbc,0,'x'};
    write_im(f,5,label,sizeof(label),7,0); ROOT_CHECK(f->stores==1 && f->last_privilege==MATTER_IM_MANAGE);
    read_im(f,false,30,8); read_im(f,true,21,8); read_im(other,false,30,7);
    write_im(f,5,label,sizeof(label),8,0); ROOT_CHECK(f->stores==1); /* No-op. */
    write_im(f,5,(const uint8_t*)"new",3,7,MATTER_IM_DATA_VERSION_MISMATCH); ROOT_CHECK(f->stores==1);
    f->fail_store=true; write_im(f,5,(const uint8_t*)"new",3,8,MATTER_IM_FAILURE); ROOT_CHECK(f->stores==2);
    f->fail_store=false; read_im(f,false,30,8);
    f->denied=MATTER_IM_UNSUPPORTED_ACCESS; write_im(f,5,label,sizeof(label),8,MATTER_IM_UNSUPPORTED_ACCESS); ROOT_CHECK(f->stores==2); f->denied=0;
    write_im(f,6,(const uint8_t*)"pl",2,8,0); ROOT_CHECK(f->last_privilege==MATTER_IM_ADMINISTER && !memcmp(f->durable.settings.location,"PL",2));
    write_im(f,6,(const uint8_t*)"PL",2,9,0); ROOT_CHECK(f->stores==3);
    write_im(f,6,(const uint8_t*)"!X",2,9,MATTER_IM_CONSTRAINT_ERROR);
    write_im(f,6,(const uint8_t*)"P",1,9,MATTER_IM_CONSTRAINT_ERROR);
    memset(f->expected,'a',33); write_im(f,5,f->expected,33,9,MATTER_IM_CONSTRAINT_ERROR);
    write_im(f,5,f->expected,32,9,0); write_im(f,5,NULL,0,10,0); read_im(f,false,30,11);
    path=(Matter_Im_Path_T){0,0x28,5};
    const uint8_t wrong[]={4,1}, bad_utf8[]={0x0c,1,0xc0}, trailing[]={0x0c,0,4,1};
    ROOT_CHECK(f->write.validate(f->root,&path,wrong,sizeof(wrong))==MATTER_IM_INVALID_DATA_TYPE);
    ROOT_CHECK(f->write.validate(f->root,&path,bad_utf8,sizeof(bad_utf8))==MATTER_IM_INVALID_DATA_TYPE);
    ROOT_CHECK(f->write.validate(f->root,&path,trailing,sizeof(trailing))==MATTER_IM_INVALID_DATA_TYPE);
    /* Application-simulated restart/reset and random DataVersion seeds. */
    ROOT_CHECK(matter_root_delete(f->root)==MATTER_OK); f->root=NULL; f->durable.basic_version=UINT32_MAX;
    root_open(f); read_im(f,false,30,UINT32_MAX);
    write_im(f,5,(const uint8_t*)"reset",5,UINT32_MAX,0); read_im(f,false,30,0);
    ROOT_CHECK(matter_root_delete(f->root)==MATTER_OK); f->root=NULL;
    root_text(&f->durable.unique_id,"simulated-reset-identity-2"); f->durable.basic_version=101;
    root_open(f); read_im(f,false,30,101);
    root_release(other); root_release(f);
#ifdef MATTER_TEST_ALLOC
    ROOT_CHECK(!live); f=root_fixture(); Matter_Root_Port_T port=root_port(f);
    calls=0; fail_at=1; ROOT_CHECK(!matter_root_new(&port) && !f->loads && !live); fail_at=0;
    for(unsigned i=2;i<=3;++i) { fail_at=calls+i; ROOT_CHECK(!matter_root_new(&port) && !live); fail_at=0; }
    root_open(f); read_im(f,false,30,7); root_release(f); ROOT_CHECK(!live);
    puts("PASS root OOM: allocation failure, cleanup and recovery");
#endif
#ifdef MATTER_TEST_ALLOC
    GcFixture* g=gc_fixture(); Matter_Root_Port_T rp=root_port(g->f);
    Matter_Root_Commissioning_Port_T cp={g,gc_begin,gc_cleanup,gc_regulatory,NULL};
    for(unsigned i=1;i<=4;++i) { fail_at=calls+i; ROOT_CHECK(!matter_root_new_commissioning(&rp,&g->config,&cp,0) && !live); fail_at=0; }
    gc_release(g,0);
#endif
    commissioning_tests();
    boot_events();
    wifi_tests();
    puts("PASS root: 30 attributes, wildcard/chunks/filters, metadata, persistence, permissions, errors, two instances and reset/version wrap");
    return 0;
}

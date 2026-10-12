#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "model/matter_im_write.h"
#define CHECK(c) do { if (!(c)) { fprintf(stderr,"Write test:%d: %s\n",__LINE__,#c); abort(); } } while (0)
#ifdef MATTER_TEST_ALLOC
static size_t live,calls,fail_at;
void* matter_test_calloc(size_t n,size_t z) { if(++calls==fail_at) return NULL; void* p=calloc(n,z); if(p) ++live; return p; }
void matter_test_free(void* p) { if(p) { CHECK(live); --live; } free(p); }
#endif
#include "test_write_model.h"
static WriteModel* create(size_t capacity) {
    WriteModel* m=calloc(1,sizeof(*m)); CHECK(m);
    Matter_Im_Write_Port_T p=write_port(m); Matter_Im_Write_Config_T c={{1,0x1234,false},1000,capacity,true};
    m->active=matter_im_write_new(&p,&c,0); CHECK(m->active); return m;
}
static void release(WriteModel* m) { CHECK(matter_im_write_delete(m->active)==MATTER_OK); free(m); }
static Matter_Rx_Decision_T decision(const uint8_t* data,size_t size) {
    return (Matter_Rx_Decision_T){.action=MATTER_RX_NEW_RESPONDER,.session=1,
        .header={.protocol_id=1,.opcode=6,.exchange_id=0x1234,.exchange_flags=5},.payload=data,.payload_size=size};
}
static Matter_Im_Write_Message_T start(WriteModel* m,const uint8_t* data,size_t size) {
    Matter_Rx_Decision_T d=decision(data,size); CHECK(matter_im_write_receive_at(m->active,&d,0)==MATTER_OK);
    CHECK(matter_im_write_receive_at(m->active,&d,0)==MATTER_WOULD_BLOCK && !m->auths);
    CHECK(matter_im_write_process(m->active,0)==MATTER_PENDING);
    Matter_Im_Write_Message_T out; CHECK(matter_im_write_output(m->active,&out)==MATTER_OK); return out;
}
static void expect(Matter_Im_Write_Message_T out,uint8_t code,bool root) {
    if(root) { const uint8_t expected[]={0x15,0x24,0,code,0x24,0xff,13,0x18};
        if(out.opcode!=1 || out.size!=8 || memcmp(out.data,expected,8)) fprintf(stderr,"Expected StatusResponse %u, got opcode=%u size=%zu\n",code,out.opcode,out.size);
        CHECK(out.opcode==1 && out.size==8 && !memcmp(out.data,expected,8)); }
    else { CHECK(out.opcode==7 && out.size==sizeof(write_response));
        for(size_t i=0;i<out.size;++i) CHECK(out.data[i]==(i==20 ? code : write_response[i])); }
}
#include "test_write_lists.h"
#include "test_write_readonly.h"
int main(void) {
    readonly_lists();
    WriteModel* m=create(1024); memcpy(m->input,write_request,sizeof(write_request));
    Matter_Rx_Decision_T d=decision(m->input,sizeof(write_request));
    CHECK(matter_im_write_receive_at(m->active,&d,0)==MATTER_OK); memset(m->input,0,sizeof(m->input));
    CHECK(matter_im_write_process(m->active,0)==MATTER_PENDING);
    Matter_Im_Write_Message_T out; CHECK(matter_im_write_output(m->active,&out)==MATTER_OK); expect(out,0,false);
    CHECK(m->writes==1 && m->version==8 && m->stored_size==2 && m->stored[0]==4 && m->stored[1]==42);
    CHECK(matter_im_write_process(m->active,1)==MATTER_PENDING && m->writes==1);
    CHECK(matter_im_write_receive_at(m->active,&d,1)==MATTER_INVALID_STATE);
    CHECK(matter_im_write_confirm(m->active,1)==MATTER_INVALID_STATE);
    CHECK(!matter_im_write_awaiting_delivery(m->active) && !matter_im_write_awaiting_delivery(NULL));
    CHECK(matter_im_write_sent_at(m->active,2)==MATTER_OK && matter_im_write_awaiting_delivery(m->active));
    CHECK(matter_im_write_confirm(m->active,3)==MATTER_OK && !matter_im_write_awaiting_delivery(m->active));
    CHECK(matter_im_write_state(m->active)==MATTER_IM_WRITE_COMPLETE); release(m);
    for(unsigned mode=0;mode<15;++mode) {
        m=create(mode==12 ? 8 : 1024); uint8_t code=MATTER_IM_FAILURE;
        if(mode<2) { m->deny=code=mode ? MATTER_IM_ACCESS_RESTRICTED : MATTER_IM_UNSUPPORTED_ACCESS; m->second_deny=mode!=0; }
        if(mode==2) m->describe_error=code=MATTER_IM_UNSUPPORTED_ATTRIBUTE;
        if(mode==3) m->describe_error=code=MATTER_IM_UNSUPPORTED_WRITE;
        if(mode==4) { m->metadata.timed=true; code=MATTER_IM_NEEDS_TIMED_INTERACTION; }
        if(mode==5) { m->metadata.fabric_scoped=true; code=MATTER_IM_UNSUPPORTED_ACCESS; }
        if(mode==6) { m->metadata.list=true; code=MATTER_IM_UNSUPPORTED_WRITE; }
        if(mode==7) { m->version=8; code=MATTER_IM_DATA_VERSION_MISMATCH; }
        if(mode==8) m->version_error=true;
        if(mode==9) m->validation_error=code=MATTER_IM_CONSTRAINT_ERROR;
        if(mode==10) m->metadata.privilege=MATTER_IM_VIEW;
        if(mode==11) m->validation_error=0xfe;
        if(mode==12) code=MATTER_IM_RESOURCE_EXHAUSTED;
        if(mode==13) m->describe_error=0xfe;
        if(mode==14) m->deny=0xfe;
        expect(start(m,write_request,sizeof(write_request)),code,mode==12);
        CHECK(!m->writes && !m->stored_size); release(m);
    }
    for(size_t n=0;n<sizeof(write_request);++n) {
        m=create(1024); expect(start(m,write_request,n),MATTER_IM_INVALID_ACTION,true); CHECK(!m->auths); release(m);
    }
    for(unsigned mode=0;mode<14;++mode) {
        m=create(1024); memcpy(m->input,write_request,sizeof(write_request)); size_t n=sizeof(write_request);
        uint8_t code=MATTER_IM_INVALID_ACTION; bool root=true;
        if(mode==0) { m->input[1]=0x29; code=MATTER_IM_TIMED_REQUEST_MISMATCH; }
        if(mode==1) m->input[18]=3; /* Duplicate path field. */
        if(mode==2) m->input[12]=8; /* Missing endpoint. */
        if(mode==3) { m->input[23]=101; code=MATTER_IM_CONSTRAINT_ERROR; root=false; }
        if(mode==4) { m->input[21]=0x20; code=MATTER_IM_INVALID_DATA_TYPE; root=false; }
        if(mode==5) { memmove(m->input+5,m->input+25,n-25); n-=20; } /* Empty. */
        if(mode==6) { memmove(m->input+45,m->input+25,n-25); memcpy(m->input+25,write_request+5,20); n+=20; }
        if(mode==7) { memmove(m->input+27,m->input+25,n-25); m->input[25]=0x29; m->input[26]=3; n+=2; } /* Wrong level field => malformed. */
        if(mode==8) { memmove(m->input+28,m->input+26,n-26); m->input[26]=0x29; m->input[27]=3; n+=2; } /* Chunked. */
        if(mode==9) m->input[12]=5; /* ListIndex replaces endpoint. */
        if(mode==10) { memmove(m->input+26,m->input+24,n-24); m->input[24]=0x29; m->input[25]=2; n+=2; } /* Duplicate data. */
        if(mode==11) m->input[7]=3; /* Optional version absent (unknown tag). */
        if(mode==12) { memmove(m->input+6,m->input+9,n-9); n-=3; } /* Version omitted. */
        if(mode==13) { memmove(m->input+6,m->input+3,n-3); m->input[3]=0x28; m->input[4]=3; m->input[5]=0x18; n+=3; } /* Broken root. */
        out=start(m,m->input,n);
        if(mode==11 || mode==12) { expect(out,0,false); CHECK(m->writes==1 && !m->versions); }
        else { expect(out,code,root); CHECK(!m->writes); if(root) CHECK(!m->auths); }
        release(m);
    }
    /* Any schema accepted by provider; normalization preserves value payload. */
    static const uint8_t values[][12]={{0x2c,2,2,'o','k'}, {0x30,2,2,0,0xff}, {0x34,2}, {0x35,2,0x24,0,9,0x18}, {0x36,2,0x18}};
    const size_t sizes[]={5,5,2,6,3};
    for(unsigned i=0;i<5;++i) {
        m=create(1024); m->any_type=true; memcpy(m->input,write_request,21); memcpy(m->input+21,values[i],sizes[i]);
        memcpy(m->input+21+sizes[i],write_request+24,sizeof(write_request)-24);
        out=start(m,m->input,sizeof(write_request)-3+sizes[i]); expect(out,i==4 ? MATTER_IM_INVALID_DATA_TYPE : 0,false);
        CHECK(m->writes==(i==4 ? 0u : 1u));
        if(i!=4) CHECK(m->stored_size==sizes[i]-1 && m->stored[0]==(values[i][0]&31) && !memcmp(m->stored+1,values[i]+2,sizes[i]-2));
        release(m);
    }
    for(unsigned mode=0;mode<3;++mode) {
        m=create(8); memcpy(m->input,write_request,1); m->input[1]=0x29; m->input[2]=0;
        memcpy(m->input+3,write_request+1,sizeof(write_request)-1);
        if(mode==1) m->deny=MATTER_IM_UNSUPPORTED_ACCESS;
        if(mode==2) m->result.status=MATTER_IM_FAILURE;
        d=decision(m->input,sizeof(write_request)+2); CHECK(matter_im_write_receive_at(m->active,&d,0)==MATTER_OK);
        CHECK(matter_im_write_process(m->active,0)==MATTER_OK && matter_im_write_state(m->active)==MATTER_IM_WRITE_COMPLETE);
        CHECK(m->writes==(mode==1 ? 0u : 1u) && matter_im_write_output(m->active,&out)==MATTER_INVALID_STATE); release(m);
    }
    m=create(1024); m->result=(Matter_Im_Write_Result_T){1,true,99}; out=start(m,write_request,sizeof(write_request));
    CHECK(out.opcode==7 && out.size==31 && out.data[20]==1 && out.data[22]==1 && out.data[23]==99 && m->writes==1 && m->version==7); release(m);
    /* Timed window starts at actual send. Queue before ACK, evaluate original RX. */
    for(unsigned mode=0;mode<6;++mode) {
        m=create(1024); d=decision(write_timed,sizeof(write_timed)); d.header.opcode=10;
        CHECK(matter_im_write_receive_at(m->active,&d,0)==MATTER_OK && matter_im_write_process(m->active,0)==MATTER_PENDING);
        CHECK(matter_im_write_output(m->active,&out)==MATTER_OK); expect(out,0,true);
        CHECK(matter_im_write_sent_at(m->active,100)==MATTER_OK && matter_im_write_sent_at(m->active,101)==MATTER_INVALID_STATE);
        CHECK(!matter_im_write_awaiting_delivery(m->active)); /* Still owns timed continuation. */
        memcpy(m->input,write_request,sizeof(write_request)); m->input[1]=mode==2 ? 0x28 : 0x29;
        d=decision(m->input,sizeof(write_request)); if(mode==3) d.header.opcode=8; if(mode==4) d.header.opcode=10;
        CHECK(matter_im_write_receive_at(m->active,&d,mode==1 ? 200 : 199)==MATTER_OK);
        CHECK(matter_im_write_process(m->active,300)==MATTER_PENDING && !m->auths);
        CHECK(matter_im_write_confirm(m->active,300)==MATTER_OK);
        if(mode==5) { CHECK(matter_im_write_cancel(m->active)==MATTER_OK && matter_im_write_process(m->active,301)==MATTER_INVALID_STATE && !m->writes); }
        else { m->metadata.timed=true; CHECK(matter_im_write_process(m->active,301)==MATTER_PENDING && matter_im_write_output(m->active,&out)==MATTER_OK);
            expect(out,!mode ? 0 : mode==1 ? MATTER_IM_TIMEOUT : mode==2 ? MATTER_IM_TIMED_REQUEST_MISMATCH : MATTER_IM_INVALID_ACTION,mode!=0);
            CHECK(m->writes==(!mode ? 1u : 0u)); }
        release(m);
    }
    for(unsigned phase=0;phase<4;++phase) {
        m=create(1024); d=decision(write_request,sizeof(write_request)); CHECK(matter_im_write_receive_at(m->active,&d,0)==MATTER_OK);
        if(phase) CHECK(matter_im_write_process(m->active,0)==MATTER_PENDING);
        if(phase>1) CHECK(matter_im_write_sent_at(m->active,1)==MATTER_OK);
        if(phase==3) CHECK(matter_im_write_cancel(m->active)==MATTER_OK); else CHECK(matter_im_write_process(m->active,1000)==MATTER_PORT_ERROR);
        CHECK(m->writes==(phase ? 1u : 0u) && matter_im_write_confirm(m->active,1001)==MATTER_INVALID_STATE); release(m);
    }
    m=create(1024); d=decision(write_request,sizeof(write_request)); ++d.session;
    CHECK(matter_im_write_receive_at(m->active,&d,0)==MATTER_INVALID_ARGUMENT); --d.session; ++d.header.exchange_id;
    CHECK(matter_im_write_receive_at(m->active,&d,0)==MATTER_INVALID_ARGUMENT); --d.header.exchange_id; d.payload=m->input; d.payload_size=1025;
    CHECK(matter_im_write_receive_at(m->active,&d,0)==MATTER_LIMIT_REACHED); release(m);
    /* Boundary preflight includes optional ClusterStatus before committing. */
    for(size_t cap=30;cap<=31;++cap) {
        m=create(cap); out=start(m,write_request,sizeof(write_request));
        expect(out,cap==30 ? MATTER_IM_RESOURCE_EXHAUSTED : 0,false);
        CHECK(m->writes==(cap==31 ? 1u : 0u)); release(m);
    }
    /* Recheck mutable version and permissions at process, not at RX. */
    m=create(1024); d=decision(write_request,sizeof(write_request));
    CHECK(matter_im_write_receive_at(m->active,&d,10)==MATTER_OK);
    CHECK(matter_im_write_process(m->active,9)==MATTER_INVALID_ARGUMENT);
    m->version=9; CHECK(matter_im_write_process(m->active,10)==MATTER_PENDING && matter_im_write_output(m->active,&out)==MATTER_OK);
    expect(out,MATTER_IM_DATA_VERSION_MISMATCH,false); CHECK(!m->writes && !m->validations); release(m);
    /* Separate live instances never share input, effects or lifecycle. */
    m=create(1024); WriteModel* other=create(1024);
    expect(start(m,write_request,sizeof(write_request)),0,false);
    other->deny=MATTER_IM_UNSUPPORTED_ACCESS;
    expect(start(other,write_request,sizeof(write_request)),MATTER_IM_UNSUPPORTED_ACCESS,false);
    CHECK(m->writes==1 && m->version==8 && !other->writes && other->version==7); release(other); release(m);
    /* Missing continuation revision cannot inherit it from TimedRequest. Zero
     * timeout has no valid RX instant; maximum timeout and saturation are valid. */
    for(unsigned mode=0;mode<4;++mode) {
        m=create(1024); memcpy(m->input,write_timed,sizeof(write_timed));
        if(!mode) m->input[3]=0;
        if(mode>=2) { m->input[3]=0xff; m->input[4]=0xff; }
        uint64_t base=mode==3 ? UINT64_MAX-500 : 0;
        if(base) {
            CHECK(matter_im_write_delete(m->active)==MATTER_OK);
            Matter_Im_Write_Port_T p=write_port(m); Matter_Im_Write_Config_T c={{1,0x1234,false},1000,1024,true};
            m->active=matter_im_write_new(&p,&c,base); CHECK(m->active);
        }
        d=decision(m->input,sizeof(write_timed)); d.header.opcode=10;
        CHECK(matter_im_write_receive_at(m->active,&d,base)==MATTER_OK && matter_im_write_process(m->active,base)==MATTER_PENDING);
        CHECK(matter_im_write_sent_at(m->active,base+100)==MATTER_OK && matter_im_write_confirm(m->active,base+100)==MATTER_OK);
        memcpy(m->input,write_request,sizeof(write_request)); m->input[1]=0x29;
        size_t n=sizeof(write_request); if(mode==1) { m->input[n-4]=0x18; n-=3; }
        d=decision(m->input,n);
        CHECK(matter_im_write_receive_at(m->active,&d,base+100)==MATTER_OK);
        CHECK(matter_im_write_process(m->active,base+101)==MATTER_PENDING && matter_im_write_output(m->active,&out)==MATTER_OK);
        expect(out,mode==0 ? MATTER_IM_TIMEOUT : mode==1 ? MATTER_IM_INVALID_ACTION : 0,mode<2);
        CHECK(m->writes==(mode>=2 ? 1u : 0u)); release(m);
    }
    m=create(1024); Matter_Im_Write_Port_T invalid_port=write_port(m);
    Matter_Im_Write_Config_T invalid_config={{1,1,false},1,1024,true};
    invalid_port.version=NULL; CHECK(!matter_im_write_new(&invalid_port,&invalid_config,0));
    invalid_port=write_port(m); invalid_config.pase_commissionee=false;
    CHECK(!matter_im_write_new(&invalid_port,&invalid_config,0));
    invalid_config.pase_commissionee=true; invalid_config.output_capacity=7;
    CHECK(!matter_im_write_new(&invalid_port,&invalid_config,0)); release(m);
    test_write_lists();
#ifdef MATTER_TEST_ALLOC
    m=create(1024); Matter_Im_Write_Port_T p=write_port(m); Matter_Im_Write_Config_T c={{1,1,false},1,1024,true};
    fail_at=calls+1; CHECK(!matter_im_write_new(&p,&c,0)); fail_at=0; release(m); CHECK(!live);
#endif
    puts("PASS Write: literal response, access/schema/version/preflight, normalized values, bounds/OOM, timed RX, suppress and terminal lifecycle");
    return 0;
}

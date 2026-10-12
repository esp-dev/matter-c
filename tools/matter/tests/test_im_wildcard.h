#include "test_im_model.h"
static ImTestModel* wild_new(size_t capacity,bool fast) {
    ImTestModel* m=calloc(1,sizeof(*m)); CHECK(m); m->size=24;
    Matter_Im_Read_Port_T p=model_port(m,fast);
    Matter_Im_Read_Config_T c={{1,0x1234,false},10000,capacity,true};
    m->active=matter_im_read_new(&p,&c,0); CHECK(m->active); return m;
}
static void wild_delete(ImTestModel* m) { CHECK(matter_im_read_delete(m->active)==MATTER_OK); free(m); }
static void wild_receive(ImTestModel* m,size_t n) {
    Matter_Rx_Decision_T d=decision(m->input,n); CHECK(matter_im_read_receive(m->active,&d)==MATTER_OK);
}
static void wild_start(ImTestModel* m,unsigned mask,unsigned attr,unsigned filters) {
    wild_receive(m,model_request(m,mask,(Matter_Im_Path_T){0,0x28,attr},filters)); model_process(m,0);
}
static unsigned wild_reports(ImTestModel* m,unsigned* errors,bool revoke) {
    unsigned total=0; *errors=0;
    for(unsigned i=0;i<MATTER_IM_READ_MAX_RESULTS+1;++i) {
        Matter_Im_Read_Message_T out; bool more; unsigned bad;
        CHECK(matter_im_read_output(m->active,&out)==MATTER_OK && out.opcode==5);
        total+=model_report(m,out.data,out.size,&more,&bad); *errors+=bad;
        CHECK(matter_im_read_sent(m->active)==MATTER_OK && matter_im_read_confirm(m->active,i+1)==MATTER_OK);
        if(!more) { CHECK(matter_im_read_state(m->active)==MATTER_IM_READ_COMPLETE); return total; }
        if(revoke) m->deny=true;
        const uint8_t success[]={0x15,0x24,0,0,0x24,0xff,13,0x18};
        Matter_Rx_Decision_T d=decision(success,sizeof(success)); d.header.opcode=1;
        CHECK(matter_im_read_receive(m->active,&d)==MATTER_OK); model_process(m,i+1);
    }
    CHECK(false); return 0;
}
static void test_im_wildcard(void) {
    /* Every combination of endpoint/cluster/attribute presence. */
    for(unsigned mask=0;mask<8;++mask) {
        ImTestModel* m=wild_new(128,true); wild_start(m,mask,2,0); unsigned errors;
        unsigned count=(mask&1 ? 1 : 2)*(mask&2 ? 1 : 2)*(mask&4 ? 1 : 6);
        CHECK(wild_reports(m,&errors,false)==count && !errors && m->reads==count);
        wild_delete(m);
    }
    for(unsigned mode=0;mode<9;++mode) {
        ImTestModel* m=wild_new(128,mode!=6); unsigned nf=1, want=18, reads=18;
        m->filters[0].cluster=0x28; m->filters[0].version=7;
        if(mode==0) { /* All 4 clusters unchanged -> no read and empty final report. */
            nf=4; want=reads=0;
            for(unsigned i=0;i<4;++i) { m->filters[i].endpoint=(uint16_t)(i/2); m->filters[i].cluster=0x28+i%2; m->filters[i].version=7+i; }
        }
        if(mode==1 || mode==2) { nf=2; m->filters[1]=m->filters[0]; if(mode==1) { ++m->filters[1].version; want=reads=24; } }
        if(mode==3) { m->filters[0].endpoint=99; want=reads=24; }
        if(mode==4) { m->override_version=true; m->version=UINT32_MAX; m->filters[0].version=UINT32_MAX; }
        if(mode==5) { m->changing=true; reads=24; } /* Fast version disagrees, coherent read now agrees. */
        if(mode==6) reads=24; /* Existing providers can filter by returned snapshot. */
        if(mode==7) { m->version_error=true; want=reads=18; } /* Unmatched clusters are unaffected. */
        if(mode==8) { m->deny=true; m->unreadable=true; want=reads=12; }
        wild_start(m,0,0,nf); unsigned errors;
        CHECK(wild_reports(m,&errors,false)==want && errors==(mode==7 ? 6u : 0u) && m->reads==reads);
        if(mode==3 || mode==6) CHECK(!m->versions);
        wild_delete(m);
    }
    ImTestModel* m=wild_new(128,true); m->deny=true; m->filters[0].cluster=0x28; m->filters[0].version=7;
    wild_start(m,7,3,1); unsigned errors;
    CHECK(wild_reports(m,&errors,false)==0 && errors==1 && !m->reads && !m->versions); wild_delete(m);
    m=wild_new(34,true); wild_start(m,0,0,0); CHECK(wild_reports(m,&errors,true)==20 && !errors && m->reads==24); wild_delete(m);
    m=wild_new(128,true); m->size=0; wild_start(m,0,0,0); CHECK(wild_reports(m,&errors,false)==0 && !errors); wild_delete(m);
    m=wild_new(128,true); m->size=MATTER_IM_READ_MAX_RESULTS; wild_start(m,0,0,0); CHECK(wild_reports(m,&errors,false)==MATTER_IM_READ_MAX_RESULTS && !errors && m->reads==MATTER_IM_READ_MAX_RESULTS); wild_delete(m);
    m=wild_new(128,true);
    for(unsigned i=0;i<16;++i) { m->filters[i].cluster=0x28; m->filters[i].version=7; }
    wild_start(m,0,0,16); CHECK(wild_reports(m,&errors,false)==18 && !errors && m->reads==18); wild_delete(m);
    /* Literal normative shapes: anonymous AttributePath LIST; concrete filter
     * ClusterPath LIST uses tags 1/2, not AttributePath's tags 2/3. */
    m=wild_new(128,true); m->filters[0].cluster=0x28; m->filters[0].version=7;
    size_t n=model_request(m,0,(Matter_Im_Path_T){0},1);
    const uint8_t expected[]={0x15,0x36,0,0x17,0x18,0x18,0x29,3,0x36,4,0x15,0x37,0,0x24,1,0,0x24,2,0x28,0x18,0x24,1,7,0x18,0x18,0x24,0xff,13,0x18};
    CHECK(n==sizeof(expected) && !memcmp(m->input,expected,n)); wild_delete(m);
    for(unsigned mode=0;mode<9;++mode) {
        m=wild_new(128,true); m->filters[0].cluster=0x28; m->filters[0].version=7;
        n=model_request(m,mode==4 ? 1 : 0,(Matter_Im_Path_T){0},mode==1 ? 17 : mode==0 ? 1 : 0);
        uint8_t status=1;
        if(mode==0) { m->input[17]=1; status=0x80; } /* Duplicate endpoint in filter LIST. */
        if(mode==1) status=0x89;
        if(mode==2) { m->size=MATTER_IM_READ_MAX_RESULTS+1; status=0x89; }
        if(mode==3) m->bad_enum=2;
        if(mode==4) m->bad_enum=1;
        if(mode==5) m->bad_enum=3;
        if(mode>=6) {
            wild_receive(m,n); CHECK(matter_im_read_process(m->active,0)==MATTER_PENDING);
            CHECK(matter_im_read_state(m->active)==MATTER_IM_READ_EXPANDING);
            if(mode==6) CHECK(matter_im_read_process(m->active,10000)==MATTER_PORT_ERROR);
            if(mode==7) CHECK(matter_im_read_cancel(m->active)==MATTER_OK);
            if(mode==8) { while(matter_im_read_state(m->active)==MATTER_IM_READ_EXPANDING) CHECK(matter_im_read_process(m->active,1)==MATTER_PENDING);
                CHECK(matter_im_read_state(m->active)==MATTER_IM_READ_COLLECTING && m->reads==8); CHECK(matter_im_read_cancel(m->active)==MATTER_OK); }
            Matter_Im_Read_Message_T out; CHECK(matter_im_read_output(m->active,&out)==MATTER_INVALID_STATE); wild_delete(m); continue;
        }
        wild_receive(m,n); model_process(m,0); Matter_Im_Read_Message_T out;
        CHECK(matter_im_read_output(m->active,&out)==MATTER_OK && out.opcode==1 && out.data[3]==status && !m->reads);
        if(mode<2) CHECK(!m->enumerations && !m->descriptions);
        wild_delete(m);
    }
    puts("PASS IM wildcard: 8 selector forms, >9 results, access omission, version filters/all matches, fallback/race, limits, bounded work and cancel");
}

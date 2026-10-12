#include "test_write_list_model.h"
static WriteListModel* wl_create(size_t capacity) {
    WriteListModel* m=calloc(1,sizeof(*m)); CHECK(m); m->version=7;
    Matter_Im_Write_Port_T p=wl_port(m); Matter_Im_Write_Config_T c={{1,0x1234,false},1000,capacity,true};
    m->active=matter_im_write_new(&p,&c,0); CHECK(m->active); return m;
}
static Matter_Im_Write_Message_T wl_run(WriteListModel* m,uint64_t now) {
    Matter_Rx_Decision_T d=decision(m->input,m->input_size);
    CHECK(matter_im_write_receive_at(m->active,&d,now)==MATTER_OK && matter_im_write_process(m->active,now)==MATTER_PENDING);
    Matter_Im_Write_Message_T out; CHECK(matter_im_write_output(m->active,&out)==MATTER_OK); return out;
}
static void wl_reply(Matter_Im_Write_Message_T out,bool add,uint8_t code) {
    (void)add; /* Both report the concrete attribute, without ListIndex=null. */
    expect(out,code,false);
}
static void wl_free(WriteListModel* m) { CHECK(matter_im_write_delete(m->active)==MATTER_OK); free(m); }
static void test_write_lists(void) {
    WriteListModel* m=wl_create(128); wl_request(m,false,true,7,0); wl_reply(wl_run(m,0),false,0);
    CHECK(m->writes==1 && m->version==8 && matter_im_write_sent_at(m->active,1)==MATTER_OK);
    CHECK(!matter_im_write_awaiting_delivery(m->active)); /* More list chunks own the same quota. */
    wl_request(m,true,false,8,3); Matter_Rx_Decision_T d=decision(m->input,m->input_size);
    CHECK(matter_im_write_receive_at(m->active,&d,2)==MATTER_OK && matter_im_write_receive_at(m->active,&d,2)==MATTER_WOULD_BLOCK);
    CHECK(matter_im_write_process(m->active,3)==MATTER_PENDING && m->writes==1);
    CHECK(matter_im_write_confirm(m->active,4)==MATTER_OK && matter_im_write_state(m->active)==MATTER_IM_WRITE_WAIT_CHUNK);
    CHECK(matter_im_write_process(m->active,5)==MATTER_PENDING); Matter_Im_Write_Message_T out;
    CHECK(matter_im_write_output(m->active,&out)==MATTER_OK); wl_reply(out,true,0);
    CHECK(m->count==1 && m->items[0]==3 && m->version==9 && m->writes==2);
    CHECK(matter_im_write_process(m->active,6)==MATTER_PENDING && m->writes==2);
    CHECK(matter_im_write_sent_at(m->active,6)==MATTER_OK && matter_im_write_confirm(m->active,7)==MATTER_OK);
    CHECK(matter_im_write_state(m->active)==MATTER_IM_WRITE_COMPLETE); wl_free(m);
    /* Per-IB errors preserve previous changes; optional version is never inherited. */
    for(unsigned mode=0;mode<8;++mode) {
        m=wl_create(128); wl_request(m,false,true,7,0); wl_reply(wl_run(m,0),false,0);
        CHECK(matter_im_write_sent_at(m->active,0)==MATTER_OK && matter_im_write_confirm(m->active,0)==MATTER_OK);
        wl_request(m,true,false,mode==0 ? 7 : -1,mode==1 ? 99 : 2);
        if(mode==2) m->deny=true;
        if(mode==3) m->fail_write=true;
        if(mode==4) m->input[16]=3; /* Different attribute in same exchange. */
        if(mode==5) m->count=64;
        if(mode==6 || mode==7) {
            d=decision(m->input,m->input_size); CHECK(matter_im_write_receive_at(m->active,&d,1)==MATTER_OK);
            if(mode==6) CHECK(matter_im_write_cancel(m->active)==MATTER_OK); else CHECK(matter_im_write_process(m->active,1000)==MATTER_PORT_ERROR);
            CHECK(m->writes==1 && m->version==8 && matter_im_write_confirm(m->active,1000)==MATTER_INVALID_STATE);
        } else {
            out=wl_run(m,1);
            if(mode==4) expect(out,MATTER_IM_INVALID_ACTION,true);
            else wl_reply(out,true,mode==0 ? MATTER_IM_DATA_VERSION_MISMATCH : mode==1 ? MATTER_IM_CONSTRAINT_ERROR :
                mode==2 ? MATTER_IM_UNSUPPORTED_ACCESS : mode==3 ? MATTER_IM_FAILURE : MATTER_IM_RESOURCE_EXHAUSTED);
            CHECK(m->version==8 && m->writes==(mode==3 ? 2u : 1u));
        }
        wl_free(m);
    }
    /* Message count bounded independently of provider capacity. */
    m=wl_create(128);
    for(unsigned i=0;i<=MATTER_IM_WRITE_MAX_CHUNKS;++i) {
        wl_request(m,false,true,-1,0); out=wl_run(m,i);
        if(i==MATTER_IM_WRITE_MAX_CHUNKS) { expect(out,MATTER_IM_RESOURCE_EXHAUSTED,true); CHECK(m->writes==i); }
        else wl_reply(out,false,0);
        CHECK(matter_im_write_sent_at(m->active,i)==MATTER_OK && matter_im_write_confirm(m->active,i)==MATTER_OK);
    }
    CHECK(matter_im_write_state(m->active)==MATTER_IM_WRITE_COMPLETE); wl_free(m);
    for(unsigned mode=0;mode<5;++mode) {
        m=wl_create(mode==3 ? 30 : 128); wl_request(m,mode!=0,true,-1,1);
        if(mode==0) { /* Nonempty REPLACE forbidden for ordinary lists. */
            size_t at=20; memmove(m->input+at+2,m->input+at,m->input_size-at); m->input[at]=4; m->input[at+1]=1; m->input_size+=2;
        }
        if(mode==1) { memmove(m->input+3,m->input+1,m->input_size-1); m->input[1]=0x29; m->input[2]=0; m->input_size+=2; }
        if(mode==2) { /* Valid TLV, but numeric ListIndex is forbidden. */
            memmove(m->input+20,m->input+19,m->input_size-19); ++m->input_size;
            m->input[17]=0x24; m->input[19]=0;
        }
        if(mode==4) { /* Timed chunking forbidden, even after a valid TimedRequest. */
            d=decision(write_timed,sizeof(write_timed)); d.header.opcode=10;
            CHECK(matter_im_write_receive_at(m->active,&d,0)==MATTER_OK && matter_im_write_process(m->active,0)==MATTER_PENDING);
            CHECK(matter_im_write_sent_at(m->active,0)==MATTER_OK && matter_im_write_confirm(m->active,0)==MATTER_OK); m->input[1]=0x29;
        }
        out=wl_run(m,1);
        if(mode==3) wl_reply(out,true,MATTER_IM_RESOURCE_EXHAUSTED);
        else expect(out,MATTER_IM_INVALID_ACTION,mode!=0); /* Valid shape: per-path implementation limit. */
        CHECK(!m->writes); wl_free(m);
    }
    /* Final suppression, missing continuation revision, and single timed ADD. */
    for(unsigned mode=0;mode<3;++mode) {
        m=wl_create(128);
        if(mode==2) {
            d=decision(write_timed,sizeof(write_timed)); d.header.opcode=10;
            CHECK(matter_im_write_receive_at(m->active,&d,0)==MATTER_OK && matter_im_write_process(m->active,0)==MATTER_PENDING);
        } else { wl_request(m,false,true,7,0); wl_reply(wl_run(m,0),false,0); }
        CHECK(matter_im_write_sent_at(m->active,0)==MATTER_OK && matter_im_write_confirm(m->active,0)==MATTER_OK);
        wl_request(m,true,false,-1,4);
        if(!mode) { memmove(m->input+3,m->input+1,m->input_size-1); m->input[1]=0x29; m->input[2]=0; m->input_size+=2; }
        if(mode==1) { m->input[m->input_size-4]=0x18; m->input_size-=3; }
        if(mode==2) m->input[1]=0x29;
        d=decision(m->input,m->input_size); CHECK(matter_im_write_receive_at(m->active,&d,1)==MATTER_OK);
        CHECK(matter_im_write_process(m->active,1)==(!mode ? MATTER_OK : MATTER_PENDING));
        if(!mode) CHECK(matter_im_write_state(m->active)==MATTER_IM_WRITE_COMPLETE && m->count==1 && m->version==9);
        else { CHECK(matter_im_write_output(m->active,&out)==MATTER_OK);
            if(mode==1) { expect(out,MATTER_IM_INVALID_ACTION,true); CHECK(m->writes==1 && !m->count); }
            else { wl_reply(out,true,0); CHECK(m->writes==1 && m->count==1); }
        }
        wl_free(m);
    }
    puts("PASS Write lists: clear/ADD literal statuses, RX before ACK, versions, partial effects, shape/capacity/count limits, timed prohibition and abort");
}

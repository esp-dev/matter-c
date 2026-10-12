/* Included after the existing untimed fixture helpers. */
static InvokeModel* timed_start(uint16_t timeout) {
    InvokeModel* m=create(1024); memcpy(m->input,timed_request,sizeof(timed_request));
    m->input[3]=(uint8_t)timeout; m->input[4]=(uint8_t)(timeout>>8);
    Matter_Rx_Decision_T d=decision(m->input,sizeof(timed_request)); d.header.opcode=10;
    CHECK(matter_im_invoke_receive_at(m->active,&d,0)==MATTER_OK);
    CHECK(matter_im_invoke_process(m->active,0)==MATTER_PENDING && !m->auths);
    Matter_Im_Invoke_Message_T out; CHECK(matter_im_invoke_output(m->active,&out)==MATTER_OK);
    expect_status(out,0,true);
    CHECK(matter_im_invoke_sent(m->active)==MATTER_INVALID_STATE);
    return m;
}
static Matter_Rx_Decision_T timed_command(InvokeModel* m) {
    memcpy(m->input,invoke_request,sizeof(invoke_request)); m->input[3]=0x29;
    return decision(m->input,sizeof(invoke_request));
}
static void test_invoke_timed(void) {
    for(unsigned mode=0;mode<8;++mode) {
        InvokeModel* m=timed_start(mode==4 ? 0 : mode==7 ? UINT16_MAX : 100);
        m->metadata.timed=mode!=7; /* Timed also works for commands without the quality. */
        Matter_Rx_Decision_T d=timed_command(m);
        CHECK(matter_im_invoke_receive_at(m->active,&d,1)==MATTER_INVALID_STATE); /* Not sent yet. */
        CHECK(matter_im_invoke_process(m->active,99)==MATTER_PENDING); /* Enqueue delay is not the window. */
        CHECK(matter_im_invoke_sent_at(m->active,100)==MATTER_OK);
        CHECK(!matter_im_invoke_awaiting_delivery(m->active)); /* Timed Invoke has not executed yet. */
        CHECK(matter_im_invoke_sent_at(m->active,101)==MATTER_INVALID_STATE); /* Retry cannot reset. */
        if(mode==2) m->input[3]=0x28;
        if(mode==3) { d.header.opcode=10; d.payload=timed_request; d.payload_size=sizeof(timed_request); }
        if(mode==5) d.header.opcode=6;
        if(mode==6) { m->input[sizeof(invoke_request)-4]=0x18; d.payload_size-=3; } /* Missing revision after valid TimedRequest. */
        uint64_t received=mode==1 ? 200 : mode==4 ? 100 : 199;
        if(mode==7) CHECK(matter_im_invoke_confirm(m->active,101)==MATTER_OK);
        ++d.session; CHECK(matter_im_invoke_receive_at(m->active,&d,received)==MATTER_INVALID_ARGUMENT); --d.session;
        ++d.header.exchange_id; CHECK(matter_im_invoke_receive_at(m->active,&d,received)==MATTER_INVALID_ARGUMENT); --d.header.exchange_id;
        CHECK(matter_im_invoke_receive(m->active,&d)==MATTER_INVALID_ARGUMENT);
        CHECK(matter_im_invoke_receive_at(m->active,&d,received)==MATTER_OK);
        CHECK(matter_im_invoke_receive_at(m->active,&d,received)==MATTER_WOULD_BLOCK);
        if(mode!=7) {
            CHECK(matter_im_invoke_process(m->active,300)==MATTER_PENDING && !m->auths);
            CHECK(matter_im_invoke_state(m->active)==MATTER_IM_INVOKE_IN_FLIGHT);
            CHECK(matter_im_invoke_confirm(m->active,300)==MATTER_OK);
        }
        CHECK(matter_im_invoke_state(m->active)==MATTER_IM_INVOKE_WAIT_INVOKE);
        CHECK(matter_im_invoke_process(m->active,301)==MATTER_PENDING);
        Matter_Im_Invoke_Message_T out; CHECK(matter_im_invoke_output(m->active,&out)==MATTER_OK);
        if(!mode || mode==7) {
            CHECK(m->executions==1 && out.opcode==9 && out.size==sizeof(invoke_response) && !memcmp(out.data,invoke_response,out.size));
        } else {
            uint8_t code=mode==1 || mode==4 ? MATTER_IM_TIMEOUT : mode==2 ? MATTER_IM_TIMED_REQUEST_MISMATCH : MATTER_IM_INVALID_ACTION;
            expect_status(out,code,true); CHECK(!m->auths && !m->executions);
        }
        CHECK(matter_im_invoke_sent_at(m->active,302)==MATTER_OK && matter_im_invoke_confirm(m->active,303)==MATTER_OK);
        CHECK(matter_im_invoke_state(m->active)==MATTER_IM_INVOKE_COMPLETE); release(m);
    }
    /* An expired idle window still returns a protocol TIMEOUT to a late invoke. */
    InvokeModel* m=timed_start(1);
    CHECK(matter_im_invoke_sent_at(m->active,100)==MATTER_OK && matter_im_invoke_confirm(m->active,101)==MATTER_OK);
    CHECK(matter_im_invoke_process(m->active,200)==MATTER_PENDING && !m->executions);
    Matter_Rx_Decision_T d=timed_command(m);
    CHECK(matter_im_invoke_receive_at(m->active,&d,199)==MATTER_INVALID_ARGUMENT);
    CHECK(matter_im_invoke_receive_at(m->active,&d,200)==MATTER_OK && matter_im_invoke_process(m->active,201)==MATTER_PENDING);
    Matter_Im_Invoke_Message_T out; CHECK(matter_im_invoke_output(m->active,&out)==MATTER_OK); expect_status(out,MATTER_IM_TIMEOUT,true); release(m);
    /* Saturating deadline and maximum Timeout cannot wrap into immediate expiry. */
    m=create(1024); CHECK(matter_im_invoke_delete(m->active)==MATTER_OK);
    Matter_Im_Invoke_Port_T p=invoke_port(m); Matter_Im_Invoke_Config_T c={{1,0x1234,false},1000,1024,true};
    m->active=matter_im_invoke_new(&p,&c,UINT64_MAX-200); CHECK(m->active);
    memcpy(m->input,timed_request,sizeof(timed_request)); m->input[3]=m->input[4]=255;
    d=decision(m->input,sizeof(timed_request)); d.header.opcode=10;
    CHECK(matter_im_invoke_receive_at(m->active,&d,UINT64_MAX-200)==MATTER_OK && matter_im_invoke_process(m->active,UINT64_MAX-200)==MATTER_PENDING);
    CHECK(matter_im_invoke_sent_at(m->active,UINT64_MAX-100)==MATTER_OK && matter_im_invoke_confirm(m->active,UINT64_MAX-99)==MATTER_OK);
    d=timed_command(m);
    CHECK(matter_im_invoke_receive_at(m->active,&d,UINT64_MAX-2)==MATTER_OK && matter_im_invoke_process(m->active,UINT64_MAX-1)==MATTER_PENDING && m->executions==1); release(m);
    /* Truncated/wrong/duplicate/missing timeout and overflowing uint16. */
    for(unsigned mode=0;mode<6;++mode) {
        m=create(1024); memcpy(m->input,timed_request,sizeof(timed_request)); size_t n=sizeof(timed_request);
        if(mode==0) --n;
        if(mode==1) m->input[1]=0x21; /* signed */
        if(mode==2) m->input[2]=1; /* timeout omitted */
        if(mode==3) { memmove(m->input+7,m->input+5,n-5); m->input[1]=0x26; m->input[5]=1; m->input[6]=0; n+=2; }
        if(mode==4) { memcpy(m->input+n-1,"\x24\x00\x01\x18",4); n+=3; }
        if(mode==5) { m->input[5]=0x18; n=6; } /* revision missing */
        d=decision(m->input,n); d.header.opcode=10;
        CHECK(matter_im_invoke_receive_at(m->active,&d,0)==MATTER_OK && matter_im_invoke_process(m->active,0)==MATTER_PENDING);
        CHECK(matter_im_invoke_output(m->active,&out)==MATTER_OK); expect_status(out,MATTER_IM_INVALID_ACTION,true);
        CHECK(!m->auths); release(m);
    }
    for(unsigned phase=0;phase<5;++phase) {
        m=timed_start(100); d=timed_command(m);
        if(phase) CHECK(matter_im_invoke_sent_at(m->active,100)==MATTER_OK);
        if(phase>=2) CHECK(matter_im_invoke_receive_at(m->active,&d,150)==MATTER_OK);
        if(phase==3) CHECK(matter_im_invoke_confirm(m->active,200)==MATTER_OK);
        if(phase==4) CHECK(matter_im_invoke_process(m->active,1000)==MATTER_PORT_ERROR);
        else CHECK(matter_im_invoke_cancel(m->active)==MATTER_OK);
        CHECK(!m->executions && matter_im_invoke_process(m->active,1001)==MATTER_INVALID_STATE && matter_im_invoke_confirm(m->active,1001)==MATTER_INVALID_STATE);
        release(m);
    }
    puts("PASS Timed Invoke: first-send window, RX before ACK, delayed process, exact deadline/zero/uint16/overflow, mismatch/order/schema, cancel and absolute budget");
}

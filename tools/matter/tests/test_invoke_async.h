/* Async completion uses existing wire assertions and callback reentry guards. */
typedef struct { InvokeModel model; unsigned polls,cancels; } AsyncInvokeModel;
static Matter_Result_T async_start(void* u,const Matter_Im_Command_Path_T* p,const uint8_t* data,size_t size,
    Matter_Tlv_Writer_T* out,Matter_Im_Command_Result_T* result,uint64_t* token) {
    InvokeModel* m=u; unsigned mode=m->malformed; m->malformed=0;
    *result=invoke_execute(u,p,data,size,out); m->malformed=mode; *token=77;
    return MATTER_PENDING;
}
static Matter_Result_T async_poll(void* u,uint64_t token,Matter_Tlv_Writer_T* out,Matter_Im_Command_Result_T* result) {
    AsyncInvokeModel* a=u; InvokeModel* m=&a->model; invoke_guard(m); CHECK(token==77 && m->executions==1);
    if(++a->polls==1) return MATTER_PENDING;
    if(m->malformed==2) return MATTER_PORT_ERROR;
    *result=(Matter_Im_Command_Result_T){0};
    if(out) {
        if(m->malformed==1) {
            m->token=(Matter_Tlv_Element_T){.type=MATTER_TLV_ARRAY}; CHECK(matter_tlv_write(out,&m->token,0)==MATTER_TLV_OK);
            m->token.type=MATTER_TLV_END; CHECK(matter_tlv_write(out,&m->token,0)==MATTER_TLV_OK); return MATTER_OK;
        }
        const uint8_t body[]={0x15,0x24,0,7,0x24,1,1,0x18};
        CHECK(matter_tlv_init(&m->reader,body,sizeof(body),4)==MATTER_TLV_OK);
        while(matter_tlv_next(&m->reader,&m->token)==MATTER_TLV_OK) {
            CHECK(matter_tlv_write(out,&m->token,0)==MATTER_TLV_OK);
        }
    }
    return MATTER_OK;
}
static void async_cancel(void* u,uint64_t token) {
    AsyncInvokeModel* a=u; invoke_guard(&a->model); CHECK(token==77); ++a->cancels;
}
static void test_invoke_async(void) {
    for(unsigned mode=0;mode<6;++mode) {
        AsyncInvokeModel* a=calloc(1,sizeof(*a)); CHECK(a); InvokeModel* m=&a->model;
        Matter_Im_Invoke_Port_T p=invoke_port(m); Matter_Im_Invoke_Async_Port_T ap={async_start,async_poll,async_cancel};
        Matter_Im_Invoke_Config_T c={{1,0x1234,false},1000,1024,true}; m->malformed=mode<3?mode:0;
        m->active=matter_im_invoke_new_async(&p,&ap,&c,0); CHECK(m->active);
        Matter_Rx_Decision_T d=decision(invoke_request,sizeof(invoke_request));
        CHECK(matter_im_invoke_receive_at(m->active,&d,0)==MATTER_OK && matter_im_invoke_process(m->active,0)==MATTER_PENDING);
        CHECK(matter_im_invoke_state(m->active)==MATTER_IM_INVOKE_PENDING);
        Matter_Im_Invoke_Message_T out; CHECK(matter_im_invoke_output(m->active,&out)==MATTER_INVALID_STATE);
        if(mode<3) {
            CHECK(matter_im_invoke_process(m->active,1)==MATTER_PENDING && a->polls==1);
            CHECK(matter_im_invoke_process(m->active,2)==MATTER_PENDING && a->polls==2);
            CHECK(matter_im_invoke_output(m->active,&out)==MATTER_OK);
            if(mode) expect_status(out,MATTER_IM_FAILURE,false);
            else CHECK(out.size==sizeof(invoke_response) && !memcmp(out.data,invoke_response,out.size));
            CHECK(matter_im_invoke_sent(m->active)==MATTER_OK && matter_im_invoke_confirm(m->active,3)==MATTER_OK);
        } else if(mode==3) CHECK(matter_im_invoke_process(m->active,1000)==MATTER_PORT_ERROR);
        else if(mode==4) { m->deny=MATTER_IM_UNSUPPORTED_ACCESS; CHECK(matter_im_invoke_process(m->active,1)==MATTER_PENDING); }
        CHECK(matter_im_invoke_delete(m->active)==MATTER_OK && m->executions==1 && a->cancels==(mode>=2?1u:0u)); free(a);
    }
    puts("PASS async Invoke: deferred immutable response, provider error/schema, timeout/revocation/delete and callback reentry");
}

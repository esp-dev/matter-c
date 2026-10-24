/* Included after the wildcard/complex fixtures. Public Read API only; scalar snapshots
 * require no external value allocation, isolating resident metadata changes. */
static void read_reclaim_tests(void) {
    for(unsigned order=0;order<2;++order) {
        ImTestModel* m=wild_new(40,true); m->size=MATTER_IM_READ_MAX_RESULTS;
        wild_start(m,0,0,0); unsigned seen=0,blocks=0;
#ifdef MATTER_TEST_ALLOC
        size_t reclaimed_bytes=0;
#endif
        for(unsigned chunk=0;chunk<MATTER_IM_READ_MAX_RESULTS;++chunk) {
            Matter_Im_Read_Message_T out; bool more; unsigned errors;
            CHECK(!matter_im_read_output(m->active,&out) && out.opcode==5);
            unsigned n=model_report(m,out.data,out.size,&more,&errors); CHECK(n==1 && !errors);
            /* Independently enforce wire order and the original captured value. */
            CHECK(matter_tlv_init(&m->reader,out.data,out.size,8)==MATTER_TLV_OK);
            bool found=false;
            while(matter_tlv_next(&m->reader,&m->element)==MATTER_TLV_OK)
                if(m->element.type==MATTER_TLV_UNSIGNED && m->element.tag.control==1 &&
                    m->element.tag.number==2 && m->element.unsigned_value>=1000) {
                    CHECK(!found && m->element.unsigned_value==1000+seen); found=true;
                }
            CHECK(found); ++seen;
            CHECK(!matter_im_read_sent(m->active));
            if(!more) { CHECK(seen==MATTER_IM_READ_MAX_RESULTS && !matter_im_read_confirm(m->active,chunk+1)); break; }
#ifdef MATTER_TEST_ALLOC
            size_t held=live,bytes=live_bytes;
#endif
            const uint8_t success[]={0x15,0x24,0,0,0x24,0xff,13,0x18};
            Matter_Rx_Decision_T d=decision(success,sizeof(success)); d.header.opcode=1;
            if(order) {
                CHECK(!matter_im_read_confirm(m->active,chunk+1));
                CHECK(matter_im_read_process(m->active,chunk+1)==MATTER_PENDING);
            } else {
                CHECK(!matter_im_read_receive(m->active,&d)); model_process(m,chunk+1);
                CHECK(matter_im_read_state(m->active)==MATTER_IM_READ_IN_FLIGHT);
            }
#ifdef MATTER_TEST_ALLOC
            CHECK(live==held); /* Either acknowledgement alone retains all pages. */
#endif
            if(order) CHECK(!matter_im_read_receive(m->active,&d));
            else CHECK(!matter_im_read_confirm(m->active,chunk+1));
            model_process(m,chunk+1);
            bool retired=seen>=9 && (seen-9)%16==0;
            if(retired) ++blocks;
#ifdef MATTER_TEST_ALLOC
            CHECK(live==held-(retired?1:0));
            if(retired) reclaimed_bytes+=bytes-live_bytes;
#endif
        }
        CHECK(seen==512 && m->reads==512 && blocks==32);
#ifdef MATTER_TEST_ALLOC
        printf("MEMORY Read prefix: ack_order=%u pages=%u requested_bytes_released=%zu\n",order,blocks,reclaimed_bytes);
#endif
        wild_delete(m);
#ifdef MATTER_TEST_ALLOC
        CHECK(!live && !live_bytes);
#endif
    }
#ifdef MATTER_TEST_ALLOC
    /* OOM after retired pages: RX input/work allocation failure leaves the
     * interaction retryable; deferred workspace OOM terminates with status. */
    for(unsigned site=0;site<3;++site) {
        ImTestModel* m=wild_new(40,true); m->size=48; wild_start(m,0,0,0);
        for(unsigned i=0;i<26;++i) {
            CHECK(!matter_im_read_sent(m->active) && !matter_im_read_confirm(m->active,i+1));
            const uint8_t success[]={0x15,0x24,0,0,0x24,0xff,13,0x18};
            Matter_Rx_Decision_T d=decision(success,sizeof(success)); d.header.opcode=1;
            if(i==25) {
                size_t held=live,bytes=live_bytes; fail_at=calls+site+1;
                if(site<2) {
                    CHECK(matter_im_read_receive(m->active,&d)==MATTER_LIMIT_REACHED); fail_at=0;
                    CHECK(live==held && live_bytes==bytes && matter_im_read_state(m->active)==MATTER_IM_READ_WAIT_STATUS);
                } else {
                    fail_at=0; CHECK(!matter_im_read_receive(m->active,&d)); model_process(m,i+1);
                    CHECK(!matter_im_read_sent(m->active));
                    CHECK(!matter_im_read_receive(m->active,&d)); model_process(m,i+1);
                    CHECK(!matter_im_read_confirm(m->active,i+1));
                    fail_at=calls+1; model_process(m,i+1); fail_at=0;
                    Matter_Im_Read_Message_T out; CHECK(!matter_im_read_output(m->active,&out));
                    CHECK(out.opcode==1 && out.data[3]==MATTER_IM_RESOURCE_EXHAUSTED);
                    CHECK(!matter_im_read_sent(m->active) && !matter_im_read_confirm(m->active,i+1));
                    break;
                }
            }
            CHECK(!matter_im_read_receive(m->active,&d)); model_process(m,i+1);
        }
        CHECK(m->reads==48); wild_delete(m); CHECK(!live && !live_bytes);
    }
#endif
    puts("PASS Read prefix reclamation: all512 frozen ordered results, 32 whole pages per ACK order, partial pages retained and continuation OOM after retirement");
}
typedef struct { ImTestModel model; ImValues list; } ReclaimList;
static Matter_Im_Status_T reclaim_list_read(void* user,const Matter_Im_Path_T* path,bool filtered,Matter_Im_Value_T* value) {
    ReclaimList* f=user;
    if(model_index(path)!=8) return model_read(user,path,filtered,value);
    model_guard(&f->model); ++f->model.reads;
    *value=(Matter_Im_Value_T){.type=MATTER_TLV_ARRAY,.data_version=7,.data=f->list.data,.size=f->list.size};
    return MATTER_IM_SUCCESS;
}
static void read_reclaim_list_test(void) {
    ReclaimList* f=calloc(1,sizeof(*f)); CHECK(f);
    f->model.size=32; f->model.override_version=true; f->model.version=7;
    f->list.short_list=true; f->list.type=MATTER_TLV_ARRAY;
    const uint8_t list[]={0x16,0x04,1,0x04,2,0x04,3,0x18};
    memcpy(f->list.data,list,sizeof(list)); f->list.size=sizeof(list);
    Matter_Im_Read_Port_T port=model_port(&f->model,true); port.read=reclaim_list_read;
    Matter_Im_Read_Config_T config={{1,0x1234,false},10000,36,true};
    f->model.active=matter_im_read_new(&port,&config,0); CHECK(f->model.active);
    wild_start(&f->model,0,0,0); memset(f->list.data,0xff,sizeof(list));
    unsigned seen=0;
    for(unsigned chunk=0;chunk<40;++chunk) {
        Matter_Im_Read_Message_T out; bool more; unsigned errors;
        CHECK(!matter_im_read_output(f->model.active,&out) && out.opcode==5);
        if(seen==8) {
            more=values_report(&f->list,out.data,out.size);
            if(f->list.received==3) ++seen;
        } else {
            CHECK(model_report(&f->model,out.data,out.size,&more,&errors)==1 && !errors); ++seen;
        }
        CHECK(!matter_im_read_sent(f->model.active) && !matter_im_read_confirm(f->model.active,chunk+1));
        if(!more) break;
#ifdef MATTER_TEST_ALLOC
        size_t held=live;
#endif
        const uint8_t success[]={0x15,0x24,0,0,0x24,0xff,13,0x18};
        Matter_Rx_Decision_T d=decision(success,sizeof(success)); d.header.opcode=1;
        CHECK(!matter_im_read_receive(f->model.active,&d)); model_process(&f->model,chunk+1);
#ifdef MATTER_TEST_ALLOC
        if(seen==8) CHECK(live==held); /* The last inline ARRAY pins this whole first page. */
        if(seen==9) CHECK(live+1==held); /* Only after the final ADD is consumed. */
#endif
    }
    CHECK(seen==32 && f->model.reads==32 && f->list.received==3 && f->list.replacements==1 && f->list.appends);
    CHECK(!matter_im_read_delete(f->model.active)); free(f);
#ifdef MATTER_TEST_ALLOC
    CHECK(!live && !live_bytes);
#endif
    puts("PASS Read retired page boundary: poisoned provider, inline partial ARRAY pins its page until final ADD, remaining paths survive");
}

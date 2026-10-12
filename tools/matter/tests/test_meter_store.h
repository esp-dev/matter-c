/* Shared StoreTest heap/workspaces; real atomic backend and EEM/event producers. */
typedef struct { StoreTest* store; Matter_Eem_Sample_T sample; } MeterTest;
static Matter_Result_T meter_sample(void* u,Matter_Eem_Sample_T* out) { *out=((MeterTest*)u)->sample; return MATTER_OK; }
static Matter_Result_T meter_load(void* u,Matter_Eem_Checkpoint_T* out) { return matter_store_host_eem_load(((MeterTest*)u)->store->store,out); }
static Matter_Result_T meter_save(void* u,const Matter_Eem_Checkpoint_T* in) { return matter_store_host_eem_store(((MeterTest*)u)->store->store,in); }
static void meter_store_restored(StoreTest* t) {
    Matter_Eem_Checkpoint_T saved; uint64_t high;
    OC_CHECK(matter_store_host_eem_load(t->store,&saved)==MATTER_OK && saved.initialized && saved.generation==8);
    OC_CHECK(saved.raw_mwh[0]==40 && saved.raw_mwh[1]==80 && saved.total_mwh[0]==1165 && saved.total_mwh[1]==2330);
    OC_CHECK(matter_store_host_event_load(t->store,&high)==MATTER_OK && high==UINT64_C(0x20000000000020));
    read_file(t); OC_CHECK(matter_store_tlv_decode(t->bytes,t->size,&t->data)==MATTER_OK);
    OC_CHECK(t->data.eem.total_mwh[0]==1165 && t->data.eem.total_mwh[1]==2330 && t->data.event_high==high);
    Matter_Events_Port_T ep={t->store,matter_store_host_event_load,matter_store_host_event_store};
    Matter_Events_T events=matter_events_new(&ep); OC_CHECK(events);
    uint64_t position; OC_CHECK(matter_events_position(events,&position)==MATTER_OK && position==high);
    OC_CHECK(matter_events_delete(events)==MATTER_OK);
    puts("PASS meter restore: exact import/export/raw/generation and >2^53 event high-water; rollback/reset preserve node state");
}
static void meter_store_seed(StoreTest* t) {
    MeterTest* m=calloc(1,sizeof(*m)); OC_CHECK(m); m->store=t;
    Matter_Eem_Checkpoint_T saved,candidate; uint64_t high;
    OC_CHECK(matter_store_host_eem_load(t->store,&saved)==MATTER_OK && !saved.initialized);
    OC_CHECK(matter_store_host_event_load(t->store,&high)==MATTER_OK && !high);
    Matter_Events_Port_T ep={t->store,matter_store_host_event_load,matter_store_host_event_store};
    Matter_Events_T events=matter_events_new(&ep); OC_CHECK(events);
    Matter_Eem_Port_T port={m,meter_sample,meter_load,meter_save};
    Matter_Eem_Config_T cfg={.endpoint=1,.percent_max=100,.fixed_max_mwh=1,.max_age_ms=3000,.events=events};
    Matter_Cluster_T eem=matter_eem_new(&port,&cfg,0); OC_CHECK(eem);
    m->sample=(Matter_Eem_Sample_T){.raw_mwh={100,200},.generation=7,.available=true}; bool ready;
    OC_CHECK(matter_eem_refresh(eem,0,&ready)==MATTER_OK);
    m->sample.raw_mwh[0]=1100; m->sample.raw_mwh[1]=2200; m->sample.sampled_ms=1000;
    OC_CHECK(matter_eem_refresh(eem,1000,&ready)==MATTER_OK);
    OC_CHECK(matter_store_host_eem_load(t->store,&saved)==MATTER_OK && saved.total_mwh[0]==1000 && saved.total_mwh[1]==2000);
    read_file(t); memcpy(t->copy,t->bytes,t->size); t->copy_size=t->size;
    m->sample.raw_mwh[0]=1225; m->sample.raw_mwh[1]=2450; m->sample.sampled_ms=2000;
    for(unsigned fault=1;fault<=4;++fault) {
        matter_store_file_fault(t->file,fault);
        OC_CHECK(matter_eem_refresh(eem,2000,&ready)==MATTER_PORT_ERROR); same_file(t);
        OC_CHECK(matter_store_host_eem_load(t->store,&candidate)==MATTER_OK && candidate.total_mwh[0]==1000 && candidate.total_mwh[1]==2000);
        Matter_Im_Value_T value; Matter_Cluster_Request_T q={0};
        OC_CHECK(matter_cluster_read(eem,1,&q,&value)==0 && value.type==MATTER_TLV_NULL);
        OC_CHECK(matter_cluster_read(eem,2,&q,&value)==0 && value.type==MATTER_TLV_NULL);
        OC_CHECK(matter_store_host_event_store(t->store,64)==MATTER_PORT_ERROR); same_file(t);
    }
    matter_store_file_fault(t->file,0);
#ifdef MATTER_TEST_ALLOC
    fail_at=calls+1; OC_CHECK(matter_eem_refresh(eem,2000,&ready)==MATTER_PORT_ERROR); fail_at=0; same_file(t);
    fail_at=calls+1; OC_CHECK(matter_store_host_event_store(t->store,64)==MATTER_LIMIT_REACHED); fail_at=0; same_file(t);
#endif
    OC_CHECK(matter_eem_refresh(eem,2000,&ready)==MATTER_OK);
    OC_CHECK(matter_store_host_eem_load(t->store,&saved)==MATTER_OK && saved.total_mwh[0]==1125 && saved.total_mwh[1]==2250);
    OC_CHECK(matter_cluster_delete(eem)==MATTER_OK);
    eem=matter_eem_new(&port,&cfg,0); OC_CHECK(eem); m->sample.sampled_ms=0;
    OC_CHECK(matter_eem_refresh(eem,0,&ready)==MATTER_OK); /* Same raw is not counted twice. */
    m->sample.generation=8; m->sample.raw_mwh[0]=m->sample.raw_mwh[1]=0; m->sample.sampled_ms=1000;
    OC_CHECK(matter_eem_refresh(eem,1000,&ready)==MATTER_OK); /* Real source replacement rebases both. */
    m->sample.raw_mwh[0]=40; m->sample.raw_mwh[1]=80; m->sample.sampled_ms=2000;
    OC_CHECK(matter_eem_refresh(eem,2000,&ready)==MATTER_OK);
    OC_CHECK(matter_store_host_eem_load(t->store,&saved)==MATTER_OK);
    candidate=saved; --candidate.total_mwh[0]; OC_CHECK(matter_store_host_eem_store(t->store,&candidate)==MATTER_INVALID_ARGUMENT);
    candidate=saved; --candidate.generation; OC_CHECK(matter_store_host_eem_store(t->store,&candidate)==MATTER_INVALID_ARGUMENT);
    candidate=saved; candidate.raw_mwh[0]=MATTER_EEM_LIMIT+1; OC_CHECK(matter_store_host_eem_store(t->store,&candidate)==MATTER_INVALID_ARGUMENT);
    candidate=saved; candidate.initialized=false; OC_CHECK(matter_store_host_eem_store(t->store,&candidate)==MATTER_INVALID_ARGUMENT);
    OC_CHECK(matter_cluster_delete(eem)==MATTER_OK && matter_events_delete(events)==MATTER_OK);
    OC_CHECK(matter_store_host_event_load(t->store,&high)==MATTER_OK && high==32);
    events=matter_events_new(&ep); OC_CHECK(events); uint64_t position;
    OC_CHECK(matter_events_position(events,&position)==MATTER_OK && position==32);
    Matter_Event_Path_T path={1,MATTER_EEM_CLUSTER,0}; const uint8_t payload[]={0x15,0x18};
    matter_store_file_fault(t->file,4);
    OC_CHECK(matter_events_append(events,&path,1,0,false,payload,sizeof(payload))==MATTER_PORT_ERROR);
    OC_CHECK(matter_events_position(events,&position)==MATTER_OK && position==32);
    matter_store_file_fault(t->file,0);
    OC_CHECK(matter_events_append(events,&path,1,0,false,payload,sizeof(payload))==MATTER_OK);
    OC_CHECK(matter_events_position(events,&position)==MATTER_OK && position==33);
    OC_CHECK(matter_store_host_event_load(t->store,&high)==MATTER_OK && high==64);
    OC_CHECK(matter_events_delete(events)==MATTER_OK);
    OC_CHECK(matter_store_host_event_store(t->store,63)==MATTER_INVALID_ARGUMENT);
    OC_CHECK(matter_store_host_event_store(t->store,UINT64_C(0x20000000000020))==MATTER_OK);
    meter_store_restored(t);
    t->data.eem.raw_mwh[0]=MATTER_EEM_LIMIT; t->data.eem.total_mwh[1]=MATTER_EEM_LIMIT; t->data.event_high=UINT64_MAX;
    size_t size=0; OC_CHECK(matter_store_tlv_encode(&t->data,t->copy,sizeof(t->copy),&size)==MATTER_OK);
    OC_CHECK(matter_store_tlv_decode(t->copy,size,&t->previous)==MATTER_OK && t->previous.eem.raw_mwh[0]==MATTER_EEM_LIMIT &&
        t->previous.eem.total_mwh[1]==MATTER_EEM_LIMIT && t->previous.event_high==UINT64_MAX);
    t->data.eem.raw_mwh[0]=-1; OC_CHECK(!matter_store_data_valid(&t->data));
    t->data.eem.raw_mwh[0]=MATTER_EEM_LIMIT+1; OC_CHECK(!matter_store_data_valid(&t->data));
    t->data.eem.raw_mwh[0]=0; t->data.eem.total_mwh[1]=MATTER_EEM_LIMIT+1; OC_CHECK(!matter_store_data_valid(&t->data));
    free(m);
    puts("PASS meter persistence: EEM/events commit before publish, file faults/OOM, retry without double count, generation, bounds and reservation restart");
}
static void meter_staging(const char* path) {
    size_t n=strlen(path)+5; char* temp=calloc(n,1); OC_CHECK(temp); snprintf(temp,n,"%s.tmp",path);
    FILE* file=fopen(temp,"wb"); OC_CHECK(file && fwrite("interrupted",1,11,file)==11 && fclose(file)==0); free(temp);
    /* Left on purpose: the independent load process must use the committed file. */
}

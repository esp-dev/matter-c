typedef struct {
    uint64_t high; bool fail;
    Matter_Diagnostics_Snapshot_T snapshot;
    Matter_Event_Record_T records[MATTER_EVENTS_CAPACITY];
} BootEvents;
static Matter_Result_T boot_load(void* u,uint64_t* n) { *n=((BootEvents*)u)->high; return MATTER_OK; }
static Matter_Result_T boot_store(void* u,uint64_t n) { BootEvents* b=u; if(b->fail) return MATTER_PORT_ERROR; b->high=n; return MATTER_OK; }
static Matter_Result_T boot_snapshot(void* u,Matter_Diagnostics_Snapshot_T* s) { *s=((BootEvents*)u)->snapshot; return MATTER_OK; }
static Matter_Result_T boot_reset(void* u) { (void)u; return MATTER_OK; }
static void boot_events(void) {
    BootEvents* b=calloc(1,sizeof(*b)); ROOT_CHECK(b);
    Matter_Events_Port_T ep={b,boot_load,boot_store}; Matter_Events_T log=matter_events_new(&ep); ROOT_CHECK(log);
    RootFixture* f=root_fixture(); f->durable.software_version=0x12345678; root_open(f);
    const Matter_Event_Def_T* meta=matter_cluster_event(matter_root_cluster(f->root,0x28),0);
    ROOT_CHECK(meta && meta->priority==2 && meta->privilege==MATTER_IM_VIEW && !meta->fabric_scoped);
    b->fail=true; ROOT_CHECK(matter_root_startup(f->root,log,99)==MATTER_PORT_ERROR);
    uint64_t next; ROOT_CHECK(matter_events_position(log,&next)==MATTER_OK && !next);
    b->fail=false; ROOT_CHECK(matter_root_startup(f->root,log,100)==MATTER_OK && matter_root_startup(f->root,log,999)==MATTER_OK);
    const Matter_Event_Path_T start={0,0x28,0},boot={0,0x33,3}; size_t count;
    ROOT_CHECK(matter_events_copy(log,&start,0,b->records,&count)==MATTER_OK && count==1);
    const uint8_t startup[]={0x15,0x26,0,0x78,0x56,0x34,0x12,0x18};
    ROOT_CHECK(!b->records[0].number && b->records[0].timestamp_ms==100 && b->records[0].priority==2 &&
        b->records[0].size==sizeof(startup) && !memcmp(b->records[0].data,startup,sizeof(startup)));
    b->snapshot.general.boot_reason=6;
    Matter_Diagnostics_Port_T dp={b,boot_snapshot,boot_reset}; Matter_Diagnostics_T diag=matter_diagnostics_new(&dp,1,2); ROOT_CHECK(diag);
    meta=matter_cluster_event(diag,3); ROOT_CHECK(meta && meta->priority==2 && meta->privilege==MATTER_IM_VIEW && !meta->fabric_scoped);
    b->snapshot.general.boot_reason=7; ROOT_CHECK(matter_diagnostics_refresh(diag)==MATTER_PORT_ERROR && matter_diagnostics_boot(diag,log,101)==MATTER_PORT_ERROR);
    b->snapshot.general.boot_reason=6; ROOT_CHECK(matter_diagnostics_refresh(diag)==MATTER_OK);
    ROOT_CHECK(matter_diagnostics_boot(diag,log,102)==MATTER_OK && matter_diagnostics_boot(diag,log,999)==MATTER_OK);
    ROOT_CHECK(matter_events_copy(log,&boot,0,b->records,&count)==MATTER_OK && count==1 && b->records[0].number==1);
    const uint8_t reason[]={0x15,0x24,0,6,0x18};
    ROOT_CHECK(b->records[0].size==sizeof(reason) && !memcmp(b->records[0].data,reason,sizeof(reason)) && b->records[0].priority==2);
    ROOT_CHECK(matter_diagnostics_delete(diag)==MATTER_OK && matter_events_delete(log)==MATTER_OK); root_release(f); free(b);
    puts("PASS boot events: metadata, SoftwareVersion, backend reason, first-event ordering, retry/failure and exactly once");
}

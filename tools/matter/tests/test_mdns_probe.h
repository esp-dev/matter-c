static void probe_tests(void) {
    Matter_Mdns_Windows_T h=calloc(1,sizeof(*h)),peer=calloc(1,sizeof(*peer)); CHECK(h && peer);
    Matter_Discovery_T d=matter_discovery_commissionable(mac,random_id,840,1,5540); CHECK(d);
    Matter_Mdns_Record_T record=*matter_discovery_record(d);
    h->iface.ipv6[0]=0xfe; h->iface.ipv6[1]=0x80; h->iface.ipv6[15]=200; peer->iface=h->iface;
    CHECK(prepare(h,&record)); h->request=1; h->publishing=true; h->phase=1;
    for(int delta=-1;delta<=1;++delta) {
        record.port=(uint16_t)(5540+delta); CHECK(prepare(peer,&record));
        size_t n=packet(peer,true,false); memcpy(h->rx,peer->tx,n); h->probe_lost=false;
        CHECK(parse(h,n) && !h->conflict && h->probe_lost==(delta>0));
        CHECK(h->probe_count[0]==2 && h->probe_count[1]==1);
    }
    record.port=5540; CHECK(prepare(peer,&record)); h->probe_lost=false;
    /* Unsigned RDATA ordering, independent names, compressed SRV equality. */
    peer->iface.ipv6[15]=99; size_t n=packet(peer,true,false); memcpy(h->rx,peer->tx,n);
    /* prepare copied AAAA into records; update it as well for packet generation. */
    CHECK(prepare(peer,&record)); n=packet(peer,true,false); memcpy(h->rx,peer->tx,n);
    CHECK(parse(h,n) && !h->probe_lost);
    peer->iface.ipv6[15]=201; CHECK(prepare(peer,&record)); n=packet(peer,true,false); memcpy(h->rx,peer->tx,n);
    CHECK(parse(h,n) && h->probe_lost); h->probe_lost=false; peer->iface=h->iface;
    /* Wire order differs from sort order: TXT decides before a lower SRV port. */
    record.port=5539; CHECK(prepare(peer,&record)); n=packet(peer,true,false); memcpy(h->rx,peer->tx,n);
    size_t pos=12; for(unsigned i=0;i<2;++i) { CHECK(name(h->rx,n,&pos,h->name)); pos+=4; }
    for(unsigned i=0;i<3;++i) {
        CHECK(name(h->rx,n,&pos,h->name)); unsigned type=get16(h->rx+pos),len=get16(h->rx+pos+8); pos+=10;
        if(type==16) h->rx[pos+1]++;
        pos+=len;
    }
    CHECK(parse(h,n) && h->probe_lost); h->probe_lost=false;
    /* Complete validation precedes any deferred retry or conflict state. */
    for(size_t cut=0;cut<n;++cut) CHECK(!parse(h,cut) && !h->probe_lost && !h->conflict);
    set16(h->rx+10,1); CHECK(!parse(h,n) && !h->probe_lost);
    /* Extra / missing / duplicate records compare as sets, not wire order. */
    n=ka_question(h,h->instance,255,false); ka_record(h,&n,(unsigned)h->txt_start,120,8);
    CHECK(parse(h,n) && !h->probe_lost); /* Peer list is a strict prefix. */
    ka_record(h,&n,1,120,8); ka_record(h,&n,(unsigned)h->txt_start,120,8);
    CHECK(parse(h,n) && !h->probe_lost && h->probe_count[0]==2);
    size_t data=ka_record(h,&n,1,120,8); set16(h->rx+data-10,65);
    CHECK(parse(h,n) && h->probe_lost && h->probe_count[0]==3); h->probe_lost=false;
    set16(h->rx+data-8,3); CHECK(parse(h,n) && !h->probe_lost); /* Other class. */
    /* Authority without a matching question and known answers do not claim. */
    n=ka_question(h,NULL,0,false); data=ka_record(h,&n,1,120,8); h->rx[data+5]++;
    CHECK(parse(h,n) && !h->probe_lost && !h->conflict);
    set16(h->rx+8,0); set16(h->rx+6,1); CHECK(parse(h,n) && !h->probe_lost && !h->conflict);
    /* Response is only authoritative after first probe, including other types. */
    set16(h->rx+2,0x8400); h->phase=0; CHECK(parse(h,n) && !h->conflict);
    h->phase=1; CHECK(parse(h,n) && h->conflict); h->conflict=false;
    set16(h->rx+data-10,65); CHECK(parse(h,n) && h->conflict); h->conflict=false;
    /* Published host defends a probe without turning Authority into a failure. */
    h->installed=true; h->request=0; h->now=h->last_response=1000; h->peer_local=h->rx_multicast=true;
    n=packet(peer,true,false); memcpy(h->rx,peer->tx,n); CHECK(parse(h,n) && h->query_probe && !h->conflict);
    queue_reply(h,0); CHECK(h->queries[0].probe && h->queries[0].due==1000);
    n=ka_question(h,h->service,12,false); CHECK(parse(h,n)); queue_reply(h,0);
    CHECK(!h->queries[1].probe);
    uint32_t extra; h->now=1249; CHECK(!multicast_masks(h,0,&extra));
    h->now=1250; CHECK(multicast_masks(h,0,&extra) && !(multicast_masks(h,0,&extra)&1));
    h->now=2000; CHECK(multicast_masks(h,0,&extra)&1);
    memset(h->queries,0,sizeof(h->queries));
    n=ka_question(h,h->instance,255,false); set16(h->rx+n-2,0x8001);
    data=ka_record(h,&n,1,120,8); h->rx[data+5]++; CHECK(parse(h,n) && h->query_probe);
    queue_reply(h,0); CHECK(h->queries[0].unicast && h->queries[0].due==h->now && !h->queries[0].multicast);
    CHECK(remove_record(h,1)); h->request=0; h->installed=false;
    /* Drive actual core completion/backend/cancel transitions with no sockets. */
    h->sockets[0]=h->sockets[1]=INVALID_SOCKET;
    Matter_T owner=matter_new(NULL); CHECK(owner && matter_start(owner)==MATTER_OK);
    Matter_Mdns_Port_T port={h,publish,remove_record,cancel,detach};
    h->module=matter_mdns_new(owner,&port,matter_discovery_record(d)); CHECK(h->module);
    h->generation=1; CHECK(matter_mdns_backend(h->module,1,true)==MATTER_OK);
    CHECK(matter_mdns_start(h->module)==MATTER_OK && matter_mdns_process(h->module)==MATTER_PENDING);
    h->schedule=false; h->phase=1; h->probe_lost=true;
    uint64_t request=h->request;
    CHECK(matter_mdns_windows_poll(h,2100)==MATTER_PENDING && h->request==request && h->phase==0 && h->due==3100);
    CHECK(matter_mdns_windows_poll(h,3099)==MATTER_WOULD_BLOCK && !matter_mdns_is_published(h->module));
    /* Simulate successful three-probe completion, then authoritative conflict. */
    h->installed=true; h->phase=4; CHECK(complete(h,MATTER_OPERATION_SUCCEEDED)==MATTER_OK);
    CHECK(matter_mdns_is_published(h->module)); h->conflict=true;
    CHECK(matter_mdns_windows_poll(h,3100)==MATTER_PENDING && !h->installed && !matter_mdns_is_published(h->module));
    CHECK(h->generation==2 && matter_mdns_process(h->module)==MATTER_PENDING && h->request>request);
    h->schedule=false; h->phase=1; h->conflict=true;
    CHECK(matter_mdns_windows_poll(h,3200)==MATTER_OK && !h->request && h->retry_after==8200);
    CHECK(matter_mdns_process(h->module)==MATTER_PORT_ERROR);
    CHECK(matter_mdns_retry(h->module)==MATTER_OK && matter_mdns_process(h->module)==MATTER_PENDING);
    CHECK(matter_mdns_windows_poll(h,3300)==MATTER_WOULD_BLOCK && h->due>=8200);
    CHECK(matter_stop(owner)==MATTER_PENDING && matter_mdns_process(h->module)==MATTER_PENDING);
    h->probe_lost=h->conflict=true; /* Cancel wins, even with a queued event. */
    CHECK(matter_mdns_windows_poll(h,3400)==MATTER_OK && !h->request && !h->probe_lost && !h->conflict);
    CHECK(matter_mdns_process(h->module)==MATTER_OK && matter_get_state(owner)==MATTER_STATE_STOPPED);
    CHECK(matter_mdns_delete(h->module)==MATTER_OK && matter_delete(owner)==MATTER_OK);
    matter_discovery_delete(d); free(peer); free(h);
}

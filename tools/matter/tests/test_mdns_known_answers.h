/* Bounded private-engine tests; the publication and packet buffers live on heap. */
static size_t ka_question(Matter_Mdns_Windows_T h,const char* owner,uint16_t type,bool tc) {
    memset(h->rx,0,CAP); set16(h->rx+2,tc?0x0200:0); set16(h->rx+4,owner?1:0);
    if(!owner) return 12;
    void* p=mdns_string_make(h->rx,CAP,h->rx+12,owner,strlen(owner),NULL); CHECK(p);
    p=mdns_htons(p,type); p=mdns_htons(p,1); return (uint8_t*)p-h->rx;
}
/* Return RDATA offset for explicit corruptions. Explicit backward pointers
 * below test compression independently of the writer. */
static size_t ka_record(Matter_Mdns_Windows_T h,size_t* n,unsigned which,uint32_t ttl,unsigned section) {
    mdns_record_t r=answer_record(h,which); r.rclass=1; r.ttl=ttl;
    memset(&h->table,0,sizeof(h->table));
    void* end=which==h->txt_start?mdns_answer_add_txt_record(h->rx,CAP,h->rx+*n,
        h->records+which,h->count-which,1,ttl,&h->table):
        mdns_answer_add_record(h->rx,CAP,h->rx+*n,r,&h->table);
    CHECK(end); size_t start=*n; *n=(uint8_t*)end-h->rx;
    CHECK(name(h->rx,*n,&start,h->name));
    set16(h->rx+section,get16(h->rx+section)+1); return start+10;
}
static unsigned ka_pending(Matter_Mdns_Windows_T h) {
    unsigned n=0; for(unsigned i=0;i<QUERY_SLOTS;++i) n+=!!(h->queries[i].unicast|h->queries[i].multicast); return n;
}
static void known_answer_tests(void) {
    Matter_Mdns_Windows_T h=calloc(1,sizeof(*h)),other=calloc(1,sizeof(*other)); CHECK(h && other);
    Matter_Discovery_T d=matter_discovery_commissionable(mac,random_id,840,1,5540); CHECK(d);
    h->iface.index=13; h->iface.ipv6[0]=0xfe; h->iface.ipv6[1]=0x80; h->iface.ipv6[15]=1;
    CHECK(prepare(h,matter_discovery_record(d))); h->installed=h->peer_local=h->rx_multicast=true;
    h->peer.sin6_family=AF_INET6; h->peer.sin6_port=htons(5353); h->peer.sin6_addr.s6_addr[15]=2;
    h->now=h->last_response=1000;
    uint32_t txt=UINT32_C(1)<<h->txt_start;
    const uint32_t ttls[]={0,59,60,61,UINT32_MAX};
    for(unsigned i=0;i<=h->txt_start;++i) for(unsigned t=0;t<5;++t) {
        size_t n=ka_question(h,h->records[i].name.str,h->records[i].type,false);
        ka_record(h,&n,i,ttls[t],6); CHECK(parse(h,n));
        CHECK(h->known_answers==(ttls[t]>=60?(UINT32_C(1)<<i):0));
        CHECK(h->multicast_answers==(ttls[t]>=60?0:(UINT32_C(1)<<i)) && !h->conflict);
    }
    /* Semantic name equality, with explicitly backward compressed PTR RDATA. */
    size_t n=ka_question(h,h->instance,255,false),data=ka_record(h,&n,0,60,6);
    h->rx[data]=0xc0; h->rx[data+1]=12; set16(h->rx+data-2,2); n=data+2;
    for(size_t i=12;i<data;++i) if(h->rx[i]>='a' && h->rx[i]<='z') h->rx[i]-='a'-'A';
    CHECK(parse(h,n) && h->known_answers==1 && h->multicast_answers==(2|txt));
    n=ka_question(h,h->hostname,28,false); data=ka_record(h,&n,1,60,6);
    h->rx[data+6]=0xc0; h->rx[data+7]=12; set16(h->rx+data-2,8); n=data+8;
    CHECK(parse(h,n) && h->known_answers==2);
    /* Wrong class, owner, port, priority, weight, target, address and TXT bytes. */
    for(unsigned variant=0;variant<8;++variant) {
        unsigned which=variant==6?2:variant==7?(unsigned)h->txt_start:1;
        n=ka_question(h,h->instance,255,false); size_t rr_start=n; data=ka_record(h,&n,which,60,6);
        if(variant==0) set16(h->rx+data-8,3);
        else if(variant==1) h->rx[rr_start+1]^=1;
        else if(variant==2) h->rx[data+5]^=1;
        else if(variant==3) h->rx[data+1]=1;
        else if(variant==4) h->rx[data+3]=1;
        else if(variant==5) h->rx[data+7]^=1;
        else if(variant==6) h->rx[data+15]^=1;
        else h->rx[data+2]^=1;
        CHECK(parse(h,n) && !h->known_answers && !h->conflict);
    }
    /* Only Answer is a known-answer list. Probes request defense, not teardown. */
    n=ka_question(h,h->instance,255,false); ka_record(h,&n,1,60,10);
    CHECK(parse(h,n) && !h->known_answers && h->multicast_answers==(2|txt));
    n=ka_question(h,h->instance,255,false); data=ka_record(h,&n,1,60,8); h->rx[data+5]^=1;
    CHECK(parse(h,n) && !h->conflict && h->query_probe);
    n=ka_question(h,h->instance,255,false); ka_record(h,&n,1,60,6);
    h->legacy=true; CHECK(parse(h,n) && !h->known_answers && h->unicast_answers==(2|txt)); h->legacy=false;
    CHECK(parse(h,n) && h->multicast_answers==txt && additionals(h,txt,h->known_answers)==(4|(UINT32_C(1)<<NSEC_HOST)));
    size_t out=response_packet(h,txt,additionals(h,txt,h->known_answers),false);
    CHECK(out && get16(h->tx+6)==1 && get16(h->tx+10)==2); /* SRV not reintroduced. */
    /* Initial TC + final questionless known answers; never answer early. */
    n=ka_question(h,h->instance,255,true); CHECK(parse(h,n)); queue_reply(h,0);
    CHECK(ka_pending(h)==1 && h->queries[0].due>=1400 && h->queries[0].due<=1500);
    uint64_t due=h->queries[0].due; uint32_t extra;
    h->now=1399; CHECK(!multicast_masks(h,0,&extra));
    n=ka_question(h,NULL,0,false); ka_record(h,&n,1,60,6); CHECK(parse(h,n)); queue_reply(h,0);
    CHECK(h->queries[0].due==due && h->queries[0].multicast==txt && h->queries[0].known==2);
    /* A TC continuation extends the wait; malformed tails have no effects. */
    h->now=1400; n=ka_question(h,NULL,0,true); ka_record(h,&n,2,60,6);
    for(size_t cut=0;cut<n;++cut) CHECK(!parse(h,cut) && h->queries[0].due==due);
    CHECK(parse(h,n)); queue_reply(h,0);
    CHECK(h->queries[0].due>=1800 && h->queries[0].due<=1900 && h->queries[0].known==6);
    due=h->queries[0].due;
    /* Source/family/destination isolation, then valid source suppresses rest. */
    n=ka_question(h,NULL,0,true); ka_record(h,&n,(unsigned)h->txt_start,60,6); CHECK(parse(h,n));
    h->peer.sin6_addr.s6_addr[15]=3; queue_reply(h,0); h->peer.sin6_addr.s6_addr[15]=2;
    queue_reply(h,1); h->rx_multicast=false; queue_reply(h,0); h->rx_multicast=true;
    h->peer.sin6_port=htons(4444); queue_reply(h,0); h->peer.sin6_port=htons(5353);
    CHECK(h->queries[0].due==due && h->queries[0].multicast==txt);
    queue_reply(h,0); CHECK(!ka_pending(h)); queue_reply(h,0); CHECK(!ka_pending(h));
    /* Two queriers: A knows SRV, B needs it. Union after suppression. */
    h->now=2000; n=ka_question(h,h->instance,255,true); ka_record(h,&n,1,60,6); CHECK(parse(h,n)); queue_reply(h,0);
    h->peer.sin6_addr.s6_addr[15]=3;
    n=ka_question(h,h->instance,33,false); CHECK(parse(h,n)); queue_reply(h,0);
    h->now=2600; CHECK(multicast_masks(h,0,&extra)==(2|txt) && extra==(4|(UINT32_C(1)<<NSEC_HOST)));
    CHECK(!multicast_masks(h,1,&extra) && !ka_pending(other));
    /* Fixed slots: the ninth query cannot clobber any existing entry. */
    for(unsigned i=2;i<QUERY_SLOTS;++i) { CHECK(parse(h,n)); queue_reply(h,0); }
    CHECK(ka_pending(h)==QUERY_SLOTS); memcpy(other->queries,h->queries,sizeof(h->queries));
    CHECK(parse(h,n)); queue_reply(h,0); CHECK(!memcmp(other->queries,h->queries,sizeof(h->queries)));
    CHECK(remove_record(h,1) && !ka_pending(h)); h->request=0;
    h->now=UINT64_MAX-10; n=ka_question(h,h->instance,255,true); CHECK(parse(h,n)); queue_reply(h,0);
    CHECK(h->queries[0].due==UINT64_MAX); detach(h); CHECK(!ka_pending(h));
    /* QU uses the same suppression/TC state, with an immediate unique reply
     * normally; no legacy question snapshot may bypass the TC timer. */
    h->now=h->last_response=3000;
    n=ka_question(h,h->instance,255,true); set16(h->rx+n-2,0x8001);
    ka_record(h,&n,1,60,6); CHECK(parse(h,n)); queue_reply(h,0);
    CHECK(h->queries[0].unicast==txt && !h->queries[0].multicast &&
        h->queries[0].due>=3400 && h->queries[0].due<=3500 && !h->replies[0].size);
    n=ka_question(h,NULL,0,false); ka_record(h,&n,(unsigned)h->txt_start,60,6);
    CHECK(parse(h,n)); queue_reply(h,0); CHECK(!ka_pending(h));
    n=ka_question(h,h->instance,255,false); set16(h->rx+n-2,0x8001);
    CHECK(parse(h,n)); queue_reply(h,0); CHECK(h->queries[0].due==h->now);
    detach(h);
    /* Entropy failure or two rejected samples drop only the new query. */
    n=ka_question(h,h->instance,255,true); CHECK(parse(h,n));
    for(unsigned mode=1;mode<=2;++mode) {
        rng_fault=mode; rng_calls=0; queue_reply(h,0);
        CHECK(!ka_pending(h) && rng_calls==mode && h->installed);
    }
    rng_fault=0;
    printf("mDNS bounded query state: %zu bytes (%u slots); adapter %zu bytes\n",
        sizeof(h->queries),QUERY_SLOTS,sizeof(*h));
    /* Invalid supported RDATA is rejected atomically, even when unrelated. */
    n=ka_question(h,h->instance,255,true); data=ka_record(h,&n,1,60,6);
    set16(h->rx+data-2,6); CHECK(!parse(h,data+6) && !h->known_answers);
    n=ka_question(h,h->hostname,28,true); data=ka_record(h,&n,2,60,6);
    set16(h->rx+data-2,15); CHECK(!parse(h,data+15));
    n=ka_question(h,h->instance,16,true); data=ka_record(h,&n,(unsigned)h->txt_start,60,6);
    h->rx[data]=255; CHECK(!parse(h,n));
    h->legacy=true; n=ka_question(h,h->instance,255,true); CHECK(!parse(h,n));
    h->legacy=false; set16(h->rx+2,0x8200); CHECK(!parse(h,n));
    matter_discovery_delete(d); free(h); free(other);
}

/* Synthesized records share the existing mask/TC queue, no new RX allocation. */
static void nsec_tests(void) {
    Matter_Mdns_Windows_T h=calloc(1,sizeof(*h)); CHECK(h);
    Matter_Discovery_T d=matter_discovery_commissionable(mac,random_id,840,1,5540); CHECK(d);
    h->iface.ipv6[0]=0xfe; h->iface.ipv6[1]=0x80; h->iface.ipv6[15]=1;
    CHECK(prepare(h,matter_discovery_record(d)));
    h->installed=h->peer_local=h->rx_multicast=true; h->now=h->last_response=1000;
    h->peer.sin6_family=AF_INET6; h->peer.sin6_port=htons(5353);
    uint32_t host_bit=UINT32_C(1)<<NSEC_HOST,instance_bit=UINT32_C(1)<<NSEC_INSTANCE;
    const uint16_t missing[]={1,15,47,256,65535};
    for(unsigned host=0;host<2;++host) for(unsigned legacy=0;legacy<2;++legacy) {
        const char* owner=host?h->hostname:h->instance; uint32_t bit=host?host_bit:instance_bit;
        for(unsigned i=0;i<sizeof(missing)/sizeof(*missing);++i) {
            h->legacy=legacy!=0;
            size_t n=ka_question(h,owner,missing[i],false); set16(h->rx,0x1234);
            CHECK(parse(h,n) && (legacy?h->unicast_answers:h->multicast_answers)==bit && !h->conflict);
            CHECK(!additionals(h,bit,0));
            size_t out=response_packet(h,bit,0,legacy!=0),pos=legacy?n:12;
            CHECK(out && get16(h->tx+2)==0x8400 && get16(h->tx+6)==1 && !get16(h->tx+8) && !get16(h->tx+10));
            CHECK(get16(h->tx)==(legacy?0x1234:0) && get16(h->tx+4)==legacy);
            CHECK(name(h->tx,out,&pos,h->name) && !_stricmp(h->name,owner));
            CHECK(get16(h->tx+pos)==47 && get16(h->tx+pos+2)==(legacy?1:0x8001) && get32(h->tx+pos+4)==(legacy?10:120));
            size_t len=get16(h->tx+pos+8); pos+=10; CHECK(out-pos==len);
            CHECK(legacy?h->tx[pos]<64:(h->tx[pos]&0xc0)==0xc0);
            CHECK(name(h->tx,out,&pos,h->target) && !_stricmp(h->target,owner));
            static const uint8_t instance_bitmap[]={0,5,0,0,0x80,0,0x40},host_bitmap[]={0,4,0,0,0,0x08};
            CHECK(out-pos==(host?sizeof(host_bitmap):sizeof(instance_bitmap)) &&
                !memcmp(h->tx+pos,host?host_bitmap:instance_bitmap,out-pos));
        }
    }
    h->legacy=false;
    /* Existing positive and ANY queries are unchanged, shared/unknown names silent. */
    size_t n=ka_question(h,h->hostname,28,false); CHECK(parse(h,n) && h->multicast_answers==4);
    n=ka_question(h,h->instance,255,false); CHECK(parse(h,n) && h->multicast_answers==(2|(UINT32_C(1)<<h->txt_start)));
    const char* shared[]={h->service,h->subtypes[0],"absent.local."};
    for(unsigned i=0;i<3;++i) { n=ka_question(h,shared[i],1,false); CHECK(parse(h,n) && !h->multicast_answers); }
    n=ka_question(h,h->hostname,1,false); set16(h->rx+n-2,3); CHECK(parse(h,n) && !h->multicast_answers);
    set16(h->rx+n-2,255); CHECK(parse(h,n) && h->multicast_answers==host_bit);
    h->installed=false; CHECK(parse(h,n) && !h->multicast_answers); h->installed=true;
    /* Mixed positive/negative questions retain both answers. */
    n=ka_question(h,h->hostname,1,false);
    void* p=mdns_string_make(h->rx,CAP,h->rx+n,h->instance,strlen(h->instance),NULL); CHECK(p);
    p=mdns_htons(p,33); p=mdns_htons(p,1); set16(h->rx+4,2); n=(uint8_t*)p-h->rx;
    CHECK(parse(h,n) && h->multicast_answers==(host_bit|2));
    CHECK(additionals(h,host_bit|2,0)==((UINT32_C(1)<<h->txt_start)|4));
    /* Build a known NSEC with an uncompressed next-name; copy just its RR. */
    memset(&h->table,0,sizeof(h->table));
    void* rr_end=nsec_write(h,h->tx+12,CAP,true,true); CHECK(rr_end);
    size_t rr_size=(uint8_t*)rr_end-h->tx-12;
    for(unsigned ttl=59;ttl<=60;++ttl) {
        n=ka_question(h,h->hostname,1,false); size_t rr=n;
        memcpy(h->rx+n,h->tx+12,rr_size); n+=rr_size; set16(h->rx+6,1);
        CHECK(name(h->rx,n,&rr,h->name)); mdns_htonl(h->rx+rr+4,ttl);
        CHECK(parse(h,n) && h->known_answers==(ttl==60?host_bit:0) && h->multicast_answers==(ttl==60?0:host_bit));
    }
    /* Next Domain Name is ignored, bitmap determines semantic known state. */
    size_t pos=12; CHECK(name(h->rx,n,&pos,h->name)); pos+=4;
    CHECK(name(h->rx,n,&pos,h->name)); pos+=10; h->rx[pos+1]^=1;
    CHECK(parse(h,n) && h->known_answers==host_bit);
    CHECK(name(h->rx,n,&pos,h->target)); size_t bitmap=pos;
    h->rx[bitmap+5]|=1; CHECK(parse(h,n) && !h->known_answers); h->rx[bitmap+5]&=~1;
    /* NSEC with unsupported window or broken internal RDATA is ignored alone. */
    h->rx[bitmap]=1; CHECK(parse(h,n) && !h->known_answers && h->multicast_answers==host_bit);
    h->rx[bitmap]=0; h->rx[bitmap+1]=33; CHECK(parse(h,n) && !h->known_answers);
    h->rx[bitmap+1]=0; CHECK(parse(h,n) && !h->known_answers);
    for(size_t cut=0;cut<n;++cut) CHECK(!parse(h,cut)); /* Outer RDLENGTH still mandatory. */
    /* Known NSEC can arrive in the final TC packet, for the same source only. */
    n=ka_question(h,h->hostname,1,true); CHECK(parse(h,n)); queue_reply(h,0);
    CHECK(h->queries[0].multicast==host_bit && h->queries[0].due>=1400 && h->queries[0].due<=1500);
    n=ka_question(h,NULL,0,false); memcpy(h->rx+n,h->tx+12,rr_size); n+=rr_size; set16(h->rx+6,1);
    pos=12; CHECK(name(h->rx,n,&pos,h->name)); mdns_htonl(h->rx+pos+4,60);
    CHECK(parse(h,n)); h->peer.sin6_addr.s6_addr[15]=2; queue_reply(h,0); CHECK(ka_pending(h)==1);
    h->peer.sin6_addr.s6_addr[15]=0; queue_reply(h,0); CHECK(!ka_pending(h));
    /* Compressed next-name is also accepted in known answers. */
    size_t wire=response_packet(h,host_bit,0,false); CHECK(wire);
    memcpy(h->rx,h->tx,wire); set16(h->rx+2,0);
    CHECK(parse(h,wire) && h->known_answers==host_bit);
    /* Broken internal NSEC must not discard a valid positive question. */
    n=ka_question(h,h->instance,33,false); pos=n;
    p=mdns_string_make(h->rx,CAP,h->rx+n,h->hostname,strlen(h->hostname),NULL); CHECK(p);
    p=mdns_htons(p,47); p=mdns_htons(p,1); p=mdns_htonl(p,120); p=mdns_htons(p,2);
    p=mdns_htons(p,0xffff); n=(uint8_t*)p-h->rx; set16(h->rx+6,1);
    CHECK(parse(h,n) && !h->known_answers && h->multicast_answers==2);
    /* Writer never crosses its packet budget, including incomplete names. */
    for(size_t cap=12;cap<80;++cap) {
        memset(h->tx,0xa5,CAP); memset(&h->table,0,sizeof(h->table));
        void* end=nsec_write(h,h->tx+12,cap,true,false);
        CHECK(h->tx[cap]==0xa5 && (!end || (uint8_t*)end<=h->tx+cap));
    }
    /* QU NSEC goes unicast immediately, keeping the TC path available. */
    n=ka_question(h,h->hostname,1,false); set16(h->rx+n-2,0x8001); CHECK(parse(h,n)); queue_reply(h,0);
    CHECK(h->queries[0].unicast==host_bit && !h->queries[0].multicast && h->queries[0].due==1000);
    CHECK(remove_record(h,1) && !ka_pending(h));
    matter_discovery_delete(d); free(h);
}

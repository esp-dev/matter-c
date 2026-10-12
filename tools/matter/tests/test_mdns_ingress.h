/* Private adapter tests, included after its implementation. Large state stays
 * on heap; no socket or public test hooks needed for policy/wire validation. */
static size_t make_question(Matter_Mdns_Windows_T h,uint16_t id,uint16_t type,uint16_t cl) {
    memset(h->rx,0,CAP); set16(h->rx,id); set16(h->rx+4,1);
    void* p=mdns_string_make(h->rx,CAP,h->rx+12,h->instance,strlen(h->instance),NULL); CHECK(p);
    p=mdns_htons(p,type); p=mdns_htons(p,cl); return (uint8_t*)p-h->rx;
}
static void check_reply(Matter_Mdns_Windows_T h,size_t n,bool legacy) {
    CHECK(n>=12 && n<=(legacy?512:CAP) && get16(h->tx)==(legacy?0x1234:0));
    CHECK(get16(h->tx+4)==(legacy?1:0) && get16(h->tx+6)==2 && get16(h->tx+10)==2);
    size_t pos=12;
    if(legacy) { CHECK(!memcmp(h->rx+12,h->tx+12,h->question_end-12)); pos=h->question_end; }
    unsigned records=get16(h->tx+6)+get16(h->tx+10); bool srv=false,txt=false,aaaa=false,a=false;
    for(unsigned i=0;i<records;++i) {
        CHECK(name(h->tx,n,&pos,h->name) && n-pos>=10);
        uint16_t type=get16(h->tx+pos),cl=get16(h->tx+pos+2),len=get16(h->tx+pos+8);
        CHECK(cl==(legacy?1:0x8001) && get32(h->tx+pos+4)==(legacy?10:TTL)); pos+=10;
        CHECK(len<=n-pos);
        if(type==33) {
            srv=true; CHECK(get16(h->tx+pos+4)==5540);
            if(legacy) CHECK(h->tx[pos+6]<64); /* Uncompressed SRV target. */
            size_t end=pos+6; CHECK(name(h->tx,n,&end,h->target) && end==pos+len && !strcmp(h->target,h->hostname));
        } else if(type==16) { txt=true; CHECK(txt_valid(h->tx+pos,len)); }
        else if(type==28) { aaaa=true; CHECK(len==16 && !memcmp(h->tx+pos,h->iface.ipv6,16)); }
        else if(type==1) { a=true; CHECK(len==4 && !memcmp(h->tx+pos,h->iface.ipv4,4)); }
        else CHECK(false);
        pos+=len;
    }
    CHECK(pos==n && srv && txt && aaaa && a);
}
static void ingress_tests(void) {
    Matter_Mdns_Windows_T h=calloc(1,sizeof(*h)); CHECK(h);
    h->iface=(Matter_Mdns_Windows_Interface_T){.index=13,.ipv4_index=7,.ipv6={0xfe,0x80},
        .ipv4={192,168,136,1},.has_ipv4=true,.ipv4_prefix_length=24}; h->iface.ipv6[15]=1;
    Matter_Discovery_T d=matter_discovery_operational(mac,random_id,1,5540); CHECK(d);
    CHECK(prepare(h,matter_discovery_record(d)));
    SOCKADDR_IN6 peer={.sin6_family=AF_INET6,.sin6_port=htons(5353)};
    peer.sin6_addr.s6_addr[0]=0xfe; peer.sin6_addr.s6_addr[1]=0x80; peer.sin6_addr.s6_addr[15]=2;
    static const uint8_t group6[16]={0xff,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0xfb},group4[]={224,0,0,251};
    size_t n=make_question(h,0x1234,255,1); h->now=1000; h->last_response=1000;
    CHECK(ingress(h,0,&peer,13,group6,64,0,n) && h->peer_local && h->rx_multicast && !h->legacy);
    CHECK(parse(h,n) && h->respond && !h->unicast_answers); h->respond=false;
    CHECK(!ingress(h,0,&peer,12,group6,64,0,n));
    CHECK(!ingress(h,0,&peer,0,group6,64,0,n));
    CHECK(!ingress(h,0,&peer,13,group6,0,0,n));
    CHECK(!ingress(h,0,&peer,13,group6,256,0,n));
    CHECK(!ingress(h,0,&peer,13,group6,64,MSG_TRUNC,n));
    CHECK(!ingress(h,0,&peer,13,group6,64,MSG_CTRUNC,n));
    CHECK(!ingress(h,0,&peer,13,group6,64,0,11));
    CHECK(!ingress(h,0,&peer,13,group6,64,0,CAP+1));
    peer.sin6_addr.s6_addr[0]=0xff; CHECK(!ingress(h,0,&peer,13,group6,255,0,n)); peer.sin6_addr.s6_addr[0]=0xfe;
    /* QU and direct unicast: normal mDNS ID0/no questions/cache flush. */
    n=make_question(h,0x1234,255,0x8001);
    CHECK(ingress(h,0,&peer,13,group6,64,0,n) && parse(h,n) && !h->respond && h->unicast_answers);
    check_reply(h,unicast_packet(h),false);
    h->now=31000; CHECK(parse(h,n) && h->respond); h->now=1000; h->respond=false;
    n=make_question(h,0x1234,255,1);
    CHECK(ingress(h,0,&peer,13,h->iface.ipv6,64,0,n) && parse(h,n) && h->unicast_answers);
    peer.sin6_addr.s6_addr[0]=0x20;
    CHECK(!ingress(h,0,&peer,13,h->iface.ipv6,255,0,n));
    CHECK(ingress(h,0,&peer,13,group6,64,0,n) && parse(h,n) && h->respond && !h->unicast_answers);
    peer.sin6_addr.s6_addr[0]=0xfe; h->respond=false;
    /* Legacy response goes to the actual source endpoint, echoes question/ID. */
    peer.sin6_port=htons(44444);
    CHECK(ingress(h,0,&peer,13,group6,64,0,n) && h->legacy && parse(h,n));
    check_reply(h,unicast_packet(h),true);
    h->installed=true;
    for(unsigned i=0;i<5;++i) { h->peer.sin6_port=htons((uint16_t)(44444+i)); queue_reply(h,0); }
    for(unsigned i=0;i<4;++i) CHECK(h->replies[i].size && h->replies[i].peer.sin6_port==htons((uint16_t)(44444+i)));
    memset(h->rx,0,CAP); CHECK(h->replies[0].packet[0]==0x12); /* owned snapshot */
    CHECK(remove_record(h,1)); for(unsigned i=0;i<4;++i) CHECK(!h->replies[i].size);
    h->request=0; h->installed=false;
    n=make_question(h,0x1234,255,1); CHECK(ingress(h,0,&peer,13,group6,64,0,n));
    for(size_t cut=0;cut<n;++cut) CHECK(!parse(h,cut) && !h->unicast_answers);
    CHECK(parse(h,n)); queue_reply(h,0); CHECK(!h->replies[0].size);
    /* A malformed trailing RR cannot queue a response or change conflict state. */
    set16(h->rx+10,1); CHECK(!parse(h,n) && !h->unicast_answers && !h->conflict);
    n=make_question(h,0x1234,255,1); h->rx[12]=0xc0; h->rx[13]=0; CHECK(!parse(h,n));
    /* Responses from a non-mDNS port or unsolicited unicast never enter resolver. */
    n=make_question(h,0,255,1); set16(h->rx+2,0x8400);
    CHECK(!ingress(h,0,&peer,13,group6,255,0,n)); peer.sin6_port=htons(5353);
    CHECK(ingress(h,0,&peer,13,group6,64,0,n));
    CHECK(!ingress(h,0,&peer,13,h->iface.ipv6,255,0,n));
    /* IPv4 prefix, selected destination/interface, and off-link reflection. */
    SOCKADDR_IN* v4=(SOCKADDR_IN*)&peer; memset(&peer,0,sizeof(peer));
    v4->sin_family=AF_INET; v4->sin_port=htons(44444); v4->sin_addr.s_addr=htonl(0xc0a88881);
    n=make_question(h,0x1234,255,1);
    CHECK(ingress(h,1,&peer,7,group4,64,0,n) && h->peer_local && h->legacy && parse(h,n));
    check_reply(h,unicast_packet(h),true);
    CHECK(!ingress(h,1,&peer,13,group4,64,0,n));
    v4->sin_addr.s_addr=htonl(0xc0a88981); CHECK(!ingress(h,1,&peer,7,group4,255,0,n));
    v4->sin_port=htons(5353); CHECK(ingress(h,1,&peer,7,group4,64,0,n) && !h->peer_local);
    CHECK(!ingress(h,1,&peer,7,h->iface.ipv4,255,0,n));
    v4->sin_addr.s_addr=htonl(0xe00000fb); CHECK(!ingress(h,1,&peer,7,group4,255,0,n));
    /* Conventional DNS's 512-byte limit truncates only between complete RRs. */
    memset(h->target,'x',240); h->target[240]=0;
    Matter_Mdns_Txt_T txts[]={{"a",h->target},{"b",h->target}};
    Matter_Mdns_Record_T record=*matter_discovery_record(d); record.txt=txts; record.txt_count=2;
    CHECK(prepare(h,&record)); n=make_question(h,0x1234,255,1);
    v4->sin_addr.s_addr=htonl(0xc0a88881); v4->sin_port=htons(44444);
    CHECK(ingress(h,1,&peer,7,group4,64,0,n) && parse(h,n));
    size_t reply_size=unicast_packet(h);
    CHECK(reply_size && reply_size<=512 && get16(h->tx+2)==0x8600 && get16(h->tx+6)==1 && !get16(h->tx+10));
    matter_discovery_delete(d); free(h);
}

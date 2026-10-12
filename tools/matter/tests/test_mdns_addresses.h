static void address_tests(void) {
    Matter_Mdns_Windows_T h=calloc(1,sizeof(*h)),peer=calloc(1,sizeof(*peer)); CHECK(h && peer);
    Matter_Discovery_T d=matter_discovery_commissionable(mac,random_id,840,1,5540); CHECK(d);
    h->iface.ipv6[0]=0xfe; h->iface.ipv6[1]=0x80; h->iface.ipv6[15]=1;
    memcpy(h->iface.ipv4,(const uint8_t[]){192,168,1,2},4); h->iface.has_ipv4=true;
    CHECK(interface_address(&h->iface,false,h->iface.ipv6));
    CHECK(interface_address(&h->iface,true,h->iface.ipv4));
    uint8_t addr[16]={0x20,1,0x0d,0xb8}; addr[15]=7;
    CHECK(interface_address(&h->iface,false,addr) && interface_address(&h->iface,false,addr));
    CHECK(h->iface.address_count==3 && prepare(h,matter_discovery_record(d)));
    CHECK(h->address_count==3 && h->addresses==28 && h->ipv4_records==8);
    h->installed=h->rx_multicast=h->peer_local=true; h->now=2000;
    size_t n=ka_question(h,h->hostname,28,false); CHECK(parse(h,n) && h->multicast_answers==20);
    CHECK(additionals(h,20,0)==8 && additionals(h,8,0)==20);
    CHECK(nsec_byte(h,true,0)==0x40 && nsec_byte(h,true,3)==8);
    n=ka_question(h,h->hostname,1,false); CHECK(parse(h,n) && h->multicast_answers==8);
    size_t wire=response_packet(h,8,additionals(h,8,0),false),pos=12;
    CHECK(wire && get16(h->tx+6)==1 && get16(h->tx+10)==2);
    CHECK(name(h->tx,wire,&pos,h->name) && get16(h->tx+pos)==1 && get16(h->tx+pos+8)==4);
    CHECK(!memcmp(h->tx+pos+10,h->iface.ipv4,4));
    n=ka_question(h,h->hostname,28,false); ka_record(h,&n,2,60,6);
    CHECK(parse(h,n) && h->multicast_answers==16 && additionals(h,16,h->known_answers)==8);
    /* Identical co-owner replies, including a second AAAA, are not conflicts. */
    n=packet(h,false,false); memcpy(h->rx,h->tx,n); CHECK(parse(h,n) && !h->conflict);
    peer->iface=h->iface; CHECK(prepare(peer,matter_discovery_record(d)));
    h->installed=false; h->publishing=true; h->request=1; h->phase=1;
    n=packet(peer,true,false); memcpy(h->rx,peer->tx,n); CHECK(parse(h,n) && !h->probe_lost);
    /* Address set sorted independently of interface enumeration order. */
    Matter_Mdns_Host_Address_T swap=peer->iface.addresses[0]; peer->iface.addresses[0]=peer->iface.addresses[2]; peer->iface.addresses[2]=swap;
    CHECK(prepare(peer,matter_discovery_record(d))); n=packet(peer,true,false); memcpy(h->rx,peer->tx,n);
    CHECK(parse(h,n) && !h->probe_lost);
    peer->iface.ipv4[3]++; for(unsigned i=0;i<3;++i) if(peer->iface.addresses[i].ipv4) peer->iface.addresses[i].bytes[3]++;
    CHECK(prepare(peer,matter_discovery_record(d))); n=packet(peer,true,false); memcpy(h->rx,peer->tx,n);
    CHECK(parse(h,n) && h->probe_lost); h->probe_lost=false;
    for(unsigned i=3;i<MATTER_MDNS_HOST_ADDRESSES;++i) { addr[15]=(uint8_t)(i+10); CHECK(interface_address(&h->iface,false,addr)); }
    CHECK(prepare(h,matter_discovery_record(d)) && h->address_count==MATTER_MDNS_HOST_ADDRESSES && packet(h,true,false));
    addr[15]=99; CHECK(!interface_address(&h->iface,false,addr));
    h->iface.address_count++; CHECK(!prepare(h,matter_discovery_record(d))); h->iface.address_count--;
    h->iface.addresses[0].bytes[15]++; CHECK(!prepare(h,matter_discovery_record(d))); /* Missing primary. */
    CHECK(!usable_address(true,(const uint8_t[]){224,0,0,1}) && !usable_address(false,(const uint8_t[16]){0}));
    /* Duplicate response threshold differs from known-answer TTL/2. */
    h->iface.address_count=0; h->iface.has_ipv4=false; CHECK(prepare(h,matter_discovery_record(d)));
    h->installed=true; h->request=0; h->phase=5; h->now=h->last_response=1000;
    uint32_t txt=UINT32_C(1)<<h->txt_start;
    for(unsigned ttl=119;ttl<=120;++ttl) {
        memset(h->queries,0,sizeof(h->queries));
        n=ka_question(h,h->instance,255,true); CHECK(parse(h,n)); queue_reply(h,0); queue_reply(h,1);
        uint64_t due=h->queries[0].due;
        n=ka_question(h,NULL,0,false); ka_record(h,&n,1,ttl,6); set16(h->rx+2,0x8400);
        CHECK(parse(h,n)); queue_reply(h,0);
        CHECK(h->queries[0].multicast==(ttl==120?txt:2|txt) && h->queries[0].due==due);
        CHECK(h->queries[1].multicast==(2|txt)); /* Other IP family still needs it. */
        if(ttl==120) {
            CHECK(additionals(h,txt,h->queries[0].known)==(4|(UINT32_C(1)<<NSEC_HOST)));
            n=ka_question(h,NULL,0,false); ka_record(h,&n,(unsigned)h->txt_start,120,10); set16(h->rx+2,0x8400);
            for(size_t cut=0;cut<n;++cut) CHECK(!parse(h,cut) && h->queries[0].multicast==txt);
            CHECK(parse(h,n)); h->rx_multicast=false; queue_reply(h,0); CHECK(h->queries[0].multicast==txt);
            h->rx_multicast=true; queue_reply(h,0); CHECK(!h->queries[0].multicast && h->queries[1].multicast);
        }
    }
    memset(h->queries,0,sizeof(h->queries));
    n=ka_question(h,h->instance,33,true); set16(h->rx+n-2,0x8001); CHECK(parse(h,n)); queue_reply(h,0);
    CHECK(h->queries[0].unicast==2);
    n=ka_question(h,NULL,0,false); ka_record(h,&n,1,120,6); set16(h->rx+2,0x8400);
    CHECK(parse(h,n)); queue_reply(h,0); CHECK(h->queries[0].unicast==2);
    CHECK(remove_record(h,7) && !ka_pending(h));
    matter_discovery_delete(d); free(peer); free(h);
}

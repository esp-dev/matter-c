/* Private Linux I/O for the shared bounded mDNS/resolver engine.
 * Included once by matter_mdns_windows.c; no protocol parser duplication. */
Matter_Result_T matter_mdns_windows_interface(uint32_t index,Matter_Mdns_Windows_Interface_T* out) {
    if(!index || !out) return MATTER_INVALID_ARGUMENT;
    struct ifaddrs* all=NULL;
    if(getifaddrs(&all)) return MATTER_PORT_ERROR;
    Matter_Mdns_Windows_Interface_T found={.index=index,.ipv4_index=index};
    bool v6=false,mac=false; Matter_Result_T result=MATTER_OK;
    for(struct ifaddrs* a=all;a;a=a->ifa_next) {
        if(!a->ifa_addr || if_nametoindex(a->ifa_name)!=index ||
            !(a->ifa_flags&IFF_UP) || !(a->ifa_flags&IFF_MULTICAST)) continue;
        if(a->ifa_addr->sa_family==AF_PACKET) {
            const struct sockaddr_ll* p=(const struct sockaddr_ll*)a->ifa_addr;
            if(p->sll_halen==6) { memcpy(found.mac,p->sll_addr,6); mac=true; }
        } else if(a->ifa_addr->sa_family==AF_INET && a->ifa_netmask) {
            const struct sockaddr_in* p=(const struct sockaddr_in*)a->ifa_addr;
            const struct sockaddr_in* m=(const struct sockaddr_in*)a->ifa_netmask;
            uint32_t mask=ntohl(m->sin_addr.s_addr); unsigned bits=0;
            while(mask&UINT32_C(0x80000000)) { ++bits; mask<<=1; }
            if(mask) continue;
            if(!interface_address(&found,true,(const uint8_t*)&p->sin_addr)) { result=MATTER_LIMIT_REACHED; break; }
            memcpy(found.ipv4,&p->sin_addr,4); found.has_ipv4=true; found.ipv4_prefix_length=(uint8_t)bits;
        }
    }
    freeifaddrs(all);
    if(result!=MATTER_OK) return result;
    FILE* addresses=fopen("/proc/net/if_inet6","r"); if(!addresses) return MATTER_PORT_ERROR;
    char hex[33],device[17]; unsigned number,prefix,scope,flags; uint8_t bytes[16];
    int fields;
    /* getifaddrs lacks per-address DAD state. Read the selected IPv6 snapshot. */
    while((fields=fscanf(addresses,"%32s %x %x %x %x %16s",hex,&number,&prefix,&scope,&flags,device))==6) {
        if(number!=index || (flags&0x48)) continue; /* tentative or DAD failed */
        if(strlen(hex)!=32) { result=MATTER_PORT_ERROR; break; }
        for(unsigned i=0;i<16;++i) {
            unsigned value; if(sscanf(hex+i*2,"%2x",&value)!=1) { result=MATTER_PORT_ERROR; break; }
            bytes[i]=(uint8_t)value;
        }
        if(result!=MATTER_OK) break;
        if(!interface_address(&found,false,bytes)) { result=MATTER_LIMIT_REACHED; break; }
        if(bytes[0]==0xfe && (bytes[1]&0xc0)==0x80) { memcpy(found.ipv6,bytes,16); v6=true; }
    }
    if(ferror(addresses) || (fields!=EOF && fields!=6)) result=MATTER_PORT_ERROR;
    fclose(addresses); if(result!=MATTER_OK) return result;
    if(!v6 || !mac) return MATTER_OFFLINE;
    *out=found; return MATTER_OK;
}
static bool open_sockets(Matter_Mdns_Windows_T h) {
    int yes=1,ttl=255,index=(int)h->iface.index;
    int unicast6=(int)htonl(h->iface.index); /* UNICAST_IF uses network byte order. */
    int s=socket(AF_INET6,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,IPPROTO_UDP); h->sockets[0]=s;
    struct sockaddr_in6 local={.sin6_family=AF_INET6,.sin6_port=htons(5353)};
    struct ipv6_mreq group={0}; group.ipv6mr_multiaddr.s6_addr[0]=0xff; group.ipv6mr_multiaddr.s6_addr[1]=2;
    group.ipv6mr_multiaddr.s6_addr[15]=0xfb; group.ipv6mr_interface=h->iface.index;
    if(s<0 || setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes)) ||
        setsockopt(s,IPPROTO_IPV6,IPV6_V6ONLY,&yes,sizeof(yes)) ||
        setsockopt(s,IPPROTO_IPV6,IPV6_MULTICAST_IF,&index,sizeof(index)) ||
        setsockopt(s,IPPROTO_IPV6,IPV6_MULTICAST_HOPS,&ttl,sizeof(ttl)) ||
        setsockopt(s,IPPROTO_IPV6,IPV6_UNICAST_HOPS,&ttl,sizeof(ttl)) ||
        setsockopt(s,IPPROTO_IPV6,IPV6_UNICAST_IF,&unicast6,sizeof(unicast6)) ||
        setsockopt(s,IPPROTO_IPV6,IPV6_MULTICAST_LOOP,&yes,sizeof(yes)) ||
        setsockopt(s,IPPROTO_IPV6,IPV6_RECVPKTINFO,&yes,sizeof(yes)) ||
        setsockopt(s,IPPROTO_IPV6,IPV6_RECVHOPLIMIT,&yes,sizeof(yes)) ||
        bind(s,(struct sockaddr*)&local,sizeof(local)) ||
        setsockopt(s,IPPROTO_IPV6,IPV6_JOIN_GROUP,&group,sizeof(group))) goto failed;
    if(h->iface.has_ipv4) {
        s=socket(AF_INET,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,IPPROTO_UDP); h->sockets[1]=s;
        struct sockaddr_in v4={.sin_family=AF_INET,.sin_port=htons(5353)};
        struct ip_mreq g={0}; g.imr_multiaddr.s_addr=htonl(0xe00000fb); memcpy(&g.imr_interface,h->iface.ipv4,4);
        int unicast_index=(int)htonl(h->iface.ipv4_index);
        if(s<0 || setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes)) ||
            setsockopt(s,IPPROTO_IP,IP_MULTICAST_IF,&g.imr_interface,4) ||
            setsockopt(s,IPPROTO_IP,IP_MULTICAST_TTL,&ttl,sizeof(ttl)) ||
            setsockopt(s,IPPROTO_IP,IP_TTL,&ttl,sizeof(ttl)) ||
            setsockopt(s,IPPROTO_IP,IP_UNICAST_IF,&unicast_index,sizeof(unicast_index)) ||
            setsockopt(s,IPPROTO_IP,IP_MULTICAST_LOOP,&yes,sizeof(yes)) ||
            setsockopt(s,IPPROTO_IP,IP_PKTINFO,&yes,sizeof(yes)) ||
            setsockopt(s,IPPROTO_IP,IP_RECVTTL,&yes,sizeof(yes)) ||
            bind(s,(struct sockaddr*)&v4,sizeof(v4)) || setsockopt(s,IPPROTO_IP,IP_ADD_MEMBERSHIP,&g,sizeof(g))) goto failed;
    }
    return true;
failed: close_sockets(h); return false;
}

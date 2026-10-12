/* Private immutable address snapshot. Primary fields retain socket routing;
 * all usable addresses on that interface participate in DNS ownership. */
static bool usable_address(bool v4,const uint8_t* a) {
    if(v4) return a[0] && a[0]!=127 && a[0]<224;
    static const uint8_t mapped[12]={0,0,0,0,0,0,0,0,0,0,0xff,0xff};
    bool prefix=false; for(unsigned i=0;i<15;++i) prefix|=a[i]!=0;
    return (prefix || a[15]>1) && a[0]!=0xff && memcmp(a,mapped,12);
}
static bool interface_address(Matter_Mdns_Windows_Interface_T* iface,bool v4,const uint8_t* bytes) {
    if(!usable_address(v4,bytes)) return true;
    if(iface->address_count>MATTER_MDNS_HOST_ADDRESSES) return false;
    for(unsigned i=0;i<iface->address_count;++i)
        if(iface->addresses[i].ipv4==v4 && !memcmp(iface->addresses[i].bytes,bytes,v4?4:16)) return true;
    if(iface->address_count==MATTER_MDNS_HOST_ADDRESSES) return false;
    Matter_Mdns_Host_Address_T* a=&iface->addresses[iface->address_count++];
    memset(a,0,sizeof(*a)); a->ipv4=v4; memcpy(a->bytes,bytes,v4?4:16); return true;
}
static const void* address_data(const mdns_record_t* r) {
    return r->type==MDNS_RECORDTYPE_A?(const void*)&r->data.a.addr.sin_addr:(const void*)&r->data.aaaa.addr.sin6_addr;
}
static bool prepare_addresses(Matter_Mdns_Windows_T h) {
    if(h->iface.address_count>MATTER_MDNS_HOST_ADDRESSES) return false;
    /* Index2 remains the primary IPv6 record for existing callers/fixtures. */
    h->addresses=4; h->ipv4_records=0; h->address_count=1; h->host_order[0]=2;
    bool primary=false,v4=!h->iface.has_ipv4;
    unsigned count=h->iface.address_count;
    if(!count) count=h->iface.has_ipv4?2:1;
    for(unsigned i=0;i<count;++i) {
        bool is4=h->iface.address_count?h->iface.addresses[i].ipv4:i!=0;
        const uint8_t* bytes=h->iface.address_count?h->iface.addresses[i].bytes:is4?h->iface.ipv4:h->iface.ipv6;
        if(!usable_address(is4,bytes)) return false;
        if(!is4 && !memcmp(bytes,h->iface.ipv6,16)) { primary=true; continue; }
        if(is4 && h->iface.has_ipv4 && !memcmp(bytes,h->iface.ipv4,4)) v4=true;
        bool duplicate=false;
        for(unsigned j=0;j<h->address_count;++j) {
            const mdns_record_t* r=&h->records[h->host_order[j]];
            if(r->type==(is4?1:28) && !memcmp(address_data(r),bytes,is4?4:16)) duplicate=true;
        }
        if(duplicate) continue;
        if(h->address_count==MATTER_MDNS_HOST_ADDRESSES) return false;
        unsigned index=(unsigned)h->count++; mdns_record_t* r=&h->records[index];
        *r=(mdns_record_t){.name=string(h->hostname),.type=is4?MDNS_RECORDTYPE_A:MDNS_RECORDTYPE_AAAA};
        if(is4) memcpy(&r->data.a.addr.sin_addr,bytes,4); else memcpy(&r->data.aaaa.addr.sin6_addr,bytes,16);
        h->addresses|=UINT32_C(1)<<index; if(is4) h->ipv4_records|=UINT32_C(1)<<index;
        unsigned at=0;
        while(at<h->address_count) {
            const mdns_record_t* other=&h->records[h->host_order[at]];
            if(r->type<other->type || (r->type==other->type && memcmp(address_data(r),address_data(other),is4?4:16)<0)) break;
            ++at;
        }
        for(unsigned j=h->address_count;j>at;--j) h->host_order[j]=h->host_order[j-1];
        h->host_order[at]=(uint8_t)index; ++h->address_count;
    }
    return primary && v4;
}

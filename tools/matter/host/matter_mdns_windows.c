#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <iphlpapi.h>
#include <bcrypt.h>
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <strings.h>
/* Private spelling compatibility; the DNS engine and opaque API are shared. */
typedef int SOCKET;
typedef unsigned DWORD;
typedef struct sockaddr SOCKADDR;
typedef struct sockaddr_in SOCKADDR_IN;
typedef struct sockaddr_in6 SOCKADDR_IN6;
#define INVALID_SOCKET (-1)
#define closesocket close
#define _stricmp strcasecmp
#define _strnicmp strncasecmp
#endif
#include "matter_host_platform.h"
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "matter_mdns_windows.h"
#include "matter_resolver_windows.h"
/* Only the bounded writer is used. Socket helpers and receive parser from
 * this dependency are deliberately not used on untrusted network packets. */
#include "vendor/mdns/mdns.h"

enum { CAP=1200, MAX_RECORDS=22, TTL=120, QUERY_SLOTS=8, NSEC_INSTANCE=30, NSEC_HOST=31, PROBE_RECORDS=MATTER_MDNS_HOST_ADDRESSES+1 };
#define NSEC_MASK ((UINT32_C(1)<<NSEC_INSTANCE)|(UINT32_C(1)<<NSEC_HOST))
#ifdef _WIN32
typedef union { WSACMSGHDR align; char bytes[WSA_CMSG_SPACE(sizeof(IN6_PKTINFO))+WSA_CMSG_SPACE(sizeof(int))]; } Control;
#else
typedef union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(struct in6_pktinfo))+CMSG_SPACE(sizeof(int))]; } Control;
#endif
typedef struct {
    SOCKADDR_IN6 peer; uint64_t due; size_t size; unsigned socket_index;
    uint8_t packet[CAP];
} Unicast_Reply;
typedef struct {
    SOCKADDR_IN6 peer; uint64_t due;
    uint32_t unicast, multicast, known; unsigned socket_index;
    bool tc, rx_multicast, probe;
} Pending_Query;
typedef struct { uint16_t type,cl,offset,len; } Probe_Record;
typedef struct { uint16_t type; uint8_t owner; } Probe_Question;
struct Matter_Mdns_Windows {
    Matter_Mdns_T module; Matter_Mdns_Windows_Interface_T iface;
    SOCKET sockets[2];
#ifdef _WIN32
    WSADATA startup; LPFN_WSARECVMSG receive[2];
#endif
    Control control;
    mdns_record_t records[MAX_RECORDS]; size_t count,txt_start;
    uint32_t addresses,ipv4_records; unsigned address_count;
    uint8_t host_order[MATTER_MDNS_HOST_ADDRESSES];
    mdns_string_table_t table;
    char service[96],instance[164],hostname[80],subtypes[4][164],name[256],target[256];
    uint8_t rx[CAP],tx[CAP],txt[512]; size_t txt_size;
    uint64_t request,now,due,last_response,generation,retry_after;
    Probe_Question probe_questions[64];
    Probe_Record probe_records[2][PROBE_RECORDS]; unsigned probe_count[2];
    uint8_t compare[CAP]; /* Canonical comparison scratch; other operand uses tx. */
    bool probe_lost,query_probe;
    unsigned phase,jitter; bool publishing,installed,cancelled,respond,conflict,schedule;
    SOCKADDR_IN6 peer; bool rx_multicast,peer_local,legacy;
    uint32_t unicast_answers, multicast_answers, known_answers, duplicate_answers; size_t question_end;
    unsigned question_count; bool query, query_tc;
    Pending_Query queries[QUERY_SLOTS]; /* Masks only; bounded per-source TC state. */
    Unicast_Reply replies[4]; /* Per-instance heap, no allocation in RX/poll. */
};
static uint16_t get16(const uint8_t* p) { return (uint16_t)((p[0]<<8)|p[1]); }
static uint32_t get32(const uint8_t* p) { return ((uint32_t)get16(p)<<16)|get16(p+2); }
static void set16(uint8_t* p,uint16_t n) { p[0]=(uint8_t)(n>>8); p[1]=(uint8_t)n; }
static uint64_t after(uint64_t n,unsigned delay) { return UINT64_MAX-n<delay?UINT64_MAX:n+delay; }
static bool label(const char* s,bool underscore) {
    if(!s) return false;
    size_t n=strlen(s); if(!n || n>63) return false;
    for(size_t i=0;i<n;++i) if(!((s[i]>='a' && s[i]<='z') || (s[i]>='A' && s[i]<='Z') ||
        (s[i]>='0' && s[i]<='9') || s[i]=='-' || (underscore && s[i]=='_'))) return false;
    return s[0]!='-' && s[n-1]!='-';
}
static mdns_string_t string(const char* s) { return (mdns_string_t){s,strlen(s)}; }
static void network_cleanup(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}
static void close_sockets(Matter_Mdns_Windows_T h) {
    for(unsigned i=0;i<2;++i) if(h->sockets[i]!=INVALID_SOCKET) { closesocket(h->sockets[i]); h->sockets[i]=INVALID_SOCKET; }
}
#include "matter_mdns_addresses.h"
#ifdef _WIN32
Matter_Result_T matter_mdns_windows_interface(uint32_t index,Matter_Mdns_Windows_Interface_T* out) {
    if(!index || !out) return MATTER_INVALID_ARGUMENT;
    ULONG size=0; ULONG r=GetAdaptersAddresses(AF_UNSPEC,GAA_FLAG_SKIP_DNS_SERVER,NULL,NULL,&size);
    if(r!=ERROR_BUFFER_OVERFLOW || !size || size>1024*1024) return MATTER_PORT_ERROR;
    IP_ADAPTER_ADDRESSES* all=malloc(size); if(!all) return MATTER_LIMIT_REACHED;
    r=GetAdaptersAddresses(AF_UNSPEC,GAA_FLAG_SKIP_DNS_SERVER,NULL,all,&size);
    Matter_Result_T result=MATTER_OFFLINE; Matter_Mdns_Windows_Interface_T found={.index=index};
    if(r!=NO_ERROR) result=MATTER_PORT_ERROR;
    else for(IP_ADAPTER_ADDRESSES* a=all;a;a=a->Next) {
        if(a->Ipv6IfIndex!=index || a->OperStatus!=IfOperStatusUp || a->PhysicalAddressLength!=6 ||
            (a->Flags&IP_ADAPTER_NO_MULTICAST)) continue;
        memcpy(found.mac,a->PhysicalAddress,6); found.ipv4_index=a->IfIndex;
        bool v6=false;
        for(IP_ADAPTER_UNICAST_ADDRESS* u=a->FirstUnicastAddress;u;u=u->Next) {
            if(u->DadState!=IpDadStatePreferred && u->DadState!=IpDadStateDeprecated) continue;
            if(u->Address.lpSockaddr->sa_family==AF_INET6) {
                const SOCKADDR_IN6* ip=(const SOCKADDR_IN6*)u->Address.lpSockaddr;
                if(!interface_address(&found,false,(const uint8_t*)&ip->sin6_addr)) { result=MATTER_LIMIT_REACHED; goto finished; }
                if(IN6_IS_ADDR_LINKLOCAL(&ip->sin6_addr)) { memcpy(found.ipv6,&ip->sin6_addr,16); v6=true; }
            } else if(u->Address.lpSockaddr->sa_family==AF_INET) {
                const SOCKADDR_IN* ip=(const SOCKADDR_IN*)u->Address.lpSockaddr;
                if(!interface_address(&found,true,(const uint8_t*)&ip->sin_addr)) { result=MATTER_LIMIT_REACHED; goto finished; }
                memcpy(found.ipv4,&ip->sin_addr,4); found.has_ipv4=true;
                found.ipv4_prefix_length=u->OnLinkPrefixLength<=32?u->OnLinkPrefixLength:0;
            }
        }
        if(v6) { *out=found; result=MATTER_OK; } break;
    }
finished:
    free(all); return result;
}
static bool open_sockets(Matter_Mdns_Windows_T h) {
    DWORD yes=1,ttl=255,index=h->iface.index; u_long nonblock=1;
    SOCKET s=socket(AF_INET6,SOCK_DGRAM,IPPROTO_UDP); h->sockets[0]=s;
    SOCKADDR_IN6 local={.sin6_family=AF_INET6,.sin6_port=htons(5353)};
    struct ipv6_mreq group={0}; group.ipv6mr_multiaddr.s6_addr[0]=0xff; group.ipv6mr_multiaddr.s6_addr[1]=2;
    group.ipv6mr_multiaddr.s6_addr[15]=0xfb; group.ipv6mr_interface=index;
    if(s==INVALID_SOCKET || setsockopt(s,SOL_SOCKET,SO_REUSEADDR,(char*)&yes,sizeof(yes)) ||
        setsockopt(s,IPPROTO_IPV6,IPV6_V6ONLY,(char*)&yes,sizeof(yes)) ||
        setsockopt(s,IPPROTO_IPV6,IPV6_MULTICAST_IF,(char*)&index,sizeof(index)) ||
        setsockopt(s,IPPROTO_IPV6,IPV6_MULTICAST_HOPS,(char*)&ttl,sizeof(ttl)) ||
        setsockopt(s,IPPROTO_IPV6,IPV6_UNICAST_HOPS,(char*)&ttl,sizeof(ttl)) ||
        setsockopt(s,IPPROTO_IPV6,IPV6_UNICAST_IF,(char*)&index,sizeof(index)) ||
        setsockopt(s,IPPROTO_IPV6,IPV6_MULTICAST_LOOP,(char*)&yes,sizeof(yes)) ||
        setsockopt(s,IPPROTO_IPV6,IPV6_PKTINFO,(char*)&yes,sizeof(yes)) ||
        setsockopt(s,IPPROTO_IPV6,IPV6_HOPLIMIT,(char*)&yes,sizeof(yes)) ||
        bind(s,(SOCKADDR*)&local,sizeof(local)) ||
        setsockopt(s,IPPROTO_IPV6,IPV6_JOIN_GROUP,(char*)&group,sizeof(group)) || ioctlsocket(s,FIONBIO,&nonblock)) goto failed;
    if(h->iface.has_ipv4) {
        s=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP); h->sockets[1]=s;
        SOCKADDR_IN v4={.sin_family=AF_INET,.sin_port=htons(5353)};
        struct ip_mreq g={0}; g.imr_multiaddr.s_addr=htonl(0xe00000fb); memcpy(&g.imr_interface,h->iface.ipv4,4);
        DWORD unicast_index=htonl(h->iface.ipv4_index);
        if(s==INVALID_SOCKET || setsockopt(s,SOL_SOCKET,SO_REUSEADDR,(char*)&yes,sizeof(yes)) ||
            setsockopt(s,IPPROTO_IP,IP_MULTICAST_IF,(char*)&g.imr_interface,4) ||
            setsockopt(s,IPPROTO_IP,IP_MULTICAST_TTL,(char*)&ttl,sizeof(ttl)) ||
            setsockopt(s,IPPROTO_IP,IP_TTL,(char*)&ttl,sizeof(ttl)) ||
            setsockopt(s,IPPROTO_IP,IP_UNICAST_IF,(char*)&unicast_index,sizeof(unicast_index)) ||
            setsockopt(s,IPPROTO_IP,IP_MULTICAST_LOOP,(char*)&yes,sizeof(yes)) ||
            setsockopt(s,IPPROTO_IP,IP_PKTINFO,(char*)&yes,sizeof(yes)) ||
            setsockopt(s,IPPROTO_IP,IP_RECVTTL,(char*)&yes,sizeof(yes)) ||
            bind(s,(SOCKADDR*)&v4,sizeof(v4)) || setsockopt(s,IPPROTO_IP,IP_ADD_MEMBERSHIP,(char*)&g,sizeof(g)) ||
            ioctlsocket(s,FIONBIO,&nonblock)) goto failed;
    }
    for(unsigned i=0;i<2;++i) if(h->sockets[i]!=INVALID_SOCKET) {
        GUID extension=WSAID_WSARECVMSG; DWORD bytes=0;
        if(WSAIoctl(h->sockets[i],SIO_GET_EXTENSION_FUNCTION_POINTER,&extension,sizeof(extension),
            &h->receive[i],sizeof(h->receive[i]),&bytes,NULL,NULL)) goto failed;
    }
    return true;
failed: close_sockets(h); return false;
}
#else
#include "matter_mdns_linux_io.h"
#endif
static bool prepare(Matter_Mdns_Windows_T h,const Matter_Mdns_Record_T* r) {
    if(!r || !label(r->instance,false) || !label(r->hostname,false) || !label(r->service,true) || !r->protocol ||
        (strcmp(r->protocol,"_udp") && strcmp(r->protocol,"_tcp")) || !r->port ||
        !r->txt_count || r->txt_count>8 || r->subtype_count>4 || !r->txt || (r->subtype_count && !r->subtypes)) return false;
    snprintf(h->service,sizeof(h->service),"%s.%s.local.",r->service,r->protocol);
    snprintf(h->instance,sizeof(h->instance),"%s.%s",r->instance,h->service);
    snprintf(h->hostname,sizeof(h->hostname),"%s.local.",r->hostname);
    h->count=0; h->txt_size=0;
    h->records[h->count++]=(mdns_record_t){.name=string(h->service),.type=MDNS_RECORDTYPE_PTR,.data.ptr.name=string(h->instance)};
    h->records[h->count++]=(mdns_record_t){.name=string(h->instance),.type=MDNS_RECORDTYPE_SRV,
        .data.srv={.port=r->port,.name=string(h->hostname)}};
    mdns_record_t* a=&h->records[h->count++]; *a=(mdns_record_t){.name=string(h->hostname),.type=MDNS_RECORDTYPE_AAAA};
    memcpy(&a->data.aaaa.addr.sin6_addr,h->iface.ipv6,16);
    if(!prepare_addresses(h)) return false;
    for(size_t i=0;i<r->subtype_count;++i) {
        if(!label(r->subtypes[i],true)) return false;
        snprintf(h->subtypes[i],sizeof(h->subtypes[i]),"%s._sub.%s",r->subtypes[i],h->service);
        h->records[h->count++]=(mdns_record_t){.name=string(h->subtypes[i]),.type=MDNS_RECORDTYPE_PTR,.data.ptr.name=string(h->instance)};
    }
    h->txt_start=h->count;
    for(size_t i=0;i<r->txt_count;++i) {
        const char* key=r->txt[i].key; const char* value=r->txt[i].value;
        if(!label(key,false) || !value) return false;
        size_t k=strlen(key),v=strlen(value),n=k+v+1;
        if(n>255 || n+1>sizeof(h->txt)-h->txt_size) return false;
        for(size_t j=0;j<i;++j) if(!_stricmp(key,r->txt[j].key)) return false;
        h->txt[h->txt_size++]=(uint8_t)n; memcpy(h->txt+h->txt_size,key,k); h->txt_size+=k;
        h->txt[h->txt_size++]='='; memcpy(h->txt+h->txt_size,value,v); h->txt_size+=v;
        h->records[h->count++]=(mdns_record_t){.name=string(h->instance),.type=MDNS_RECORDTYPE_TXT,
            .data.txt={.key=string(key),.value=string(value)}};
    }
    return true;
}
static void* nsec_write(Matter_Mdns_Windows_T,void*,size_t,bool,bool);
static size_t packet(Matter_Mdns_Windows_T h,bool probe,bool goodbye) {
    memset(h->tx,0,12); memset(&h->table,0,sizeof(h->table));
    void* p=h->tx+12; unsigned count=0;
    if(probe) {
        const char* names[]={h->instance,h->hostname};
        for(unsigned i=0;i<2;++i) {
            p=mdns_string_make(h->tx,CAP,p,names[i],strlen(names[i]),&h->table); if(!p || (uint8_t*)p>h->tx+CAP-4) return 0;
            p=mdns_htons(p,255); p=mdns_htons(p,1);
        }
        set16(h->tx+4,2);
    } else set16(h->tx+2,0x8400);
    for(size_t i=0;i<h->txt_start;++i) {
        mdns_record_t r=h->records[i];
        if((probe && r.type==MDNS_RECORDTYPE_PTR) || (goodbye && (r.type==MDNS_RECORDTYPE_A || r.type==MDNS_RECORDTYPE_AAAA))) continue;
        r.rclass=1|(!probe && r.type!=MDNS_RECORDTYPE_PTR?0x8000:0); r.ttl=goodbye?0:TTL;
        p=mdns_answer_add_record(h->tx,CAP,p,r,&h->table); if(!p) return 0; ++count;
    }
    p=mdns_answer_add_txt_record(h->tx,CAP,p,h->records+h->txt_start,h->count-h->txt_start,probe?1:0x8001,goodbye?0:TTL,&h->table);
    if(!p) return 0;
    ++count;
    set16(h->tx+(probe?8:6),(uint16_t)count);
    if(!probe && !goodbye && !h->ipv4_records) {
        p=nsec_write(h,p,CAP,true,false); if(!p) return 0; set16(h->tx+10,1);
    }
    return (uint8_t*)p-h->tx;
}
static bool send_multicast(Matter_Mdns_Windows_T h,size_t n,unsigned index) {
    if(!n) return false;
    if(!index) {
        SOCKADDR_IN6 v6={.sin6_family=AF_INET6,.sin6_port=htons(5353),.sin6_scope_id=h->iface.index};
        v6.sin6_addr.s6_addr[0]=0xff; v6.sin6_addr.s6_addr[1]=2; v6.sin6_addr.s6_addr[15]=0xfb;
        return sendto(h->sockets[0],(char*)h->tx,(int)n,0,(SOCKADDR*)&v6,sizeof(v6))==(int)n;
    }
    SOCKADDR_IN v4={.sin_family=AF_INET,.sin_port=htons(5353)}; v4.sin_addr.s_addr=htonl(0xe00000fb);
    return sendto(h->sockets[1],(char*)h->tx,(int)n,0,(SOCKADDR*)&v4,sizeof(v4))==(int)n;
}
static bool send_packet(Matter_Mdns_Windows_T h,size_t n) {
    return send_multicast(h,n,0) && (h->sockets[1]==INVALID_SOCKET || send_multicast(h,n,1));
}
static bool transmit(Matter_Mdns_Windows_T h,bool probe,bool goodbye) { return send_packet(h,packet(h,probe,goodbye)); }
/* Bounded decompression: only backward pointers, 128 labels/hops, full name
 * <=255 bytes. Reject truncation instead of parsing a partially received RR. */
static bool name(const uint8_t* b,size_t n,size_t* pos,char* out) {
    size_t p=*pos,w=0,end=0;
    for(unsigned hop=0;hop<128;++hop) {
        if(p>=n) return false;
        uint8_t len=b[p++];
        if(!len) { if(!end) end=p; out[w]=0; *pos=end; return true; }
        if((len&0xc0)==0xc0) {
            if(p>=n) return false;
            size_t target=((size_t)(len&63)<<8)|b[p++];
            if(target<12 || target>=p-2) return false;
            if(!end) end=p;
            p=target; continue;
        }
        if(len>63 || len>n-p || w+len+1>255) return false;
        for(size_t i=0;i<len;++i) if(b[p+i]<33 || b[p+i]>126 || b[p+i]=='.') return false;
        memcpy(out+w,b+p,len); w+=len; out[w++]='.'; p+=len;
    }
    return false;
}
static bool txt_valid(const uint8_t* p,size_t n) {
    for(size_t i=0;i<n;) { unsigned len=p[i++]; if(len>n-i) return false; i+=len; }
    return true;
}
/* Synthesized NSEC describes only names probed with ANY. Bit47 is NOT set.
 * No type >255 is published by this adapter. Shared PTR names are excluded. */
static uint8_t nsec_byte(Matter_Mdns_Windows_T h,bool host,unsigned index) {
    return host?(index==0 && h->ipv4_records?0x40:index==3?0x08:0):(index==2?0x80:index==4?0x40:0);
}
static uint32_t known_nsec(Matter_Mdns_Windows_T h,size_t p,size_t len) {
    size_t end=p+len;
    /* Unsupported/malformed NSEC RDATA is ignored, not the entire message
     * (RFC6762 6.1). The outer RR must still fit the received datagram. */
    if(!name(h->rx,end,&p,h->target) || end-p<3 || h->rx[p] ||
        !h->rx[p+1] || h->rx[p+1]>32 || end-p!=(size_t)h->rx[p+1]+2) return 0;
    unsigned bytes=h->rx[p+1]; p+=2;
    bool host=!_stricmp(h->name,h->hostname);
    if(!host && _stricmp(h->name,h->instance)) return 0;
    /* Next Domain Name is deliberately ignored on RX, as required by mDNS. */
    for(unsigned i=0;i<32;++i) if((i<bytes?h->rx[p+i]:0)!=nsec_byte(h,host,i)) return 0;
    return UINT32_C(1)<<(host?NSEC_HOST:NSEC_INSTANCE);
}
static void* nsec_write(Matter_Mdns_Windows_T h,void* start,size_t capacity,bool host,bool legacy) {
    const char* owner=host?h->hostname:h->instance;
    size_t offset=(uint8_t*)start-h->tx;
    void* p=mdns_string_make(h->tx,capacity,start,owner,strlen(owner),&h->table);
    if(!p || (uint8_t*)p>h->tx+capacity-10) return NULL;
    p=mdns_htons(p,47); p=mdns_htons(p,legacy?1:0x8001); p=mdns_htonl(p,legacy?10:TTL);
    uint8_t* length=p; p=mdns_htons(p,0); uint8_t* data=p;
    if(legacy) p=mdns_string_make(h->tx,capacity,p,owner,strlen(owner),NULL);
    else {
        if((uint8_t*)p>h->tx+capacity-2) return NULL;
        p=mdns_htons(p,(uint16_t)(0xc000|offset));
    }
    unsigned bytes=host?4:5;
    if(!p || (uint8_t*)p>h->tx+capacity-(2+bytes)) return NULL;
    uint8_t* b=p; *b++=0; *b++=(uint8_t)bytes;
    for(unsigned i=0;i<bytes;++i) *b++=nsec_byte(h,host,i);
    set16(length,(uint16_t)(b-data)); return b;
}
/* Compare semantic DNS names (including compressed PTR/SRV targets), but
 * compare TXT bytes exactly. Validate supported RDATA even for unrelated RRs. */
static bool known_record(Matter_Mdns_Windows_T h,size_t n,size_t p,uint16_t type,
    uint16_t cl,uint16_t len,uint32_t ttl,uint32_t* matched) {
    if(type==47) {
        uint32_t mask=known_nsec(h,p,len); if(cl==1 && ttl>=TTL/2) *matched|=mask;
        return true;
    }
    if(type==12 || type==33) {
        size_t end=p+(type==33?6:0);
        if((type==33 && len<7) || !name(h->rx,n,&end,h->target) || end!=p+len) return false;
    } else if((type==28 && len!=16) || (type==1 && len!=4)) return false;
    else if(type==16 && !txt_valid(h->rx+p,len)) return false;
    if(cl!=1 || ttl<TTL/2) return true;
    for(size_t i=0;i<=h->txt_start;++i) {
        const mdns_record_t* r=&h->records[i];
        if(type!=r->type || _stricmp(h->name,r->name.str)) continue;
        bool same=type==12?!_stricmp(h->target,r->data.ptr.name.str):
            type==33?!get16(h->rx+p) && !get16(h->rx+p+2) && get16(h->rx+p+4)==r->data.srv.port && !_stricmp(h->target,h->hostname):
            type==28 || type==1?!memcmp(h->rx+p,address_data(r),type==28?16:4):
            type==16?len==h->txt_size && !memcmp(h->rx+p,h->txt,len):false;
        if(same) *matched|=UINT32_C(1)<<i;
    }
    return true;
}
#include "matter_mdns_probe.h"
static bool parse(Matter_Mdns_Windows_T h,size_t n) {
    h->unicast_answers=h->multicast_answers=h->known_answers=h->duplicate_answers=0; h->question_end=0;
    h->respond=h->query=h->query_tc=h->query_probe=false; h->question_count=0;
    memset(h->probe_count,0,sizeof(h->probe_count));
    if(n<12) return false;
    uint16_t flags=get16(h->rx+2); bool query=(flags&0x8000)==0,tc=(flags&0x0200)!=0;
    if((flags&0x780f) || (tc && (!query || h->legacy))) return false;
    unsigned q=get16(h->rx+4),answers=get16(h->rx+6),authority=get16(h->rx+8),additional=get16(h->rx+10);
    if(q+answers+authority+additional>64) return false;
    bool conflict=false,probe=false; size_t p=12;
    uint32_t unicast=0,multicast=0,known=0,duplicates=0;
    for(unsigned i=0;i<q;++i) {
        if(!name(h->rx,n,&p,h->name) || n-p<4) return false;
        uint16_t type=get16(h->rx+p),raw_class=get16(h->rx+p+2),cl=raw_class&0x7fff; p+=4;
        h->probe_questions[i]=(Probe_Question){.type=type,
            .owner=(cl==1 || cl==255)?probe_owner(h):0};
        if(query && (cl==1 || cl==255)) {
            uint32_t bits=0;
            for(size_t j=0;j<h->count;++j)
                if(!_stricmp(h->name,h->records[j].name.str) && (type==255 || type==h->records[j].type))
                    bits|=UINT32_C(1)<<(j<h->txt_start?j:h->txt_start);
            /* Do not claim absence before successful ANY probing, for shared
             * names, other classes, or an ANY query with positive answers. */
            if(!bits && type!=255 && h->installed) {
                if(!_stricmp(h->name,h->instance)) bits=UINT32_C(1)<<NSEC_INSTANCE;
                else if(!_stricmp(h->name,h->hostname)) bits=UINT32_C(1)<<NSEC_HOST;
            }
            bool qu=(raw_class&0x8000)!=0 || !h->rx_multicast;
            if(h->peer_local && (h->legacy || qu)) {
                unicast|=bits;
                if(!h->legacy && h->now>=after(h->last_response,TTL*250)) multicast|=bits;
            } else if(!h->legacy) multicast|=bits;
        }
    }
    size_t question_end=p;
    for(unsigned i=0;i<answers+authority+additional;++i) {
        if(!name(h->rx,n,&p,h->name) || n-p<10) return false;
        uint16_t type=get16(h->rx+p),cl=get16(h->rx+p+2)&0x7fff,len=get16(h->rx+p+8);
        uint32_t ttl=get32(h->rx+p+4); p+=10; if(len>n-p) return false;
        uint32_t match=0;
        if(!known_record(h,n,p,type,cl,len,ttl,&match)) return false;
        if(query && !h->legacy && i<answers) known|=match;
        if(!query && ttl>=TTL) duplicates|=match;
        unsigned owner=probe_owner(h);
        if(query && !h->legacy && i>=answers && i<answers+authority && cl==1 && type!=47 && owner &&
            probe_question(h,q,owner,type)) {
            probe=true;
            if(probing(h) && !tc && !probe_insert(h,owner-1,(Probe_Record){type,cl,(uint16_t)p,len})) return false;
        }
        /* Only responses assert ownership. Before our first probe they may
         * be stale; query Answer/Authority never force a published name down. */
        if(!query && cl==1 && ttl && owner && (h->installed || probing(h)) && type!=47) {
            uint32_t same=0;
            if(!known_record(h,n,p,type,cl,len,TTL,&same)) return false;
            bool ours=(owner==1 && (type==16 || type==33)) || (owner==2 && (type==28 || (type==1 && h->ipv4_records)));
            if((ours && !same) || (!ours && probing(h))) conflict=true;
        }
        p+=len;
    }
    if(p!=n) return false;
    bool lost=false;
    if(probing(h) && !tc) for(unsigned owner=0;owner<2;++owner) {
        int order=0; if(!probe_order(h,owner,&order)) return false;
        if(order<0) lost=true;
    }
    if(lost) h->probe_lost=true;
    if(conflict) h->conflict=true;
    h->unicast_answers=unicast&~known; h->multicast_answers=multicast&~known;
    h->duplicate_answers=duplicates; h->known_answers=known; h->question_end=question_end; h->question_count=q;
    h->respond=h->multicast_answers!=0; h->query=query; h->query_tc=tc;
    h->query_probe=probe && !((unicast|multicast)&~((UINT32_C(1)<<h->txt_start)|2|h->addresses|NSEC_MASK));
    return true;
}
static uint32_t additionals(Matter_Mdns_Windows_T h,uint32_t answers,uint32_t known) {
    uint32_t extra=0;
    if(answers&~(h->addresses|NSEC_MASK)) extra=(UINT32_C(1)<<h->txt_start)|2|h->addresses;
    if((answers|extra)&h->addresses) {
        extra|=h->addresses;
        if(!h->ipv4_records) extra|=UINT32_C(1)<<NSEC_HOST;
    }
    return extra&~answers&~known;
}
/* A reply is built only after full query validation. Echo legacy questions at
 * their original offsets, so backward compression pointers remain valid. */
static size_t response_packet(Matter_Mdns_Windows_T h,uint32_t answers,uint32_t additional,bool legacy) {
    size_t capacity=legacy?512:CAP;
    if(!answers || (legacy && h->question_end>capacity)) return 0;
    memset(h->tx,0,12); memset(&h->table,0,sizeof(h->table)); set16(h->tx+2,0x8400);
    void* p=h->tx+12;
    if(legacy) {
        set16(h->tx,get16(h->rx)); set16(h->tx+4,get16(h->rx+4));
        memcpy(h->tx+12,h->rx+12,h->question_end-12); p=h->tx+h->question_end;
    }
    for(unsigned section=0;section<2;++section) {
        unsigned count=0; uint32_t mask=section?additional:answers;
        for(size_t i=0;i<=NSEC_HOST;++i) if(mask&(UINT32_C(1)<<i)) {
            if(i==NSEC_INSTANCE || i==NSEC_HOST) {
                void* next=nsec_write(h,p,capacity,i==NSEC_HOST,legacy);
                if(!next) { set16(h->tx+2,0x8600); set16(h->tx+(section?10:6),(uint16_t)count); return (uint8_t*)p-h->tx; }
                p=next; ++count; continue;
            }
            mdns_record_t r=h->records[i]; r.ttl=legacy?10:TTL;
            r.rclass=1|(!legacy && r.type!=MDNS_RECORDTYPE_PTR?0x8000:0);
            /* Conventional DNS must not compress the SRV target (RFC2782). */
            mdns_string_table_t* table=legacy && r.type==MDNS_RECORDTYPE_SRV?NULL:&h->table;
            void* next=i==h->txt_start?mdns_answer_add_txt_record(h->tx,capacity,p,h->records+i,h->count-i,r.rclass,r.ttl,&h->table):
                mdns_answer_add_record(h->tx,capacity,p,r,table);
            if(!next) { set16(h->tx+2,0x8600); set16(h->tx+(section?10:6),(uint16_t)count); return (uint8_t*)p-h->tx; }
            p=next; ++count;
        }
        set16(h->tx+(section?10:6),(uint16_t)count);
    }
    return (uint8_t*)p-h->tx;
}
static size_t unicast_packet(Matter_Mdns_Windows_T h) {
    return response_packet(h,h->unicast_answers,additionals(h,h->unicast_answers,h->known_answers),h->legacy);
}
/* Rejection sampling: uniform 0..100, at most two OS RNG calls. */
static bool response_delay(unsigned base,unsigned* out) {
    for(unsigned i=0;i<2;++i) { uint32_t n;
        if(!matter_host_random(&n,sizeof(n))) return false;
        if(n<UINT32_MAX-UINT32_MAX%101) { *out=base+n%101; return true; }
    }
    return false; /* Drop on RNG failure; no unbounded retry on owner. */
}
static bool same_source(const Pending_Query* q,Matter_Mdns_Windows_T h,unsigned index) {
    if(q->socket_index!=index || q->rx_multicast!=h->rx_multicast || q->peer.sin6_family!=h->peer.sin6_family) return false;
    if(!index) return q->peer.sin6_port==h->peer.sin6_port && !memcmp(&q->peer.sin6_addr,&h->peer.sin6_addr,16);
    const SOCKADDR_IN* a=(const SOCKADDR_IN*)&q->peer; const SOCKADDR_IN* b=(const SOCKADDR_IN*)&h->peer;
    return a->sin_port==b->sin_port && a->sin_addr.s_addr==b->sin_addr.s_addr;
}
static void queue_query(Matter_Mdns_Windows_T h,unsigned index) {
    unsigned delay=0;
    if(!h->question_count) {
        /* Continuations have no questions. Never suppress another source's
         * pending answer; all changes happen after full datagram validation. */
        bool have=false;
        for(unsigned i=0;i<QUERY_SLOTS;++i) if(h->queries[i].tc && same_source(&h->queries[i],h,index)) have=true;
        if(!have || (h->query_tc && !response_delay(400,&delay))) return;
        for(unsigned i=0;i<QUERY_SLOTS;++i) {
            Pending_Query* q=&h->queries[i];
            if(!q->tc || !same_source(q,h,index)) continue;
            q->known|=h->known_answers; q->unicast&=~q->known; q->multicast&=~q->known;
            if(h->query_tc) q->due=after(h->now,delay);
            if(!q->unicast && !q->multicast) memset(q,0,sizeof(*q));
        }
        return;
    }
    if(!h->unicast_answers && !h->multicast_answers) return;
    for(unsigned i=0;i<QUERY_SLOTS;++i) if(!h->queries[i].unicast && !h->queries[i].multicast) {
        bool shared=(h->unicast_answers&~((UINT32_C(1)<<h->txt_start)|2|h->addresses|NSEC_MASK))!=0;
        if((h->query_tc || (!h->query_probe && (shared || h->multicast_answers || h->question_count>1))) &&
            !response_delay(h->query_tc?400:20,&delay)) return;
        h->queries[i]=(Pending_Query){.peer=h->peer,.due=after(h->now,delay),
            .unicast=h->unicast_answers,.multicast=h->multicast_answers,.known=h->known_answers,
            .socket_index=index,.tc=h->query_tc,.rx_multicast=h->rx_multicast,.probe=h->query_probe};
        return;
    } /* Bounded pressure: drop this query, never overwrite another source. */
}
static void queue_reply(Matter_Mdns_Windows_T h,unsigned socket_index) {
    if(!h->installed || h->request || h->conflict) return;
    if(!h->query) {
        /* A multicast answer reaches all queriers on this family. It cannot
         * replace a direct/legacy reply or suppress another family's queue. */
        if(!h->rx_multicast || h->legacy) return;
        for(unsigned i=0;i<QUERY_SLOTS;++i) {
            Pending_Query* q=&h->queries[i];
            if(q->socket_index!=socket_index) continue;
            q->multicast&=~h->duplicate_answers;
            q->known|=h->duplicate_answers;
            if(!q->multicast && !q->unicast) memset(q,0,sizeof(*q));
        }
        return;
    }
    if(!h->legacy) { queue_query(h,socket_index); return; }
    if(!h->unicast_answers) return;
    for(unsigned i=0;i<4;++i) if(!h->replies[i].size) {
        size_t n=unicast_packet(h); if(!n) return;
        Unicast_Reply* r=&h->replies[i]; r->peer=h->peer; r->socket_index=socket_index;
        r->size=n; memcpy(r->packet,h->tx,n);
        /* Unique SRV/TXT/AAAA answers need no shared-record random delay. */
        r->due=after(h->now,(h->unicast_answers&~((UINT32_C(1)<<h->txt_start)|2|h->addresses|NSEC_MASK))?20+h->jitter%101:0);
        return;
    } /* Bounded pressure: querier retries; never overwrite another peer's reply. */
}
static bool publish(void* u,uint64_t request,const Matter_Mdns_Record_T* r) {
    Matter_Mdns_Windows_T h=u; uint8_t random;
    if(h->request || h->installed || !prepare(h,r) || !packet(h,false,false) ||
        !matter_host_random(&random,1)) return false;
    memset(h->queries,0,sizeof(h->queries)); memset(h->replies,0,sizeof(h->replies));
    h->request=request; h->publishing=true; h->cancelled=h->conflict=h->respond=h->probe_lost=false;
    h->phase=0; h->jitter=random%251; h->schedule=true; return true;
}
static bool remove_record(void* u,uint64_t request) {
    Matter_Mdns_Windows_T h=u; if(h->request || !h->installed) return false;
    memset(h->replies,0,sizeof(h->replies)); memset(h->queries,0,sizeof(h->queries));
    h->request=request; h->publishing=false; h->phase=0; h->due=h->now; h->respond=false; return true;
}
static void cancel(void* u,uint64_t request) { Matter_Mdns_Windows_T h=u; if(h->request==request) h->cancelled=true; }
static void detach(void* u) { Matter_Mdns_Windows_T h=u; h->module=NULL; h->request=0; h->respond=false; memset(h->queries,0,sizeof(h->queries)); memset(h->replies,0,sizeof(h->replies)); }
Matter_Mdns_Windows_T matter_mdns_windows_new(Matter_T owner,const Matter_Mdns_Windows_Interface_T* iface,const Matter_Mdns_Record_T* record) {
    if(!owner || !iface || !iface->index || iface->ipv6[0]!=0xfe || (iface->ipv6[1]&0xc0)!=0x80) return NULL;
    Matter_Mdns_Windows_T h=calloc(1,sizeof(*h)); if(!h) return NULL;
    h->sockets[0]=h->sockets[1]=INVALID_SOCKET; h->iface=*iface;
#ifdef _WIN32
    if(WSAStartup(MAKEWORD(2,2),&h->startup)) { free(h); return NULL; }
#endif
    Matter_Mdns_Port_T port={h,publish,remove_record,cancel,detach};
    if(!prepare(h,record) || !packet(h,false,false) || !open_sockets(h) || !(h->module=matter_mdns_new(owner,&port,record))) {
        close_sockets(h); network_cleanup(); free(h); return NULL;
    }
    h->generation=1; (void)matter_mdns_backend(h->module,1,true); return h;
}
Matter_Mdns_T matter_mdns_windows_module(Matter_Mdns_Windows_T h) { return h?h->module:NULL; }
static Matter_Result_T complete(Matter_Mdns_Windows_T h,Matter_Operation_Result_T result) {
    uint64_t request=h->request; h->request=0; return matter_mdns_complete(h->module,request,result);
}
/* This binding advertises one link-local IPv6 address and optionally one IPv4
 * address. Only these selected on-link prefixes may receive unicast replies. */
static bool local_peer(Matter_Mdns_Windows_T h,unsigned i,const SOCKADDR_IN6* peer) {
    if(!i) return IN6_IS_ADDR_LINKLOCAL(&peer->sin6_addr);
    const SOCKADDR_IN* p=(const SOCKADDR_IN*)peer;
    unsigned bits=h->iface.ipv4_prefix_length;
    if(!h->iface.has_ipv4 || !bits || bits>32) return false;
    uint32_t mask=UINT32_MAX<<(32-bits),address=ntohl(p->sin_addr.s_addr);
    uint32_t host=address&~mask;
    return (address&mask)==(get32(h->iface.ipv4)&mask) && (bits>=31 || (host && host!=~mask));
}
static bool ingress(Matter_Mdns_Windows_T h,unsigned i,const SOCKADDR_IN6* peer,
    uint32_t index,const uint8_t* destination,int hops,DWORD flags,size_t n) {
    if(n<12 || n>CAP || (flags&(MSG_TRUNC|MSG_CTRUNC)) || hops<=0 || hops>255 ||
        !index || index!=(i?h->iface.ipv4_index:h->iface.index)) return false;
    bool multicast,local; uint16_t port;
    if(!i) {
        static const uint8_t group[16]={0xff,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0xfb};
        if(peer->sin6_family!=AF_INET6 || IN6_IS_ADDR_UNSPECIFIED(&peer->sin6_addr) ||
            IN6_IS_ADDR_MULTICAST(&peer->sin6_addr) || IN6_IS_ADDR_V4MAPPED(&peer->sin6_addr) || IN6_IS_ADDR_LOOPBACK(&peer->sin6_addr)) return false;
        multicast=!memcmp(destination,group,16); local=!memcmp(destination,h->iface.ipv6,16); port=ntohs(peer->sin6_port);
    } else {
        const SOCKADDR_IN* p=(const SOCKADDR_IN*)peer; uint32_t source=ntohl(p->sin_addr.s_addr);
        if(p->sin_family!=AF_INET || !source || (source>>24)==127 || (source>>24)>=224) return false;
        multicast=get32(destination)==UINT32_C(0xe00000fb); local=h->iface.has_ipv4 && !memcmp(destination,h->iface.ipv4,4); port=ntohs(p->sin_port);
    }
    if(!port || (!multicast && !local)) return false;
    bool onlink=local_peer(h,i,peer),response=(get16(h->rx+2)&0x8000)!=0;
    /* Our resolver sends only QM queries. It must ignore unsolicited unicast
     * responses, even with TTL255. Multicast on the selected link is local
     * by RFC6762 section11; TTL255 is a sender recommendation, not RX proof. */
    if(response && (!multicast || port!=5353)) return false;
    if(!response && ((!multicast || port!=5353) && !onlink)) return false;
    h->peer=*peer; if(!i) h->peer.sin6_scope_id=h->iface.index;
    h->rx_multicast=multicast; h->peer_local=onlink; h->legacy=port!=5353;
    return true;
}
/* Shared publication/resolution ingress policy; one datagram per call. */
#ifdef _WIN32
static Matter_Result_T read_packet(Matter_Mdns_Windows_T h,unsigned i,size_t* size) {
    SOCKADDR_IN6 peer={0}; WSABUF buffer={CAP,(char*)h->rx}; WSAMSG message={0}; DWORD n=0;
    message.name=(SOCKADDR*)&peer; message.namelen=sizeof(peer); message.lpBuffers=&buffer; message.dwBufferCount=1;
    message.Control.buf=h->control.bytes; message.Control.len=sizeof(h->control.bytes);
    if(h->receive[i](h->sockets[i],&message,&n,NULL,NULL)) {
        int error=WSAGetLastError(); return error==WSAEWOULDBLOCK || error==WSAEMSGSIZE || error==WSAECONNRESET?MATTER_WOULD_BLOCK:MATTER_PORT_ERROR;
    }
    uint32_t index=0; int hops=0; uint8_t destination[16]={0};
    for(WSACMSGHDR* c=WSA_CMSG_FIRSTHDR(&message);c;c=WSA_CMSG_NXTHDR(&message,c)) {
        if(c->cmsg_level==IPPROTO_IPV6 && c->cmsg_type==IPV6_PKTINFO && c->cmsg_len>=WSA_CMSG_LEN(sizeof(IN6_PKTINFO))) {
            IN6_PKTINFO info; memcpy(&info,WSA_CMSG_DATA(c),sizeof(info)); index=info.ipi6_ifindex; memcpy(destination,&info.ipi6_addr,16);
        } else if(c->cmsg_level==IPPROTO_IP && c->cmsg_type==IP_PKTINFO && c->cmsg_len>=WSA_CMSG_LEN(sizeof(IN_PKTINFO))) {
            IN_PKTINFO info; memcpy(&info,WSA_CMSG_DATA(c),sizeof(info)); index=info.ipi_ifindex; memcpy(destination,&info.ipi_addr,4);
        } else if(((c->cmsg_level==IPPROTO_IPV6 && c->cmsg_type==IPV6_HOPLIMIT) ||
            (c->cmsg_level==IPPROTO_IP && c->cmsg_type==IP_TTL)) && c->cmsg_len>=WSA_CMSG_LEN(sizeof(int))) memcpy(&hops,WSA_CMSG_DATA(c),sizeof(hops));
    }
    if(!ingress(h,i,&peer,index,destination,hops,message.dwFlags,n)) return MATTER_WOULD_BLOCK;
    *size=n; return MATTER_OK;
}
#else
static Matter_Result_T read_packet(Matter_Mdns_Windows_T h,unsigned i,size_t* size) {
    SOCKADDR_IN6 peer={0}; struct iovec buffer={h->rx,CAP};
    struct msghdr message={.msg_name=&peer,.msg_namelen=sizeof(peer),.msg_iov=&buffer,.msg_iovlen=1,
        .msg_control=h->control.bytes,.msg_controllen=sizeof(h->control.bytes)};
    ssize_t n=recvmsg(h->sockets[i],&message,MSG_DONTWAIT);
    if(n<0) return errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR || errno==ECONNREFUSED?MATTER_WOULD_BLOCK:MATTER_PORT_ERROR;
    uint32_t index=0; int hops=0; uint8_t destination[16]={0};
    for(struct cmsghdr* c=CMSG_FIRSTHDR(&message);c;c=CMSG_NXTHDR(&message,c)) {
        if(c->cmsg_level==IPPROTO_IPV6 && c->cmsg_type==IPV6_PKTINFO && c->cmsg_len==CMSG_LEN(sizeof(struct in6_pktinfo))) {
            struct in6_pktinfo info; memcpy(&info,CMSG_DATA(c),sizeof(info)); index=info.ipi6_ifindex; memcpy(destination,&info.ipi6_addr,16);
        } else if(c->cmsg_level==IPPROTO_IP && c->cmsg_type==IP_PKTINFO && c->cmsg_len==CMSG_LEN(sizeof(struct in_pktinfo))) {
            struct in_pktinfo info; memcpy(&info,CMSG_DATA(c),sizeof(info)); index=info.ipi_ifindex; memcpy(destination,&info.ipi_addr,4);
        } else if(((c->cmsg_level==IPPROTO_IPV6 && c->cmsg_type==IPV6_HOPLIMIT) ||
            (c->cmsg_level==IPPROTO_IP && c->cmsg_type==IP_TTL)) && c->cmsg_len==CMSG_LEN(sizeof(int))) memcpy(&hops,CMSG_DATA(c),sizeof(hops));
    }
    if(!ingress(h,i,&peer,index,destination,hops,(DWORD)message.msg_flags,(size_t)n)) return MATTER_WOULD_BLOCK;
    *size=(size_t)n; return MATTER_OK;
}
#endif
/* Union needs AFTER per-query suppression. A known answer from A can never
 * remove the same RR requested by B, including optional additional records. */
static uint32_t multicast_masks(Matter_Mdns_Windows_T h,unsigned index,uint32_t* extra) {
    uint32_t answers=0; *extra=0;
    for(unsigned i=0;i<QUERY_SLOTS;++i) {
        Pending_Query* q=&h->queries[i];
        if(q->socket_index!=index || h->now<q->due ||
            h->now<after(h->last_response,q->probe?250:1000)) continue;
        answers|=q->multicast; *extra|=additionals(h,q->multicast,q->known);
    }
    *extra&=~answers; return answers;
}
static Matter_Result_T answer_queries(Matter_Mdns_Windows_T h) {
    bool sent=false;
    for(unsigned i=0;i<QUERY_SLOTS;++i) {
        Pending_Query* q=&h->queries[i];
        if(!q->unicast || h->now<q->due) continue;
        size_t n=response_packet(h,q->unicast,additionals(h,q->unicast,q->known),false);
        int length=q->socket_index?sizeof(SOCKADDR_IN):sizeof(SOCKADDR_IN6);
        if(n) (void)sendto(h->sockets[q->socket_index],(const char*)h->tx,(int)n,0,(SOCKADDR*)&q->peer,length);
        q->unicast=0; if(!q->multicast) memset(q,0,sizeof(*q));
        sent=true; /* Unicast remains best effort if a querier has departed. */
    }
    {
        bool multicast=false;
        for(unsigned index=0;index<2;++index) {
            uint32_t extra,answers=multicast_masks(h,index,&extra); if(!answers) continue;
            if(!send_multicast(h,response_packet(h,answers,extra,false),index)) return MATTER_PORT_ERROR;
            multicast=sent=true;
            for(unsigned i=0;i<QUERY_SLOTS;++i) {
                Pending_Query* q=&h->queries[i];
                if(q->socket_index==index && h->now>=q->due &&
                    h->now>=after(h->last_response,q->probe?250:1000)) { q->multicast=0; if(!q->unicast) memset(q,0,sizeof(*q)); }
            }
        }
        if(multicast) h->last_response=h->now;
    }
    return sent?MATTER_OK:MATTER_WOULD_BLOCK;
}
Matter_Result_T matter_mdns_windows_poll(Matter_Mdns_Windows_T h,uint64_t now) {
    if(!h || now<h->now) return MATTER_INVALID_ARGUMENT;
    h->now=now;
    if(h->schedule) { h->due=after(now,h->jitter); if(h->due<h->retry_after) h->due=h->retry_after; h->schedule=false; }
    if(h->request && h->publishing && h->cancelled && !h->installed) {
        h->probe_lost=h->conflict=false; return complete(h,MATTER_OPERATION_CANCELLED);
    }
    for(unsigned i=0;i<2;++i) if(h->sockets[i]!=INVALID_SOCKET) {
        size_t n; Matter_Result_T r=read_packet(h,i,&n);
        if(r==MATTER_OK && parse(h,n)) queue_reply(h,i);
        else if(r==MATTER_PORT_ERROR) goto lost;
    }
    if(h->request && !h->publishing) h->conflict=h->probe_lost=false; /* Stop wins. */
    if(h->conflict) {
        memset(h->queries,0,sizeof(h->queries)); memset(h->replies,0,sizeof(h->replies));
        h->conflict=h->probe_lost=false;
        if(h->installed) {
            /* Revoke local publication before starting another ANY probing
             * sequence; retain the binding, names, and application session. */
            h->installed=false; h->request=0; h->phase=0; h->retry_after=now;
            if(h->generation==UINT64_MAX || matter_mdns_backend(h->module,++h->generation,true)!=MATTER_OK) goto lost;
            return MATTER_PENDING;
        }
        if(h->request) { h->phase=0; h->retry_after=after(now,5000); return complete(h,MATTER_OPERATION_FAILED); }
    }
    if(h->probe_lost) {
        h->probe_lost=false; h->phase=0; h->due=h->retry_after=after(now,1000);
        /* Ignore stale claims until the next first probe. This also limits
         * repeated tie losses to at most one per second per binding. */
        return MATTER_PENDING;
    }
    for(unsigned i=0;i<4;++i) {
        Unicast_Reply* r=&h->replies[i];
        if(!r->size || now<r->due) continue;
        int length=r->socket_index?sizeof(SOCKADDR_IN):sizeof(SOCKADDR_IN6);
        /* Best effort: a disappeared/unreachable querier must not tear down
         * the publication. No pending I/O; any failed response is retried by peer. */
        (void)sendto(h->sockets[r->socket_index],(const char*)r->packet,(int)r->size,0,(SOCKADDR*)&r->peer,length);
        r->size=0;
    }
    if(h->request && now>=h->due) {
        if(h->publishing) {
            bool probe=h->phase<3;
            if(!transmit(h,probe,false)) goto lost;
            ++h->phase; h->due=after(now,probe?250:1000);
            if(!probe) {
                h->installed=true; h->last_response=now; h->respond=false;
                return complete(h,MATTER_OPERATION_SUCCEEDED);
            }
        } else {
            if(!transmit(h,false,true)) goto lost;
            if(++h->phase==2) { h->installed=false; return complete(h,MATTER_OPERATION_SUCCEEDED); }
            h->due=after(now,1000);
        }
        return MATTER_PENDING;
    }
    if(h->installed && !h->request && h->phase==4 && now>=h->due && now>=after(h->last_response,1000)) {
        if(!transmit(h,false,false)) goto lost;
        h->phase=5; h->last_response=now; h->respond=false; return MATTER_OK;
    }
    if(h->installed && !h->request) {
        Matter_Result_T r=answer_queries(h); if(r==MATTER_PORT_ERROR) goto lost;
        return r;
    }
    return MATTER_WOULD_BLOCK;
lost:
    memset(h->queries,0,sizeof(h->queries)); memset(h->replies,0,sizeof(h->replies));
    close_sockets(h); h->installed=false; h->request=0; h->respond=false;
    (void)matter_mdns_backend(h->module,++h->generation,false); return MATTER_PORT_ERROR;
}
Matter_Result_T matter_mdns_windows_delete(Matter_Mdns_Windows_T h) {
    if(!h) return MATTER_OK;
    Matter_Result_T r=matter_mdns_delete(h->module); if(r) return r;
    close_sockets(h); network_cleanup(); free(h); return MATTER_OK;
}

typedef struct {
    uint64_t id,deadline,due,srv_expires,txt_expires,address_expires;
    char instance[54],target[256];
    Matter_Resolver_Answer_T answer; Matter_Operation_Result_T outcome;
    unsigned attempts; bool done,scheduled,has_address;
} Resolve_Job;
struct Matter_Resolver_Windows { Matter_Mdns_Windows_T io; Resolve_Job jobs[4]; uint64_t next; bool offline; };
static Resolve_Job* job(Matter_Resolver_Windows_T r,uint64_t id) {
    for(unsigned i=0;i<4;++i) if(r->jobs[i].id==id) return &r->jobs[i];
    return NULL;
}
static Matter_Result_T resolve_start(void* u,const Matter_Resolver_Query_T* q,uint64_t* id) {
    Matter_Resolver_Windows_T r=u;
    if(!r || !q || !id || !q->node_id || q->node_id>UINT64_C(0xffffffefffffffff)) return MATTER_INVALID_ARGUMENT;
    if(r->offline || q->interface_id!=r->io->iface.index) return MATTER_OFFLINE;
    Resolve_Job* j=job(r,0); if(!j || r->next==UINT64_MAX) return MATTER_LIMIT_REACHED;
    memset(j,0,sizeof(*j)); j->id=++r->next; j->scheduled=true;
    static const char hex[]="0123456789ABCDEF";
    for(unsigned i=0;i<8;++i) { j->instance[2*i]=hex[q->compressed_fabric[i]>>4]; j->instance[2*i+1]=hex[q->compressed_fabric[i]&15]; }
    snprintf(j->instance+16,sizeof(j->instance)-16,"-%016llX._matter._tcp.local.",(unsigned long long)q->node_id);
    j->answer.idle_ms=500; j->answer.active_ms=300; j->answer.active_threshold_ms=4000;
    *id=j->id; return MATTER_PENDING;
}
static Matter_Result_T resolve_take(void* u,uint64_t id,Matter_Operation_Result_T* outcome,Matter_Resolver_Answer_T* answer) {
    Matter_Resolver_Windows_T r=u; if(!r || !id || !outcome || !answer) return MATTER_INVALID_ARGUMENT;
    Resolve_Job* j=job(r,id); if(!j) return MATTER_INVALID_STATE;
    if(!j->done) return MATTER_PENDING;
    *outcome=j->outcome; if(j->outcome==MATTER_OPERATION_SUCCEEDED) *answer=j->answer;
    memset(j,0,sizeof(*j)); return MATTER_OK;
}
static void resolve_cancel(void* u,uint64_t id) {
    Matter_Resolver_Windows_T r=u; Resolve_Job* j=r && id?job(r,id):NULL;
    if(j && !j->done) { j->outcome=MATTER_OPERATION_CANCELLED; j->done=true; }
}
Matter_Resolver_Port_T matter_resolver_windows_port(Matter_Resolver_Windows_T r) { return (Matter_Resolver_Port_T){r,resolve_start,resolve_take,resolve_cancel}; }
static uint32_t decimal(const uint8_t* p,size_t n,uint32_t maximum,uint32_t fallback) {
    if(!n || n>7 || (n>1 && *p=='0')) return fallback;
    uint32_t v=0;
    for(size_t i=0;i<n;++i) { if(p[i]<'0' || p[i]>'9') return fallback; v=v*10+p[i]-'0'; }
    return v<=maximum?v:fallback;
}
static void resolve_txt(Resolve_Job* j,const uint8_t* p,size_t n) {
    j->answer.idle_ms=500; j->answer.active_ms=300; j->answer.active_threshold_ms=4000;
    unsigned seen=0;
    for(size_t i=0;i<n;) {
        unsigned len=p[i++]; const uint8_t* v=p+i; i+=len; if(len<4 || v[3]!='=') continue;
        unsigned key=!_strnicmp((const char*)v,"SII",3)?1:!_strnicmp((const char*)v,"SAI",3)?2:!_strnicmp((const char*)v,"SAT",3)?4:0;
        if(!key || (seen&key)) continue;
        seen|=key;
        uint32_t value=decimal(v+4,len-4,key==4?65535:3600000,key==1?500:key==2?300:4000);
        if(key==1) j->answer.idle_ms=value; else if(key==2) j->answer.active_ms=value; else j->answer.active_threshold_ms=value;
    }
}
static bool ipv6_unicast(const uint8_t* a) {
    if(a[0]==0xff) return false;
    bool nonzero=false; for(unsigned i=0;i<16;++i) nonzero|=a[i]!=0;
    static const uint8_t mapped[12]={0,0,0,0,0,0,0,0,0,0,0xff,0xff};
    return nonzero && memcmp(a,mapped,12);
}
/* Validate the WHOLE response before applying any RR; then SRV/TXT before AAAA,
 * regardless of record order. Names/workspaces stay in the heap-owned I/O. */
static bool resolve_packet(Matter_Resolver_Windows_T r,size_t n) {
    Matter_Mdns_Windows_T h=r->io;
    if(n<12 || get16(h->rx) || (get16(h->rx+2)&0xfa0f)!=0x8000) return false;
    unsigned questions=get16(h->rx+4),records=get16(h->rx+6)+get16(h->rx+8)+get16(h->rx+10);
    if(questions+records>64) return false;
    for(unsigned pass=0;pass<3;++pass) {
        size_t p=12;
        for(unsigned i=0;i<questions;++i) { if(!name(h->rx,n,&p,h->name) || n-p<4) return false; p+=4; }
        for(unsigned i=0;i<records;++i) {
            if(!name(h->rx,n,&p,h->name) || n-p<10) return false;
            uint16_t type=get16(h->rx+p),cl=get16(h->rx+p+2)&0x7fff,len=get16(h->rx+p+8);
            uint32_t ttl=get32(h->rx+p+4); p+=10; if(len>n-p) return false;
            if(type==33) { size_t end=p+6; if(len<7 || !name(h->rx,n,&end,h->target) || end!=p+len) return false; }
            if((type==28 && len!=16) || (type==16 && !txt_valid(h->rx+p,len))) return false;
            if(pass && cl==1) for(unsigned k=0;k<4;++k) {
                Resolve_Job* j=&r->jobs[k]; if(!j->id || j->done) continue;
                uint64_t expires=ttl?after(h->now,(ttl>120?120:ttl)*1000):0;
                if(pass==1 && !_stricmp(h->name,j->instance)) {
                    if(type==33 && !get16(h->rx+p) && !get16(h->rx+p+2) && get16(h->rx+p+4)) {
                        if(_stricmp(h->target,j->target) || j->answer.peer.port!=get16(h->rx+p+4) || !ttl) j->has_address=false;
                        memcpy(j->target,h->target,strlen(h->target)+1); j->answer.peer.port=get16(h->rx+p+4); j->srv_expires=expires;
                    } else if(type==16) { resolve_txt(j,h->rx+p,len); j->txt_expires=expires; }
                } else if(pass==2 && type==28 && j->srv_expires>h->now && !_stricmp(h->name,j->target)) {
                    if(!ttl) { if(!memcmp(j->answer.peer.address,h->rx+p,16)) j->has_address=false; }
                    else if(ipv6_unicast(h->rx+p) && (!j->has_address || j->address_expires<=h->now ||
                        !memcmp(j->answer.peer.address,h->rx+p,16) || (h->rx[p]==0xfe && (h->rx[p+1]&0xc0)==0x80))) {
                        memcpy(j->answer.peer.address,h->rx+p,16); j->has_address=true; j->address_expires=expires;
                    }
                }
            }
            p+=len;
        }
        if(p!=n) return false;
    }
    return true;
}
static bool resolve_query(Matter_Resolver_Windows_T r,Resolve_Job* j) {
    Matter_Mdns_Windows_T h=r->io; memset(h->tx,0,12); memset(&h->table,0,sizeof(h->table));
    void* p=h->tx+12; unsigned count=j->target[0]?3:2;
    for(unsigned i=0;i<count;++i) {
        const char* q=i==2?j->target:j->instance;
        p=mdns_string_make(h->tx,CAP,p,q,strlen(q),&h->table); if(!p || (uint8_t*)p>h->tx+CAP-4) return false;
        p=mdns_htons(p,i==0?33:i==1?16:28); p=mdns_htons(p,1);
    }
    set16(h->tx+4,(uint16_t)count); return send_packet(h,(uint8_t*)p-h->tx);
}
Matter_Resolver_Windows_T matter_resolver_windows_new(const Matter_Mdns_Windows_Interface_T* iface) {
    if(!iface || !iface->index) return NULL;
    Matter_Resolver_Windows_T r=calloc(1,sizeof(*r)); if(!r) return NULL;
    r->io=calloc(1,sizeof(*r->io)); if(!r->io) { free(r); return NULL; }
    r->io->iface=*iface; r->io->sockets[0]=r->io->sockets[1]=INVALID_SOCKET;
#ifdef _WIN32
    if(WSAStartup(MAKEWORD(2,2),&r->io->startup)) { free(r->io); free(r); return NULL; }
#endif
    if(!open_sockets(r->io)) { network_cleanup(); free(r->io); free(r); return NULL; }
    return r;
}
Matter_Result_T matter_resolver_windows_poll(Matter_Resolver_Windows_T r,uint64_t now) {
    if(!r || now<r->io->now) return MATTER_INVALID_ARGUMENT;
    Matter_Mdns_Windows_T h=r->io; h->now=now;
    for(unsigned i=0;i<2;++i) if(h->sockets[i]!=INVALID_SOCKET) for(unsigned budget=0;budget<4;++budget) {
        size_t n; Matter_Result_T result=read_packet(h,i,&n);
        if(result==MATTER_PORT_ERROR) { close_sockets(h); r->offline=true; break; }
        if(result!=MATTER_OK) break;
        (void)resolve_packet(r,n);
    }
    for(unsigned i=0;i<4;++i) {
        Resolve_Job* j=&r->jobs[i]; if(!j->id || j->done) continue;
        if(j->scheduled) { j->scheduled=false; j->deadline=after(now,5000); j->due=now; }
        if(r->offline || now>=j->deadline) { j->done=true; j->outcome=MATTER_OPERATION_FAILED; }
        else if(j->has_address && j->address_expires>now && j->srv_expires>now && j->txt_expires>now) { j->done=true; j->outcome=MATTER_OPERATION_SUCCEEDED; }
        else if(now>=j->due) {
            if(!resolve_query(r,j)) { j->done=true; j->outcome=MATTER_OPERATION_FAILED; }
            j->due=after(now,1000u<<(j->attempts<2?j->attempts++:2));
        }
    }
    return MATTER_OK;
}
Matter_Result_T matter_resolver_windows_delete(Matter_Resolver_Windows_T r) {
    if(!r) return MATTER_OK;
    for(unsigned i=0;i<4;++i) if(r->jobs[i].id) return MATTER_BUSY;
    close_sockets(r->io); network_cleanup(); free(r->io); free(r); return MATTER_OK;
}

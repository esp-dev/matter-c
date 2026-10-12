/* Test-only raw injector: fixed IPv6 cases, loopback/link-local destinations.
 * Requires CAP_NET_RAW; the Matter node and receiving tests do not. */
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void put16(uint8_t* p,unsigned x) { p[0]=(uint8_t)(x>>8); p[1]=(uint8_t)x; }
static unsigned sum(const uint8_t* p,size_t n,unsigned s) {
    while(n>=2) { s+=(unsigned)p[0]*256+p[1]; p+=2; n-=2; }
    if(n) s+=(unsigned)*p*256;
    return s;
}
int main(int argc,char** argv) {
    if(argc!=5) { fputs("usage: ipv6-inject ADDRESS SCOPE PORT CASE(0..13)\n",stderr); return 2; }
    struct sockaddr_in6 peer={.sin6_family=AF_INET6};
    if(inet_pton(AF_INET6,argv[1],&peer.sin6_addr)!=1 ||
        (!IN6_IS_ADDR_LOOPBACK(&peer.sin6_addr) && !IN6_IS_ADDR_LINKLOCAL(&peer.sin6_addr))) return 2;
    char* end; unsigned long scope=strtoul(argv[2],&end,10); if(*end || scope>UINT32_MAX) return 2;
    peer.sin6_scope_id=(uint32_t)scope;
    unsigned long port=strtoul(argv[3],&end,10); if(*end || !port || port>65535) return 2;
    unsigned long which=strtoul(argv[4],&end,10); if(*end || which>13) return 2;
    static const unsigned sizes[]={1,1232,1233,1224,1225,1216,1217,1,1,16,16,1,1,0};
    unsigned payload=sizes[which],extension=(which==3 || which==4 || which==7 || which==8)?8:(which==5 || which==6)?16:0;
    uint8_t* packet=calloc(1,2048); if(!packet) return 1;
    uint8_t* udp=packet+40+extension;
    packet[0]=0x60; packet[6]=extension?(which==5 || which==6?0:60):17; packet[7]=64;
    /* The local destination is also a valid local source. No spoofed remote. */
    memcpy(packet+8,&peer.sin6_addr,16); memcpy(packet+24,&peer.sin6_addr,16);
    if(extension) {
        packet[40]=extension==16?60:17; packet[41]=0;
        packet[42]=1; packet[43]=4; /* PadN */
        if(extension==16) { packet[48]=17; packet[49]=0; packet[50]=1; packet[51]=4; }
    }
    put16(udp,59998); put16(udp+2,(unsigned)port); put16(udp+4,8+payload);
    for(unsigned i=0;i<payload;++i) udp[8+i]=(uint8_t)(which+i);
    unsigned check=sum(packet+8,32,8+payload+17); check=sum(udp,8+payload,check);
    while(check>>16) check=(check&65535)+(check>>16);
    put16(udp+6,(~check&65535)?~check&65535:65535);
    if(which==7) packet[41]=10; /* Extension claims more bytes than exist. */
    if(which==8) udp[6]^=1;     /* Incorrect UDP checksum after valid extension. */
    if(which==11) put16(udp+6,0); /* IPv6 zero checksum must be rejected. */
    if(which==12) put16(udp+4,100); /* UDP length larger than IPv6 payload. */
    put16(packet+4,extension+8+payload);
    int fd=socket(AF_INET6,SOCK_RAW|SOCK_CLOEXEC,IPPROTO_RAW),result=1;
    if(fd<0) { perror("raw injector (CAP_NET_RAW required)"); goto done; }
    if(which==9 || which==10) {
        /* Atomic fragment, then two real fragments of a 24-byte UDP datagram. */
        memmove(packet+48,udp,8+payload); packet[6]=44; packet[40]=17;
        memset(packet+41,0,7); packet[47]=(uint8_t)(which+1);
        unsigned first=which==9?24:16; put16(packet+4,8+first); put16(packet+42,which==10?1:0);
        if(sendto(fd,packet,48+first,0,(struct sockaddr*)&peer,sizeof(peer))!=(ssize_t)(48+first)) goto io;
        if(which==10) {
            memmove(packet+48,packet+64,8); put16(packet+4,16); put16(packet+42,16);
            if(sendto(fd,packet,56,0,(struct sockaddr*)&peer,sizeof(peer))!=56) goto io;
        }
    } else if(sendto(fd,packet,48+extension+payload,0,(struct sockaddr*)&peer,sizeof(peer))!=(ssize_t)(48+extension+payload)) goto io;
    printf("Injected case %lu, payload %u, extensions %u\n",which,payload,extension); result=0; goto done;
io: perror("send raw IPv6");
done: if(fd>=0) close(fd); free(packet); return result;
}

/* Actual Linux IPv6 RX, with a separate privileged fixed-case packet injector.
 * Receiver stays unprivileged; each rejected packet is followed by good data. */
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include "matter_host_platform.h"
#include "matter_udp_windows.h"
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"IPv6:%d: %s\n",__LINE__,#x); exit(1); } } while(0)
typedef struct { unsigned count; size_t size; uint8_t first; } Received;
static void receive(void* u,const Matter_Udp_Datagram_T* d) {
    Received* r=u; ++r->count; r->size=d->size; r->first=d->data[0];
    CHECK(d->path.interface_id && d->path.peer.port==59998 && d->path.local.address[15]==1);
}
static void inject(const char* exe,unsigned port,unsigned which) {
    char p[8],c[8]; snprintf(p,sizeof(p),"%u",port); snprintf(c,sizeof(c),"%u",which);
    pid_t child=fork(); CHECK(child>=0);
    if(!child) { execl(exe,exe,"::1","0",p,c,(char*)NULL); _exit(127); }
    int status; CHECK(waitpid(child,&status,0)==child && WIFEXITED(status) && WEXITSTATUS(status)==0);
}
/* Prove policy negatives reach a bare socket and identify both fragment forms. */
static void baseline(const char* injector) {
    int fd=socket(AF_INET6,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,IPPROTO_UDP); CHECK(fd>=0);
    int yes=1; CHECK(!setsockopt(fd,IPPROTO_IPV6,IPV6_RECVFRAGSIZE,&yes,sizeof(yes)));
    struct sockaddr_in6 a={.sin6_family=AF_INET6,.sin6_addr=IN6ADDR_LOOPBACK_INIT};
    socklen_t length=sizeof(a); CHECK(!bind(fd,(struct sockaddr*)&a,length)); CHECK(!getsockname(fd,(struct sockaddr*)&a,&length));
    uint8_t* bytes=malloc(1500); CHECK(bytes);
    static const unsigned sizes[]={1,1232,1233,1224,1225,1216,1217,0,0,16,16,0,0,0};
    for(unsigned i=0;i<14;++i) {
        inject(injector,ntohs(a.sin6_port),i);
        union { struct cmsghdr align; char bytes[CMSG_SPACE(sizeof(int))]; } control;
        struct iovec b={bytes,1500}; struct msghdr m={.msg_iov=&b,.msg_iovlen=1,.msg_control=control.bytes,.msg_controllen=sizeof(control.bytes)};
        ssize_t got=-1; uint64_t until=matter_host_now()+100;
        do { got=recvmsg(fd,&m,MSG_DONTWAIT); if(got>=0) break; CHECK(errno==EAGAIN || errno==EWOULDBLOCK); matter_host_sleep(1); } while(matter_host_now()<until);
        if(sizes[i] || i==13) CHECK(got==(ssize_t)sizes[i]); else CHECK(got<0);
        if(i==9 || i==10) {
            struct cmsghdr* c=CMSG_FIRSTHDR(&m); CHECK(c && c->cmsg_level==IPPROTO_IPV6 && c->cmsg_type==IPV6_RECVFRAGSIZE);
            int size=0; memcpy(&size,CMSG_DATA(c),sizeof(size)); CHECK(size>0);
        }
    }
    free(bytes); close(fd);
    puts("PASS kernel baseline: oversize+extensions deliver without filter; atomic/reassembled FRAGSIZE; malformed packets rejected");
}
int main(void) {
    const char* injector=getenv("MATTER_IPV6_INJECTOR");
    CHECK(injector && *injector);
    baseline(injector);
    Received r={0}; Matter_T owner=matter_new(NULL); CHECK(owner && matter_start(owner)==MATTER_OK);
    Matter_Udp_Address_T address={0}; address.address[15]=1;
    Matter_Udp_Listener_T listener={.user=&r,.received=receive};
    Matter_Udp_Windows_T host=matter_udp_windows_new(owner,&address,0,&listener); CHECK(host);
    Matter_Udp_T udp=matter_udp_windows_module(host); CHECK(matter_udp_start(udp)==MATTER_OK);
    CHECK(matter_udp_windows_local(host,&address)==MATTER_OK);
    static const unsigned accepted[]={1,1232,0,1224,0,1216,0,0,0,0,0,0,0,0};
    for(unsigned which=0;which<14;++which) {
        unsigned before=r.count; inject(injector,address.port,which);
        uint64_t until=matter_host_now()+100;
        do { Matter_Result_T result=matter_udp_windows_poll(host);
            CHECK(result==MATTER_OK || result==MATTER_WOULD_BLOCK || result==MATTER_LIMIT_REACHED || result==MATTER_INVALID_ARGUMENT);
            matter_host_sleep(1);
        } while(matter_host_now()<until);
        CHECK(r.count==before+(accepted[which]?1u:0u));
        if(accepted[which]) CHECK(r.size==accepted[which] && r.first==which);
        inject(injector,address.port,0); until=matter_host_now()+1000;
        while(r.count==before+(accepted[which]?1u:0u) && matter_host_now()<until) {
            (void)matter_udp_windows_poll(host); matter_host_sleep(1);
        }
        CHECK(r.count==before+(accepted[which]?2u:1u) && r.first==0);
    }
    CHECK(matter_udp_stop(udp)==MATTER_PENDING);
    while(matter_udp_is_active(udp)) (void)matter_udp_process(udp);
    CHECK(matter_udp_windows_delete(host)==MATTER_OK);
    /* Wildcard IPv6 binding still confines RX to the selected interface. */
    unsigned loop=if_nametoindex("lo"); CHECK(loop);
    for(unsigned match=0;match<2;++match) {
        address=(Matter_Udp_Address_T){0}; unsigned before=r.count;
        host=matter_udp_windows_new(owner,&address,match?loop:UINT32_MAX,&listener); CHECK(host);
        udp=matter_udp_windows_module(host); CHECK(matter_udp_start(udp)==MATTER_OK);
        CHECK(matter_udp_windows_local(host,&address)==MATTER_OK);
        inject(injector,address.port,0); uint64_t until=matter_host_now()+100;
        do { Matter_Result_T result=matter_udp_windows_poll(host); CHECK(result==MATTER_OK || result==MATTER_WOULD_BLOCK); matter_host_sleep(1); } while(matter_host_now()<until);
        CHECK(r.count==before+match);
        CHECK(matter_udp_stop(udp)==MATTER_PENDING);
        while(matter_udp_is_active(udp)) (void)matter_udp_process(udp);
        CHECK(matter_udp_windows_delete(host)==MATTER_OK);
    }
    puts("PASS wildcard IPv6 bind: matching interface receives, different interface drops");
    CHECK(matter_stop(owner)==MATTER_OK && matter_delete(owner)==MATTER_OK);
    puts("PASS IPv6: 14 raw cases, exact MTU incl. extensions, checksum/length, fragments, empty; recovery after each");
    return 0;
}

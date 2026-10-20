/* Linux laboratory interposition only; never linked into the Matter library.
 * Fail exactly one operational SRV/TXT resolver query in this process. Ordinary
 * publications/probes and all other processes/interfaces remain untouched. */
#define _GNU_SOURCE
#include <sys/socket.h>
#include <netinet/in.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

static int log_fd=-1;
static int injected;

__attribute__((destructor)) static void cleanup(void) {
    if(log_fd>=0) close(log_fd);
}
static unsigned get16(const uint8_t* p) { return ((unsigned)p[0]<<8)|p[1]; }
static int resolver_query(const void* data,size_t size,const struct sockaddr* peer,socklen_t length) {
    if(!peer || peer->sa_family!=AF_INET6 || length<sizeof(struct sockaddr_in6)) return 0;
    const struct sockaddr_in6* address=(const struct sockaddr_in6*)peer;
    if(ntohs(address->sin6_port)!=5353 || address->sin6_addr.s6_addr[0]!=0xff ||
        address->sin6_addr.s6_addr[1]!=2 || address->sin6_addr.s6_addr[15]!=0xfb || size<17) return 0;
    const uint8_t* p=data;
    if(get16(p) || get16(p+2) || get16(p+4)!=2 || get16(p+6) || get16(p+8) || get16(p+10)) return 0;
    size_t offset=12;
    while(offset<size && p[offset]) {
        unsigned n=p[offset++];
        if(n>63 || n>size-offset) return 0;
        offset+=n;
    }
    if(offset>=size || size-++offset<4) return 0;
    return get16(p+offset)==33 && get16(p+offset+2)==1;
}
ssize_t sendto(int fd,const void* data,size_t size,int flags,const struct sockaddr* peer,socklen_t length) {
    static ssize_t (*next)(int,const void*,size_t,int,const struct sockaddr*,socklen_t);
    if(!next) *(void**)(&next)=dlsym(RTLD_NEXT,"sendto");
    if(!next) _exit(126);
    const char* path=getenv("MATTER_TEST_DNS_FAILURE_LOG");
    if(path && !injected && resolver_query(data,size,peer,length)) {
        /* Open lazily: the Valgrind launcher can load this library too, but
         * only the requestor's matching query may claim the one-shot marker. */
        log_fd=open(path,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);
        if(log_fd<0) _exit(126);
        struct timespec now;
        if(clock_gettime(CLOCK_MONOTONIC,&now)) _exit(126);
        char line[144];
        int n=snprintf(line,sizeof(line),"{\"operation\":\"sendto\",\"errno\":%d,\"monotonic_ms\":%llu}\n",
            ENETUNREACH,(unsigned long long)now.tv_sec*1000+(unsigned long long)now.tv_nsec/1000000);
        if(n<=0 || (size_t)n>=sizeof(line) || write(log_fd,line,(size_t)n)!=n) _exit(126);
        injected=1; errno=ENETUNREACH; return -1;
    }
    return next(fd,data,size,flags,peer,length);
}

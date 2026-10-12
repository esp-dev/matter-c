/* Test-only Linux interposer, enabled by a marker after CASE/Read completes.
 * Only the selected DUT port; no keys/payloads logged. First RX is RemoveFabric.
 * loss: drop first response, duplicate request. noack: drop all subsequent RX.
 * The controller and production executable are unmodified. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct {
    unsigned port,rx,tx; bool noack,pending; int fd,flags;
    size_t size,controls,response_size; socklen_t names;
    unsigned char bytes[1232],control[256],response[1232]; struct sockaddr_storage name;
    const char* marker; FILE* log;
} Faults;
static Faults* state;
static ssize_t (*send_real)(int,const struct msghdr*,int);
static ssize_t (*recv_real)(int,struct msghdr*,int);
static void initialize(void) {
    if(send_real) return;
    *(void**)(&send_real)=dlsym(RTLD_NEXT,"sendmsg"); *(void**)(&recv_real)=dlsym(RTLD_NEXT,"recvmsg");
    if(!send_real || !recv_real) abort();
    const char* marker=getenv("MATTER_REMOVE_MARKER"); if(!marker) return;
    state=calloc(1,sizeof(*state)); if(!state) abort();
    state->marker=marker; state->port=(unsigned)strtoul(getenv("MATTER_REMOVE_PORT"),NULL,10);
    state->noack=!strcmp(getenv("MATTER_REMOVE_MODE"),"noack");
    state->log=fopen(getenv("MATTER_REMOVE_LOG"),"w"); if(!state->log) abort();
    setvbuf(state->log,NULL,_IONBF,0);
}
static bool selected(int fd) {
    if(!state || access(state->marker,F_OK)) return false;
    struct sockaddr_in6 address; socklen_t size=sizeof(address);
    return !getsockname(fd,(struct sockaddr*)&address,&size) && address.sin6_family==AF_INET6 && ntohs(address.sin6_port)==state->port;
}
ssize_t sendmsg(int fd,const struct msghdr* m,int flags) {
    initialize();
    if(selected(fd) && m->msg_iovlen==1 && m->msg_iov[0].iov_len>40) {
        size_t n=m->msg_iov[0].iov_len; if(n>sizeof(state->response)) abort();
        if(!state->tx++) {
            memcpy(state->response,m->msg_iov[0].iov_base,n); state->response_size=n;
            fprintf(state->log,"response first%s\n",state->noack?"":" dropped");
            if(!state->noack) return (ssize_t)n;
        } else {
            bool same=n==state->response_size && !memcmp(state->response,m->msg_iov[0].iov_base,n);
            fprintf(state->log,"response retry same=%u\n",same); if(!same) abort();
        }
    }
    return send_real(fd,m,flags);
}
ssize_t recvmsg(int fd,struct msghdr* m,int flags) {
    initialize();
    if(state && state->pending && fd==state->fd) {
        if(m->msg_iovlen!=1 || m->msg_iov[0].iov_len<state->size || m->msg_controllen<state->controls || m->msg_namelen<state->names) abort();
        memcpy(m->msg_iov[0].iov_base,state->bytes,state->size); memcpy(m->msg_control,state->control,state->controls); memcpy(m->msg_name,&state->name,state->names);
        m->msg_controllen=state->controls; m->msg_namelen=state->names; m->msg_flags=state->flags;
        state->pending=false; fputs("request duplicated\n",state->log); return (ssize_t)state->size;
    }
    ssize_t r=recv_real(fd,m,flags);
    if(r>0 && selected(fd)) {
        if(state->rx++ && state->noack) { fputs("rx dropped\n",state->log); errno=EAGAIN; return -1; }
        if(state->rx==1 && !state->noack) {
            if(m->msg_iovlen!=1 || (size_t)r>sizeof(state->bytes) || m->msg_controllen>sizeof(state->control) || m->msg_namelen>sizeof(state->name) || (m->msg_flags&(MSG_TRUNC|MSG_CTRUNC))) abort();
            state->pending=true; state->fd=fd; state->size=(size_t)r; state->controls=m->msg_controllen; state->names=m->msg_namelen; state->flags=m->msg_flags;
            memcpy(state->bytes,m->msg_iov[0].iov_base,state->size); memcpy(state->control,m->msg_control,state->controls); memcpy(&state->name,m->msg_name,state->names);
        }
    }
    return r;
}
__attribute__((destructor)) static void finish(void) { if(state) { fclose(state->log); free(state); state=NULL; } }

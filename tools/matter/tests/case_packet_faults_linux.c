/* Test-only, single-owner Linux DUT interposer. No changes to node/controller.
 * Only recvmsg/sendmsg on explicit DUT port, only observed CASE exchanges.
 * Bounded heap records; no keys or payload bytes are written to the log. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "codec/matter_message_header.h"
#include "codec/matter_protocol_header.h"
enum { LIMIT=96, BYTES=1232 };
typedef struct { uint64_t node; uint32_t final_counter; uint16_t exchange; bool resumed; } Exchange;
typedef struct { uint64_t node; uint32_t counter; size_t size; unsigned hits; bool tx; uint8_t bytes[BYTES]; } Record;
typedef struct {
    Exchange exchanges[24]; unsigned nex, count, changes, retries, errors;
    Record records[LIMIT];
    bool duplicate, data_loss, resume_ack_loss, pending; unsigned port; int fd;
    uint8_t bytes[BYTES], control[256]; struct sockaddr_storage name;
    size_t size, controls; socklen_t names; int flags;
    FILE* log;
} Faults;
static Faults* state;
static ssize_t (*send_real)(int,const struct msghdr*,int);
static ssize_t (*recv_real)(int,struct msghdr*,int);
static void initialize(void) {
    if(send_real) return;
    *(void**)(&send_real)=dlsym(RTLD_NEXT,"sendmsg"); *(void**)(&recv_real)=dlsym(RTLD_NEXT,"recvmsg");
    if(!send_real || !recv_real) abort();
    const char* mode=getenv("MATTER_CASE_FAULTS"),*path=getenv("MATTER_CASE_FAULT_LOG"),*port=getenv("MATTER_CASE_FAULT_PORT");
    if(!mode || !path || !port) return;
    if(strcmp(mode,"drop") && strcmp(mode,"duplicate") && strcmp(mode,"data-loss") && strcmp(mode,"resume-ack-loss")) abort();
    state=calloc(1,sizeof(*state)); if(!state) abort();
    state->port=(unsigned)strtoul(port,NULL,10); state->duplicate=!strcmp(mode,"duplicate");
    state->data_loss=!strcmp(mode,"data-loss"); state->resume_ack_loss=!strcmp(mode,"resume-ack-loss");
    if(!state->port || state->port>65535 || !(state->log=fopen(path,"w"))) abort();
    setvbuf(state->log,NULL,_IONBF,0);
}
static bool socket_matches(int fd) {
    if(!state) return false;
    struct sockaddr_in6 address; socklen_t size=sizeof(address);
    return !getsockname(fd,(struct sockaddr*)&address,&size) && address.sin6_family==AF_INET6 && ntohs(address.sin6_port)==state->port;
}
static bool change(int fd,const struct msghdr* m,size_t size,bool tx) {
    if(!socket_matches(fd) || m->msg_iovlen!=1 || size>BYTES || size>m->msg_iov[0].iov_len) return false;
    const uint8_t* p=m->msg_iov[0].iov_base; Matter_Message_Header_T h; Matter_Protocol_Header_T ph; size_t n,k;
    if(matter_message_header_read(p,size,&h,&n)!=MATTER_MESSAGE_OK || h.session_id || h.security_flags ||
        matter_protocol_header_read(p+n,size-n,&ph,&k)!=MATTER_MESSAGE_OK || ph.protocol_id || ph.vendor_id) return false;
    uint64_t node=tx?h.destination_id:h.source_node_id; if(!node) return false;
    bool known=false; for(unsigned i=0;i<state->nex;++i) if(state->exchanges[i].node==node && state->exchanges[i].exchange==ph.exchange_id) known=true;
    if(!known && !tx && ph.opcode==0x30) {
        if(state->nex==24) { ++state->errors; return false; }
        state->exchanges[state->nex++]=(Exchange){.node=node,.exchange=ph.exchange_id}; known=true;
    }
    if(!known || (ph.opcode!=0x10 && ph.opcode!=0x30 && ph.opcode!=0x31 && ph.opcode!=0x32 && ph.opcode!=0x33 && ph.opcode!=0x40)) return false;
    Exchange* exchange=NULL;
    for(unsigned i=0;i<state->nex;++i) if(state->exchanges[i].node==node && state->exchanges[i].exchange==ph.exchange_id) exchange=&state->exchanges[i];
    if(exchange && tx && ph.opcode==0x33) exchange->resumed=true;
    if(exchange && !tx && ph.opcode==0x40) exchange->final_counter=h.message_counter;
    if(state->data_loss && ph.opcode==0x10) return false;
    if(state->resume_ack_loss && !(exchange && exchange->resumed && tx && ph.opcode==0x10 &&
        ph.acknowledged_message_counter==exchange->final_counter)) return false;
    for(unsigned i=0;i<state->count;++i) {
        Record* r=&state->records[i];
        if(r->node==node && r->counter==h.message_counter && r->tx==tx) {
            bool same=r->size==size && !memcmp(r->bytes,p,size); ++r->hits; ++state->retries; if(!same) ++state->errors;
            fprintf(state->log,"retry %s opcode=%02x same=%u\n",tx?"tx":"rx",ph.opcode,same); return false;
        }
    }
    if(state->count==LIMIT) { ++state->errors; return false; }
    Record* r=&state->records[state->count++]; r->node=node; r->counter=h.message_counter; r->tx=tx; r->size=size; memcpy(r->bytes,p,size);
    /* ACKs get fresh counters. Drop only the first standalone ACK of each
     * direction/exchange, otherwise there would never be a recovery. */
    if(ph.opcode==0x10) for(unsigned i=0;i+1<state->count;++i) {
        Record* old=&state->records[i]; Matter_Message_Header_T oh; Matter_Protocol_Header_T op; size_t on,ok;
        if(old->node==node && old->tx==tx && matter_message_header_read(old->bytes,old->size,&oh,&on)==MATTER_MESSAGE_OK &&
            matter_protocol_header_read(old->bytes+on,old->size-on,&op,&ok)==MATTER_MESSAGE_OK && op.opcode==0x10 && op.exchange_id==ph.exchange_id) return false;
    }
    ++state->changes; fprintf(state->log,"%s %s opcode=%02x\n",state->duplicate?"duplicate":"drop",tx?"tx":"rx",ph.opcode); return true;
}
ssize_t sendmsg(int fd,const struct msghdr* m,int flags) {
    initialize(); size_t size=m->msg_iovlen==1?m->msg_iov[0].iov_len:0;
    bool alter=change(fd,m,size,true);
    if(alter && !state->duplicate) return (ssize_t)size;
    ssize_t r=send_real(fd,m,flags);
    if(alter && r==(ssize_t)size && send_real(fd,m,flags)!=r) ++state->errors;
    return r;
}
ssize_t recvmsg(int fd,struct msghdr* m,int flags) {
    initialize();
    if(state && state->pending && fd==state->fd) {
        if(m->msg_iovlen!=1 || m->msg_iov[0].iov_len<state->size || m->msg_controllen<state->controls || m->msg_namelen<state->names) abort();
        memcpy(m->msg_iov[0].iov_base,state->bytes,state->size); memcpy(m->msg_control,state->control,state->controls); memcpy(m->msg_name,&state->name,state->names);
        m->msg_controllen=state->controls; m->msg_namelen=state->names; m->msg_flags=state->flags; state->pending=false; return (ssize_t)state->size;
    }
    ssize_t r=recv_real(fd,m,flags);
    if(r>0 && !(m->msg_flags&(MSG_TRUNC|MSG_CTRUNC)) && change(fd,m,(size_t)r,false)) {
        if(!state->duplicate) { errno=EAGAIN; return -1; }
        if(state->pending || m->msg_controllen>sizeof(state->control) || m->msg_namelen>sizeof(state->name)) abort();
        state->pending=true;state->fd=fd;state->size=(size_t)r;state->controls=m->msg_controllen;state->names=m->msg_namelen;state->flags=m->msg_flags;
        memcpy(state->bytes,m->msg_iov[0].iov_base,state->size);memcpy(state->control,m->msg_control,state->controls);memcpy(&state->name,m->msg_name,state->names);
    }
    return r;
}
__attribute__((destructor)) static void finish(void) {
    if(!state) return;
    fprintf(state->log,"summary changes=%u retries=%u errors=%u pending=%u\n",state->changes,state->retries,state->errors,state->pending);
    fclose(state->log); memset(state,0,sizeof(*state));free(state);state=NULL;
}

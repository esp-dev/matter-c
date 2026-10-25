#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#define CHECK(x) do{if(!(x)){fprintf(stderr,"BTP:%d: %s\n",__LINE__,#x);abort();}}while(0)
static size_t calls,live,fail_at;
static void* btp_calloc(size_t n,size_t s){++calls;if(calls==fail_at)return NULL;void* p=calloc(n,s);if(p)++live;return p;}
static void btp_free(void* p){if(p){CHECK(live);--live;free(p);}}
#define calloc btp_calloc
#define free btp_free
#include "transport/matter_btp.c"
#undef calloc
#undef free

static Matter_Btp_T connected(uint16_t mtu){
    Matter_Btp_T b=matter_btp_new(mtu,0);CHECK(b);
    uint8_t request[]={0x65,0x6c,4,0,0,0,(uint8_t)mtu,(uint8_t)(mtu>>8),4};
    CHECK(matter_btp_receive(b,request,sizeof(request),0)==MATTER_OK);
    const uint8_t* out;size_t size;CHECK(matter_btp_output(b,&out,&size,0)==MATTER_OK&&size==6&&out[2]==4);
    CHECK(matter_btp_sent(b,0)==MATTER_OK&&matter_btp_ready(b));
    const uint8_t ack[]={8,0,0};CHECK(matter_btp_receive(b,ack,sizeof(ack),1)==MATTER_OK);return b;
}
static void transmit(uint16_t mtu,size_t size,unsigned repetitions){
    Matter_Btp_T b=connected(mtu);uint8_t* payload=malloc(size),*copy=malloc(size);CHECK(payload&&copy);
    for(size_t i=0;i<size;++i)payload[i]=(uint8_t)(i*19);
    uint8_t peer=1;uint64_t now=2;unsigned frames=0;
    for(unsigned r=0;r<repetitions;++r){
        CHECK(matter_btp_send(b,payload,size)==MATTER_OK&&matter_btp_send(b,payload,size)==MATTER_BUSY);
        CHECK(matter_btp_send_take(b)==MATTER_PENDING);size_t written=0;
        while(written<size){const uint8_t *out,*again;size_t n,m;
            CHECK(matter_btp_output(b,&out,&n,now)==MATTER_OK);
            CHECK(matter_btp_output(b,&again,&m,now)==MATTER_OK&&out==again&&n==m);
            CHECK(n<=(size_t)mtu-3&&n<=244);size_t cursor=1+(!!(out[0]&8));uint8_t sequence=out[cursor++];
            CHECK(sequence==(uint8_t)(++frames));if(out[0]&1){CHECK(!written);CHECK((out[cursor]|((size_t)out[cursor+1]<<8))==size);cursor+=2;}
            CHECK(n>cursor&&n-cursor<=size-written);memcpy(copy+written,out+cursor,n-cursor);written+=n-cursor;
            CHECK(!!(out[0]&4)==(written==size));CHECK(matter_btp_sent(b,now++)==MATTER_OK);
            CHECK(matter_btp_send_take(b)==MATTER_PENDING);
            uint8_t ack[]={8,sequence,peer++};CHECK(matter_btp_receive(b,ack,sizeof(ack),now++)==MATTER_OK);
        }
        CHECK(matter_btp_send_take(b)==MATTER_OK&&!memcmp(payload,copy,size));
    }
    CHECK(b->rx_next==peer);matter_btp_delete(b);CHECK(!live);free(payload);free(copy);
}
static void receive_message(uint16_t mtu){
    Matter_Btp_T b=connected(mtu);uint8_t* payload=malloc(1232);CHECK(payload);for(unsigned i=0;i<1232;++i)payload[i]=(uint8_t)i;
    uint8_t frame[244],peer=1,ack=0;bool ack_present=false;size_t used=0;uint64_t now=2;
    while(used<1232){size_t cursor=1;uint8_t flags=used?2:1;
        if(ack_present){flags|=8;frame[cursor++]=ack;}frame[cursor++]=peer++;
        if(!used){frame[cursor++]=0xd0;frame[cursor++]=4;}
        size_t count=1232-used;if(count>b->fragment-cursor)count=b->fragment-cursor;
        if(count==1232-used)flags|=4;
        frame[0]=flags;memcpy(frame+cursor,payload+used,count);used+=count;
        CHECK(matter_btp_receive(b,frame,cursor+count,now)==MATTER_OK);
        const uint8_t* out;size_t n;now+=200;CHECK(matter_btp_output(b,&out,&n,now)==MATTER_OK&&out[0]==8&&n==3);
        ack=out[2];ack_present=true;CHECK(matter_btp_sent(b,now++)==MATTER_OK);
    }
    const uint8_t* out;size_t n;CHECK(matter_btp_received(b,&out,&n)==MATTER_OK&&n==1232&&!memcmp(out,payload,n));
    matter_btp_received_release(b);CHECK(matter_btp_received(b,&out,&n)==MATTER_WOULD_BLOCK);
    matter_btp_delete(b);CHECK(!live);free(payload);
}
static void failures(void){
    fail_at=calls+1;CHECK(!matter_btp_new(247,0));fail_at=0;CHECK(!live);
    Matter_Btp_T b=connected(247);fail_at=calls+1;
    const uint8_t body[]={5,1,1,0,42};CHECK(matter_btp_receive(b,body,sizeof(body),2)==MATTER_PORT_ERROR);fail_at=0;matter_btp_delete(b);CHECK(!live);
    b=connected(247);uint8_t future_ack[]={8,9,1};CHECK(matter_btp_receive(b,future_ack,sizeof(future_ack),2)==MATTER_PORT_ERROR);matter_btp_delete(b);
    b=connected(247);uint8_t bad_sequence[]={5,2,1,0,42};CHECK(matter_btp_receive(b,bad_sequence,sizeof(bad_sequence),2)==MATTER_PORT_ERROR);matter_btp_delete(b);
    b=connected(247);uint8_t too_large[]={1,1,0xd1,4};CHECK(matter_btp_receive(b,too_large,sizeof(too_large),2)==MATTER_PORT_ERROR);matter_btp_delete(b);
    b=connected(247);uint8_t partial[]={5,1,2,0,42};CHECK(matter_btp_receive(b,partial,sizeof(partial),2)==MATTER_PORT_ERROR);matter_btp_delete(b);
    for(size_t n=1;n<5;++n){b=connected(247);CHECK(matter_btp_receive(b,partial,n,2)==MATTER_PORT_ERROR);matter_btp_delete(b);}
    b=matter_btp_new(247,0);CHECK(b&&matter_btp_process(b,5000)==MATTER_PORT_ERROR);matter_btp_delete(b);
    b=connected(247);const uint8_t* p;size_t n;CHECK(matter_btp_output(b,&p,&n,199)==MATTER_WOULD_BLOCK);
    CHECK(matter_btp_output(b,&p,&n,201)==MATTER_OK);CHECK(matter_btp_sent(b,201)==MATTER_OK);
    CHECK(matter_btp_process(b,15200)==MATTER_OK&&matter_btp_process(b,15201)==MATTER_PORT_ERROR);matter_btp_delete(b);
    b=matter_btp_new(247,0);uint8_t unknown[]={0x65,0x6c,3,0,0,0,247,0,4};
    CHECK(matter_btp_receive(b,unknown,sizeof(unknown),0)==MATTER_OK&&matter_btp_output(b,&p,&n,0)==MATTER_OK&&p[2]==0);
    CHECK(matter_btp_sent(b,0)==MATTER_OK&&!matter_btp_ready(b)&&matter_btp_process(b,1)==MATTER_PORT_ERROR);matter_btp_delete(b);CHECK(!live);
}
int main(void){transmit(23,1232,1);transmit(247,1232,1);transmit(247,1,600);receive_message(23);receive_message(247);failures();puts("PASS BTP: negotiation, fragmentation, windows, wrapping ACK/sequence, immutable TX, timeout, malformed RX, OOM and cleanup");return 0;}

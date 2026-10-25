#include "matter_btp.h"
#include "../ports/matter_udp_port.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

enum { BEGIN=1, CONTINUE=2, END=4, ACK=8, WINDOW=4, FRAGMENT=244,
       ACK_TIMEOUT=15000, SEND_ACK=200, HANDSHAKE_TIMEOUT=5000 };
struct Matter_Btp {
    uint16_t mtu,fragment;uint8_t window,rx_next,rx_last,tx_next,oldest,outstanding,rx_unacked;
    uint64_t now,response_deadline,ack_deadline,send_ack_at;
    uint8_t *rx;size_t rx_size,rx_used;
    const uint8_t* tx;size_t tx_size,tx_used;
    bool requested,ready,failed,ack_pending,rx_complete,tx_done,last_valid;
    uint8_t last_sequence;
    uint8_t output[FRAGMENT];size_t output_size,output_payload;
    bool output_handshake,output_ack,output_data;
};
static void wipe(void* p,size_t n){volatile uint8_t* b=p;while(n--)*b++=0;}
static uint64_t after(uint64_t now,unsigned duration){return UINT64_MAX-now<duration?UINT64_MAX:now+duration;}
static Matter_Result_T fail(Matter_Btp_T b){b->failed=true;return MATTER_PORT_ERROR;}
Matter_Btp_T matter_btp_new(uint16_t mtu,uint64_t now){
    if(mtu<23||mtu>517)return NULL;
    Matter_Btp_T b=calloc(1,sizeof(*b));if(!b)return NULL;
    b->mtu=mtu;b->now=now;b->response_deadline=after(now,HANDSHAKE_TIMEOUT);return b;
}
void matter_btp_delete(Matter_Btp_T b){if(b){if(b->rx)wipe(b->rx,b->rx_size);free(b->rx);wipe(b,sizeof(*b));free(b);}}
Matter_Result_T matter_btp_process(Matter_Btp_T b,uint64_t now){
    if(!b||now<b->now)return MATTER_INVALID_ARGUMENT;
    b->now=now;if(b->failed)return MATTER_PORT_ERROR;
    if((!b->ready&&now>=b->response_deadline)||(b->outstanding&&now>=b->ack_deadline))return fail(b);
    return MATTER_OK;
}
static Matter_Result_T handshake(Matter_Btp_T b,const uint8_t* p,size_t n){
    if(n!=9||p[0]!=0x65||p[1]!=0x6c||!p[8])return fail(b);
    bool version=false;for(unsigned i=2;i<6;++i)version|=(p[i]&15)==4||(p[i]>>4)==4;
    uint16_t mtu=(uint16_t)(p[6]|((uint16_t)p[7]<<8));
    if(mtu&&mtu<23)return fail(b);
    if(!mtu||mtu>b->mtu)mtu=b->mtu;
    b->fragment=mtu-3;if(b->fragment>FRAGMENT)b->fragment=FRAGMENT;
    b->window=p[8]<WINDOW?p[8]:WINDOW;b->requested=true;
    b->output[0]=0x65;b->output[1]=0x6c;b->output[2]=version?4:0;
    b->output[3]=(uint8_t)b->fragment;b->output[4]=(uint8_t)(b->fragment>>8);b->output[5]=b->window;
    b->output_size=6;b->output_handshake=true;return MATTER_OK;
}
Matter_Result_T matter_btp_receive(Matter_Btp_T b,const uint8_t* p,size_t n,uint64_t now){
    if(!b||!p||!n)return MATTER_INVALID_ARGUMENT;
    if(matter_btp_process(b,now)!=MATTER_OK)return fail(b);
    if(!b->requested)return handshake(b,p,n);
    if(!b->ready||n>b->fragment||n<2||(p[0]&~15))return fail(b);
    uint8_t flags=p[0],ack=0;size_t cursor=1;
    if(flags&ACK){
        if(n<3)return fail(b);
        ack=p[cursor++];unsigned count=(uint8_t)(ack-b->oldest);
        if(!b->outstanding||count>=b->outstanding)return fail(b);
        ++count;
        if(b->last_valid&&(uint8_t)(b->last_sequence-b->oldest)<count)b->tx_done=true;
        b->oldest=(uint8_t)(ack+1);b->outstanding-=(uint8_t)count;
        if(b->outstanding)b->ack_deadline=after(now,ACK_TIMEOUT);
    }
    uint8_t sequence=p[cursor++];
    if(sequence!=b->rx_next||b->rx_unacked>=b->window)return fail(b);
    ++b->rx_next;b->rx_last=sequence;++b->rx_unacked;
    if(!b->ack_pending)b->send_ack_at=after(now,SEND_ACK);
    b->ack_pending=true;
    if(!(flags&(BEGIN|CONTINUE|END)))return flags==ACK&&cursor==n?MATTER_OK:fail(b);
    if(b->rx_complete)return fail(b);
    if(flags&BEGIN){
        if(b->rx||(flags&CONTINUE)||n-cursor<2)return fail(b);
        size_t size=p[cursor]|((size_t)p[cursor+1]<<8);cursor+=2;
        if(!size||size>MATTER_UDP_MAX_PAYLOAD)return fail(b);
        b->rx=calloc(1,size);if(!b->rx)return fail(b);
        b->rx_size=size;b->rx_used=0;
    } else if(!b->rx||!(flags&CONTINUE))return fail(b);
    size_t payload=n-cursor;
    if(payload>b->rx_size-b->rx_used||(!payload)||(!(flags&END)&&n!=b->fragment))return fail(b);
    memcpy(b->rx+b->rx_used,p+cursor,payload);b->rx_used+=payload;
    if(flags&END){if(b->rx_used!=b->rx_size)return fail(b);b->rx_complete=true;}
    else if(b->rx_used==b->rx_size)return fail(b);
    return MATTER_OK;
}
Matter_Result_T matter_btp_received(Matter_Btp_T b,const uint8_t** p,size_t* n){
    if(!b||!p||!n)return MATTER_INVALID_ARGUMENT;
    if(b->failed)return MATTER_PORT_ERROR;
    if(!b->rx_complete)return MATTER_WOULD_BLOCK;
    *p=b->rx;*n=b->rx_size;return MATTER_OK;
}
void matter_btp_received_release(Matter_Btp_T b){if(b&&b->rx_complete){wipe(b->rx,b->rx_size);free(b->rx);b->rx=NULL;b->rx_size=b->rx_used=0;b->rx_complete=false;}}
Matter_Result_T matter_btp_send(Matter_Btp_T b,const uint8_t* p,size_t n){
    if(!b||!p||!n||n>MATTER_UDP_MAX_PAYLOAD)return MATTER_INVALID_ARGUMENT;
    if(!b->ready||b->failed)return MATTER_OFFLINE;
    if(b->tx)return MATTER_BUSY;
    b->tx=p;b->tx_size=n;b->tx_used=0;b->tx_done=false;b->last_valid=false;return MATTER_OK;
}
Matter_Result_T matter_btp_send_take(Matter_Btp_T b){
    if(!b)return MATTER_INVALID_ARGUMENT;
    if(!b->tx)return MATTER_INVALID_STATE;
    if(!b->failed&&!b->tx_done)return MATTER_PENDING;
    Matter_Result_T r=b->failed?MATTER_PORT_ERROR:MATTER_OK;
    b->tx=NULL;b->tx_size=b->tx_used=0;b->tx_done=b->last_valid=false;return r;
}
Matter_Result_T matter_btp_output(Matter_Btp_T b,const uint8_t** p,size_t* n,uint64_t now){
    if(!b||!p||!n)return MATTER_INVALID_ARGUMENT;
    if(matter_btp_process(b,now)!=MATTER_OK)return MATTER_PORT_ERROR;
    if(!b->output_size){
        if(!b->ready||b->outstanding>=b->window)return MATTER_WOULD_BLOCK;
        unsigned credit=b->window-b->outstanding;
        bool data=b->tx&&b->tx_used<b->tx_size&&(credit>1||b->ack_pending);
        bool ack=b->ack_pending&&(data||now>=b->send_ack_at||b->window-b->rx_unacked<=2);
        if(!data&&!ack)return MATTER_WOULD_BLOCK;
        uint8_t flags=data?(b->tx_used?CONTINUE:BEGIN):0;size_t c=1;
        if(ack){flags|=ACK;b->output[c++]=b->rx_last;}
        b->output[c++]=b->tx_next;
        if(data&&!b->tx_used){b->output[c++]=(uint8_t)b->tx_size;b->output[c++]=(uint8_t)(b->tx_size>>8);}
        size_t payload=data?b->tx_size-b->tx_used:0;
        if(payload>b->fragment-c)payload=b->fragment-c;
        if(data){memcpy(b->output+c,b->tx+b->tx_used,payload);if(payload==b->tx_size-b->tx_used)flags|=END;}
        b->output[0]=flags;b->output_size=c+payload;b->output_payload=payload;b->output_ack=ack;b->output_data=data;
    }
    *p=b->output;*n=b->output_size;return MATTER_OK;
}
Matter_Result_T matter_btp_sent(Matter_Btp_T b,uint64_t now){
    if(!b||!b->output_size)return MATTER_INVALID_ARGUMENT;
    if(matter_btp_process(b,now)!=MATTER_OK)return MATTER_PORT_ERROR;
    if(b->output_handshake){b->ready=b->output[2]!=0;b->failed=!b->ready;b->tx_next=1;b->oldest=0;b->outstanding=1;b->ack_deadline=after(now,ACK_TIMEOUT);}
    else {
        if(!b->outstanding){b->oldest=b->tx_next;b->ack_deadline=after(now,ACK_TIMEOUT);}
        ++b->outstanding;
        if(b->output_data){b->tx_used+=b->output_payload;if(b->tx_used==b->tx_size){b->last_sequence=b->tx_next;b->last_valid=true;}}
        ++b->tx_next;
        if(b->output_ack){b->rx_unacked=(uint8_t)(b->rx_last-b->output[1]);b->ack_pending=b->rx_unacked!=0;}
    }
    b->output_size=b->output_payload=0;b->output_handshake=b->output_ack=b->output_data=false;return MATTER_OK;
}
bool matter_btp_ready(Matter_Btp_T b){return b&&b->ready&&!b->failed;}

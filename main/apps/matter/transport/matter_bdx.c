#include "matter_bdx.h"
#include "../codec/matter_tlv_validate.h"
#include <stdlib.h>
#include <string.h>
struct Matter_Bdx {
    Matter_Bdx_Sink_T sink; uint64_t now,deadline,limit,length,bytes;
    uint32_t counter; uint16_t block,proposed,protocol; uint8_t opcode,stage;
    bool opened,failed,done; uint8_t output[239]; size_t output_size;
    Matter_Tlv_Validation_Workspace_T validation; Matter_Tlv_Tag_T tags[32];
};
static uint64_t read_le(const uint8_t* p,unsigned n) { uint64_t v=0; for(unsigned i=0;i<n;++i) v|=(uint64_t)p[i]<<(8*i); return v; }
static void write_le(uint8_t* p,uint32_t v,unsigned n) { for(unsigned i=0;i<n;++i) p[i]=(uint8_t)(v>>(8*i)); }
static void touch(Matter_Bdx_T b,uint64_t now) { b->now=now; b->deadline=now>UINT64_MAX-300000?UINT64_MAX:now+300000; }
static void discard(Matter_Bdx_T b) { if(b->opened) { b->sink.cancel(b->sink.user); b->opened=false; } }
static Matter_Result_T fail(Matter_Bdx_T b,uint16_t status,bool reply) {
    discard(b); b->failed=true; b->done=!reply; b->opcode=reply?0x40:0; b->protocol=0;
    memset(b->output,0,8); b->output[0]=1; b->output[2]=2; write_le(b->output+6,status,2); b->output_size=8;
    return MATTER_OK; /* An error report still needs reliable transport/drain. */
}
Matter_Bdx_T matter_bdx_new(const uint8_t* fd,size_t n,uint16_t block,uint64_t limit,const Matter_Bdx_Sink_T* p,uint64_t now) {
    if(!fd || !n || n>233 || !limit || !p || !p->open || !p->write || !p->finish || !p->cancel ||
        block<16 || block>1024 || (block>128 && (block&(block-1)))) return NULL;
    Matter_Bdx_T b=calloc(1,sizeof(*b)); if(!b) return NULL;
    b->sink=*p; b->limit=limit; b->proposed=block; touch(b,now);
    b->protocol=2; b->opcode=4; b->output[0]=0x20; write_le(b->output+2,block,2);
    write_le(b->output+4,(uint32_t)n,2); memcpy(b->output+6,fd,n); b->output_size=n+6;
    return b;
}
Matter_Result_T matter_bdx_output(Matter_Bdx_T b,Matter_Bdx_Message_T* out) {
    if(!b || !out) return MATTER_INVALID_ARGUMENT;
    if(!b->opcode) return MATTER_WOULD_BLOCK;
    *out=(Matter_Bdx_Message_T){b->output,b->output_size,b->protocol,b->opcode}; return MATTER_OK;
}
Matter_Result_T matter_bdx_sent(Matter_Bdx_T b,uint64_t now) {
    if(!b || !b->opcode || now<b->now) return MATTER_INVALID_STATE;
    if(b->opcode==4) b->stage=1;
    if(b->opcode==0x10) b->stage=2;
    if(b->opcode==0x14 || b->opcode==0x40) b->done=true;
    b->opcode=0; touch(b,now); return MATTER_OK;
}
Matter_Result_T matter_bdx_receive(Matter_Bdx_T b,uint16_t protocol,uint8_t op,const uint8_t* d,size_t n,uint64_t now) {
    if(!b || !d || b->done || b->failed || now<b->now) return MATTER_INVALID_STATE;
    if(now>=b->deadline) return fail(b,0x1f,true);
    touch(b,now);
    if(protocol==0 && op==0x40) return fail(b,0x1f,false);
    if(protocol!=2 || b->opcode) return fail(b,0x18,true);
    if(b->stage==1 && op==5) {
        if(n<4) return fail(b,0x16,true);
        if((d[0]&15)!=0) return fail(b,0x53,true);
        if((d[0]&0x70)!=0x20) return fail(b,0x50,true);
        b->block=(uint16_t)read_le(d+2,2); size_t pos=4;
        if(!b->block || b->block>b->proposed || (b->block>128 && (b->block&(b->block-1)))) return fail(b,0x16,true);
        if(d[1]&1) { unsigned len=(d[1]&16)?8:4; if(n-pos<len) return fail(b,0x16,true); b->length=read_le(d+pos,len); pos+=len; }
        if(b->length>b->limit) return fail(b,0x12,true);
        if(pos<n) {
            const Matter_Tlv_Validation_Options_T options={1024,128,2048,4,false,0,0}; Matter_Tlv_Validation_Report_T report;
            if(matter_tlv_validate(d+pos,n-pos,&options,&b->validation,b->tags,32,&report)!=MATTER_TLV_OK) return fail(b,0x16,true);
        }
        if(b->sink.open(b->sink.user)!=MATTER_OK) return fail(b,0x1f,true);
        b->opened=true;
    } else if(b->stage==2 && (op==0x11 || op==0x12)) {
        if(n<4 || n-4>b->block || (op==0x11 && n-4!=b->block)) return fail(b,0x16,true);
        if(read_le(d,4)!=b->counter) return fail(b,0x17,true);
        uint64_t size=n-4;
        if(size>b->limit-b->bytes || (b->length && size>b->length-b->bytes)) return fail(b,0x14,true);
        if(size && b->sink.write(b->sink.user,d+4,(size_t)size)!=MATTER_OK) return fail(b,0x1f,true);
        b->bytes+=size;
        if(op==0x12) {
            if(b->length && b->bytes!=b->length) return fail(b,0x14,true);
            Matter_Result_T r=b->sink.finish(b->sink.user,b->bytes);
            if(r!=MATTER_OK) return fail(b,r==MATTER_INVALID_ARGUMENT?0x14:0x1f,true);
            b->opcode=0x14; write_le(b->output,b->counter,4); b->output_size=4; return MATTER_OK;
        }
        ++b->counter;
    } else return fail(b,0x18,true);
    b->opcode=0x10; b->output_size=4; write_le(b->output,b->counter,4); return MATTER_OK;
}
Matter_Result_T matter_bdx_process(Matter_Bdx_T b,uint64_t now) {
    if(!b || now<b->now) return MATTER_INVALID_ARGUMENT;
    b->now=now;
    if(!b->done && !b->failed && now>=b->deadline) return fail(b,0x1f,true);
    return MATTER_OK;
}
Matter_Result_T matter_bdx_result(Matter_Bdx_T b,uint64_t* bytes) {
    if(!b || !bytes) return MATTER_INVALID_ARGUMENT;
    *bytes=b->bytes; return !b->done?MATTER_PENDING:b->failed?MATTER_PORT_ERROR:MATTER_OK;
}
void matter_bdx_cancel(Matter_Bdx_T b) { if(b) (void)fail(b,0x1f,false); }
void matter_bdx_delete(Matter_Bdx_T b) { if(b) { if(!b->done || b->failed) discard(b); memset(b,0,sizeof(*b)); free(b); } }

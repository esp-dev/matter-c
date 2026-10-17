#include "matter_ota_file.h"
#include "codec/matter_tlv_validate.h"
#include <mbedtls/sha256.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct Matter_Ota_File {
    char* path; char* partial; FILE* file; bool owned,ready,parsed;
    uint16_t vendor,product; uint32_t current,version; uint64_t total,received;
    size_t header_size,used; uint8_t header[1040],digest[32];
    mbedtls_sha256_context sha,whole; uint8_t image_digest[32]; uint64_t serial; bool valid;
    Matter_Tlv_Validation_Workspace_T validation; Matter_Tlv_Tag_T tags[32];
};
static uint64_t le(const uint8_t* p,unsigned n) { uint64_t v=0; for(unsigned i=0;i<n;++i) v|=(uint64_t)p[i]<<(8*i); return v; }
void matter_ota_file_cancel(Matter_Ota_File_T f) {
    if(!f) return;
    if(f->file) { (void)fclose(f->file); f->file=NULL; }
    if(f->owned) { (void)remove(f->partial); f->owned=false; }
    f->ready=false; f->valid=false;
}
void matter_ota_file_delete(Matter_Ota_File_T f) {
    if(f) { matter_ota_file_cancel(f); mbedtls_sha256_free(&f->sha); mbedtls_sha256_free(&f->whole); free(f->path); free(f->partial); free(f); }
}
Matter_Ota_File_T matter_ota_file_new(const char* path,uint16_t vendor,uint16_t product,uint32_t current) {
    if(!path || !*path || strlen(path)>4096) return NULL;
    Matter_Ota_File_T f=calloc(1,sizeof(*f)); if(!f) return NULL;
    size_t n=strlen(path); f->path=malloc(n+1); f->partial=malloc(n+6);
    if(!f->path || !f->partial) { matter_ota_file_delete(f); return NULL; }
    memcpy(f->path,path,n+1); memcpy(f->partial,path,n); memcpy(f->partial+n,".part",6);
    f->vendor=vendor; f->product=product; f->current=current; mbedtls_sha256_init(&f->sha); mbedtls_sha256_init(&f->whole); return f;
}
Matter_Result_T matter_ota_file_prepare(Matter_Ota_File_T f,uint32_t version) {
    if(!f || version<=f->current || f->owned) return MATTER_INVALID_STATE;
    f->version=version; f->total=f->received=0; f->header_size=f->used=0; f->parsed=f->ready=f->valid=false; return MATTER_OK;
}
static Matter_Result_T open_file(void* u) {
    Matter_Ota_File_T f=u; if(!f || f->owned || !f->version) return MATTER_INVALID_STATE;
    /* C runtime exclusive create: another instance/stale download is preserved. */
    f->file=fopen(f->partial,"wbx"); if(!f->file) return MATTER_PORT_ERROR;
    f->owned=true;
    if(mbedtls_sha256_starts(&f->sha,0) || mbedtls_sha256_starts(&f->whole,0)) { matter_ota_file_cancel(f); return MATTER_PORT_ERROR; }
    return MATTER_OK;
}
static bool header(Matter_Ota_File_T f) {
    const Matter_Tlv_Validation_Options_T options={1024,128,2048,4,false,0,0}; Matter_Tlv_Validation_Report_T report;
    const uint8_t* d=f->header+16; size_t n=f->header_size; Matter_Tlv_Reader_T r; Matter_Tlv_Element_T e;
    if(!n || d[0]!=0x15 || matter_tlv_validate(d,n,&options,&f->validation,f->tags,32,&report)!=MATTER_TLV_OK ||
        matter_tlv_init(&r,d,n,4)!=MATTER_TLV_OK || matter_tlv_next(&r,&e)!=MATTER_TLV_OK) return false;
    unsigned seen=0; uint64_t payload=0,min=0,max=UINT32_MAX;
    while(matter_tlv_next(&r,&e)==MATTER_TLV_OK && e.type!=MATTER_TLV_END) {
        if(e.tag.control!=1) return false;
        uint32_t tag=e.tag.number;
        if(tag>9) { if((e.type==MATTER_TLV_STRUCTURE || e.type==MATTER_TLV_LIST || e.type==MATTER_TLV_ARRAY) && matter_tlv_skip_container(&r)!=MATTER_TLV_OK) return false; continue; }
        seen|=1u<<tag;
        if(tag==3 || tag==7) {
            if(e.type!=MATTER_TLV_UTF8 || !e.size || e.size>(tag==3?64u:256u)) return false;
        } else if(tag==9) {
            if(e.type!=MATTER_TLV_BYTES || e.size!=32) return false;
            memcpy(f->digest,e.data,32);
        } else {
            if(e.type!=MATTER_TLV_UNSIGNED) return false;
            uint64_t v=e.unsigned_value;
            if(tag==0 && v && v!=f->vendor) return false;
            if(tag==1 && v && v!=f->product) return false;
            if(tag==2 && v!=f->version) return false;
            if(tag==4) payload=v;
            if(tag==5) { if(v>UINT32_MAX) return false; min=v; }
            if(tag==6) { if(v>UINT32_MAX) return false; max=v; }
            if(tag==8 && v!=1) return false;
        }
    }
    return matter_tlv_next(&r,&e)==MATTER_TLV_DONE && (seen&0x31f)==0x31f &&
        min<=f->current && f->current<=max && payload==f->total-16-f->header_size;
}
static Matter_Result_T write_file(void* u,const uint8_t* d,size_t n) {
    Matter_Ota_File_T f=u;
    if(!f || !f->file || !d || n>1024 || n>MATTER_OTA_FILE_LIMIT-f->received) return MATTER_INVALID_ARGUMENT;
    size_t pos=0;
    while(pos<n && !f->parsed) {
        size_t target=f->used<16?16:16+f->header_size;
        size_t take=target-f->used; if(take>n-pos) take=n-pos;
        memcpy(f->header+f->used,d+pos,take); f->used+=take; pos+=take;
        if(f->used==16 && !f->header_size) {
            if(le(f->header,4)!=UINT32_C(0x1beef11e)) return MATTER_INVALID_ARGUMENT;
            f->total=le(f->header+4,8); f->header_size=(size_t)le(f->header+12,4);
            if(!f->header_size || f->header_size>1024 || f->total<16+f->header_size || f->total>MATTER_OTA_FILE_LIMIT) return MATTER_LIMIT_REACHED;
        }
        if(f->header_size && f->used==16+f->header_size) { if(!header(f)) return MATTER_INVALID_ARGUMENT; f->parsed=true; }
    }
    if(f->total && n>f->total-f->received) return MATTER_INVALID_ARGUMENT;
    if(pos<n && mbedtls_sha256_update(&f->sha,d+pos,n-pos)) return MATTER_PORT_ERROR;
    if(mbedtls_sha256_update(&f->whole,d,n) || fwrite(d,1,n,f->file)!=n) return MATTER_PORT_ERROR;
    f->received+=n; return MATTER_OK;
}
static Matter_Result_T finish_file(void* u,uint64_t bytes) {
    Matter_Ota_File_T f=u; uint8_t digest[32];
    if(!f || !f->file || !f->parsed || bytes!=f->total || bytes!=f->received ||
        mbedtls_sha256_finish(&f->sha,digest) || memcmp(digest,f->digest,32) ||
        mbedtls_sha256_finish(&f->whole,f->image_digest)) return MATTER_INVALID_ARGUMENT;
    int r=fclose(f->file); f->file=NULL;
    if(r) return MATTER_PORT_ERROR;
    f->ready=true; return MATTER_OK;
}
static void cancel_file(void* u) { matter_ota_file_cancel(u); }
Matter_Bdx_Sink_T matter_ota_file_sink(Matter_Ota_File_T f) { return (Matter_Bdx_Sink_T){f,open_file,write_file,finish_file,cancel_file}; }
int matter_ota_file_progress(Matter_Ota_File_T f) {
    if(!f || (!f->owned && !f->ready) || !f->parsed || !f->total || f->total>MATTER_OTA_FILE_LIMIT || f->received>f->total) return -1;
    /* Header/write validation bounds both counters to 64 MiB. */
    return (int)(f->received*100/f->total);
}
int matter_ota_file_last_progress(Matter_Ota_File_T f) {
    if(!f || !f->parsed || !f->total || f->total>MATTER_OTA_FILE_LIMIT || f->received>f->total) return -1;
    /* Counts survive cancellation; prepare clears them for the next transfer.
     * The validated 64 MiB limit bounds multiplication and nearest rounding. */
    return (int)((f->received*100+f->total/2)/f->total);
}
Matter_Result_T matter_ota_file_commit(Matter_Ota_File_T f) {
    if(!f || !f->ready || !f->owned || f->file || f->serial==UINT64_MAX) return MATTER_INVALID_STATE;
    if(rename(f->partial,f->path)) return MATTER_PORT_ERROR;
    f->owned=false; f->ready=false; f->valid=true; ++f->serial; return MATTER_OK;
}
uint64_t matter_ota_file_artifact(Matter_Ota_File_T f) { return f && f->valid?f->serial:0; }
void matter_ota_file_invalidate(Matter_Ota_File_T f) { if(f) f->valid=false; }
Matter_Result_T matter_ota_file_discard(Matter_Ota_File_T f,uint64_t artifact) {
    if(!f || !artifact || !f->valid || artifact!=f->serial || f->owned || f->file) return MATTER_INVALID_STATE;
    f->valid=false;
    return remove(f->path)?MATTER_PORT_ERROR:MATTER_OK;
}
Matter_Result_T matter_ota_file_check(Matter_Ota_File_T f,uint64_t artifact) {
    if(!f || !artifact || !f->valid || artifact!=f->serial || f->owned || f->file) return MATTER_INVALID_STATE;
    uint8_t* buffer=malloc(1024); if(!buffer) return MATTER_LIMIT_REACHED;
    FILE* file=fopen(f->path,"rb"); if(!file) { free(buffer); return MATTER_PORT_ERROR; }
    uint64_t total=0; uint8_t digest[32]; bool ok=mbedtls_sha256_starts(&f->whole,0)==0;
    while(ok) {
        size_t n=fread(buffer,1,1024,file);
        if(n>f->total-total || mbedtls_sha256_update(&f->whole,buffer,n)) { ok=false; break; }
        total+=n;
        if(n<1024) { ok=!ferror(file); break; }
    }
    ok=ok && total==f->total && !mbedtls_sha256_finish(&f->whole,digest) && !memcmp(digest,f->image_digest,32);
    if(fclose(file)) ok=false;
    free(buffer); return ok?MATTER_OK:MATTER_INVALID_ARGUMENT;
}
Matter_Result_T matter_ota_file_signed(Matter_Ota_File_T f,uint64_t artifact,Matter_Ota_Signed_T* out) {
    if(!f || !out || !artifact || !f->valid || artifact!=f->serial || f->owned || f->file) return MATTER_INVALID_STATE;
    typedef struct { uint8_t buffer[1024]; Matter_Ota_Signed_T proof; } Work;
    Work* w=calloc(1,sizeof(*w)); if(!w) return MATTER_LIMIT_REACHED;
    FILE* file=fopen(f->path,"rb"); if(!file) { free(w); return MATTER_PORT_ERROR; }
    uint64_t total=0,offset=16+f->header_size; uint8_t digest[32];
    bool ok=f->total>offset+120 && !mbedtls_sha256_starts(&f->whole,0) && !mbedtls_sha256_starts(&f->sha,0);
    while(ok) {
        size_t n=fread(w->buffer,1,sizeof(w->buffer),file),pos=0;
        if(n>f->total-total || mbedtls_sha256_update(&f->whole,w->buffer,n)) { ok=false; break; }
        if(total<offset) pos=(size_t)(offset-total<n?offset-total:n);
        while(pos<n) {
            uint64_t at=total+pos-offset; size_t take=n-pos;
            if(at<120) {
                uint64_t end=at<56?56:120; if(take>end-at) take=(size_t)(end-at);
                memcpy((at<56?w->proof.manifest+(size_t)at:w->proof.signature+(size_t)(at-56)),w->buffer+pos,take);
            } else if(mbedtls_sha256_update(&f->sha,w->buffer+pos,take)) { ok=false; break; }
            pos+=take;
        }
        total+=n;
        if(n<sizeof(w->buffer)) { ok=ok && !ferror(file); break; }
    }
    ok=ok && total==f->total && !mbedtls_sha256_finish(&f->whole,digest) && !memcmp(digest,f->image_digest,32) &&
        !mbedtls_sha256_finish(&f->sha,w->proof.digest);
    if(fclose(file)) ok=false;
    if(ok) { w->proof.body_size=total-offset-120; *out=w->proof; }
    free(w); return ok?MATTER_OK:MATTER_INVALID_ARGUMENT;
}

#include "transport/matter_bdx.h"
#include "matter_ota_file.h"
#include "codec/matter_tlv_writer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"bdx:%d %s\n",__LINE__,#x); exit(1); } } while(0)
#ifdef MATTER_TEST_ALLOC
static unsigned fail_at, allocations, live;
void* matter_test_malloc(size_t n) { if(++allocations==fail_at) return NULL; void* p=malloc(n); if(p) ++live; return p; }
void* matter_test_calloc(size_t n,size_t size) { if(++allocations==fail_at) return NULL; void* p=calloc(n,size); if(p) ++live; return p; }
void matter_test_free(void* p) { if(p) { CHECK(live); --live; } free(p); }
#endif
typedef struct { unsigned opens,writes,finishes,cancels; int fail; uint64_t bytes; uint8_t data[1030],image[2048]; char path[512],partial[518]; } Test;
static Matter_Result_T open_sink(void* u) { Test* t=u; ++t->opens; return t->fail==1?MATTER_PORT_ERROR:MATTER_OK; }
static Matter_Result_T write_sink(void* u,const uint8_t* d,size_t n) { Test* t=u; CHECK(d && n<=1024); ++t->writes; t->bytes+=n; return t->fail==2?MATTER_PORT_ERROR:MATTER_OK; }
static Matter_Result_T finish_sink(void* u,uint64_t n) { Test* t=u; CHECK(n==t->bytes); ++t->finishes; return t->fail==3?MATTER_PORT_ERROR:MATTER_OK; }
static void cancel_sink(void* u) { ++((Test*)u)->cancels; }
static Matter_Bdx_T make(Test* t) {
    t->opens=t->writes=t->finishes=t->cancels=0; t->bytes=0;
    Matter_Bdx_Sink_T sink={t,open_sink,write_sink,finish_sink,cancel_sink};
    Matter_Bdx_T b=matter_bdx_new((const uint8_t*)"ota/a%20b",9,1024,4096,&sink,0); CHECK(b); return b;
}
static void sent(Matter_Bdx_T b,uint16_t protocol,uint8_t op,uint64_t now) {
    Matter_Bdx_Message_T m; CHECK(matter_bdx_output(b,&m)==MATTER_OK && m.protocol==protocol && m.opcode==op);
    if(op==4) { static const uint8_t prefix[]={0x20,0,0,4,9,0}; CHECK(m.size==15 && !memcmp(m.data,prefix,6) && !memcmp(m.data+6,"ota/a%20b",9)); }
    CHECK(matter_bdx_sent(b,now)==MATTER_OK);
}
static void accept(Matter_Bdx_T b) { static const uint8_t a[]={0x20,0,0,4}; sent(b,2,4,0); CHECK(matter_bdx_receive(b,2,5,a,sizeof(a),1)==MATTER_OK); }
static void core(Test* t) {
    Matter_Bdx_T b=make(t); accept(b); sent(b,2,0x10,2);
    memset(t->data,0,1028); CHECK(matter_bdx_receive(b,2,0x11,t->data,1028,3)==MATTER_OK); sent(b,2,0x10,4);
    t->data[0]=1; CHECK(matter_bdx_receive(b,2,0x12,t->data,4,5)==MATTER_OK); sent(b,2,0x14,6);
    uint64_t bytes; CHECK(matter_bdx_result(b,&bytes)==MATTER_OK && bytes==1024 && t->finishes==1);
    matter_bdx_delete(b); CHECK(!t->cancels);
    for(unsigned which=0;which<11;++which) {
        t->fail=which<3?(int)which+1:0; b=make(t);
        if(which==3) { sent(b,2,4,0); CHECK(matter_bdx_process(b,299999)==MATTER_OK); CHECK(matter_bdx_result(b,&bytes)==MATTER_PENDING); CHECK(matter_bdx_process(b,300000)==MATTER_OK); }
        else if(which>=7) {
            sent(b,2,4,0); uint8_t a[]={0x20,0x11,0,4,0,0,0,0,1,0,0,0}; size_t n=12;
            if(which==8) a[0]=0x10;
            if(which==9) n=3;
            if(which==10) a[0]=0x21;
            CHECK(matter_bdx_receive(b,2,5,a,n,1)==MATTER_OK);
        } else {
            accept(b);
            if(which!=0) {
                sent(b,2,0x10,2); memset(t->data,0,1028);
                if(which==4) t->data[0]=1;
                if(which==5) { matter_bdx_cancel(b); matter_bdx_cancel(b); }
                else if(which==6) CHECK(matter_bdx_receive(b,0,0x40,t->data,8,3)==MATTER_OK);
                else CHECK(matter_bdx_receive(b,2,which==2?0x12:0x11,t->data,which==2?5:1028,3)==MATTER_OK);
            }
        }
        if(which!=5 && which!=6) sent(b,0,0x40,300001);
        CHECK(matter_bdx_result(b,&bytes)==MATTER_PORT_ERROR); matter_bdx_delete(b);
        CHECK(t->cancels==(which==0 || which==3 || which>=7?0u:1u));
    }
    t->fail=0;
    b=make(t); accept(b); matter_bdx_delete(b); CHECK(t->cancels==1);
    puts("PASS BDX: independent wire vectors, full/empty EOF, limits, negotiation, status, timeout300s, I/O failures, cancellation and cleanup");
}
static void put(Matter_Tlv_Writer_T* w,Matter_Tlv_Type_T type,int tag,uint64_t v,const void* d,size_t n) {
    Matter_Tlv_Element_T e={.type=type,.tag={.control=tag<0?0:1,.number=tag<0?0:(uint32_t)tag},.unsigned_value=v,.data=d,.size=n}; CHECK(matter_tlv_write(w,&e,0)==MATTER_TLV_OK);
}
static size_t image(Test* t) {
    static const uint8_t sha[]={0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
    memset(t->image,0,sizeof(t->image)); Matter_Tlv_Writer_T w; size_t size;
    CHECK(matter_tlv_writer_init(&w,t->image+16,1024,4)==MATTER_TLV_OK);
    put(&w,MATTER_TLV_STRUCTURE,-1,0,NULL,0);
    put(&w,MATTER_TLV_UNSIGNED,0,0xfff1,NULL,0); put(&w,MATTER_TLV_UNSIGNED,1,0x8001,NULL,0);
    put(&w,MATTER_TLV_UNSIGNED,2,2,NULL,0); put(&w,MATTER_TLV_UTF8,3,0,"v2",2);
    put(&w,MATTER_TLV_UNSIGNED,4,3,NULL,0); put(&w,MATTER_TLV_UNSIGNED,8,1,NULL,0);
    put(&w,MATTER_TLV_BYTES,9,0,sha,32); put(&w,MATTER_TLV_END,-1,0,NULL,0);
    CHECK(matter_tlv_writer_finish(&w,&size)==MATTER_TLV_OK && size<200);
    t->image[0]=0x1e; t->image[1]=0xf1; t->image[2]=0xee; t->image[3]=0x1b;
    t->image[4]=(uint8_t)(size+19); t->image[12]=(uint8_t)size; memcpy(t->image+size+16,"abc",3); return size+19;
}
static void file(Test* t,const char* path) {
    CHECK(strlen(path)<sizeof(t->path)-1); strcpy(t->path,path); snprintf(t->partial,sizeof(t->partial),"%s.part",path);
    Matter_Ota_File_T f=matter_ota_file_new(path,0xfff1,0x8001,1); CHECK(f); Matter_Bdx_Sink_T s=matter_ota_file_sink(f);
    CHECK(matter_ota_file_progress(NULL)==-1 && matter_ota_file_progress(f)==-1);
    CHECK(matter_ota_file_last_progress(NULL)==-1 && matter_ota_file_last_progress(f)==-1);
    for(unsigned which=0;which<8;++which) {
        size_t n=image(t); CHECK(matter_ota_file_prepare(f,which==7?3:2)==MATTER_OK && s.open(s.user)==MATTER_OK);
        CHECK(matter_ota_file_progress(f)==-1);
        CHECK(matter_ota_file_last_progress(f)==-1);
        /* A second instance cannot truncate the partial file. */
        if(!which) { Matter_Ota_File_T other=matter_ota_file_new(path,0xfff1,0x8001,1); CHECK(other); CHECK(matter_ota_file_prepare(other,2)==MATTER_OK); Matter_Bdx_Sink_T o=matter_ota_file_sink(other); CHECK(o.open(o.user)!=MATTER_OK); matter_ota_file_delete(other); }
        if(which==1) t->image[n-1]^=1;
        if(which==2) --n;
        if(which==3) t->image[4]++;
        if(which==4) t->image[0]=0;
        if(which==5) t->image[13]=5;
        if(which==6) t->image[19]^=1;
        Matter_Result_T r=MATTER_OK;
        int previous_progress=-1;
        for(size_t i=0;i<n && r==MATTER_OK;++i) {
            r=s.write(s.user,t->image+i,1); /* Every header boundary split. */
            if(!which) {
                int progress=matter_ota_file_progress(f);
                CHECK(matter_ota_file_last_progress(f)==(progress<0?-1:(int)(((i+1)*100+n/2)/n)));
                CHECK(progress>=previous_progress && progress<=100);
                if(i<15) CHECK(progress==-1); /* An incomplete fixed header is untrusted. */
                if(i==n-2) CHECK(progress>0 && progress<100);
                previous_progress=progress;
            }
        }
        if(r==MATTER_OK) r=s.finish(s.user,n);
        if(!which) {
            CHECK(matter_ota_file_progress(f)==100);
            CHECK(!matter_ota_file_artifact(f));
            CHECK(r==MATTER_OK && matter_ota_file_commit(f)==MATTER_OK);
            CHECK(matter_ota_file_progress(f)==-1);
            CHECK(matter_ota_file_last_progress(f)==100);
            uint64_t artifact=matter_ota_file_artifact(f); CHECK(artifact && matter_ota_file_check(f,artifact)==MATTER_OK);
            CHECK(matter_ota_file_check(f,artifact+1)==MATTER_INVALID_STATE);
#ifdef MATTER_TEST_ALLOC
            fail_at=allocations+1; CHECK(matter_ota_file_check(f,artifact)==MATTER_LIMIT_REACHED); fail_at=0;
            CHECK(matter_ota_file_check(f,artifact)==MATTER_OK);
#endif
            FILE* in=fopen(path,"rb"); CHECK(in && fread(t->data,1,sizeof(t->data),in)==n && !memcmp(t->data,t->image,n)); CHECK(!fclose(in));
            /* Replacing header, payload, truncating or appending invalidates the
             * whole-image binding even when the original payload hash matched. */
            for(unsigned mutation=0;mutation<4;++mutation) {
                memcpy(t->data,t->image,n); size_t changed=n;
                if(mutation==0) t->data[24]^=1;
                if(mutation==1) t->data[n-1]^=1;
                if(mutation==2) --changed;
                if(mutation==3) t->data[changed++]=0;
                FILE* out=fopen(path,"wb"); CHECK(out && fwrite(t->data,1,changed,out)==changed && !fclose(out));
                CHECK(matter_ota_file_check(f,artifact)!=MATTER_OK);
            }
            FILE* out=fopen(path,"wb"); CHECK(out && fwrite(t->image,1,n,out)==n && !fclose(out));
            CHECK(matter_ota_file_check(f,artifact)==MATTER_OK);
            Matter_Ota_File_T restarted=matter_ota_file_new(path,0xfff1,0x8001,1); CHECK(restarted);
            CHECK(!matter_ota_file_artifact(restarted) && matter_ota_file_check(restarted,artifact)==MATTER_INVALID_STATE);
            matter_ota_file_delete(restarted);
            matter_ota_file_invalidate(f); CHECK(!matter_ota_file_artifact(f) && matter_ota_file_check(f,artifact)==MATTER_INVALID_STATE);
            CHECK(!remove(path));
        }
        else {
            CHECK(r!=MATTER_OK); int last=matter_ota_file_last_progress(f);
            s.cancel(s.user); CHECK(matter_ota_file_progress(f)==-1 && fopen(t->partial,"rb")==NULL);
            CHECK(matter_ota_file_last_progress(f)==last);
        }
    }
    for(unsigned missing=0;missing<2;++missing) {
        size_t n=image(t);
        CHECK(matter_ota_file_prepare(f,2)==MATTER_OK && s.open(s.user)==MATTER_OK);
        CHECK(s.write(s.user,t->image,n)==MATTER_OK && s.finish(s.user,n)==MATTER_OK && matter_ota_file_commit(f)==MATTER_OK);
        uint64_t id=matter_ota_file_artifact(f); CHECK(id);
        CHECK(matter_ota_file_discard(f,0)==MATTER_INVALID_STATE && matter_ota_file_discard(f,id+1)==MATTER_INVALID_STATE);
        CHECK(matter_ota_file_check(f,id)==MATTER_OK);
        Matter_Ota_File_T other=matter_ota_file_new(path,0xfff1,0x8001,1); CHECK(other);
        CHECK(matter_ota_file_discard(other,id)==MATTER_INVALID_STATE); matter_ota_file_delete(other);
        if(missing) CHECK(!remove(path));
        CHECK(matter_ota_file_discard(f,id)==(missing?MATTER_PORT_ERROR:MATTER_OK));
        CHECK(!matter_ota_file_artifact(f) && matter_ota_file_check(f,id)==MATTER_INVALID_STATE);
        CHECK(matter_ota_file_discard(f,id)==MATTER_INVALID_STATE && fopen(path,"rb")==NULL);
    }
    matter_ota_file_delete(f); puts("PASS OTA file: fragmented header, known SHA256 abc, identity/size bounds, corrupt/truncated digest, exclusive partial, staged publish, scoped discard/I/O failure and cleanup");
}
int main(int argc,char** argv) {
    CHECK(argc==2); Test* t=calloc(1,sizeof(*t)); CHECK(t); core(t); file(t,argv[1]);
#ifdef MATTER_TEST_ALLOC
    Matter_Bdx_Sink_T sink={t,open_sink,write_sink,finish_sink,cancel_sink};
    CHECK(!live); allocations=0; fail_at=1;
    CHECK(!matter_bdx_new((const uint8_t*)"a",1,1024,4096,&sink,0) && !live);
    for(unsigned i=1;i<=3;++i) { allocations=0; fail_at=i; CHECK(!matter_ota_file_new(argv[1],1,1,1) && !live); }
    fail_at=0; puts("PASS BDX/file constructor OOM: every allocation failure releases ownership");
#endif
    free(t); return 0;
}

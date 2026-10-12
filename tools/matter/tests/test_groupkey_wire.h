#ifndef TEST_GROUPKEY_WIRE_H
#define TEST_GROUPKEY_WIRE_H
/* Independent literal TLV encoder: never uses production schema/writer. */
typedef struct { uint8_t data[256],request[300]; size_t n,request_size; } GkWire;
static void gk_byte(GkWire* w,unsigned v) { OC_CHECK(w->n<sizeof(w->data)); w->data[w->n++]=(uint8_t)v; }
static void gk_uint(GkWire* w,unsigned tag,uint64_t v) {
    unsigned width=v>UINT32_MAX?8:v>65535?4:v>255?2:1;
    gk_byte(w,0x24+(width==8?3:width==4?2:width==2?1:0)); gk_byte(w,tag);
    for(unsigned i=0;i<width;++i) gk_byte(w,(unsigned)(v>>(8*i)));
}
static void gk_args(GkWire* w,unsigned cmd,unsigned id,unsigned count,uint64_t first) {
    w->n=0; gk_byte(w,0x15);
    if(cmd==0) {
        gk_byte(w,0x35); gk_byte(w,0); gk_uint(w,0,id); gk_uint(w,1,0);
        for(unsigned i=0;i<3;++i) {
            if(i<count) {
                gk_byte(w,0x30); gk_byte(w,2+2*i); gk_byte(w,16);
                for(unsigned j=0;j<16;++j) gk_byte(w,0x42+i);
                gk_uint(w,3+2*i,first+i);
            } else { gk_byte(w,0x34); gk_byte(w,2+2*i); gk_byte(w,0x34); gk_byte(w,3+2*i); }
        }
        gk_byte(w,0x18);
    } else if(cmd!=4) gk_uint(w,0,id);
    gk_byte(w,0x18);
}
static inline void gk_request(GkWire* w,unsigned cmd) {
    static const uint8_t head[]={0x15,0x28,0,0x28,1,0x36,2,0x15,0x37,0,0x24,0,0,0x24,1,0x3f,0x24,2,0,0x18,0x35,1};
    static const uint8_t tail[]={0x18,0x18,0x24,255,13,0x18};
    memcpy(w->request,head,sizeof(head)); w->request[18]=(uint8_t)cmd;
    memcpy(w->request+sizeof(head),w->data+1,w->n-1);
    memcpy(w->request+sizeof(head)+w->n-1,tail,sizeof(tail));
    w->request_size=sizeof(head)+w->n-1+sizeof(tail);
}
#endif

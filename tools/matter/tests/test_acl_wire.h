#ifndef TEST_ACL_WIRE_H
#define TEST_ACL_WIRE_H
/* Literal encoding, independent of production TLV writer. Heap-own this fixture. */
typedef struct { uint8_t data[1024],request[1100]; size_t size,request_size; } AclWire;
static inline void aw_byte(AclWire* w,uint8_t b) { if(w->size>=sizeof(w->data)) abort(); w->data[w->size++]=b; }
static inline void aw_uint(AclWire* w,int tag,uint64_t value) {
    unsigned n=value<=255?1:value<=65535?2:value<=UINT32_MAX?4:8;
    aw_byte(w,(uint8_t)((tag<0?4:0x24)+(n==1?0:n==2?1:n==4?2:3)));
    if(tag>=0) aw_byte(w,(uint8_t)tag);
    for(unsigned i=0;i<n;++i) aw_byte(w,(uint8_t)(value>>(8*i)));
}
static inline void aw_open(AclWire* w,uint8_t type,int tag) { aw_byte(w,(uint8_t)(type+(tag<0?0:32))); if(tag>=0) aw_byte(w,(uint8_t)tag); }
static inline void aw_entry_ex(AclWire* w,uint64_t subject,unsigned privilege,unsigned mode,unsigned subjects,unsigned targets,unsigned shape) {
    aw_open(w,0x15,-1); aw_uint(w,1,privilege); aw_uint(w,2,mode);
    aw_open(w,subjects?0x16:0x14,3);
    for(unsigned i=0;i<subjects;++i) aw_uint(w,-1,subject+i);
    if(subjects) aw_byte(w,0x18);
    aw_open(w,targets?0x16:0x14,4);
    for(unsigned i=0;i<targets;++i) {
        aw_open(w,0x15,-1);
        if(shape!=4) aw_uint(w,0,0x28); else aw_open(w,0x14,0);
        if(shape==1 || shape==3) aw_uint(w,1,0); else aw_open(w,0x14,1);
        if(shape==2 || shape==3) aw_uint(w,2,0x16); else aw_open(w,0x14,2);
        aw_byte(w,0x18);
    }
    if(targets) aw_byte(w,0x18);
    aw_uint(w,254,222); /* Must be ignored in Write. */
    aw_byte(w,0x18);
}
static inline void aw_entry(AclWire* w,uint64_t subject,unsigned privilege,unsigned shape) { aw_entry_ex(w,subject,privilege,2,1,shape?1:0,shape); }
static inline void aw_list(AclWire* w,bool grant) {
    w->size=0; aw_open(w,0x16,-1); aw_entry(w,101,5,0);
    if(grant) aw_entry(w,102,1,1);
    aw_byte(w,0x18);
}
static inline void aw_request(AclWire* w,bool add,bool more,int64_t version) {
    static const uint8_t head[]={0x15,0x28,1,0x36,2,0x15};
    static const uint8_t path[]={0x37,1,0x24,2,0,0x24,3,0x1f,0x24,4,0};
    size_t n=0; memcpy(w->request,head,sizeof(head)); n+=sizeof(head);
    if(version>=0) { w->request[n++]=0x26; w->request[n++]=0; for(unsigned i=0;i<4;++i) w->request[n++]=(uint8_t)((uint64_t)version>>(8*i)); }
    memcpy(w->request+n,path,sizeof(path)); n+=sizeof(path);
    if(add) { w->request[n++]=0x34; w->request[n++]=5; }
    w->request[n++]=0x18;
    w->request[n++]=(uint8_t)(w->data[0]+32); w->request[n++]=2;
    memcpy(w->request+n,w->data+1,w->size-1); n+=w->size-1;
    w->request[n++]=0x18; w->request[n++]=0x18;
    if(more) { w->request[n++]=0x29; w->request[n++]=3; }
    w->request[n++]=0x24; w->request[n++]=255; w->request[n++]=13; w->request[n++]=0x18; w->request_size=n;
}
#endif

/* Private bounded probe comparison, included by the common DNS adapter.
 * Keep only N+1 smallest distinct peer records per owned name, where N is
 * the maximum local address count (the instance still has two records).
 * RDATA is expanded into instance-owned scratch, never retained from rx. */
static bool probing(Matter_Mdns_Windows_T h) {
    return h->request && h->publishing && !h->installed && h->phase>0 && h->phase<=3;
}
static unsigned probe_owner(Matter_Mdns_Windows_T h) {
    return !_stricmp(h->name,h->instance)?1:!_stricmp(h->name,h->hostname)?2:0;
}
static bool probe_question(Matter_Mdns_Windows_T h,unsigned count,unsigned owner,uint16_t type) {
    for(unsigned i=0;i<count;++i) if(h->probe_questions[i].owner==owner &&
        (h->probe_questions[i].type==255 || h->probe_questions[i].type==type)) return true;
    return false;
}
static bool probe_data(Matter_Mdns_Windows_T h,Probe_Record r,uint8_t* out,size_t* size) {
    if(r.offset==UINT16_MAX) {
        if(r.type==16) { memcpy(out,h->txt,h->txt_size); *size=h->txt_size; return true; }
        if(r.type==28 || r.type==1) { *size=r.type==28?16:4; memcpy(out,address_data(&h->records[r.len]),*size); return true; }
        memset(out,0,4); set16(out+4,h->records[1].data.srv.port);
        void* end=mdns_string_make(out,CAP,out+6,h->hostname,strlen(h->hostname),NULL);
        if(!end) return false;
        *size=(uint8_t*)end-out; return true;
    }
    if(r.type==1 && r.len!=4) return false;
    size_t p=r.offset,end=p+r.len,w=0; unsigned prefix=0,names=0; int suffix=0;
    /* Known compression-bearing classic DNS types; unknown types have opaque
     * RDATA and cannot use name compression (RFC3597). Preserve raw case. */
    switch(r.type) {
    case 2: case 5: case 12: case 39: names=1; break;
    case 15: case 18: case 21: case 36: prefix=2; names=1; break;
    case 33: prefix=6; names=1; break;
    case 6: names=2; suffix=20; break;
    case 14: case 17: names=2; break;
    case 47: names=1; suffix=-1; break;
    default: memcpy(out,h->rx+p,r.len); *size=r.len; return true;
    }
    if(r.len<prefix) return false;
    memcpy(out,h->rx+p,prefix); p+=prefix; w=prefix;
    for(unsigned i=0;i<names;++i) {
        if(!name(h->rx,end,&p,h->target)) return false;
        void* next=mdns_string_make(out,CAP,out+w,h->target,strlen(h->target),NULL);
        if(!next) return false;
        w=(uint8_t*)next-out;
    }
    if((suffix>=0 && end-p!=(unsigned)suffix) || end-p>CAP-w) return false;
    memcpy(out+w,h->rx+p,end-p); *size=w+end-p; return true;
}
static bool probe_compare(Matter_Mdns_Windows_T h,Probe_Record a,Probe_Record b,int* order) {
    if(a.cl!=b.cl) { *order=a.cl<b.cl?-1:1; return true; }
    if(a.type!=b.type) { *order=a.type<b.type?-1:1; return true; }
    size_t an,bn;
    if(!probe_data(h,a,h->tx,&an) || !probe_data(h,b,h->compare,&bn)) return false;
    int r=memcmp(h->tx,h->compare,an<bn?an:bn);
    *order=r?r:an<bn?-1:an>bn?1:0; return true;
}
static bool probe_insert(Matter_Mdns_Windows_T h,unsigned owner,Probe_Record r) {
    unsigned count=h->probe_count[owner],at=0;
    /* Validate canonical RDATA even if its type alone determines ordering. */
    size_t bytes; if(!probe_data(h,r,h->tx,&bytes)) return false;
    for(;at<count;++at) {
        int order; if(!probe_compare(h,r,h->probe_records[owner][at],&order)) return false;
        if(!order) return true; /* RRset, not a bag of duplicate records. */
        if(order<0) break;
    }
    if(at==PROBE_RECORDS) return true;
    if(count<PROBE_RECORDS) ++count;
    for(unsigned i=count-1;i>at;--i) h->probe_records[owner][i]=h->probe_records[owner][i-1];
    h->probe_records[owner][at]=r; h->probe_count[owner]=count; return true;
}
static bool probe_order(Matter_Mdns_Windows_T h,unsigned owner,int* order) {
    unsigned count=h->probe_count[owner],local_count=owner?h->address_count:2; *order=0;
    if(!count) return true;
    for(unsigned i=0;i<count && i<local_count;++i) {
        unsigned index=owner?h->host_order[i]:0;
        Probe_Record local={.type=owner?h->records[index].type:i?33:16,.cl=1,.offset=UINT16_MAX,.len=(uint16_t)index};
        if(!probe_compare(h,local,h->probe_records[owner][i],order)) return false;
        if(*order) return true;
    }
    *order=local_count<count?-1:local_count>count?1:0; return true;
}

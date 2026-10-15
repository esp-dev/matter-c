#include "matter_ota_query.h"
#include "../codec/matter_tlv_validate.h"
#include <stdlib.h>
#include <string.h>
struct Matter_Ota_Query {
    Matter_Ota_Query_Config_T config; Matter_Ota_Query_Port_T port;
    Matter_Ota_Provider_T provider; uint64_t generation,job,now,due,floor,provider_floor,deadline;
    bool stopped,cancelled,image_pending; unsigned failures;
    uint8_t state,published,reason; Matter_Ota_Image_T image;
    uint8_t args[64]; size_t args_size;
    Matter_Tlv_Validation_Workspace_T validation; Matter_Tlv_Tag_T tags[64];
};
static uint64_t after(uint64_t n,uint64_t delay) { return n>UINT64_MAX-delay?UINT64_MAX:n+delay; }
static uint64_t maximum(uint64_t a,uint64_t b) { return a>b?a:b; }
static bool equal(const Matter_Ota_Provider_T* a,const Matter_Ota_Provider_T* b) {
    return a->fabric==b->fabric && a->node==b->node && a->endpoint==b->endpoint;
}
static bool put(Matter_Tlv_Writer_T* w,Matter_Tlv_Type_T t,int tag,uint64_t v) {
    Matter_Tlv_Element_T e={.type=t,.tag={.control=tag<0?0:1,.number=tag<0?0:(uint32_t)tag},.unsigned_value=v};
    return matter_tlv_write(w,&e,0)==MATTER_TLV_OK;
}
Matter_Ota_Query_T matter_ota_query_new(const Matter_Ota_Query_Config_T* c,const Matter_Ota_Query_Port_T* p,uint64_t now) {
    if(!c || !p || !p->generation || !p->random || !p->start || !p->take || !p->cancel || !p->state || !p->available || c->protocol_count>8) return NULL;
    /* This stage understands synchronous BDX image locations only. */
    if(c->protocol_count>1 || (c->protocol_count && c->protocols[0]!=0)) return NULL;
    Matter_Ota_Query_T q=calloc(1,sizeof(*q)); if(!q) return NULL;
    q->config=*c; q->port=*p; q->now=now; q->state=q->published=1;
    Matter_Tlv_Writer_T w;
    bool ok=matter_tlv_writer_init(&w,q->args,sizeof(q->args),2)==MATTER_TLV_OK && put(&w,MATTER_TLV_STRUCTURE,-1,0) &&
        put(&w,MATTER_TLV_UNSIGNED,0,c->vendor) && put(&w,MATTER_TLV_UNSIGNED,1,c->product) &&
        put(&w,MATTER_TLV_UNSIGNED,2,c->version) && put(&w,MATTER_TLV_ARRAY,3,0);
    for(unsigned i=0;ok && i<c->protocol_count;++i) ok=put(&w,MATTER_TLV_UNSIGNED,-1,c->protocols[i]);
    ok=ok && put(&w,MATTER_TLV_END,-1,0) && put(&w,MATTER_TLV_UNSIGNED,4,c->hardware) &&
        put(&w,MATTER_TLV_BOOL,6,0) && put(&w,MATTER_TLV_END,-1,0) && matter_tlv_writer_finish(&w,&q->args_size)==MATTER_TLV_OK;
    if(!ok) { free(q); return NULL; } return q;
}
bool matter_ota_query_offer(Matter_Ota_Query_T q,const Matter_Ota_Offer_T* o,uint64_t now) {
    if(!q || !o || q->stopped || now<q->now || !o->provider.fabric || o->provider.fabric==255 || !o->provider.node ||
        o->provider.node>UINT64_C(0xffffffefffffffff) || o->provider.endpoint==65535 || (o->announced && o->reason>2)) return false;
    uint64_t gen=q->port.generation(q->port.user,o->provider.fabric); if(!gen) return false;
    bool same=equal(&q->provider,&o->provider) && q->generation==gen;
    if(q->job || q->image_pending) return same;
    uint64_t due=now;
    if(o->announced && o->reason==2) {
        uint32_t random; bool sampled=false;
        for(unsigned i=0;i<8;++i) { if(q->port.random(q->port.user,&random)!=MATTER_OK) return false;
            if(random<UINT32_MAX-UINT32_MAX%600) { sampled=true; break; } }
        if(!sampled) return false;
        due=after(now,((uint64_t)(random%600)+1)*1000);
    } else if(o->announced && o->reason==1) due=same?q->due:after(now,86400000);
    if(!same) { q->provider_floor=0; q->failures=0; }
    q->provider=o->provider; q->generation=gen;
    q->due=maximum(due,maximum(q->floor,q->provider_floor)); return true;
}
static bool metadata(Matter_Ota_Query_T q,const uint8_t* d,size_t n) {
    const Matter_Tlv_Validation_Options_T opt={512,256,4096,4,false,0,0}; Matter_Tlv_Validation_Report_T report;
    Matter_Tlv_Reader_T r; Matter_Tlv_Element_T e;
    if(matter_tlv_validate(d,n,&opt,&q->validation,q->tags,64,&report)!=MATTER_TLV_OK ||
        matter_tlv_init(&r,d,n,4)!=MATTER_TLV_OK || matter_tlv_next(&r,&e)!=MATTER_TLV_OK || e.type!=MATTER_TLV_LIST || e.tag.control) return false;
    while(matter_tlv_next(&r,&e)==MATTER_TLV_OK && e.type!=MATTER_TLV_END) {
        if(e.tag.control<6) return false;
        if((e.type==MATTER_TLV_STRUCTURE || e.type==MATTER_TLV_ARRAY || e.type==MATTER_TLV_LIST) && matter_tlv_skip_container(&r)!=MATTER_TLV_OK) return false;
    }
    return matter_tlv_next(&r,&e)==MATTER_TLV_DONE;
}
static bool decode(Matter_Ota_Query_T q,const uint8_t* d,size_t n) {
    const Matter_Tlv_Validation_Options_T opt={1024,256,4096,4,false,0,0}; Matter_Tlv_Validation_Report_T report;
    Matter_Tlv_Reader_T r; Matter_Tlv_Element_T e; unsigned seen=0;
    memset(&q->image,0,sizeof(q->image));
    if(!d || !n || d[0]!=0x15 || matter_tlv_validate(d,n,&opt,&q->validation,q->tags,64,&report)!=MATTER_TLV_OK ||
        matter_tlv_init(&r,d,n,4)!=MATTER_TLV_OK || matter_tlv_next(&r,&e)!=MATTER_TLV_OK) return false;
    while(matter_tlv_next(&r,&e)==MATTER_TLV_OK && e.type!=MATTER_TLV_END) {
        if(e.tag.control!=1) return false;
        unsigned tag=e.tag.number;
        if(tag>7) {
            if((e.type==MATTER_TLV_STRUCTURE || e.type==MATTER_TLV_ARRAY || e.type==MATTER_TLV_LIST) && matter_tlv_skip_container(&r)!=MATTER_TLV_OK) return false;
            continue;
        }
        seen|=1u<<tag;
        if(tag==0 || tag==1 || tag==3) {
            if(e.type!=MATTER_TLV_UNSIGNED || e.unsigned_value>UINT32_MAX || (!tag && e.unsigned_value>3)) return false;
            if(!tag) q->image.status=(uint8_t)e.unsigned_value;
            if(tag==1) q->image.delay=(uint32_t)e.unsigned_value;
            if(tag==3) q->image.version=(uint32_t)e.unsigned_value;
        } else if(tag==2 || tag==4) {
            if(e.type!=MATTER_TLV_UTF8 || !e.size || e.size>(tag==2?256u:64u) || (tag==2 && memchr(e.data,0,e.size))) return false;
            memcpy(tag==2?q->image.uri:q->image.version_string,e.data,e.size);
            if(tag==4) q->image.version_string_size=e.size;
        } else if(tag==5) {
            if(e.type!=MATTER_TLV_BYTES || e.size<8 || e.size>32) return false;
            memcpy(q->image.token,e.data,e.size); q->image.token_size=e.size;
        } else if(tag==6) {
            if(e.type!=MATTER_TLV_BOOL) return false;
            q->image.consent_needed=e.unsigned_value!=0;
        } else {
            if(e.type!=MATTER_TLV_BYTES || !metadata(q,e.data,e.size)) return false;
            memcpy(q->image.metadata,e.data,e.size); q->image.metadata_size=e.size;
        }
    }
    return matter_tlv_next(&r,&e)==MATTER_TLV_DONE && (seen&1) && (q->image.status!=1 || (seen&2)) &&
        (q->image.status!=0 || (seen&61)==61);
}
static bool uri(Matter_Ota_Query_T q) {
    const char* s=q->image.uri; size_t n=strlen(s); uint64_t node=0;
    if(!q->config.protocol_count || n<24 || memcmp(s,"bdx://",6) || s[22]!='/') return false;
    for(unsigned i=6;i<22;++i) {
        int x=s[i]>='0' && s[i]<='9'?s[i]-'0':s[i]>='A' && s[i]<='F'?s[i]-'A'+10:-1;
        if(x<0) return false;
        node=(node<<4)|(unsigned)x;
    }
    if(node!=q->provider.node) return false;
    for(size_t i=23;i<n;++i) {
        unsigned char c=(unsigned char)s[i];
        if(c=='%') {
            for(unsigned j=0;j<2;++j) { if(++i>=n) return false; c=(unsigned char)s[i];
                if(!((c>='0' && c<='9') || (c>='a' && c<='f') || (c>='A' && c<='F'))) return false; }
        } else if(!((c>='a' && c<='z') || (c>='A' && c<='Z') || (c>='0' && c<='9') || strchr("-._~!$&'()*+,;=:@/",c))) return false;
    }
    return true;
}
static void finish(Matter_Ota_Query_T q,bool ok,uint8_t im) {
    bool busy=(ok && q->image.status==1) || im==0x9c;
    uint64_t delay=ok?(uint64_t)q->image.delay*1000:0;
    q->provider_floor=after(q->now,delay);
    /* A bounded single-provider policy may forget an old selection. Carry its
     * provider delay into the conservative global floor, so switching away and
     * back (or a repeated announcement) cannot bypass that delay. */
    /* start() may spend time establishing CASE before QueryImage is sent.
     * Its completion is a conservative anchor for the 120s query floor; keep
     * it across announcements, not only in the current retry's due time. */
    q->floor=maximum(q->floor,maximum(after(q->now,120000),q->provider_floor));
    if(ok && !q->image.status && q->image.version>q->config.version && uri(q)) {
        q->image_pending=true; q->due=q->provider_floor; q->state=3; q->reason=4; q->failures=0; return;
    }
    if(busy || !ok) {
        if(q->failures<6) ++q->failures;
        uint64_t backoff=UINT64_C(120000)<<(q->failures-1); if(backoff>3600000) backoff=3600000;
        q->due=maximum(after(q->now,backoff),maximum(q->floor,q->provider_floor)); q->state=3; q->reason=busy?4:2;
    } else { q->failures=0; q->due=maximum(after(q->now,86400000),maximum(q->floor,q->provider_floor)); q->state=1; q->reason=1; }
}
Matter_Result_T matter_ota_query_process(Matter_Ota_Query_T q,uint64_t now) {
    if(!q || now<q->now) return MATTER_INVALID_ARGUMENT;
    q->now=now;
    bool live=q->generation && q->port.generation(q->port.user,q->provider.fabric)==q->generation;
    if(q->job && (q->stopped || !live || now>=q->deadline) && !q->cancelled) { q->port.cancel(q->port.user,q->job); q->cancelled=true; }
    if(q->job) {
        uint8_t im=0; const uint8_t* data=NULL; size_t size=0;
        Matter_Result_T r=q->port.take(q->port.user,q->job,&im,&data,&size);
        if(r!=MATTER_PENDING) {
            q->job=0; bool ok=r==MATTER_OK && !im && !q->cancelled && decode(q,data,size);
            finish(q,ok,im); q->cancelled=false;
        }
    }
    if(!live || q->stopped) { q->generation=0; q->image_pending=false; memset(&q->image,0,sizeof(q->image)); q->state=1; q->reason=2; }
    if(q->state!=q->published) {
        Matter_Result_T r=q->port.state(q->port.user,q->state,q->reason,now); if(r!=MATTER_OK) return r;
        q->published=q->state;
    }
    if(q->job) return MATTER_PENDING;
    if(q->stopped || !live || now<q->due) return MATTER_OK;
    if(q->image_pending) {
        q->port.available(q->port.user,&q->provider,&q->image); q->image_pending=false;
        memset(&q->image,0,sizeof(q->image)); q->due=after(now,86400000); q->state=1; q->reason=1; return MATTER_OK;
    }
    if(q->published!=2) { q->state=2; q->reason=1; return MATTER_PENDING; }
    Matter_Result_T r=q->port.start(q->port.user,&q->provider,q->args,q->args_size,&q->job);
    if(r==MATTER_BUSY || r==MATTER_WOULD_BLOCK) return MATTER_PENDING;
    q->floor=after(now,120000); q->deadline=after(now,65000);
    if(r!=MATTER_PENDING) { q->job=0; finish(q,false,0); }
    return MATTER_PENDING;
}
Matter_Result_T matter_ota_query_stop(Matter_Ota_Query_T q) { if(!q) return MATTER_OK; q->stopped=true; return q->job?MATTER_PENDING:MATTER_OK; }
Matter_Result_T matter_ota_query_delete(Matter_Ota_Query_T q) {
    if(!q) return MATTER_OK;
    if(q->job) return MATTER_BUSY;
    memset(q,0,sizeof(*q)); free(q); return MATTER_OK;
}

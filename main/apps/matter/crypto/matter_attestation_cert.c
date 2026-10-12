#include "matter_attestation_cert.h"
#include "../codec/matter_tlv_internal.h" /* Reuse bounded UTF-8 validation. */
#include <stdlib.h>
#include <string.h>
#include "mbedtls/x509_crt.h"
#include "mbedtls/platform_util.h"

typedef struct { const uint8_t* data; size_t size; } Span;
typedef struct { uint16_t vid,pid; bool has_vid,has_pid,preferred; unsigned vid_rdn,pid_rdn,rdns; } Ids;
typedef struct { mbedtls_x509_crt crt; Ids issuer,subject; } Certificate;
typedef struct {
    Certificate certs[3];
    Span oids[MATTER_ATTESTATION_MAX_DER/7]; /* Extension envelope needs >=7 B. */
    Matter_Attestation_Identity_T identity;
} Work;
static bool equal(Span a,Span b) { return a.size==b.size && (!a.size || !memcmp(a.data,b.data,a.size)); }
static Span buf(mbedtls_x509_buf b) { return (Span){b.p,b.len}; }
static int hex(unsigned c) { return c>='0'&&c<='9' ? (int)(c-'0') : c>='A'&&c<='F' ? (int)(c-'A'+10) : -1; }
/* Look only for ASCII identity substrings. BMP/Universal DirectoryStrings use
 * fixed-width code units; UTF8/T61/Printable use byte positions for ASCII. */
static unsigned character(Span s,size_t at,unsigned stride) {
    unsigned v=0;
    for(unsigned i=0;i<stride;++i) v=(v<<8)|s.data[at*stride+i];
    return v;
}
static bool common_name(const mbedtls_x509_buf* name) {
    size_t count=0;
    if(name->tag==MBEDTLS_ASN1_UTF8_STRING) {
        if(!valid_utf8(name->p,name->len)) return false;
        for(size_t i=0;i<name->len;++i) if((name->p[i]&0xc0)!=0x80) ++count;
    } else if(name->tag==MBEDTLS_ASN1_BMP_STRING || name->tag==MBEDTLS_ASN1_UNIVERSAL_STRING) {
        unsigned stride=name->tag==MBEDTLS_ASN1_BMP_STRING?2:4;
        if(name->len%stride) return false;
        count=name->len/stride;
        for(size_t i=0;i<count;++i) {
            unsigned v=character(buf(*name),i,stride);
            if(v>0x10ffff || (v>=0xd800&&v<=0xdfff)) return false;
        }
    } else if(name->tag==MBEDTLS_ASN1_PRINTABLE_STRING || name->tag==MBEDTLS_ASN1_T61_STRING) {
        count=name->len;
        if(name->tag==MBEDTLS_ASN1_PRINTABLE_STRING) for(size_t i=0;i<count;++i) {
            unsigned v=name->p[i];
            if(!((v>='a'&&v<='z')||(v>='A'&&v<='Z')||(v>='0'&&v<='9')||
                (v && strchr(" '()+,-./:=?",(int)v)))) return false;
        }
    } else return false;
    return count>=1 && count<=64;
}
static bool fallback(const mbedtls_x509_buf* cn,const char* prefix,bool* found,uint16_t* value) {
    unsigned stride=cn->tag==MBEDTLS_ASN1_BMP_STRING?2:cn->tag==MBEDTLS_ASN1_UNIVERSAL_STRING?4:1;
    if(cn->len%stride) return false;
    Span s=buf(*cn); size_t units=s.size/stride; bool prefix_seen=false;
    for(size_t i=0;i+5<=units;++i) {
        unsigned j=0;
        while(j<5 && character(s,i+j,stride)==(unsigned char)prefix[j]) ++j;
        if(j!=5) continue;
        prefix_seen=true;
        if(units-i<9) continue;
        unsigned n=0;
        for(j=0;j<4;++j) {
            int h=hex(character(s,i+5+j,stride)); if(h<0) break;
            n=(n<<4)|(unsigned)h;
        }
        if(j==4) { *found=true; *value=(uint16_t)n; return true; }
    }
    return !prefix_seen;
}
static bool ids(const mbedtls_x509_name* dn,Ids* out) {
    static const uint8_t base[]={0x2b,6,1,4,1,0x82,0xa2,0x7c,2};
    static const uint8_t cn_oid[]={0x55,4,3};
    unsigned rdn=0;
    for(const mbedtls_x509_name* n=dn;n;n=n->next) {
        if(equal(buf(n->oid),(Span){cn_oid,3}) && !common_name(&n->val)) return false;
        if(n->oid.len==sizeof(base)+1 && !memcmp(n->oid.p,base,sizeof(base)) &&
            (n->oid.p[sizeof(base)]==1 || n->oid.p[sizeof(base)]==2)) {
            bool vendor=n->oid.p[sizeof(base)]==1; unsigned value=0;
            if(n->val.len!=4 || (n->val.tag!=MBEDTLS_ASN1_UTF8_STRING && n->val.tag!=MBEDTLS_ASN1_PRINTABLE_STRING) ||
                (vendor?out->has_vid:out->has_pid)) return false;
            for(unsigned i=0;i<4;++i) { int h=hex(n->val.p[i]); if(h<0) return false; value=(value<<4)|(unsigned)h; }
            out->preferred=true;
            if(vendor) { out->has_vid=true; out->vid=(uint16_t)value; out->vid_rdn=rdn; }
            else { out->has_pid=true; out->pid=(uint16_t)value; out->pid_rdn=rdn; }
        }
        if(!n->MBEDTLS_PRIVATE(next_merged)) ++rdn;
    }
    out->rdns=rdn;
    if(out->preferred) return true; /* Never fill a missing OID from CN. */
    for(const mbedtls_x509_name* n=dn;n;n=n->next) if(equal(buf(n->oid),(Span){cn_oid,3})) {
        bool vid=false,pid=false; uint16_t v=0,p=0;
        if(!fallback(&n->val,"Mvid:",&vid,&v) || !fallback(&n->val,"Mpid:",&pid,&p) ||
            (vid&&out->has_vid) || (pid&&out->has_pid)) return false;
        if(vid) { out->has_vid=true; out->vid=v; }
        if(pid) { out->has_pid=true; out->pid=p; }
    }
    return true;
}
static bool matter_name(const Ids* i,bool dac) {
    if(!i->has_vid || !i->vid || (dac&&!i->has_pid) || (i->has_pid&&!i->pid)) return false;
    if(!i->preferred) return true;
    return i->has_pid ? i->rdns>=2 && i->vid_rdn==i->rdns-2 && i->pid_rdn==i->rdns-1 : i->vid_rdn==i->rdns-1;
}
/* mbedTLS parses X.509; inspect extension envelopes only for profile rules not
 * exposed by its public getters (criticality and duplicate unknown OIDs). */
static bool item(unsigned char** p,const uint8_t* end,int tag,Span* result) {
    unsigned char* start=*p; size_t size;
    if(mbedtls_asn1_get_tag(p,end,&size,tag)) return false;
    if((size_t)(*p-start)!=(size<128?2u:size<256?3u:4u)) return false;
    *result=(Span){*p,size}; *p+=size; return true;
}
static bool extensions(Work* w,const Certificate* cert,unsigned role) {
    const mbedtls_x509_crt* c=&cert->crt;
    if(!c->v3_ext.p || !c->v3_ext.len) return false;
    unsigned char* p=c->v3_ext.p; const uint8_t* end=p+c->v3_ext.len; Span seq;
    if(!item(&p,end,0x30,&seq) || p!=end) return false;
    p=(unsigned char*)seq.data; size_t count=0; unsigned required=0;
    while(p<end) {
        Span ext,oid,data; bool critical=false;
        if(!item(&p,end,0x30,&ext)) return false;
        unsigned char* q=(unsigned char*)ext.data; const uint8_t* ext_end=q+ext.size;
        if(!item(&q,ext_end,6,&oid) || !oid.size || count==sizeof(w->oids)/sizeof(w->oids[0])) return false;
        bool first=true;
        for(size_t i=0;i<oid.size;++i) {
            if(first && oid.data[i]==0x80) return false;
            first=!(oid.data[i]&0x80);
        }
        if(!first) return false;
        for(size_t i=0;i<count;++i) if(equal(oid,w->oids[i])) return false;
        w->oids[count++]=oid;
        if(q<ext_end && *q==1) {
            Span boolean;
            if(!item(&q,ext_end,1,&boolean) || boolean.size!=1 || boolean.data[0]!=255) return false;
            critical=true;
        }
        if(!item(&q,ext_end,4,&data) || q!=ext_end) return false;
        if(oid.size!=3 || oid.data[0]!=0x55 || oid.data[1]!=0x1d) continue;
        unsigned id=oid.data[2];
        if(id==19) {
            static const uint8_t leaf[]={0x30,0}, intermediate[]={0x30,6,1,1,255,2,1,0},
                root[]={0x30,6,1,1,255,2,1,1}, root_no_path[]={0x30,3,1,1,255};
            bool valid=role==0 ? equal(data,(Span){leaf,sizeof(leaf)}) : role==1 ?
                equal(data,(Span){intermediate,sizeof(intermediate)}) :
                equal(data,(Span){root,sizeof(root)}) || equal(data,(Span){root_no_path,sizeof(root_no_path)});
            if(!critical || !valid) return false;
            required|=1;
        } else if(id==15) {
            static const uint8_t leaf[]={3,2,7,0x80}, ca[]={3,2,1,6}, ca_sign[]={3,2,1,0x86};
            if(!critical || (role==0 ? !equal(data,(Span){leaf,4}) :
                !equal(data,(Span){ca,4}) && !equal(data,(Span){ca_sign,4}))) return false;
            required|=2;
        } else if(id==14) {
            if(critical || c->subject_key_id.len!=20) return false;
            required|=4;
        } else if(id==35) {
            if(critical || c->authority_key_id.keyIdentifier.len!=20) return false;
            required|=8;
        }
    }
    return (required&(role==2?7u:15u))==(role==2?7u:15u);
}
static bool profile(Work* w,Matter_Der_T der,unsigned role) {
    Certificate* c=&w->certs[role];
    unsigned char* p=(unsigned char*)der.data; const uint8_t* end=p+der.size; Span seq;
    if(!item(&p,end,0x30,&seq) || p!=end || mbedtls_x509_crt_parse_der(&c->crt,der.data,der.size)) return false;
    if(c->crt.version!=3 || c->crt.MBEDTLS_PRIVATE(sig_md)!=MBEDTLS_MD_SHA256 ||
        c->crt.MBEDTLS_PRIVATE(sig_pk)!=MBEDTLS_PK_ECDSA || c->crt.issuer_id.p || c->crt.subject_id.p ||
        !c->crt.serial.len || c->crt.serial.len>20 || (c->crt.serial.p[0]&0x80) ||
        (c->crt.serial.len>1 && !c->crt.serial.p[0] && !(c->crt.serial.p[1]&0x80))) return false;
    if(!ids(&c->crt.issuer,&c->issuer) || !ids(&c->crt.subject,&c->subject) || !extensions(w,c,role)) return false;
    if(role==2) return !c->subject.has_pid && !c->issuer.has_pid &&
        (!c->subject.has_vid || c->subject.vid) && equal(buf(c->crt.issuer_raw),buf(c->crt.subject_raw)) &&
        (!c->crt.authority_key_id.keyIdentifier.len || equal(buf(c->crt.authority_key_id.keyIdentifier),buf(c->crt.subject_key_id)));
    if(!matter_name(&c->subject,role==0)) return false;
    if(role==0) return matter_name(&c->issuer,false) && c->issuer.vid==c->subject.vid &&
        (!c->issuer.has_pid || c->issuer.pid==c->subject.pid);
    return !c->issuer.has_pid && (!c->issuer.has_vid || c->issuer.vid==c->subject.vid);
}
Matter_Result_T matter_attestation_cert_verify(const Matter_Credentials_Port_T* port,
    Matter_Der_T dac,Matter_Der_T pai,Matter_Der_T paa,uint16_t vid,uint16_t pid,Matter_Attestation_Identity_T* out) {
    if(!port || !port->cert_verify_chain || !out || !vid || !pid ||
        !dac.data || !dac.size || !pai.data || !pai.size || !paa.data || !paa.size) return MATTER_INVALID_ARGUMENT;
    if(dac.size>MATTER_ATTESTATION_MAX_DER || pai.size>MATTER_ATTESTATION_MAX_DER || paa.size>MATTER_ATTESTATION_MAX_DER) return MATTER_LIMIT_REACHED;
    memset(out,0,sizeof(*out)); Work* w=calloc(1,sizeof(*w));
    if(!w) return MATTER_PORT_ERROR;
    for(unsigned i=0;i<3;++i) mbedtls_x509_crt_init(&w->certs[i].crt);
    bool ok=profile(w,dac,0) && profile(w,pai,1) && profile(w,paa,2);
    if(ok) ok=w->certs[0].subject.vid==vid && w->certs[0].subject.pid==pid;
    for(unsigned i=0;ok&&i<2;++i) {
        Certificate* child=&w->certs[i]; Certificate* parent=&w->certs[i+1];
        ok=equal(buf(child->crt.issuer_raw),buf(parent->crt.subject_raw)) &&
            equal(buf(child->crt.authority_key_id.keyIdentifier),buf(parent->crt.subject_key_id));
    }
    if(ok) {
        w->identity.vendor_id=vid; w->identity.product_id=pid;
        memcpy(w->identity.paa_key_id,w->certs[2].crt.subject_key_id.p,20);
    }
    /* Profile metadata no longer borrows these allocations. Free before the
     * port parses the chain again, bounding peak rather than retaining both. */
    for(unsigned i=0;i<3;++i) mbedtls_x509_crt_free(&w->certs[i].crt);
    Matter_Result_T result=MATTER_PORT_ERROR;
    if(ok) {
        const Matter_Cert_Time_Policy_T time={MATTER_CERT_TIME_LEAF_NOT_BEFORE,{0}};
        result=port->cert_verify_chain(port->user,dac,pai,paa,&time,w->identity.public_key);
        if(result==MATTER_OK) *out=w->identity;
    }
    mbedtls_platform_zeroize(w,sizeof(*w)); free(w); return result;
}

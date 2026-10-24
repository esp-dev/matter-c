#include "matter_operational_cert.h"
#include "../codec/matter_tlv.h"
#include <stdlib.h>
#include <string.h>
#include "mbedtls/asn1write.h"
#include "matter_mbedtls_internal.h"
#include "mbedtls/platform_util.h"

/* Only schema reconstruction lives here; DER lengths/tags and cryptography use
 * mbedTLS. Reverse writing preserves the original DN and extension ordering. */
typedef struct { const uint8_t* data; size_t size; } Span;
typedef struct { uint8_t tag; uint64_t value; Span text; } Rdn;
typedef struct { Rdn rdn[5]; size_t count; } Dn;
typedef struct { uint8_t tag; Span raw, oid; } Extension;
typedef struct {
    Matter_Tlv_Reader_T reader;
    Matter_Tlv_Element_T token;
    Dn issuer, subject;
    Span serial, public_key, signature, skid, akid, tbs;
    Extension extensions[40]; /* More than can fit with required fields in 400 B. */
    size_t extension_count, eku_count;
    uint8_t eku[6], path_len;
    bool ca, has_path, invalid_node;
    uint16_t usage;
    uint32_t before, after;
    Matter_Operational_Identity_T identity;
    uint8_t der[MATTER_OPERATIONAL_MAX_DER];
    size_t der_size;
} Certificate;
#if MBEDTLS_VERSION_MAJOR >= 4
typedef char Matter_Key_Hash_Alignment[(offsetof(Certificate,der)%4)==0?1:-1];
#endif
static const uint8_t extension_ids[] = {0,19,15,37,14,35};
static const uint8_t extension_oids[][3] = {{0},{0x55,0x1d,19},{0x55,0x1d,15},
    {0x55,0x1d,37},{0x55,0x1d,14},{0x55,0x1d,35}};
static bool same(Span a, Span b) { return a.size == b.size && !memcmp(a.data,b.data,a.size); }
static bool next(Certificate* c) { return matter_tlv_next(&c->reader,&c->token)==MATTER_TLV_OK; }
static bool token(Certificate* c, Matter_Tlv_Type_T type, unsigned tag) {
    return next(c) && c->token.type==type && c->token.tag.control==(tag ? 1 : 0) && c->token.tag.number==tag;
}
static bool number(Certificate* c, unsigned tag, uint64_t max, uint64_t* value) {
    if (!token(c,MATTER_TLV_UNSIGNED,tag) || c->token.unsigned_value>max) return false;
    *value=c->token.unsigned_value; return true;
}
static bool bytes(Certificate* c, unsigned tag, size_t min, size_t max, Span* value) {
    if (!token(c,MATTER_TLV_BYTES,tag) || c->token.size<min || c->token.size>max) return false;
    *value=(Span){c->token.data,c->token.size}; return true;
}
static bool printable(Span s) {
    for(size_t i=0;i<s.size;++i) {
        uint8_t v=s.data[i];
        if(!((v>='a'&&v<='z')||(v>='A'&&v<='Z')||(v>='0'&&v<='9')||
            (v && strchr(" '()+,-./:=?",v)))) return false;
    }
    return true;
}
static bool dn(Certificate* c, unsigned tag, Dn* d) {
    if(!token(c,MATTER_TLV_LIST,tag)) return false;
    while(next(c) && c->token.type!=MATTER_TLV_END) {
        unsigned t=c->token.tag.number, base=t&0x7f;
        if(c->token.tag.control!=1 || d->count==5 || !base || base>23 || (t>127&&base>15)) return false;
        Rdn* r=&d->rdn[d->count++]; r->tag=(uint8_t)t;
        if(base<=16) {
            if(c->token.type!=MATTER_TLV_UTF8) return false;
            r->text=(Span){c->token.data,c->token.size};
            if(t>127 && !printable(r->text)) return false;
            if(base==16) for(size_t i=0;i<r->text.size;++i) if(r->text.data[i]>127) return false;
        } else {
            if(c->token.type!=MATTER_TLV_UNSIGNED || (base==22&&c->token.unsigned_value>UINT32_MAX)) return false;
            r->value=c->token.unsigned_value;
        }
    }
    return c->reader.error==MATTER_TLV_OK && c->token.type==MATTER_TLV_END && d->count;
}
/* Strict DER envelope for opaque future extensions; no unknown critical
 * extension can silently acquire trust. Preserve unknown noncritical bytes. */
static bool der_item(unsigned char** p, const uint8_t* end, int tag, Span* value) {
    unsigned char* start=*p; size_t n;
    if(mbedtls_asn1_get_tag(p,end,&n,tag)) return false;
    size_t header=(size_t)(*p-start);
    if(header!=(n<128?2u:n<256?3u:4u)) return false;
    *value=(Span){*p,n}; *p+=n; return true;
}
static bool future(Span raw, Span* oid) {
    unsigned char* p=(unsigned char*)raw.data; const uint8_t* end=raw.data+raw.size; Span value;
    if(!der_item(&p,end,0x30,&value) || p!=end) return false;
    p=(unsigned char*)value.data;
    if(!der_item(&p,end,MBEDTLS_ASN1_OID,oid) || !oid->size) return false;
    /* OID subidentifiers must be minimally encoded and terminated. */
    bool first=true;
    for(size_t i=0;i<oid->size;++i) {
        if(first&&oid->data[i]==0x80) return false;
        first=!(oid->data[i]&0x80);
    }
    if(!first) return false;
    /* DER DEFAULT FALSE must be omitted. TRUE is an unsupported critical OID. */
    return der_item(&p,end,MBEDTLS_ASN1_OCTET_STRING,&value) && p==end;
}
static bool extensions(Certificate* c) {
    if(!token(c,MATTER_TLV_LIST,10)) return false;
    unsigned seen=0;
    while(next(c) && c->token.type!=MATTER_TLV_END) {
        unsigned tag=c->token.tag.number;
        if(c->token.tag.control!=1 || tag<1 || tag>6 || c->extension_count==40 || (tag<6&&(seen&(1u<<tag)))) return false;
        seen|=1u<<tag;
        Extension* x=&c->extensions[c->extension_count++]; x->tag=(uint8_t)tag;
        x->oid=tag<6 ? (Span){extension_oids[tag],3} : (Span){0};
        if(tag==1) {
            if(c->token.type!=MATTER_TLV_STRUCTURE || !token(c,MATTER_TLV_BOOL,1)) return false;
            c->ca=c->token.unsigned_value!=0;
            if(!next(c)) return false;
            if(c->token.type!=MATTER_TLV_END) {
                if(!c->ca || c->token.type!=MATTER_TLV_UNSIGNED || c->token.tag.control!=1 ||
                    c->token.tag.number!=2 || c->token.unsigned_value>255) return false;
                c->has_path=true; c->path_len=(uint8_t)c->token.unsigned_value;
                if(!token(c,MATTER_TLV_END,0)) return false;
            }
        } else if(tag==2) {
            if(c->token.type!=MATTER_TLV_UNSIGNED || c->token.unsigned_value>0x1ff) return false;
            c->usage=(uint16_t)c->token.unsigned_value;
        } else if(tag==3) {
            if(c->token.type!=MATTER_TLV_ARRAY) return false;
            while(next(c) && c->token.type!=MATTER_TLV_END) {
                if(c->token.type!=MATTER_TLV_UNSIGNED || c->token.tag.control || !c->token.unsigned_value ||
                    c->token.unsigned_value>6 || c->eku_count==6) return false;
                c->eku[c->eku_count++]=(uint8_t)c->token.unsigned_value;
            }
            if(c->reader.error || !c->eku_count) return false;
        } else {
            if(c->token.type!=MATTER_TLV_BYTES) return false;
            x->raw=(Span){c->token.data,c->token.size};
            if(tag==6) { if(!future(x->raw,&x->oid)) return false; }
            else {
                if(x->raw.size!=20) return false;
                if(tag==4) c->skid=x->raw; else c->akid=x->raw;
            }
        }
        for(size_t i=0;i+1<c->extension_count;++i) if(same(x->oid,c->extensions[i].oid)) return false;
        /* A known OID disguised as future-extension is never permitted. */
        if(tag==6) for(unsigned i=1;i<=5;++i) if(same(x->oid,(Span){extension_oids[i],3})) return false;
    }
    return !c->reader.error && c->token.type==MATTER_TLV_END && (seen&0x36)==0x36;
}
static bool profile(Certificate* c, Matter_Operational_Type_T type) {
    unsigned seen=0;
    for(size_t i=0;i<c->subject.count;++i) {
        Rdn* r=&c->subject.rdn[i]; unsigned t=r->tag;
        if(t<17 || t>23) continue;
        if(t!=22 && (seen&(1u<<t))) return false;
        seen|=1u<<t;
        if(t==17) {
            if(!r->value || r->value>UINT64_C(0xffffffefffffffff)) { c->invalid_node=true; return false; }
            c->identity.node_id=r->value;
        } else if(t==21) {
            if(!r->value) return false;
            c->identity.fabric_id=r->value;
        } else if(t==22) {
            if(c->identity.cat_count==3 || !(r->value&0xffff)) return false;
            for(unsigned j=0;j<c->identity.cat_count;++j) if((c->identity.cats[j]>>16)==(r->value>>16)) return false;
            c->identity.cats[c->identity.cat_count++]=(uint32_t)r->value;
        } else if(t==18 || t==23) return false;
    }
    if(type==MATTER_CERT_NOC) {
        if((seen&~(1u<<22))!=((1u<<17)|(1u<<21)) || c->ca || c->usage!=1 || c->eku_count!=2 ||
            !((c->eku[0]==1&&c->eku[1]==2)||(c->eku[0]==2&&c->eku[1]==1))) return false;
    } else {
        if((seen&~(1u<<21))!=(1u<<(type==MATTER_CERT_ICAC?19:20)) || !c->ca ||
            (c->usage!=0x60&&c->usage!=0x61) || c->eku_count) return false;
        if(type==MATTER_CERT_RCAC) {
            if(!same(c->akid,c->skid) || c->issuer.count!=c->subject.count) return false;
            for(size_t i=0;i<c->issuer.count;++i) {
                const Rdn* a=&c->issuer.rdn[i]; const Rdn* b=&c->subject.rdn[i];
                if(a->tag!=b->tag || a->value!=b->value || a->text.size!=b->text.size ||
                    (a->text.size && !same(a->text,b->text))) return false;
            }
        }
    }
    uint8_t hash[20]; /* SHA-1 is only the mandated key identifier, never a signature. */
    const uint8_t* key=c->public_key.data;
#if MBEDTLS_VERSION_MAJOR >= 4
    /* IDF's SHA-1 driver reads words directly. TLV keys may be unaligned in
     * flash. DER output has not been built yet: reuse its aligned heap storage
     * for the 65-byte public key without another allocation or stack buffer. */
    memcpy(c->der,key,c->public_key.size); key=c->der;
#endif
    if(matter_mbedtls_sha1(key,c->public_key.size,hash) || memcmp(hash,c->skid.data,20)) return false;
    return !c->after || c->after>=c->before;
}
static bool parse(Certificate* c, Matter_Cert_Tlv_T in, Matter_Operational_Type_T type) {
    uint64_t v;
    if(matter_tlv_init(&c->reader,in.data,in.size,4)!=MATTER_TLV_OK || !token(c,MATTER_TLV_STRUCTURE,0) ||
        !bytes(c,1,1,20,&c->serial) || !number(c,2,1,&v) || v!=1 || !dn(c,3,&c->issuer) ||
        !number(c,4,UINT32_MAX,&v)) return false;
    c->before=(uint32_t)v;
    if(!number(c,5,UINT32_MAX,&v)) return false;
    c->after=(uint32_t)v;
    if(!dn(c,6,&c->subject) || !number(c,7,1,&v) || v!=1 || !number(c,8,1,&v) || v!=1 ||
        !bytes(c,9,65,65,&c->public_key) || c->public_key.data[0]!=4 || !extensions(c) ||
        !bytes(c,11,64,64,&c->signature) || !token(c,MATTER_TLV_END,0) ||
        matter_tlv_next(&c->reader,&c->token)!=MATTER_TLV_DONE) return false;
    /* Serial is already a DER INTEGER payload, not an unsigned magnitude. */
    if((c->serial.data[0]&0x80) || (c->serial.size>1 && !c->serial.data[0] && !(c->serial.data[1]&0x80))) return false;
    return profile(c,type);
}

typedef struct { uint8_t* p; uint8_t* start; bool failed; } Der;
static void raw(Der* d, const uint8_t* p, size_t n) {
    if(!d->failed && mbedtls_asn1_write_raw_buffer(&d->p,d->start,p,n)<0) d->failed=true;
}
static void wrap(Der* d, unsigned tag, const uint8_t* end) {
    if(d->failed) return;
    if(mbedtls_asn1_write_len(&d->p,d->start,(size_t)(end-d->p))<0 ||
        mbedtls_asn1_write_tag(&d->p,d->start,(unsigned char)tag)<0) d->failed=true;
}
static void value(Der* d, unsigned tag, Span s) { const uint8_t* end=d->p; raw(d,s.data,s.size); wrap(d,tag,end); }
static void integer(Der* d, unsigned n) {
    if(!d->failed && mbedtls_asn1_write_int(&d->p,d->start,(int)n)<0) d->failed=true;
}
static void signature_integer(Der* d, const uint8_t* p) {
    size_t n=32; while(n>1 && !*p) { ++p; --n; }
    const uint8_t* end=d->p; raw(d,p,n);
    if(*p&0x80) { const uint8_t zero=0; raw(d,&zero,1); }
    wrap(d,2,end);
}
static void name(Der* d, const Dn* dn_value) {
    static const uint8_t ids[]={0,3,4,5,6,7,8,10,11,12,41,42,43,44,46,65};
    static const uint8_t domain[]={0x09,0x92,0x26,0x89,0x93,0xf2,0x2c,0x64,1,0x19};
    const uint8_t* end=d->p;
    for(size_t i=dn_value->count;i>0;--i) {
        const Rdn* r=&dn_value->rdn[i-1]; unsigned base=r->tag&0x7f;
        const uint8_t* rdn_end=d->p;
        if(base>=17) {
            uint8_t text[16], oid[]={0x2b,6,1,4,1,0x82,0xa2,0x7c,1,(uint8_t)(base-16)};
            size_t n=base==22?8:16; uint64_t v=r->value;
            for(size_t j=n;j>0;--j) { text[j-1]=(uint8_t)"0123456789ABCDEF"[v&15]; v>>=4; }
            value(d,12,(Span){text,n}); value(d,6,(Span){oid,sizeof(oid)});
        } else {
            value(d,base==16?22:r->tag>127?19:12,r->text);
            if(base==16) value(d,6,(Span){domain,sizeof(domain)});
            else { uint8_t oid[]={0x55,4,ids[base]}; value(d,6,(Span){oid,3}); }
        }
        wrap(d,0x30,rdn_end); wrap(d,0x31,rdn_end);
    }
    wrap(d,0x30,end);
}
static bool leap(unsigned y) { return y%4==0 && (y%100!=0 || y%400==0); }
static void date(Der* d, uint32_t seconds, bool forever) {
    static const unsigned months[]={31,28,31,30,31,30,31,31,30,31,30,31};
    unsigned y=2000,m=1,day=seconds/86400, v[6]; uint8_t text[15];
    while(day>=365u+leap(y)) { day-=365u+leap(y); ++y; }
    while(day>=months[m-1]+(m==2&&leap(y))) { day-=months[m-1]+(m==2&&leap(y)); ++m; }
    v[0]=y; v[1]=m; v[2]=day+1; v[3]=(seconds/3600)%24; v[4]=(seconds/60)%60; v[5]=seconds%60;
    if(forever) { v[0]=9999; v[1]=12; v[2]=31; v[3]=23; v[4]=59; v[5]=59; }
    bool general=v[0]>=2050; size_t n=0;
    for(unsigned i=0;i<6;++i) {
        if(!i&&general) { text[n++]=(uint8_t)('0'+v[i]/1000); text[n++]=(uint8_t)('0'+v[i]/100%10); }
        text[n++]=(uint8_t)('0'+v[i]/10%10); text[n++]=(uint8_t)('0'+v[i]%10);
    }
    text[n++]='Z'; value(d,general?24:23,(Span){text,n});
}
static void extension(Der* d, const Certificate* c, const Extension* x) {
    if(x->tag==6) { raw(d,x->raw.data,x->raw.size); return; }
    const uint8_t* end=d->p;
    if(x->tag==1) {
        if(c->has_path) integer(d,c->path_len);
        if(c->ca) { const uint8_t t=255; value(d,1,(Span){&t,1}); }
        wrap(d,0x30,end);
    } else if(x->tag==2) {
        uint8_t bits[3]={0}; unsigned highest=0;
        for(unsigned i=0;i<9;++i) if(c->usage&(1u<<i)) { bits[1+i/8]|=(uint8_t)(0x80u>>(i%8)); highest=i; }
        bits[0]=(uint8_t)(7-highest%8); value(d,3,(Span){bits,2+highest/8});
    } else if(x->tag==3) {
        for(size_t i=c->eku_count;i>0;--i) {
            uint8_t oid[]={0x2b,6,1,5,5,7,3,0};
            oid[7]=c->eku[i-1]<=4?c->eku[i-1]:c->eku[i-1]==5?8:9;
            value(d,6,(Span){oid,sizeof(oid)});
        }
        wrap(d,0x30,end);
    } else if(x->tag==4) value(d,4,c->skid);
    else { value(d,0x80,c->akid); wrap(d,0x30,end); }
    wrap(d,4,end);
    if(x->tag<=3) { const uint8_t t=255; value(d,1,(Span){&t,1}); }
    uint8_t oid[]={0x55,0x1d,extension_ids[x->tag]}; value(d,6,(Span){oid,3}); wrap(d,0x30,end);
}
static bool encode(Certificate* c) {
    static const uint8_t algorithm[]={0x30,0x0a,6,8,0x2a,0x86,0x48,0xce,0x3d,4,3,2};
    static const uint8_t key_algorithm[]={0x30,0x13,6,7,0x2a,0x86,0x48,0xce,0x3d,2,1,6,8,0x2a,0x86,0x48,0xce,0x3d,3,1,7};
    Der d={c->der+sizeof(c->der),c->der,false}; const uint8_t* end=d.p;
    signature_integer(&d,c->signature.data+32); signature_integer(&d,c->signature.data); wrap(&d,0x30,end);
    const uint8_t zero=0; raw(&d,&zero,1); wrap(&d,3,end); raw(&d,algorithm,sizeof(algorithm));
    const uint8_t* tbs_end=d.p; const uint8_t* extensions_end=d.p;
    for(size_t i=c->extension_count;i>0;--i) extension(&d,c,&c->extensions[i-1]);
    wrap(&d,0x30,extensions_end); wrap(&d,0xa3,extensions_end);
    const uint8_t* key_end=d.p; raw(&d,c->public_key.data,65); raw(&d,&zero,1); wrap(&d,3,key_end);
    raw(&d,key_algorithm,sizeof(key_algorithm)); wrap(&d,0x30,key_end);
    name(&d,&c->subject); const uint8_t* validity_end=d.p;
    date(&d,c->after,!c->after); date(&d,c->before,false); wrap(&d,0x30,validity_end);
    name(&d,&c->issuer); raw(&d,algorithm,sizeof(algorithm)); value(&d,2,c->serial);
    const uint8_t* version_end=d.p; integer(&d,2); wrap(&d,0xa0,version_end);
    wrap(&d,0x30,tbs_end);
    const uint8_t* tbs_start=d.p;
    wrap(&d,0x30,end);
    if(d.failed) return false;
    c->tbs=(Span){c->der+(tbs_start-d.p),(size_t)(tbs_end-tbs_start)};
    c->der_size=(size_t)(end-d.p); memmove(c->der,d.p,c->der_size); return true;
}
static void release(void* p, size_t size) { if(p) { mbedtls_platform_zeroize(p,size); free(p); } }
static Matter_Result_T input(Matter_Cert_Tlv_T c) {
    return !c.data || !c.size ? MATTER_INVALID_ARGUMENT : c.size>400 ? MATTER_LIMIT_REACHED : MATTER_OK;
}
Matter_Result_T matter_operational_cert_verify_root(const Matter_Crypto_Port_T* port, Matter_Cert_Tlv_T in) {
    if(!port || !port->ecdsa_verify) return MATTER_INVALID_ARGUMENT;
    Matter_Result_T r=input(in); if(r!=MATTER_OK) return r;
    Certificate* c=calloc(1,sizeof(*c));
    r=MATTER_PORT_ERROR;
    if(c && parse(c,in,MATTER_CERT_RCAC) && encode(c))
        r=port->ecdsa_verify(port->user,c->public_key.data,c->tbs.data,c->tbs.size,c->signature.data);
    release(c,sizeof(*c)); return r;
}
Matter_Result_T matter_operational_cert_decode(Matter_Cert_Tlv_T in, Matter_Operational_Type_T type,
    uint8_t* out, size_t capacity, size_t* size) {
    Matter_Result_T r=input(in);
    if(r!=MATTER_OK) return r;
    if(!out || !size || type<MATTER_CERT_NOC || type>MATTER_CERT_RCAC) return MATTER_INVALID_ARGUMENT;
    if(capacity!=600) return MATTER_LIMIT_REACHED;
    memset(out,0,capacity); *size=0;
    Certificate* c=calloc(1,sizeof(*c));
    bool ok=c && parse(c,in,type) && encode(c);
    if(ok) { memcpy(out,c->der,c->der_size); *size=c->der_size; }
    release(c,sizeof(*c)); return ok ? MATTER_OK : MATTER_PORT_ERROR;
}
Matter_Result_T matter_operational_cert_verify(const Matter_Credentials_Port_T* port,
    Matter_Cert_Tlv_T noc, Matter_Cert_Tlv_T icac, Matter_Cert_Tlv_T root, uint64_t fabric,
    const Matter_Cert_Time_Policy_T* time, Matter_Operational_Identity_T* identity) {
    if(!port || !port->cert_verify_chain || !identity || !time || time->mode!=MATTER_CERT_TIME_SUPPLIED || !fabric ||
        (!icac.size&&icac.data)) return MATTER_INVALID_ARGUMENT;
    Matter_Result_T r=input(noc); if(r==MATTER_OK) r=input(root); if(r==MATTER_OK&&icac.size) r=input(icac);
    if(r!=MATTER_OK) return r;
    memset(identity,0,sizeof(*identity));
    Certificate* c=calloc(3,sizeof(*c));
    if(!c) return MATTER_PORT_ERROR;
    bool ok=parse(&c[0],noc,MATTER_CERT_NOC) && encode(&c[0]) &&
        parse(&c[2],root,MATTER_CERT_RCAC) && encode(&c[2]) &&
        (!icac.size || (parse(&c[1],icac,MATTER_CERT_ICAC) && encode(&c[1])));
    unsigned issuer=icac.size?1:2;
    if(ok) ok=c[0].identity.fabric_id==fabric && (!c[2].identity.fabric_id||c[2].identity.fabric_id==fabric) &&
        (!icac.size || ((!c[1].identity.fabric_id||c[1].identity.fabric_id==fabric) && same(c[1].akid,c[2].skid))) &&
        same(c[0].akid,c[issuer].skid);
    r=MATTER_PORT_ERROR;
    if(ok) r=(port->operational_verify_chain ? port->operational_verify_chain : port->cert_verify_chain)
        (port->user,(Matter_Der_T){c[0].der,c[0].der_size},
        icac.size?(Matter_Der_T){c[1].der,c[1].der_size}:(Matter_Der_T){0},
        (Matter_Der_T){c[2].der,c[2].der_size},time,c[0].identity.public_key);
    if(r==MATTER_OK) *identity=c[0].identity;
    release(c,3*sizeof(*c)); return r;
}

Matter_Result_T matter_operational_cert_inspect(Matter_Cert_Tlv_T in,Matter_Operational_Type_T type,
    Matter_Operational_Identity_T* out,bool* invalid_node) {
    if(!out || !invalid_node || type<MATTER_CERT_NOC || type>MATTER_CERT_RCAC) return MATTER_INVALID_ARGUMENT;
    memset(out,0,sizeof(*out)); *invalid_node=false;
    Matter_Result_T r=input(in); if(r!=MATTER_OK) return r;
    typedef struct { Certificate c; mbedtls_ecp_group group; mbedtls_ecp_point point; } Work;
    Work* w=calloc(1,sizeof(*w)); if(!w) return MATTER_PORT_ERROR;
    mbedtls_ecp_group_init(&w->group); mbedtls_ecp_point_init(&w->point);
    bool ok=parse(&w->c,in,type); *invalid_node=w->c.invalid_node;
    if(ok) ok=!mbedtls_ecp_group_load(&w->group,MBEDTLS_ECP_DP_SECP256R1) &&
        !mbedtls_ecp_point_read_binary(&w->group,&w->point,w->c.public_key.data,65) && !mbedtls_ecp_check_pubkey(&w->group,&w->point);
    if(ok) { *out=w->c.identity; memcpy(out->public_key,w->c.public_key.data,65); }
    mbedtls_ecp_point_free(&w->point); mbedtls_ecp_group_free(&w->group); release(w,sizeof(*w));
    return ok?MATTER_OK:MATTER_PORT_ERROR;
}

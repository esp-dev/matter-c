#include "matter_discovery.h"
#include <stdlib.h>
#include <stdio.h>

struct Matter_Discovery {
    Matter_Mdns_Record_T record;
    Matter_Mdns_Txt_T txt[2]; const char* subtypes[3];
    char instance[34],host[13],subtype[3][19],discriminator[5],mode[2];
};
static void hex(char* out,const uint8_t* bytes,size_t n) {
    static const char digits[]="0123456789ABCDEF";
    for(size_t i=0;i<n;++i) { out[2*i]=digits[bytes[i]>>4]; out[2*i+1]=digits[bytes[i]&15]; }
    out[n*2]=0;
}
static Matter_Discovery_T create(const uint8_t mac[6],uint16_t port) {
    if(!mac || !port) return NULL;
    Matter_Discovery_T d=calloc(1,sizeof(*d)); if(!d) return NULL;
    hex(d->host,mac,6);
    d->record=(Matter_Mdns_Record_T){.instance=d->instance,.hostname=d->host,.port=port,
        .txt=d->txt,.subtypes=d->subtypes};
    for(unsigned i=0;i<3;++i) d->subtypes[i]=d->subtype[i];
    return d;
}
Matter_Discovery_T matter_discovery_commissionable(const uint8_t mac[6],const uint8_t random[8],uint16_t disc,uint8_t mode,uint16_t port) {
    if(!random || disc>4095 || mode>3) return NULL;
    Matter_Discovery_T d=create(mac,port); if(!d) return NULL;
    hex(d->instance,random,8); snprintf(d->discriminator,sizeof(d->discriminator),"%u",disc);
    d->mode[0]=(char)('0'+mode);
    snprintf(d->subtype[0],sizeof(d->subtype[0]),"_L%u",disc);
    snprintf(d->subtype[1],sizeof(d->subtype[1]),"_S%u",disc>>8);
    snprintf(d->subtype[2],sizeof(d->subtype[2]),"_CM");
    d->txt[0]=(Matter_Mdns_Txt_T){"D",d->discriminator}; d->txt[1]=(Matter_Mdns_Txt_T){"CM",d->mode};
    d->record.service="_matterc"; d->record.protocol="_udp";
    d->record.txt_count=2; d->record.subtype_count=mode?3:2; return d;
}
Matter_Discovery_T matter_discovery_operational(const uint8_t mac[6],const uint8_t fabric[8],uint64_t node,uint16_t port) {
    if(!fabric || !node || node>UINT64_C(0xffffffefffffffff)) return NULL;
    Matter_Discovery_T d=create(mac,port); if(!d) return NULL;
    hex(d->instance,fabric,8); d->instance[16]='-'; uint8_t bytes[8];
    for(unsigned i=0;i<8;++i) bytes[7-i]=(uint8_t)(node>>(i*8));
    hex(d->instance+17,bytes,8); d->subtype[0][0]='_'; d->subtype[0][1]='I'; hex(d->subtype[0]+2,fabric,8);
    d->record.service="_matter"; d->record.protocol="_tcp"; d->record.subtype_count=1;
    /* Core default idle MRP interval; no optional TCP capability advertised. */
    d->txt[0]=(Matter_Mdns_Txt_T){"SII","500"}; d->record.txt_count=1; return d;
}
const Matter_Mdns_Record_T* matter_discovery_record(Matter_Discovery_T d) { return d?&d->record:NULL; }
void matter_discovery_delete(Matter_Discovery_T d) { free(d); }

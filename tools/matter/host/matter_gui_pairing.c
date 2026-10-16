#include "matter_gui_pairing.h"
#include <string.h>
bool matter_gui_pin_valid(uint32_t pin) {
    if(!pin || pin>99999998 || pin==12345678 || pin==87654321) return false;
    for(unsigned i=1;i<=8;++i) if(pin==i*11111111u) return false;
    return true;
}
bool matter_gui_pairing(uint32_t pin,uint16_t discriminator,uint16_t vendor,uint16_t product,
    char out[MATTER_GUI_QR_TEXT_BYTES]) {
    if(!out || !matter_gui_pin_valid(pin) || discriminator>4095) return false;
    uint8_t raw[11]={0}; unsigned shift=0;
    const uint32_t values[]={0,vendor,product,0,4,discriminator,pin,0};
    const unsigned widths[]={3,16,16,2,8,12,27,4};
    for(unsigned i=0;i<sizeof(values)/sizeof(values[0]);++i)
        for(unsigned b=0;b<widths[i];++b,++shift)
            raw[shift/8]|=(uint8_t)(((values[i]>>b)&1u)<<(shift%8));
    static const char alphabet[]="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-.";
    memcpy(out,"MT:",3); unsigned at=3;
    for(unsigned i=0;i<sizeof(raw);i+=3) {
        unsigned size=(unsigned)sizeof(raw)-i; if(size>3) size=3;
        uint32_t value=0; for(unsigned b=0;b<size;++b) value|=(uint32_t)raw[i+b]<<(8*b);
        unsigned count=size==3?5:size==2?4:2;
        while(count--) { out[at++]=alphabet[value%38]; value/=38; }
    }
    out[at]=0; return true;
}

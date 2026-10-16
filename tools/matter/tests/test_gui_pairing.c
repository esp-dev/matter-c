/* CHIP 363 payload command oracle; public development PIN, never live state. */
#include "matter_gui_pairing.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
int main(int argc,char** argv) {
    char qr[MATTER_GUI_QR_TEXT_BYTES];
    if(argc==5) {
        unsigned long values[4]; const unsigned long limits[]={99999998,4095,65535,65535};
        for(unsigned i=0;i<4;++i) {
            char* end; values[i]=strtoul(argv[i+1],&end,10);
            if(!*argv[i+1] || *end || values[i]>limits[i]) return 2;
        }
        if(!matter_gui_pairing((uint32_t)values[0],(uint16_t)values[1],(uint16_t)values[2],(uint16_t)values[3],qr)) return 2;
        puts(qr); return 0;
    }
    assert(argc==1);
    assert(matter_gui_pairing(20202021,3840,0xfff1,0x8001,qr));
    assert(!strcmp(qr,"MT:-24J0AFN00KA0648G00"));
    assert(!matter_gui_pairing(12345678,3840,0,0,qr));
    assert(!matter_gui_pairing(87654321,3840,0,0,qr));
    assert(!matter_gui_pairing(0,3840,0,0,qr));
    assert(!matter_gui_pairing(99999999,3840,0,0,qr));
    for(unsigned i=1;i<=8;++i) assert(!matter_gui_pin_valid(i*11111111u));
    assert(!matter_gui_pairing(20202021,4096,0,0,qr));
    assert(!matter_gui_pairing(20202021,0,0,0,NULL));
    assert(matter_gui_pairing(1,0,0,0,qr));
    assert(matter_gui_pairing(99999998,4095,65535,65535,qr));
    puts("PASS desktop QR payload and onboarding boundaries"); return 0;
}

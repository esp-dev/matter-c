#include "matter_idf_wifi_retry.h"
#include <string.h>
#include <limits.h>
static uint64_t after(uint64_t now,uint32_t delay) {
    return now>UINT64_MAX-delay?UINT64_MAX:now+delay;
}
static void defer(Matter_Idf_Wifi_Retry_T* r,uint64_t now) {
    unsigned shift=r->attempts<6?r->attempts:6;
    uint32_t delay=500u<<shift;
    if(delay>30000)delay=30000;
    r->random^=r->random<<13;r->random^=r->random>>17;r->random^=r->random<<5;
    delay=delay*9/10+r->random%(delay/5+1);
    if(delay>30000)delay=30000;
    r->due=after(now,delay);
    if(r->attempts<UINT32_MAX)++r->attempts;
}
void matter_idf_wifi_retry_init(Matter_Idf_Wifi_Retry_T* r,uint32_t random,uint64_t now) {
    memset(r,0,sizeof(*r));r->random=random?random:1;r->due=now;
}
void matter_idf_wifi_retry_enabled(Matter_Idf_Wifi_Retry_T* r,bool enabled,uint64_t now) {
    if(r->enabled!=enabled) {
        r->enabled=enabled;r->connecting=false;r->attempts=0;r->due=now;
        if(!enabled)r->online=false;
    }
}
void matter_idf_wifi_retry_result(Matter_Idf_Wifi_Retry_T* r,bool online,uint64_t now) {
    bool changed=r->online!=online||r->connecting;
    r->online=online;r->connecting=false;
    if(online){r->attempts=0;r->due=now;}
    else if(changed)defer(r,now);
}
bool matter_idf_wifi_retry_poll(Matter_Idf_Wifi_Retry_T* r,uint64_t now,bool permit) {
    if(!permit||!r->enabled||r->online)return false;
    if(r->connecting){if(now<r->until)return false;r->connecting=false;defer(r,now);}
    if(now<r->due)return false;
    r->connecting=true;r->until=after(now,20000);return true;
}

#include "../../../components/matter_c_esp32/matter_idf_wifi_retry.c"
#include <assert.h>
#include <stdio.h>
int main(void) {
    Matter_Idf_Wifi_Retry_T r;matter_idf_wifi_retry_init(&r,1,0);
    assert(!matter_idf_wifi_retry_poll(&r,0,true));
    matter_idf_wifi_retry_enabled(&r,true,0);assert(matter_idf_wifi_retry_poll(&r,0,true));
    assert(!matter_idf_wifi_retry_poll(&r,19999,true));
    assert(!matter_idf_wifi_retry_poll(&r,20000,true)&&r.due>20000);
    assert(matter_idf_wifi_retry_poll(&r,r.due,true));
    matter_idf_wifi_retry_result(&r,true,r.due);assert(r.online&&!r.attempts);
    for(unsigned n=0;n<100;++n){uint64_t now=r.due+100;matter_idf_wifi_retry_result(&r,false,now);
        assert(!matter_idf_wifi_retry_poll(&r,now,false));
        if(r.due>now)assert(!matter_idf_wifi_retry_poll(&r,r.due-1,true));
        assert(r.due-now<=30000);assert(matter_idf_wifi_retry_poll(&r,r.due,true));}
    matter_idf_wifi_retry_enabled(&r,false,r.due);assert(!matter_idf_wifi_retry_poll(&r,UINT64_MAX,true));
    matter_idf_wifi_retry_enabled(&r,true,UINT64_MAX-10);assert(matter_idf_wifi_retry_poll(&r,UINT64_MAX-10,true));
    assert(r.until==UINT64_MAX);matter_idf_wifi_retry_result(&r,true,UINT64_MAX);assert(r.online&&!r.attempts);
    puts("PASS reconnect: unavailable AP, attempt timeout, explicit-operation gate, bounded retries, repeated recovery, disable and clock bounds");
    return 0;
}

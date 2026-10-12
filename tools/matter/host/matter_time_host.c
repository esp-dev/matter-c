#include "matter_time_host.h"
#include "matter_store_file.h"
#include "matter_host_platform.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#define CLOCK_UNIX_EPOCH UINT64_C(946684800)
#define CLOCK_US_PER_SECOND UINT64_C(1000000)
#define CLOCK_US_PER_MS UINT64_C(1000)
#define CLOCK_RECORD_BYTES 16
#define CLOCK_DRIFT_MS_PER_US 10 /* 100 ppm assumed oscillator error in simulation */
#define CLOCK_MONTH_MS UINT64_C(2592000000)
struct Matter_Time_Host {
    Matter_Store_File_T file; Matter_Store_Blob_Port_T blob;
    uint64_t lkg,anchor_us,anchor_ms,now,last_store,error_us;
    uint8_t granularity,source;
};
static Matter_Result_T persist(Matter_Time_Host_T m,uint64_t value) {
    if(value<=m->lkg) return MATTER_OK;
    uint8_t data[CLOCK_RECORD_BYTES]={'M','C','U','T','C','0','0','1'};
    for(unsigned i=0;i<8;++i) data[8+i]=(uint8_t)(value>>(i*8));
    if(m->blob.replace(m->blob.user,data,sizeof(data))!=MATTER_OK) return MATTER_PORT_ERROR;
    m->lkg=value; return MATTER_OK;
}
static Matter_Result_T sample(void* u,uint64_t now,Matter_Time_Sync_Sample_T* out) {
    Matter_Time_Host_T m=u; if(!m || !out || now<m->now) return MATTER_INVALID_ARGUMENT; m->now=now;
    *out=(Matter_Time_Sync_Sample_T){0}; if(!m->granularity) return MATTER_OK;
    uint64_t elapsed=now-m->anchor_ms;
    if(elapsed>(UINT64_MAX-m->anchor_us)/CLOCK_US_PER_MS) { m->granularity=0; m->source=0; return MATTER_OK; }
    uint64_t error=elapsed/CLOCK_DRIFT_MS_PER_US;
    error=error>UINT64_MAX-m->error_us?UINT64_MAX:error+m->error_us;
    uint8_t granularity=error>UINT64_C(5000000)?MATTER_TIME_MINUTES:error>UINT64_C(50000)?MATTER_TIME_SECONDS:MATTER_TIME_MILLISECONDS;
    if(granularity>m->granularity) granularity=m->granularity;
    *out=(Matter_Time_Sync_Sample_T){m->anchor_us+elapsed*CLOCK_US_PER_MS,granularity,m->source};
    if(now-m->last_store>=CLOCK_MONTH_MS) {
        Matter_Result_T r=persist(m,out->utc_us); if(r!=MATTER_OK) return r; m->last_store=now;
    }
    return MATTER_OK;
}
static Matter_Result_T set(void* u,uint64_t utc,uint8_t granularity,uint64_t now) {
    Matter_Time_Host_T m=u; if(!m || now<m->now || granularity>MATTER_TIME_MICROSECONDS) return MATTER_INVALID_ARGUMENT;
    Matter_Result_T r=persist(m,utc); if(r!=MATTER_OK) return r;
    m->now=m->anchor_ms=m->last_store=now; m->anchor_us=utc; m->granularity=granularity;
    m->source=granularity?MATTER_TIME_SOURCE_ADMIN:MATTER_TIME_NONE;
    m->error_us=granularity>=MATTER_TIME_MILLISECONDS?CLOCK_US_PER_MS:granularity==MATTER_TIME_SECONDS?UINT64_C(50000):UINT64_C(5000000);
    return MATTER_OK;
}
static void synchronize(void* u) {
    Matter_Time_Host_T m=u; if(m->granularity) return;
    uint64_t seconds;
    if(!matter_host_epoch(&seconds) || seconds<CLOCK_UNIX_EPOCH || seconds-CLOCK_UNIX_EPOCH>UINT64_MAX/CLOCK_US_PER_SECOND) return;
    uint64_t utc=(seconds-CLOCK_UNIX_EPOCH)*CLOCK_US_PER_SECOND;
    if(persist(m,utc)!=MATTER_OK) return;
    m->anchor_us=utc; m->anchor_ms=m->last_store=m->now;
    m->granularity=MATTER_TIME_SECONDS; m->source=MATTER_TIME_SOURCE_UNKNOWN; m->error_us=CLOCK_US_PER_SECOND;
}
Matter_Time_Host_T matter_time_host_new(const char* path,uint64_t build,uint64_t now) {
    if(!path || build>UINT64_MAX/CLOCK_US_PER_SECOND) return NULL;
    Matter_Time_Host_T m=calloc(1,sizeof(*m)); if(!m) return NULL;
    size_t size=strlen(path)+sizeof(".clock"); char* name=malloc(size); if(!name) { free(m); return NULL; }
    snprintf(name,size,"%s.clock",path); m->file=matter_store_file_new(name); free(name);
    if(!m->file) { free(m); return NULL; } m->blob=matter_store_file_port(m->file);
    uint8_t data[CLOCK_RECORD_BYTES]; size_t got=0; Matter_Result_T r=m->blob.read(m->blob.user,data,sizeof(data),&got);
    if(r==MATTER_OK) {
        if(got!=sizeof(data) || memcmp(data,"MCUTC001",8)) goto fail;
        for(unsigned i=0;i<8;++i) m->lkg|=(uint64_t)data[8+i]<<(i*8);
    } else if(r!=MATTER_OFFLINE) goto fail;
    m->now=m->anchor_ms=m->last_store=now;
    if(persist(m,build*CLOCK_US_PER_SECOND)!=MATTER_OK) goto fail;
    synchronize(m); return m;
fail: (void)matter_store_file_delete(m->file); free(m); return NULL;
}
Matter_Result_T matter_time_host_delete(Matter_Time_Host_T m) {
    if(!m) return MATTER_OK;
    Matter_Result_T r=matter_store_file_delete(m->file); if(r!=MATTER_OK) return r;
    free(m); return MATTER_OK;
}
Matter_Time_Sync_Port_T matter_time_host_port(Matter_Time_Host_T m) { return (Matter_Time_Sync_Port_T){m,sample,set,synchronize}; }
Matter_Result_T matter_time_host_floor(Matter_Time_Host_T m,uint64_t seconds) {
    if(!m || seconds>UINT64_MAX/CLOCK_US_PER_SECOND) return MATTER_INVALID_ARGUMENT;
    return persist(m,seconds*CLOCK_US_PER_SECOND);
}
uint64_t matter_time_host_last_good(Matter_Time_Host_T m) { return m?m->lkg:0; }
static Matter_Result_T seconds_now(Matter_Time_Host_T m,uint64_t* seconds) {
    if(!m) return MATTER_INVALID_ARGUMENT;
    Matter_Time_Sync_Sample_T current; Matter_Result_T r=sample(m,m->now,&current); if(r!=MATTER_OK) return r;
    *seconds=(current.granularity?current.utc_us:m->lkg)/CLOCK_US_PER_SECOND; return MATTER_OK;
}
Matter_Result_T matter_time_host_timestamp(void* u,uint32_t* out) {
    uint64_t seconds; if(!out || seconds_now(u,&seconds)!=MATTER_OK || seconds>UINT32_MAX) return MATTER_PORT_ERROR;
    *out=(uint32_t)seconds; return MATTER_OK;
}
Matter_Result_T matter_time_host_cert(void* u,Matter_Cert_Time_T* out) {
    uint64_t seconds; if(!out || seconds_now(u,&seconds)!=MATTER_OK || seconds>INT64_MAX-CLOCK_UNIX_EPOCH) return MATTER_PORT_ERROR;
    time_t value=(time_t)(seconds+CLOCK_UNIX_EPOCH); struct tm calendar;
    if(value<0 || (uint64_t)value!=seconds+CLOCK_UNIX_EPOCH) return MATTER_PORT_ERROR;
#ifdef _WIN32
    if(gmtime_s(&calendar,&value)) return MATTER_PORT_ERROR;
#else
    if(!gmtime_r(&value,&calendar)) return MATTER_PORT_ERROR;
#endif
    if(calendar.tm_year<0 || calendar.tm_year>UINT16_MAX-1900) return MATTER_PORT_ERROR;
    *out=(Matter_Cert_Time_T){(uint16_t)(calendar.tm_year+1900),(uint8_t)(calendar.tm_mon+1),(uint8_t)calendar.tm_mday,
        (uint8_t)calendar.tm_hour,(uint8_t)calendar.tm_min,(uint8_t)calendar.tm_sec}; return MATTER_OK;
}

#ifndef MATTER_HOST_PLATFORM_H
#define MATTER_HOST_PLATFORM_H 1
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <time.h>
#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
static inline uint64_t matter_host_now(void) { return GetTickCount64(); }
static inline void matter_host_sleep(unsigned ms) { Sleep(ms); }
static inline bool matter_host_random(void* p,size_t n) {
    return n<=UINT32_MAX && BCryptGenRandom(NULL,p,(ULONG)n,BCRYPT_USE_SYSTEM_PREFERRED_RNG)>=0;
}
static inline bool matter_host_utc(struct tm* utc) {
    SYSTEMTIME t; GetSystemTime(&t);
    *utc=(struct tm){.tm_year=t.wYear-1900,.tm_mon=t.wMonth-1,.tm_mday=t.wDay,
        .tm_hour=t.wHour,.tm_min=t.wMinute,.tm_sec=t.wSecond}; return true;
}
static inline bool matter_host_epoch(uint64_t* seconds) {
    FILETIME t; GetSystemTimeAsFileTime(&t); ULARGE_INTEGER v;
    v.LowPart=t.dwLowDateTime; v.HighPart=t.dwHighDateTime;
    if(v.QuadPart/10000000<UINT64_C(11644473600)) return false;
    *seconds=v.QuadPart/10000000-UINT64_C(11644473600); return true;
}
#else
#include <sys/random.h>
#include <errno.h>
#include <stdlib.h>
static inline uint64_t matter_host_now(void) {
    struct timespec t;
    if(clock_gettime(CLOCK_MONOTONIC,&t)) abort(); /* Never roll session timers back. */
    return (uint64_t)t.tv_sec*1000+(unsigned)t.tv_nsec/1000000;
}
static inline void matter_host_sleep(unsigned ms) {
    struct timespec t={ms/1000,(long)(ms%1000)*1000000}; (void)nanosleep(&t,NULL);
}
static inline bool matter_host_random(void* p,size_t n) {
    uint8_t* b=p;
    while(n) { ssize_t r=getrandom(b,n,0); if(r<0 && errno==EINTR) continue;
        if(r<=0) return false;
        b+=r; n-=(size_t)r;
    } return true;
}
static inline bool matter_host_utc(struct tm* utc) {
    time_t t=time(NULL); return t!=(time_t)-1 && gmtime_r(&t,utc)!=NULL;
}
static inline bool matter_host_epoch(uint64_t* seconds) {
    struct timespec t; if(clock_gettime(CLOCK_REALTIME,&t) || t.tv_sec<0) return false;
    *seconds=(uint64_t)t.tv_sec; return true;
}
#endif
#endif

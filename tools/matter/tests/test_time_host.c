#include <stdio.h>
#include <stdint.h>
#ifdef _WIN32
#include <direct.h>
#define MAKE_DIR(p) _mkdir(p)
#define REMOVE_DIR(p) _rmdir(p)
#else
#include <sys/stat.h>
#include <unistd.h>
#define MAKE_DIR(p) mkdir(p,0700)
#define REMOVE_DIR(p) rmdir(p)
#endif
#include "matter_time_host.h"
#define CHECK(x) do { if(!(x)) { fprintf(stderr,"time-host:%d: %s\n",__LINE__,#x); return 1; } } while(0)
int main(void) {
    const uint64_t future=UINT64_C(1200000000000000);
    Matter_Time_Host_T a=matter_time_host_new("clock-a",1,100),b=matter_time_host_new("clock-b",1,100); CHECK(a && b);
    CHECK(!matter_time_host_new("clock-a",1,100)); /* Exclusive path lock. */
    Matter_Time_Sync_Port_T pa=matter_time_host_port(a),pb=matter_time_host_port(b); Matter_Time_Sync_Sample_T sa,sb;
    CHECK(pa.set(a,future,MATTER_TIME_SECONDS,100)==MATTER_OK && matter_time_host_last_good(a)==future);
    CHECK(pa.sample(a,1100,&sa)==MATTER_OK && sa.utc_us==future+1000000 && sa.source==MATTER_TIME_SOURCE_ADMIN);
    CHECK(pb.sample(b,1100,&sb)==MATTER_OK && sb.utc_us!=sa.utc_us);
    CHECK(pa.sample(a,1099,&sa)==MATTER_INVALID_ARGUMENT);
    /* Block the atomic write without permissions/root assumptions. */
    CHECK(MAKE_DIR("clock-a.clock.tmp")==0);
    CHECK(pa.set(a,future+2000000,MATTER_TIME_SECONDS,1100)==MATTER_PORT_ERROR);
    CHECK(matter_time_host_last_good(a)==future);
    CHECK(pa.sample(a,1100,&sa)==MATTER_OK && sa.utc_us==future+1000000);
    CHECK(REMOVE_DIR("clock-a.clock.tmp")==0);
    CHECK(pa.set(a,0,0,1100)==MATTER_OK && pa.sample(a,1200,&sa)==MATTER_OK && !sa.granularity);
    uint32_t seconds; CHECK(matter_time_host_timestamp(a,&seconds)==MATTER_OK && seconds==future/1000000);
    Matter_Cert_Time_T calendar; CHECK(matter_time_host_cert(a,&calendar)==MATTER_OK && calendar.year>2030);
    CHECK(matter_time_host_delete(a)==MATTER_OK); a=matter_time_host_new("clock-a",1,2000); CHECK(a && matter_time_host_last_good(a)==future);
    pa=matter_time_host_port(a); CHECK(pa.sample(a,2000,&sa)==MATTER_OK && sa.utc_us!=future); /* OS acquisition, not stale saved UTC. */
    CHECK(matter_time_host_floor(a,future/1000000+1)==MATTER_OK && matter_time_host_last_good(a)==future+1000000);
    CHECK(matter_time_host_floor(a,UINT64_MAX)==MATTER_INVALID_ARGUMENT);
    CHECK(pa.set(a,UINT64_MAX,MATTER_TIME_SECONDS,2000)==MATTER_OK && pa.sample(a,2001,&sa)==MATTER_OK && !sa.granularity);
    CHECK(matter_time_host_timestamp(a,&seconds)==MATTER_PORT_ERROR);
    CHECK(matter_time_host_delete(a)==MATTER_OK && matter_time_host_delete(b)==MATTER_OK);
    FILE* bad=fopen("clock-a.clock","wb"); CHECK(bad); CHECK(fputs("corrupt",bad)>=0 && !fclose(bad));
    CHECK(!matter_time_host_new("clock-a",1,0));
    CHECK(!matter_time_host_new("missing-parent/state",1,0));
    puts("PASS host clock: independent anchors, LKG persistence/restart/floors, overflow, missing/corrupt storage and locking"); return 0;
}

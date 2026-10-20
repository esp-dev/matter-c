/* Optional host/API regression; requires the process-local receive-fault
 * fixture. No controller, credentials, real interface change or OTA clock. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "matter_resolver_windows.h"
#include "matter_host_platform.h"
#define CHECK(c) do { if(!(c)) { fprintf(stderr,"resolver:%d: %s\n",__LINE__,#c);goto done; } ++checks; } while(0)

int main(int argc,char** argv) {
    if(argc!=2 && (argc!=3 || strcmp(argv[2],"--fail-reopen"))) return 2;
    char* end=NULL; errno=0; unsigned long index=strtoul(argv[1],&end,10);
    if(errno || end==argv[1] || *end || !index || index>UINT32_MAX) return 2;
    int result=1; unsigned checks=0;
    Matter_Resolver_Windows_T resolver=NULL;
    Matter_Resolver_Port_T port={0}; uint64_t ids[4]={0};
    Matter_Mdns_Windows_Interface_T* iface=calloc(1,sizeof(*iface));
    Matter_Resolver_Answer_T answer,unchanged; memset(&unchanged,0xa5,sizeof(unchanged));
    CHECK(iface && matter_mdns_windows_interface((uint32_t)index,iface)==MATTER_OK);
    resolver=matter_resolver_windows_new(iface);CHECK(resolver);
    port=matter_resolver_windows_port(resolver);
    Matter_Resolver_Query_T query={.node_id=2,.interface_id=(uint32_t)index};
    for(unsigned i=0;i<4;++i) CHECK(port.start(port.user,&query,&ids[i])==MATTER_PENDING && ids[i]);
    uint64_t extra=UINT64_MAX;
    CHECK(port.start(port.user,&query,&extra)==MATTER_LIMIT_REACHED && extra==UINT64_MAX);
    uint64_t last=ids[3],deadline=matter_host_now()+5000; unsigned pending=4;
    while(pending && matter_host_now()<deadline) {
        CHECK(matter_resolver_windows_poll(resolver,matter_host_now())==MATTER_OK);
        for(unsigned i=0;i<4;++i) if(ids[i]) {
            Matter_Operation_Result_T outcome=MATTER_OPERATION_SUCCEEDED;answer=unchanged;
            Matter_Result_T r=port.take(port.user,ids[i],&outcome,&answer);
            CHECK(!memcmp(&answer,&unchanged,sizeof(answer)));
            if(r==MATTER_OK) { CHECK(outcome==MATTER_OPERATION_FAILED);ids[i]=0;--pending; }
            else CHECK(r==MATTER_PENDING && outcome==MATTER_OPERATION_SUCCEEDED);
        }
        if(pending) matter_host_sleep(1);
    }
    CHECK(!pending);puts("RX_FAILURE jobs=4");
    query.interface_id=0;extra=UINT64_MAX;
    CHECK(port.start(port.user,&query,&extra)==MATTER_OFFLINE && extra==UINT64_MAX);
    query.interface_id=(uint32_t)index;
    if(argc==3) {
        CHECK(iface->has_ipv4 && getenv("MATTER_TEST_DNS_FAIL_REOPEN"));
        CHECK(port.start(port.user,&query,&extra)==MATTER_OFFLINE && extra==UINT64_MAX);
        puts("REOPEN_FAILURE id_preserved=1");
    }
    Matter_Result_T start=port.start(port.user,&query,&extra);
    printf("RECOVERY start=%d id_preserved=%u\n",start,extra==UINT64_MAX?1u:0u);
    if(start==MATTER_PENDING) ids[0]=extra;
    CHECK(start==MATTER_PENDING && extra>last && extra!=UINT64_MAX);
    CHECK(matter_resolver_windows_delete(resolver)==MATTER_BUSY);
    port.cancel(port.user,extra);
    Matter_Operation_Result_T outcome=MATTER_OPERATION_SUCCEEDED;answer=unchanged;
    CHECK(port.take(port.user,extra,&outcome,&answer)==MATTER_OK && outcome==MATTER_OPERATION_CANCELLED);
    ids[0]=0;CHECK(!memcmp(&answer,&unchanged,sizeof(answer)));
    outcome=MATTER_OPERATION_SUCCEEDED;
    CHECK(port.take(port.user,extra,&outcome,&answer)==MATTER_INVALID_STATE && outcome==MATTER_OPERATION_SUCCEEDED);
    CHECK(matter_resolver_windows_delete(resolver)==MATTER_OK);resolver=NULL;
    printf("PASS resolver receive recovery: %u\n",checks);result=0;
done:
    if(resolver) {
        for(unsigned i=0;i<4;++i) if(ids[i]) { Matter_Operation_Result_T outcome;
            port.cancel(port.user,ids[i]);(void)port.take(port.user,ids[i],&outcome,&answer); }
        if(matter_resolver_windows_delete(resolver)!=MATTER_OK) result=1;
    }
    free(iface);return result;
}

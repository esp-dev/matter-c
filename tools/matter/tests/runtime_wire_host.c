/* Real runtime/RGB/UDP fixture. Reuse test identity and application ports. */
#define main runtime_fixture_entry
#include "test_runtime.c"
#undef main
#include "wire_faults.h"
#include "matter_udp_windows.h"
#include "matter_host_platform.h"
#include "../../../examples/esp32-runtime/main/rgb_light.h"
#include <signal.h>
#include <errno.h>
typedef struct { Matter_Udp_Datagram_T packet; uint8_t bytes[1280]; } Held_Rx;
typedef struct {
    Node* node; Matter_Udp_Windows_T socket;
    uint64_t completion,due,rx_due;
    Matter_Operation_Result_T outcome;
    unsigned delay,tick,rx_held,rx_reordered;
    bool hold,arm_rx,after,stopping;
    Held_Rx* rx;
} Wire;
static volatile sig_atomic_t interrupted;
static void stop_signal(int sig) { (void)sig; interrupted=1; }
static unsigned argument(const char* text,unsigned min,unsigned max) {
    char* end; errno=0; unsigned long value=strtoul(text,&end,10);
    CHECK(end!=text && !*end && !errno && value>=min && value<=max); return (unsigned)value;
}
static void wire_received(void* u,const Matter_Udp_Datagram_T* packet) {
    Wire* w=u;
    if(w->arm_rx) {
        CHECK(w->rx && packet->size<=sizeof(w->rx->bytes));
        w->arm_rx=false; w->rx->packet=*packet;
        memcpy(w->rx->bytes,packet->data,packet->size); w->rx->packet.data=w->rx->bytes;
        w->rx_due=matter_host_now()+500; ++w->rx_held;
    } else {
        if(w->rx_due) { ++w->rx_reordered; w->rx_due=matter_host_now(); }
        received(w->node,packet);
    }
}
static void wire_sent(void* u,uint64_t id,Matter_Operation_Result_T result) {
    Wire* w=u; CHECK(!w->completion);
    w->completion=id; w->outcome=result; w->due=matter_host_now()+w->delay;
    wire_completion_pending=true;
}
static void completions(Wire* w) {
    if(w->completion && !w->hold && matter_host_now()>=w->due) {
        uint64_t id=w->completion; w->completion=0; wire_completion_pending=false; sent(w->node,id,w->outcome);
    }
}
static void snapshot(FILE* out,const char* id,const Wire* w) {
    fprintf(out,"{\"id\":\"%s\",\"record\":{\"data\":{\"core_calls\":%zu,\"core_failures\":%zu,"
        "\"core_live\":%zu,\"core_bytes\":%zu,\"core_peak\":%zu,\"held_completion\":%u,"
        "\"rx_held\":%u,\"rx_reordered\":%u,\"ack_dropped\":%u,\"unacknowledged\":%u,"
        "\"ack_before_completion\":%u,\"ack_after_completion\":%u}}}\n",
        id,wire_stats.calls,wire_stats.failures,wire_stats.live,wire_stats.bytes,wire_stats.peak,
        w->hold && w->completion?1:0,w->rx_held,w->rx_reordered,wire_stats.ack_dropped,wire_stats.unacknowledged,
        wire_stats.ack_before_completion,wire_stats.ack_after_completion);
    CHECK(!ferror(out) && fflush(out)==0);
}
static bool command(Wire* w,const char* request,FILE* replies,char stop_id[64]) {
    FILE* in=fopen(request,"r"); if(!in) return false;
    char id[64],cmd[2],extra;
    int fields=fscanf(in,"%63[0123456789abcdef:] %1s %c",id,cmd,&extra);
    fclose(in); CHECK(remove(request)==0 && fields==2);
    switch(cmd[0]) {
    case 'm': break;
    case 'a': wire_fail_after(0); break;
    case 'k': wire_ack_fault(true); break;
    case 'l': wire_ack_fault(false); break;
    case 'h': w->hold=true; break;
    case 'j': w->hold=false; break;
    case 'r':
        CHECK(!w->arm_rx && !w->rx_due);
        if(!w->rx) { w->rx=wire_calloc(1,sizeof(*w->rx)); CHECK(w->rx); }
        w->arm_rx=true; break;
    case 'q':
        CHECK(w->hold && w->completion); strcpy(stop_id,id);
        w->hold=false; w->due=matter_host_now()+200; return true;
    case 'x': strcpy(stop_id,id); w->hold=false; return true; /* Failed controller cleanup. */
    default: CHECK(cmd[0]>='1' && cmd[0]<='9'); wire_fail_after((size_t)(cmd[0]-'0')); break;
    }
    snapshot(replies,id,w); return false;
}
static void turn(Wire* w,Matter_Lab_Rgb_T rgb,uint64_t now,uint32_t* generation) {
    /* A held datagram is delivered alone before a runtime turn. Other traffic
     * can pass it during its bounded delay, preserving callback borrows. */
    if(!w->after && w->rx_due && matter_host_now()>=w->rx_due) {
        received(w->node,&w->rx->packet); w->rx_due=0;
    } else if(!w->after) (void)matter_udp_windows_poll(w->socket);
    completions(w);
    CHECK(matter_lab_rgb_process(rgb,now)==MATTER_OK); run(w->node,now);
    uint8_t pixels[3]; uint32_t current=0; CHECK(matter_lab_rgb_pixels(rgb,pixels,&current));
    if(current!=*generation) { *generation=current; matter_runtime_changed(w->node->runtime); }
    if(w->after) {
        if(w->rx_due && matter_host_now()>=w->rx_due) {
            received(w->node,&w->rx->packet); w->rx_due=0;
        } else (void)matter_udp_windows_poll(w->socket);
    }
}
int main(int argc,char** argv) {
    if(argc!=6) { fputs("runtime-wire-host <private-dir> <port> <tick-ms> <completion-ms> <before|after>\n",stderr); return 2; }
    unsigned port=argument(argv[2],1,65535);
    Wire w={0}; w.tick=argument(argv[3],1,100); w.delay=argument(argv[4],0,1000);
    CHECK(!strcmp(argv[5],"before") || !strcmp(argv[5],"after")); w.after=!strcmp(argv[5],"after");
    setvbuf(stdout,NULL,_IONBF,0); signal(SIGINT,stop_signal); signal(SIGTERM,stop_signal);
    size_t length=strlen(argv[1])+32;
    char* request=wire_malloc(length); char* path=wire_malloc(length); CHECK(request && path);
    CHECK(snprintf(request,length,"%s/wire-request.txt",argv[1])>0);
    CHECK(snprintf(path,length,"%s/control-replies.jsonl",argv[1])>0);
    FILE* replies=fopen(path,"a"); CHECK(replies);
    Node* n=node_new(0); w.node=n;
    n->settings.count=1; n->settings.networks[0].id=(Matter_Wifi_Id_T){3,{'l','a','b'}}; n->connected=n->settings.networks[0].id;
    uint64_t start=matter_host_now(),now=0;
    n->runtime=matter_runtime_new(&n->config,20202021,0); CHECK(n->runtime);
    CHECK(matter_runtime_set_resumption(n->runtime,MATTER_CASE_RESUMPTION_CHIP)==MATTER_OK);
    CHECK(matter_runtime_set_certificate_validity(n->runtime,true)==MATTER_OK);
    Matter_Lab_Rgb_T rgb=matter_lab_rgb_new(1,0); CHECK(rgb && matter_lab_rgb_attach(rgb,matter_runtime_root(n->runtime))==MATTER_OK);
    n->owner=matter_new(NULL); CHECK(n->owner && matter_start(n->owner)==MATTER_OK);
    Matter_Udp_Address_T bind={.port=(uint16_t)port}; bind.address[15]=1;
    Matter_Udp_Listener_T listener={&w,wire_received,wire_sent};
    w.socket=matter_udp_windows_new(n->owner,&bind,1,&listener); CHECK(w.socket);
    n->udp=matter_udp_windows_module(w.socket); CHECK(matter_udp_start(n->udp)==MATTER_OK);
    Matter_Events_Port_T ep={n,event_load,event_store}; n->events=matter_events_new(&ep); CHECK(n->events);
    CHECK(matter_runtime_start(n->runtime,n->owner,n->udp,n->events)==MATTER_OK);
    puts("WIRE_READY"); uint32_t generation=0; char stop_id[64]="";
    while(!interrupted && now<600000 && !w.stopping) {
        now=matter_host_now()-start;
        w.stopping=command(&w,request,replies,stop_id);
        turn(&w,rgb,now,&generation); matter_host_sleep(w.tick);
    }
    wire_fail_after(0); wire_ack_fault(false); w.hold=false;
    uint64_t deadline=matter_host_now()+30000;
    Matter_Result_T status=matter_runtime_stop(n->runtime,now);
    while(status==MATTER_PENDING) {
        CHECK(matter_host_now()<deadline); now=matter_host_now()-start;
        turn(&w,rgb,now,&generation); status=matter_runtime_stop(n->runtime,now); matter_host_sleep(1);
    }
    CHECK(!w.completion && status==MATTER_OK && matter_runtime_delete(n->runtime)==MATTER_OK); n->runtime=NULL;
    CHECK(matter_lab_rgb_delete(rgb)==MATTER_OK && matter_events_delete(n->events)==MATTER_OK); n->events=NULL;
    (void)matter_stop(n->owner);
    while(matter_get_state(n->owner)==MATTER_STATE_STOPPING) { CHECK(matter_host_now()<deadline); (void)matter_udp_process(n->udp); }
    CHECK(matter_udp_windows_delete(w.socket)==MATTER_OK && matter_delete(n->owner)==MATTER_OK); n->owner=NULL;
    free_node(n); wire_free(w.rx); wire_free(path); wire_free(request);
    CHECK(!wire_stats.live && !wire_stats.bytes);
    if(*stop_id) snapshot(replies,stop_id,&w);
    CHECK(fclose(replies)==0); puts("WIRE_PASS live=0"); return interrupted || !w.stopping?1:0;
}

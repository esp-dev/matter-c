/* Lab driver: reuse the existing host adapters/profile, two nodes in ONE
 * process and ONE owner thread. No child processes or background workers.
 * A last-fabric reset destroys only that node while the other keeps running. */
#define main single_node_entry
#include "../host/matter_node.c"
#undef main
#define REQUIRE(x) do { if(!(x)) { fprintf(stderr,"pair:%d: %s\n",__LINE__,#x); return false; } } while(0)
static bool open_node(Node* n,unsigned index,unsigned id,const char* creds,const char* state,uint64_t now,
                      const Matter_Diagnostics_Test_Trigger_T* trigger) {
    REQUIRE(matter_mdns_windows_interface(index,&n->iface)==MATTER_OK);
    /* Two virtual devices share one NIC, but need distinct DNS host identities.
     * This locally administered identifier only names DNS records: sockets use
     * the original interface index and IP addresses, not this MAC field. */
    n->iface.mac[0]=(uint8_t)((n->iface.mac[0]|2u)&~1u);
    n->iface.mac[5]^=(uint8_t)(id+1u);
    n->owner=matter_new(NULL); REQUIRE(n->owner && matter_start(n->owner)==MATTER_OK);
    /* Different short discriminators too: framework setup-code discovery may
     * filter only the high four bits of a long discriminator. */
    n->port=(uint16_t)(5541+id); n->discriminator=(uint16_t)(id?1234:3846);
    n->subscriptions_per_fabric=MATTER_HOST_SUBS_PER_FABRIC;
    n->switch_enabled=true;
    Matter_Udp_Address_T bind={.port=n->port}; Matter_Udp_Listener_T listener={n,received,sent};
    n->udp=matter_udp_windows_new(n->owner,&bind,index,&listener);
    REQUIRE(n->udp && matter_udp_start(matter_udp_windows_module(n->udp))==MATTER_OK);
    REQUIRE(matter_host_random(n->random,8));
    n->discovery=matter_discovery_commissionable(n->iface.mac,n->random,n->discriminator,0,n->port);
    REQUIRE(n->discovery && model(n,now,creds,state,20202021,NULL));
    if(trigger) {
        Matter_Diagnostics_Test_Trigger_T own=*trigger; own.user=n;
        REQUIRE(matter_server_set_test_trigger(n->server,&own)==MATTER_OK);
    }
    REQUIRE(matter_server_set_resumption(n->server,MATTER_CASE_RESUMPTION_CHIP)==MATTER_OK);
    n->resolver=matter_resolver_windows_new(&n->iface); REQUIRE(n->resolver);
    Matter_Resolver_Port_T resolver=matter_resolver_windows_port(n->resolver);
    REQUIRE(matter_server_set_resolver(n->server,&resolver)==MATTER_OK);
    Matter_Udp_Path_T route={.local=bind,.interface_id=index}; memcpy(route.local.address,n->iface.ipv6,16);
    REQUIRE(matter_server_set_outbound(n->server,&route)==MATTER_OK);
    REQUIRE(matter_server_start(n->server,n->owner,matter_udp_windows_module(n->udp),n->events)==MATTER_OK);
    matter_discovery_delete(n->discovery); n->discovery=NULL;
    REQUIRE(advertisements(n,now,false));
    printf("PAIR_READY instance=%u port=%u discriminator=%u\n",id,n->port,n->discriminator); return true;
}
static bool close_node(Node* n,uint64_t now) {
    if(!n->owner) return true;
    if(n->server) {
        Matter_Result_T r=matter_server_stop(n->server,now);
        REQUIRE(r==MATTER_OK || r==MATTER_PENDING);
        if(r==MATTER_PENDING) return false; /* Caller continues servicing BOTH nodes. */
    }
    REQUIRE(advertisements(n,now,true));
    for(unsigned i=0;i<5;++i) if(n->operational[i].owner) return false;
    (void)matter_stop(n->owner);
    if(n->mdns) { (void)matter_mdns_process(matter_mdns_windows_module(n->mdns)); (void)matter_mdns_windows_poll(n->mdns,now); }
    if(n->udp) { (void)matter_udp_windows_poll(n->udp); (void)matter_udp_process(matter_udp_windows_module(n->udp)); }
    if(matter_get_state(n->owner)!=MATTER_STATE_STOPPED) return false;
    REQUIRE(matter_mdns_windows_delete(n->mdns)==MATTER_OK); n->mdns=NULL;
    REQUIRE(matter_udp_windows_delete(n->udp)==MATTER_OK); n->udp=NULL;
    if(n->server) { REQUIRE(matter_server_delete(n->server)==MATTER_OK); n->server=NULL; }
    REQUIRE(matter_resolver_windows_delete(n->resolver)==MATTER_OK); n->resolver=NULL;
    if(n->eem) REQUIRE(matter_cluster_delete(n->eem)==MATTER_OK);
    if(n->test_switch) REQUIRE(matter_cluster_delete(n->test_switch)==MATTER_OK);
    if(n->plug_power) REQUIRE(matter_cluster_delete(n->plug_power)==MATTER_OK);
    if(n->plug_energy) REQUIRE(matter_cluster_delete(n->plug_energy)==MATTER_OK);
    if(n->plug_topology) REQUIRE(matter_cluster_delete(n->plug_topology)==MATTER_OK);
    if(n->plug_file) REQUIRE(matter_store_file_delete(n->plug_file)==MATTER_OK);
    if(n->source) REQUIRE(matter_cluster_delete(n->source)==MATTER_OK);
    free(n->source_sim); n->source_sim=NULL;
    for(unsigned i=0;i<HOST_METER_SERVICES_COUNT;++i) if(n->utilities[i]) REQUIRE(matter_cluster_delete(n->utilities[i])==MATTER_OK);
    REQUIRE(matter_time_host_delete(n->clock)==MATTER_OK); n->clock=NULL;
    for(unsigned i=0;i<3;++i) {
        if(n->phase_epm[i]) REQUIRE(matter_cluster_delete(n->phase_epm[i])==MATTER_OK);
        if(n->phase_topology[i]) REQUIRE(matter_cluster_delete(n->phase_topology[i])==MATTER_OK);
    }
    if(n->epm) REQUIRE(matter_cluster_delete(n->epm)==MATTER_OK);
    if(n->topology) REQUIRE(matter_cluster_delete(n->topology)==MATTER_OK);
    if(n->events) REQUIRE(matter_events_delete(n->events)==MATTER_OK);
    REQUIRE(matter_delete(n->owner)==MATTER_OK); n->owner=NULL;
    matter_discovery_delete(n->discovery); n->discovery=NULL;
    printf("PAIR_DELETED port=%u\n",n->port); return true;
}
int main(int argc,char** argv) {
    bool three_phase=false,source=false,services=false,wifi=false;
    uint8_t enable_key[16]={0}; bool test_events=false;
    if(argc<5) return 2;
    for(int i=5;i<argc;++i) {
        if(!strcmp(argv[i],"--three-phase")) three_phase=true;
        else if(!strcmp(argv[i],"--source-registers")) three_phase=source=true;
        else if(!strcmp(argv[i],"--meter-services")) three_phase=source=services=true;
        else if(!strcmp(argv[i],"--wifi-sim-connected")) wifi=true;
        else if(!strcmp(argv[i],"--test-event-key")) {
            if(++i==argc || !test_key(argv[i],enable_key)) return 2;
            test_events=true;
        }
        else { fputs("runtime-pair-host IFACE CREDENTIALS STATE_A STATE_B [--three-phase|--source-registers|--meter-services] [--wifi-sim-connected] [--test-event-key HEX32]\n",stderr); return 2; }
    }
    if(test_events && !services) return 2;
    unsigned long index; if(!number(argv[1],UINT32_MAX,&index) || !index || !strcmp(argv[3],argv[4])) return 2;
    setvbuf(stdout,NULL,_IONBF,0); signal(SIGINT,stop_signal); signal(SIGTERM,stop_signal);
    Node* nodes=calloc(2,sizeof(*nodes)); if(!nodes) return 1;
    nodes[0].three_phase=nodes[1].three_phase=three_phase;
    nodes[0].source_enabled=nodes[1].source_enabled=source;
    nodes[0].meter_services=nodes[1].meter_services=services;
    nodes[0].wifi_sim_connected=nodes[1].wifi_sim_connected=wifi;
    nodes[0].energy_test_enabled=nodes[1].energy_test_enabled=test_events;
    bool closing[2]={false,false},ok=true; uint64_t start=matter_host_now(),next=start;
    Matter_Diagnostics_Test_Trigger_T trigger={.user=NULL,.trigger=test_event_trigger};
    if(test_events) memcpy(trigger.enable_key,enable_key,sizeof(enable_key));
    for(unsigned i=0;i<2;++i) if(!open_node(&nodes[i],(unsigned)index,i,argv[2],argv[3+i],start,test_events?&trigger:NULL)) { ok=false; closing[0]=closing[1]=true; break; }
    if(test_events) puts("PAIR_TRIGGERS enabled=1 key=not-persisted");
    while(nodes[0].owner || nodes[1].owner) {
        uint64_t now=matter_host_now(); bool due=now>=next; if(due) next=now+1000;
        if(interrupted || now-start>240000) closing[0]=closing[1]=true;
        for(unsigned i=0;i<2;++i) {
            Node* n=&nodes[i]; if(!n->owner) continue;
            if(n->udp) (void)matter_udp_windows_poll(n->udp);
            if(n->resolver) (void)matter_resolver_windows_poll(n->resolver,now);
            if(!closing[i]) {
                if(!matter_server_reset_requested(n->server) && !meter_process(n,now)) { ok=false; closing[i]=true; }
                Matter_Result_T r=matter_server_process(n->server,now);
                if(r!=MATTER_OK && r!=MATTER_PENDING) { ok=false; closing[i]=true; }
                if(matter_server_reset_ready(n->server)) closing[i]=true;
            }
            if(closing[i]) {
                /* stop may have completed; process only while it still needs drain. */
                if(!close_node(n,now) && n->server) (void)matter_server_process(n->server,now);
                continue;
            }
            if(due && !matter_server_reset_requested(n->server) && !sample(n,now,(now-start)/1000)) { ok=false; closing[i]=true; }
            if(!advertisements(n,now,false)) { ok=false; closing[i]=true; }
            if(n->mdns) { (void)matter_mdns_process(matter_mdns_windows_module(n->mdns)); (void)matter_mdns_windows_poll(n->mdns,now); }
        }
        matter_host_sleep(5);
    }
    free(nodes); puts("PAIR_EXIT two instances deleted in same process"); return ok?0:1;
}

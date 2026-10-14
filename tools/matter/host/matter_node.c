/* Standalone owner-driven host composition, simulation credentials only. */
#include "matter_host_platform.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "matter_mdns_windows.h"
#include "matter_resolver_windows.h"
#include "matter_udp_windows.h"
#include "matter_discovery.h"
#include "clusters/matter_root.h"
#include "clusters/matter_power_topology.h"
#include "clusters/matter_epm.h"
#include "clusters/matter_eem.h"
#include "matter_server.h"
#include "matter_host_limits.h"
#include "matter_host_identity.h"
#include "matter_switch_sim.h"
#include "matter_energy_sim.h"
#include "matter_source_sim.h"
#include "matter_time_host.h"
#include "clusters/matter_identify.h"
#include "clusters/matter_meter_identification.h"
#ifndef MATTER_HOST_BUILD_UNIX
#define MATTER_HOST_BUILD_UNIX 0 /* Legacy build: explicit UTC build floor needed for --meter-services. */
#endif
#define HOST_METER_SERVICES_COUNT 3
#define HOST_UNIX_MATTER_EPOCH UINT64_C(946684800)
#define HOST_NOC_NOT_BEFORE_TAG 4

typedef struct { Matter_T owner; Matter_Mdns_Windows_T mdns; Matter_Discovery_T description; uint8_t index; } Operational;

typedef struct {
    Matter_T owner; Matter_Root_T root; Matter_Cluster_T topology,epm,eem,test_switch;
    bool switch_enabled,three_phase,wifi_sim_connected;
    bool source_enabled; Matter_Cluster_T source;
    Matter_Source_Sim_T* source_sim;
    bool meter_services,clock_fabrics_seen; Matter_Time_Host_T clock;
    Matter_Cluster_T utilities[HOST_METER_SERVICES_COUNT]; uint32_t utility_versions[HOST_METER_SERVICES_COUNT],clock_fabric_revision;
    Matter_Cluster_T phase_epm[3],phase_topology[3];
    Matter_Epm_Multi_Sample_T measurements[4];
    Matter_Epm_Measurement_T measurement_config[4];
    bool energy_test_enabled; Matter_Energy_Sim_T energy_sim;
    Matter_Events_T events; Matter_Udp_Windows_T udp; Matter_Mdns_Windows_T mdns;
    Matter_Discovery_T discovery; Matter_Mdns_Windows_Interface_T iface;
    Matter_Resolver_Windows_T resolver;
    Matter_Root_Config_T identity; Matter_Epm_Sample_T power; Matter_Eem_Sample_T energy;
    /* RAM cache; commissioned mode commits through the server store. */
    Matter_Eem_Checkpoint_T checkpoint; int64_t raw_base[2]; uint64_t high,rx_packets;
    Matter_Server_T server; Operational operational[5]; uint16_t port,discriminator,advertised_discriminator; uint8_t random[8],cm_mode;
    uint8_t observed_cm_mode; bool discovery_stopping,discovery_rotate;
} Node;
static volatile sig_atomic_t interrupted;
static void stop_signal(int sig) { (void)sig; interrupted=1; }
static Matter_Result_T load(void* u,Matter_Root_Config_T* out) { *out=((Node*)u)->identity; return MATTER_OK; }
static Matter_Result_T store(void* u,const Matter_Root_Settings_T* in) { ((Node*)u)->identity.settings=*in; return MATTER_OK; }
static uint8_t deny(void* u,Matter_Exchange_Session_T s,const Matter_Im_Path_T* p,Matter_Im_Privilege_T v) {
    (void)u; (void)s; (void)p; (void)v; return MATTER_IM_UNSUPPORTED_ACCESS;
}
static Matter_Result_T power(void* u,Matter_Epm_Sample_T* out) { *out=((Node*)u)->power; return MATTER_OK; }
static Matter_Result_T energy(void* u,Matter_Eem_Sample_T* out) { *out=((Node*)u)->energy; return MATTER_OK; }
static Matter_Result_T checkpoint_load(void* u,Matter_Eem_Checkpoint_T* out) {
    Node* n=u;
    if(n->server && matter_store_host_eem_load(matter_server_store(n->server),&n->checkpoint)!=MATTER_OK) return MATTER_PORT_ERROR;
    *out=n->checkpoint; return MATTER_OK;
}
static Matter_Result_T checkpoint_store(void* u,const Matter_Eem_Checkpoint_T* in) {
    Node* n=u;
    /* Core11.12.7.1: test effects must not survive last-fabric removal.
     * Opt-in laboratory measurements never overwrite the durable meter image. */
    if(n->server && !n->energy_test_enabled && matter_store_host_eem_store(matter_server_store(n->server),in)!=MATTER_OK) return MATTER_PORT_ERROR;
    n->checkpoint=*in; return MATTER_OK;
}
static Matter_Result_T event_load(void* u,uint64_t* out) {
    Node* n=u; if(n->server) return matter_store_host_event_load(matter_server_store(n->server),out);
    *out=n->high; return MATTER_OK;
}
static Matter_Result_T event_store(void* u,uint64_t high) {
    Node* n=u; if(n->server) return matter_store_host_event_store(matter_server_store(n->server),high);
    n->high=high; return MATTER_OK;
}
static void received(void* u,const Matter_Udp_Datagram_T* d) { Node* n=u; ++n->rx_packets; matter_server_received(n->server,d); }
static void sent(void* u,uint64_t id,Matter_Operation_Result_T result) { matter_server_sent(((Node*)u)->server,id,result); }
static void text(Matter_Root_Text_T* t,const char* str) { t->size=strlen(str); memcpy(t->data,str,t->size); }
static void switch_changed(void* u,bool on) {
    Node* n=u; printf("TEST_SWITCH endpoint=2 on=%u\n",on?1:0); matter_server_changed(n->server);
}
static uint8_t energy_trigger(void* u,uint64_t event) {
    Node* n=u;
    if(matter_server_reset_requested(n->server)) return MATTER_IM_FAILURE;
    uint8_t status=matter_energy_sim_trigger(&n->energy_sim,event,matter_host_now());
    printf("ENERGY_TEST event=%016llx status=%u\n",(unsigned long long)event,status); return status;
}
static Matter_Result_T multi_sample(void* u,Matter_Epm_Multi_Sample_T* out) { *out=*(Matter_Epm_Multi_Sample_T*)u; return MATTER_OK; }
static void identify_present(void* u,uint16_t seconds) { (void)u; printf("IDENTIFY seconds=%u presentation=simulation\n",seconds); }
static Matter_Result_T meter_identity(void* u,Matter_Meter_Id_Snapshot_T* out) {
    (void)u; *out=(Matter_Meter_Id_Snapshot_T){.type_known=true,.meter_type=2}; /* Generic synthetic meter; delivery unknown. */
    static const char serial[]="SIM-0001",protocol[]="1.0";
    out->serial.known=true; out->serial.size=sizeof(serial)-1; memcpy(out->serial.data,serial,sizeof(serial)-1);
    out->protocol.known=true; out->protocol.size=sizeof(protocol)-1; memcpy(out->protocol.data,protocol,sizeof(protocol)-1); return MATTER_OK;
}
static bool certificate_floor(const uint8_t* data,size_t size,uint64_t* floor) {
    Matter_Tlv_Reader_T reader; Matter_Tlv_Element_T element;
    if(matter_tlv_init(&reader,data,size,4)!=MATTER_TLV_OK) return false;
    while(matter_tlv_next(&reader,&element)==MATTER_TLV_OK) {
        /* Borrowed certificates were already validated by the fabric backend. */
        if(reader.depth==1 && element.tag.control==1 && element.tag.number==HOST_NOC_NOT_BEFORE_TAG && element.type==MATTER_TLV_UNSIGNED) {
            if(element.unsigned_value>*floor) *floor=element.unsigned_value;
            return true;
        }
    }
    return false;
}
static bool meter_process(Node* n,uint64_t now) {
    if(!n->meter_services) return true;
    const Matter_Fabric_View_T* fabrics=matter_server_fabrics(n->server);
    if(fabrics && (!n->clock_fabrics_seen || fabrics->revision!=n->clock_fabric_revision)) {
        uint64_t floor=0;
        /* Removing a fabric leaves a free slot; count is not an array bound. */
        for(unsigned i=0;i<MATTER_FABRIC_CAPACITY;++i) {
            const Matter_Fabric_Record_T* f=&fabrics->records[i];
            if(!f->index) continue;
            if(!certificate_floor(f->noc,f->noc_size,&floor) || !certificate_floor(f->root,f->root_size,&floor) ||
                (f->icac_size && !certificate_floor(f->icac,f->icac_size,&floor))) return false;
        }
        /* Core 3.5.6.1: commissioning updates LKG even if SetUTCTime was omitted. */
        Matter_Time_Sync_Port_T port=matter_time_host_port(n->clock); Matter_Time_Sync_Sample_T current;
        if(port.sample(port.user,now,&current)!=MATTER_OK) return false;
        if(current.granularity && current.utc_us/UINT64_C(1000000)>floor) floor=current.utc_us/UINT64_C(1000000);
        if(matter_time_host_floor(n->clock,floor)!=MATTER_OK) return false;
        n->clock_fabric_revision=fabrics->revision; n->clock_fabrics_seen=true;
    }
    for(unsigned i=0;i<HOST_METER_SERVICES_COUNT;++i) {
        Matter_Result_T r=i==1?matter_meter_identification_refresh(n->utilities[i]):matter_cluster_process(n->utilities[i],now);
        if(r!=MATTER_OK && r!=MATTER_PORT_ERROR) return false;
        uint32_t version; if(matter_cluster_version(n->utilities[i],&version)!=MATTER_OK) return false;
        if(version!=n->utility_versions[i]) { n->utility_versions[i]=version; matter_server_changed(n->server); }
    }
    return true;
}
static bool meter_model(Node* n,const char* state,uint64_t now) {
    if(MATTER_HOST_BUILD_UNIX<HOST_UNIX_MATTER_EPOCH) { fputs("--meter-services requires a UTC MATTER_HOST_BUILD_UNIX definition (CMake supplies it).\n",stderr); return false; }
    n->clock=matter_time_host_new(state,MATTER_HOST_BUILD_UNIX-HOST_UNIX_MATTER_EPOCH,now); if(!n->clock) return false;
    if(matter_server_set_clock(n->server,n->clock,matter_time_host_cert,matter_time_host_timestamp)!=MATTER_OK) return false;
    uint32_t versions[HOST_METER_SERVICES_COUNT]; if(!matter_host_random(versions,sizeof(versions))) return false;
    Matter_Identify_Port_T identify={n,identify_present}; Matter_Identify_Config_T config={versions[0],0}; /* No physical presentation on x86. */
    Matter_Meter_Id_Port_T meter={n,meter_identity}; Matter_Time_Sync_Port_T time=matter_time_host_port(n->clock);
    n->utilities[0]=matter_identify_new(&identify,&config,now);
    n->utilities[1]=matter_meter_identification_new(&meter,versions[1]);
    n->utilities[2]=matter_time_sync_new(&time,n->events,versions[2],now);
    for(unsigned i=0;i<HOST_METER_SERVICES_COUNT;++i) if(!n->utilities[i] || matter_root_attach_cluster_at(n->root,i==2?0:1,n->utilities[i])!=MATTER_OK) return false;
    /* Device Library 14.9/14.6: identity-only Utility Meter, including its
     * Reference Point base. ElectricalEnergy (tariff) condition is not used. */
    if(matter_root_add_device_type_at(n->root,1,0x511,1)!=MATTER_OK ||
        matter_root_add_device_type_at(n->root,1,0x512,1)!=MATTER_OK) return false;
    return meter_process(n,now);
}
static bool three_phase_model(Node* n,uint64_t now) {
    for(unsigned i=0;i<4;++i) {
        uint32_t versions[3]; if(!matter_host_random(versions,sizeof(versions))) return false;
        static const uint32_t aggregate[]={8,9,10,17},phase[]={4,8,9,12};
        const uint32_t* ids=i?phase:aggregate;
        for(unsigned j=0;j<4;++j) {
            Matter_Epm_Measurement_T* m=&n->measurement_config[j]; memset(m,0,sizeof(*m));
            m->attribute=ids[j]; m->range_count=1; m->measured=false; /* synthetic source */
            m->ranges[0]=(Matter_Epm_Accuracy_Range_T){.min_mw=ids[j]==17?-10000:-100000000,
                .max_mw=ids[j]==17?10000:100000000,.fixed_max_mw=1,.fields=MATTER_EPM_FIXED_MAX};
        }
        Matter_Epm_Multi_Config_T config={n->measurement_config,4,versions[0],3000,i==0};
        Matter_Epm_Multi_Port_T port={&n->measurements[i],multi_sample};
        Matter_Cluster_T c=matter_epm_new_multi(&port,&config,now);
        if(!i) { n->epm=c; if(!c) return false; continue; }
        n->phase_epm[i-1]=c; n->phase_topology[i-1]=matter_power_topology_new(versions[1]);
        Matter_Root_Endpoint_Config_T ep={.endpoint=(uint16_t)(i+2),.revision=1,.device_type=0x510,.data_version=versions[2]};
        const Matter_Root_Tag_T tag={0x0a,(uint8_t)(i+1)};
        if(!c || !n->phase_topology[i-1] || matter_root_add_tagged_endpoint(n->root,&ep,&tag,1)!=MATTER_OK ||
            matter_root_set_parent(n->root,ep.endpoint,1)!=MATTER_OK ||
            matter_root_attach_cluster_at(n->root,ep.endpoint,c)!=MATTER_OK ||
            matter_root_attach_cluster_at(n->root,ep.endpoint,n->phase_topology[i-1])!=MATTER_OK) return false;
    }
    return true;
}
static bool model(Node* n,uint64_t now,const char* credentials,const char* state,uint32_t pin,const char* ota_key) {
    uint32_t versions[7]; if(!matter_host_random(versions,sizeof(versions))) return false;
    Matter_Root_Config_T* c=&n->identity;
    text(&c->vendor_name,MATTER_HOST_VENDOR_NAME); text(&c->product_name,MATTER_HOST_PRODUCT_NAME);
    text(&c->hardware_string,"x86"); text(&c->software_string,"M12b"); text(&c->unique_id,matter_discovery_record(n->discovery)->instance);
    /* Operational instance is 33 bytes, UniqueID max32. Use ephemeral host ID. */
    if(c->unique_id.size>32) c->unique_id.size=32;
    c->vendor_id=0xfff1; c->product_id=0x8001; c->hardware_version=1; c->software_version=1; c->configuration_version=1;
    if(n->switch_enabled) c->configuration_version=2;
    if(n->three_phase) c->configuration_version=n->switch_enabled?4:3;
    if(n->source_enabled) c->configuration_version=n->switch_enabled?6:5;
    if(n->meter_services) c->configuration_version=7+(n->source_enabled?2:0)+(n->switch_enabled?1:0);
    c->configuration_version+=10; /* CSA03 changes Descriptor.DeviceTypeList. */
    c->capabilities=(Matter_Root_Capabilities_T)MATTER_HOST_CAPABILITIES;
    c->settings.location[0]='X'; c->settings.location[1]='X'; c->descriptor_version=versions[0]; c->basic_version=versions[1];
    if(credentials) {
        Matter_Server_Sim_Options_T options={.ota_public_key=ota_key,.wifi_connected=n->wifi_sim_connected};
        n->server=matter_server_new_sim(credentials,state,c,pin,now,&options); if(!n->server) return false;
        n->root=matter_server_root(n->server);
    } else { Matter_Root_Port_T rp={n,load,deny,store}; n->root=matter_root_new(&rp); }
    if(!n->root) return false;
    Matter_Root_Endpoint_Config_T ep={.endpoint=1,.revision=1,.device_type=0x510,.data_version=versions[2]};
    const Matter_Root_Tag_T tag={0x0a,1};
    if((n->three_phase?matter_root_add_tagged_endpoint(n->root,&ep,&tag,1):matter_root_add_endpoint(n->root,&ep))!=MATTER_OK) return false;
    n->topology=matter_power_topology_new(versions[2]);
    Matter_Epm_Port_T pp={n,power}; Matter_Epm_Config_T pc={.range_count=1,.measured=true,.polyphase=true,.data_version=versions[3],.max_age_ms=3000};
    pc.ranges[0]=(Matter_Epm_Accuracy_Range_T){.min_mw=-100000000,.max_mw=100000000,.percent_max=100,.fields=MATTER_EPM_PERCENT_MAX};
    if(n->three_phase) { if(!three_phase_model(n,now)) return false; }
    else n->epm=matter_epm_new(&pp,&pc,now);
    Matter_Events_Port_T ev={n,event_load,event_store}; n->events=matter_events_new(&ev);
    if(!n->events || matter_root_startup(n->root,n->events,now)!=MATTER_OK) return false;
    Matter_Eem_Port_T pe={n,energy,checkpoint_load,checkpoint_store};
    Matter_Eem_Config_T ec={.endpoint=1,.percent_max=100,.fixed_max_mwh=1,.data_version=versions[4],.max_age_ms=3000,.measured=true,.events=n->events};
    n->eem=n->three_phase?matter_eem_new_registers(&pe,&ec,now):matter_eem_new(&pe,&ec,now);
    memcpy(n->raw_base,n->checkpoint.raw_mwh,sizeof(n->raw_base));
    if(n->three_phase && !n->checkpoint.initialized) { n->raw_base[0]=INT64_C(12345678000); n->raw_base[1]=INT64_C(123450000); }
    if(n->energy_test_enabled && matter_energy_sim_init(&n->energy_sim,n->raw_base,now)!=MATTER_OK) return false;
    if(n->switch_enabled) {
        /* Explicit UI experiment; additional required plug clusters are not implemented. */
        Matter_Root_Endpoint_Config_T sw={.endpoint=2,.revision=5,.device_type=0x10a,.data_version=versions[5]};
        n->test_switch=matter_switch_sim_new(versions[6],switch_changed,n);
        if(!n->test_switch || matter_root_add_endpoint(n->root,&sw)!=MATTER_OK ||
            matter_root_attach_cluster_at(n->root,2,n->test_switch)!=MATTER_OK) return false;
    }
    if(n->source_enabled) {
        n->source_sim=calloc(1,sizeof(*n->source_sim)); if(!n->source_sim) return false;
        n->source=matter_source_sim_new(n->source_sim,c->vendor_id,versions[6],now);
        if(!n->source || matter_root_attach_cluster_at(n->root,1,n->source)!=MATTER_OK) return false;
    }
    if(n->meter_services && !meter_model(n,state,now)) return false;
    return n->topology && n->epm && n->events && n->eem &&
        matter_root_attach_cluster_at(n->root,1,n->topology)==MATTER_OK &&
        matter_root_attach_cluster_at(n->root,1,n->epm)==MATTER_OK && matter_root_attach_cluster_at(n->root,1,n->eem)==MATTER_OK;
}
static bool sample(Node* n,uint64_t now,uint64_t seconds) {
    n->power=(Matter_Epm_Sample_T){.active_mw=seconds%10<5?3600000:-1800000,.sampled_ms=now,.available=true};
    if(seconds>(uint64_t)(MATTER_EEM_LIMIT-n->raw_base[0])/1000 || seconds>(uint64_t)(MATTER_EEM_LIMIT-n->raw_base[1])/500) return false;
    n->energy=(Matter_Eem_Sample_T){.raw_mwh={n->raw_base[0]+(int64_t)(seconds*1000),n->raw_base[1]+(int64_t)(seconds*500)},
        .generation=n->checkpoint.initialized?n->checkpoint.generation:1,.sampled_ms=now,.available=true};
    if(n->three_phase) {
        n->measurements[0]=(Matter_Epm_Multi_Sample_T){.values={1234000+(int64_t)(seconds%5)*1000,250000,1500000,9500},.available=15,.sampled_ms=now};
        n->measurements[1]=(Matter_Epm_Multi_Sample_T){.values={230125,1800000+(int64_t)(seconds%5)*1000,300000,10000},.available=15,.sampled_ms=now};
        n->measurements[2]=(Matter_Epm_Multi_Sample_T){.values={231000,-750000,-100000,-4000},.available=15,.sampled_ms=now};
        n->measurements[3]=(Matter_Epm_Multi_Sample_T){.values={229500,184000,50000,1000},.available=seconds%20<15?15:0,.sampled_ms=now};
        n->power.active_mw=n->measurements[0].values[0];
        n->energy.raw_mwh[0]=n->raw_base[0]+(int64_t)(seconds*551);
        n->energy.raw_mwh[1]=n->raw_base[1]+(int64_t)(seconds*208);
    }
    if(n->energy_test_enabled) {
        if(matter_energy_sim_sample(&n->energy_sim,now)!=MATTER_OK) return false;
        n->power.active_mw=n->energy_sim.power;
        memcpy(n->energy.raw_mwh,n->energy_sim.raw,sizeof(n->energy.raw_mwh));
    }
    if(n->source) {
        matter_source_sim_sample(n->source_sim,now,seconds,n->energy.raw_mwh[0],n->energy.raw_mwh[1]);
        const Matter_Source_Snapshot_T* source=&n->source_sim->snapshot;
        if(!source->online || now-source->sampled_ms>=3000) {
            n->energy.available=false; n->power.available=false;
            for(unsigned i=0;i<4;++i) n->measurements[i].available=0;
        }
    }
    if(n->three_phase) for(unsigned i=0;i<3;++i) { bool ready; if(matter_epm_refresh(n->phase_epm[i],now,&ready)!=MATTER_OK) return false; }
    bool ready; if(matter_epm_refresh(n->epm,now,&ready)!=MATTER_OK || matter_eem_refresh(n->eem,now,&ready)!=MATTER_OK) return false;
    if(n->source) {
        if(matter_meter_source_refresh(n->source,now,&ready)!=MATTER_OK) return false;
    }
    Matter_Im_Value_T value; Matter_Cluster_Request_T q={0};
    if(matter_cluster_read(n->epm,8,&q,&value)!=MATTER_IM_SUCCESS) return false;
    uint64_t next; if(matter_events_position(n->events,&next)!=MATTER_OK) return false;
    matter_server_changed(n->server);
    printf("SAMPLE power_mW=%lld import_mWh=%lld export_mWh=%lld next_event=%llu\n",
        (long long)n->power.active_mw,(long long)n->checkpoint.total_mwh[0],(long long)n->checkpoint.total_mwh[1],(unsigned long long)next);
    return true;
}
static bool advertisements(Node* n,uint64_t now,bool stopping) {
    uint16_t discriminator=n->discriminator;
    uint8_t mode=matter_server_commissioning_mode(n->server,&discriminator);
    if(!stopping && n->server) {
        /* Observe the requested window independently of the record still being
         * withdrawn. Core 4.3.1 requires a fresh instance on each entry into
         * commissioning, even when the discriminator is reused. */
        if(mode && !n->observed_cm_mode) n->discovery_rotate=true;
        n->observed_cm_mode=mode;
    }
    if(!stopping && n->server && (n->discovery_stopping || n->cm_mode!=mode || n->advertised_discriminator!=discriminator)) {
        /* Once removal starts it must drain, including close/reopen transitions
         * which return to the old mode/discriminator before goodbye completes. */
        n->discovery_stopping=true;
        if(n->mdns) {
            (void)matter_mdns_stop(matter_mdns_windows_module(n->mdns));
            (void)matter_mdns_process(matter_mdns_windows_module(n->mdns)); (void)matter_mdns_windows_poll(n->mdns,now);
            if(matter_mdns_windows_delete(n->mdns)!=MATTER_OK) return true;
            n->mdns=NULL; matter_discovery_delete(n->discovery); n->discovery=NULL;
        }
        if(n->discovery_rotate && !matter_host_random(n->random,sizeof(n->random))) return false;
        n->discovery_rotate=false;
        n->cm_mode=mode; n->advertised_discriminator=discriminator;
        n->discovery=matter_discovery_commissionable(n->iface.mac,n->random,discriminator,mode,n->port);
        if(!n->discovery) return false;
        n->mdns=matter_mdns_windows_new(n->owner,&n->iface,matter_discovery_record(n->discovery));
        if(!n->mdns || matter_mdns_start(matter_mdns_windows_module(n->mdns))!=MATTER_OK) return false;
        n->discovery_stopping=false;
    }
    const Matter_Fabric_View_T* view=matter_server_fabrics(n->server);
    for(unsigned i=0;i<5;++i) {
        Operational* a=&n->operational[i]; const Matter_Fabric_Record_T* record=view?&view->records[i]:NULL;
        if(stopping && !a->owner) { matter_discovery_delete(a->description); memset(a,0,sizeof(*a)); continue; }
        uint8_t index=!stopping && record?record->index:0;
        if(a->owner && (a->index!=index || (index && strcmp(matter_discovery_record(a->description)->instance,record->discovery_instance)))) {
            (void)matter_stop(a->owner);
            if(a->mdns) { (void)matter_mdns_process(matter_mdns_windows_module(a->mdns)); (void)matter_mdns_windows_poll(a->mdns,now); }
            if(matter_get_state(a->owner)!=MATTER_STATE_STOPPED) continue;
            if(matter_mdns_windows_delete(a->mdns)!=MATTER_OK || matter_delete(a->owner)!=MATTER_OK) return false;
            matter_discovery_delete(a->description); memset(a,0,sizeof(*a));
        }
        if(!a->owner && index) {
            a->index=index; a->owner=matter_new(NULL); a->description=matter_discovery_operational(n->iface.mac,record->compressed_id,record->node_id,n->port);
            if(!a->owner || !a->description || matter_start(a->owner)!=MATTER_OK) return false;
            a->mdns=matter_mdns_windows_new(a->owner,&n->iface,matter_discovery_record(a->description));
            if(!a->mdns || matter_mdns_start(matter_mdns_windows_module(a->mdns))!=MATTER_OK) return false;
            printf("FABRIC index=%u instance=%s\n",index,matter_discovery_record(a->description)->instance);
        }
        if(a->mdns && (matter_mdns_process(matter_mdns_windows_module(a->mdns))==MATTER_PORT_ERROR || matter_mdns_windows_poll(a->mdns,now)==MATTER_PORT_ERROR)) return false;
    }
    return true;
}
static bool number(const char* str,unsigned long max,unsigned long* out) {
    if(!str || !*str || *str=='-') return false;
    char* end; errno=0; unsigned long n=strtoul(str,&end,10);
    if(errno || *end || n>max) return false;
    *out=n; return true;
}
static bool test_key(const char* str,uint8_t key[16]) {
    if(strlen(str)!=32) return false;
    uint8_t any=0;
    for(unsigned i=0;i<16;++i) {
        unsigned value=0;
        for(unsigned j=0;j<2;++j) {
            unsigned char c=(unsigned char)str[2*i+j]; unsigned digit;
            if(c>='0' && c<='9') digit=c-'0';
            else if(c>='a' && c<='f') digit=c-'a'+10;
            else if(c>='A' && c<='F') digit=c-'A'+10;
            else return false;
            value=value*16+digit;
        }
        key[i]=(uint8_t)value; any|=key[i];
    }
    return any!=0;
}
int main(int argc,char** argv) {
    unsigned long index=0,seconds=30,port=0,disc=3840,pin=20202021; bool operational=false;
    const char* credentials=NULL; const char* state=NULL; const char* ota_file=NULL; const char* ota_key=NULL; const char* ota_boot=NULL;
    Matter_Case_Resumption_Profile_T resumption_profile=MATTER_CASE_RESUMPTION_CHIP;
    bool chip_validity=false,test_switch=false,three_phase=false,source_registers=false,meter_services=false,wifi_sim_connected=false;
    Matter_Diagnostics_Test_Trigger_T trigger={.trigger=energy_trigger}; bool energy_test=false;
    for(int i=1;i<argc;++i) {
        if(!strcmp(argv[i],"--test-event-key")) { if(++i==argc || !test_key(argv[i],trigger.enable_key)) return 2; energy_test=true; continue; }
        if(!strcmp(argv[i],"--three-phase")) { three_phase=true; continue; }
        if(!strcmp(argv[i],"--source-registers")) { source_registers=true; continue; }
        if(!strcmp(argv[i],"--meter-services")) { meter_services=true; continue; }
        if(!strcmp(argv[i],"--test-switch")) { test_switch=true; continue; }
        if(!strcmp(argv[i],"--wifi-sim-connected")) { wifi_sim_connected=true; continue; }
        if(!strcmp(argv[i],"--certificate-validity")) {
            if(++i==argc) return 2;
            if(!strcmp(argv[i],"strict")) chip_validity=false;
            else if(!strcmp(argv[i],"chip")) chip_validity=true;
            else return 2;
            continue;
        }
        if(!strcmp(argv[i],"--ota-sim-boot")) { if(++i==argc) return 2; ota_boot=argv[i]; if(strcmp(ota_boot,"fail") && strcmp(ota_boot,"hold")) return 2; continue; }
        if(!strcmp(argv[i],"--ota-sim-key")) { if(++i==argc) return 2; ota_key=argv[i]; continue; }
        if(!strcmp(argv[i],"--ota-file")) { if(++i==argc) return 2; ota_file=argv[i]; continue; }
        if(!strcmp(argv[i],"--credentials") || !strcmp(argv[i],"--state")) {
            bool cert=!strcmp(argv[i],"--credentials"); if(++i==argc) return 2;
            if(cert) credentials=argv[i]; else state=argv[i]; continue;
        }
        if(!strcmp(argv[i],"--case-resumption-profile")) {
            if(++i==argc) return 2;
            if(!strcmp(argv[i],"spec")) resumption_profile=MATTER_CASE_RESUMPTION_SPEC;
            else if(!strcmp(argv[i],"chip")) resumption_profile=MATTER_CASE_RESUMPTION_CHIP;
            else return 2;
            continue;
        }
        if(!strcmp(argv[i],"--operational-fixture")) { operational=true; continue; }
        unsigned long* target=NULL,max=0;
        if(!strcmp(argv[i],"--interface")) { target=&index; max=UINT32_MAX; }
        else if(!strcmp(argv[i],"--seconds")) { target=&seconds; max=86400; }
        else if(!strcmp(argv[i],"--port")) { target=&port; max=65535; }
        else if(!strcmp(argv[i],"--discriminator")) { target=&disc; max=4095; }
        else if(!strcmp(argv[i],"--pin")) { target=&pin; max=99999998; }
        if(!target || ++i==argc || !number(argv[i],max,target)) {
            fprintf(stderr,"Usage: matter-node --interface IPv6Index [--seconds 30] [--port 0] [--discriminator 3840] [--credentials DIR --state FILE --pin 20202021] [--wifi-sim-connected] [--ota-file IMAGE] [--ota-sim-key RAW_PUBLIC_KEY] [--ota-sim-boot fail|hold] [--operational-fixture] [--case-resumption-profile spec|chip] [--certificate-validity strict|chip] [--test-switch] [--three-phase [--source-registers] [--meter-services]] [--test-event-key HEX32]\n"); return 2;
        }
    }
    if(source_registers && !three_phase) { fputs("--source-registers requires --three-phase\n",stderr); return 2; }
    if(wifi_sim_connected && !credentials) { fputs("--wifi-sim-connected requires --credentials\n",stderr); return 2; }
    if(meter_services && (!three_phase || !credentials)) { fputs("--meter-services requires --three-phase and --credentials\n",stderr); return 2; }
    if(energy_test && (!credentials || three_phase)) return 2; /* trigger profile remains the legacy aggregate fixture */
    if(!index || !seconds) { fprintf(stderr,"Select an interface with a preferred link-local IPv6 address; seconds=1..86400.\n"); return 2; }
    if((ota_boot && !ota_key) || (ota_key && !ota_file) || (credentials && (!state || operational || !pin)) || (!credentials && (state || ota_file || ota_key || chip_validity))) return 2;
    setvbuf(stdout,NULL,_IONBF,0); signal(SIGINT,stop_signal); signal(SIGTERM,stop_signal);
    Node* n=calloc(1,sizeof(*n)); if(!n) return 1;
    n->switch_enabled=test_switch; n->three_phase=three_phase;
    n->wifi_sim_connected=wifi_sim_connected;
    n->source_enabled=source_registers;
    n->meter_services=meter_services;
    n->energy_test_enabled=energy_test; trigger.user=n;
    int result=1; bool started=false; uint64_t start=matter_host_now(),now=start;
    if(matter_mdns_windows_interface((uint32_t)index,&n->iface)!=MATTER_OK) { fprintf(stderr,"Interface has no supported IPv6/MAC/multicast binding.\n"); goto done; }
    n->owner=matter_new(NULL); if(!n->owner || matter_start(n->owner)!=MATTER_OK) goto done;
    started=true;
    /* Receive on every advertised IPv6 address; the port enforces iface via pktinfo. */
    Matter_Udp_Address_T bind={.port=(uint16_t)port};
    Matter_Udp_Listener_T listener={.user=n,.received=received,.sent=sent};
    n->udp=matter_udp_windows_new(n->owner,&bind,(uint32_t)index,&listener);
    if(!n->udp || matter_udp_start(matter_udp_windows_module(n->udp))!=MATTER_OK || matter_udp_windows_local(n->udp,&bind)!=MATTER_OK) goto done;
    if(!matter_host_random(n->random,8)) goto done;
    n->port=bind.port; n->discriminator=(uint16_t)disc;
    /* Explicit fixture identity from Core4.3.2 examples, never a commissioned fabric. */
    static const uint8_t fabric[]={0x87,0xe1,0xb0,4,0xe2,0x35,0xa1,0x30};
    n->discovery=operational?matter_discovery_operational(n->iface.mac,fabric,1,bind.port):
        matter_discovery_commissionable(n->iface.mac,n->random,(uint16_t)disc,0,bind.port);
    if(!n->discovery || !model(n,now,credentials,state,(uint32_t)pin,ota_key)) goto done;
    if(n->server) {
        if(energy_test && matter_server_set_test_trigger(n->server,&trigger)!=MATTER_OK) goto done;
        if(ota_file && matter_server_set_ota_file(n->server,ota_file)!=MATTER_OK) goto done;
        if(matter_server_set_resumption(n->server,resumption_profile)!=MATTER_OK) goto done;
        if(matter_server_set_certificate_validity(n->server,chip_validity)!=MATTER_OK) goto done;
        printf("CASE resumption-profile=%s cache=volatile\n",resumption_profile==MATTER_CASE_RESUMPTION_CHIP?"chip":"spec");
        printf("CERTIFICATE validity=%s attestation=leaf-not-before\n",chip_validity?"chip":"strict");
        n->resolver=matter_resolver_windows_new(&n->iface); if(!n->resolver) goto done;
        Matter_Resolver_Port_T resolver=matter_resolver_windows_port(n->resolver);
        if(matter_server_set_resolver(n->server,&resolver)!=MATTER_OK) goto done;
        Matter_Udp_Path_T outbound={.local=bind,.interface_id=(uint32_t)index};
        memcpy(outbound.local.address,n->iface.ipv6,16);
        if(matter_server_set_outbound(n->server,&outbound)!=MATTER_OK) goto done;
        if(matter_server_start(n->server,n->owner,matter_udp_windows_module(n->udp),n->events)!=MATTER_OK) goto done;
        n->advertised_discriminator=(uint16_t)disc; n->cm_mode=matter_server_commissioning_mode(n->server,&n->advertised_discriminator);
        n->observed_cm_mode=n->cm_mode; /* Boot already selected the initial instance. */
        matter_discovery_delete(n->discovery);
        n->discovery=matter_discovery_commissionable(n->iface.mac,n->random,n->advertised_discriminator,n->cm_mode,bind.port);
        if(!n->discovery) goto done;
    }
    n->mdns=matter_mdns_windows_new(n->owner,&n->iface,matter_discovery_record(n->discovery));
    if(!n->mdns || matter_mdns_start(matter_mdns_windows_module(n->mdns))!=MATTER_OK) goto done;
    if(matter_server_ota_trial(n->server) && ota_boot) {
        puts("OTA_SIM_TRIAL_WAIT");
        if(!strcmp(ota_boot,"hold")) while(!interrupted && matter_host_now()-start<seconds*1000) matter_host_sleep(10);
        puts("OTA_SIM_BOOT_FAILED"); result=0; goto done;
    }
    if(matter_server_ota_boot_ready(n->server)!=MATTER_OK) goto done;
    const Matter_Mdns_Record_T* record=matter_discovery_record(n->discovery);
    printf("NODE instance=%s service=%s.%s.local. host=%s.local. port=%u interface=%lu mode=%s\n",
        record->instance,record->service,record->protocol,record->hostname,bind.port,index,operational?"operational-fixture":n->cm_mode?"CM1":"CM0");
    printf("SIMULATION %s.\n",n->server?"PASE/CASE/IM, durable fabrics/EEM/event high-water; simulated source resumes at saved raw; development attestation":"discovery only, closed commissioning, volatile EPM/EEM");
    if(n->three_phase) puts("THREE_PHASE aggregate=1 phases=3,4,5 energy=physical-registers phase-energy=absent L3-unavailable=15..19s-of-20s synthetic-only");
    if(n->source) printf("SOURCE_REGISTERS endpoint=1 cluster=%08lx channels=%lu schema=1 synthetic-only\n",(unsigned long)matter_cluster_id(n->source),(unsigned long)n->source_sim->count);
    if(n->switch_enabled) puts("TEST_SWITCH endpoint=2 on=0 profile=incomplete-ui-demo state=volatile");
    if(energy_test) puts("ENERGY_TEST enabled=1 laboratory-only mode=normal key=not-persisted measurements=volatile");
    bool announced=false; uint64_t next_sample=now;
    while(!interrupted && (now=matter_host_now())-start<seconds*1000) {
        if(!matter_server_reset_requested(n->server) && now>=next_sample) { if(!sample(n,now,(now-start)/1000)) goto done; next_sample=now+1000; }
        Matter_Result_T r=matter_udp_windows_poll(n->udp);
        if(r!=MATTER_OK && r!=MATTER_WOULD_BLOCK && r!=MATTER_LIMIT_REACHED && r!=MATTER_INVALID_ARGUMENT) goto done;
        if(n->resolver) (void)matter_resolver_windows_poll(n->resolver,now);
        if(!matter_server_reset_requested(n->server) && !meter_process(n,now)) { fputs("Meter services process failed\n",stderr); goto done; }
        r=matter_server_process(n->server,now); if(r!=MATTER_OK && r!=MATTER_PENDING) { fprintf(stderr,"Server process failed: %d\n",r); goto done; }
        if(matter_server_ota_reboot_requested(n->server)) { puts("OTA_SIM_REBOOT"); result=0; goto done; }
        if(matter_server_reset_ready(n->server)) { puts("RESET last fabric removed; commissioned state erased, restart for a fresh instance."); result=0; goto done; }
        if(!advertisements(n,now,false)) { fprintf(stderr,"Discovery state transition failed\n"); goto done; }
        if(matter_mdns_process(matter_mdns_windows_module(n->mdns))==MATTER_PORT_ERROR ||
            matter_mdns_windows_poll(n->mdns,now)==MATTER_PORT_ERROR) { fprintf(stderr,"mDNS publication failed (I/O or name conflict); stop and retry with a fresh instance.\n"); goto done; }
        if(!announced && matter_mdns_is_published(matter_mdns_windows_module(n->mdns))) { puts("PUBLISHED"); announced=true; }
        matter_host_sleep(10); /* This executable owns scheduling; the library never sleeps. */
    }
    result=announced?0:1;
done:
    if(n->server) {
        while(matter_server_stop(n->server,matter_host_now())==MATTER_PENDING) {
            if(n->resolver) (void)matter_resolver_windows_poll(n->resolver,matter_host_now());
            (void)matter_udp_windows_poll(n->udp); (void)matter_server_process(n->server,matter_host_now()); matter_host_sleep(1);
        }
    }
    for(;;) {
        (void)advertisements(n,matter_host_now(),true); bool pending=false;
        for(unsigned i=0;i<5;++i) pending|=n->operational[i].owner!=NULL;
        if(!pending) break;
        matter_host_sleep(10);
    }
    if(started) {
        (void)matter_stop(n->owner);
        while(matter_get_state(n->owner)==MATTER_STATE_STOPPING) {
            if(n->mdns) {
                (void)matter_mdns_process(matter_mdns_windows_module(n->mdns));
                (void)matter_mdns_windows_poll(n->mdns,matter_host_now());
            }
            if(n->udp) { (void)matter_udp_windows_poll(n->udp); (void)matter_udp_process(matter_udp_windows_module(n->udp)); }
            matter_host_sleep(10);
        }
    }
    if(matter_mdns_windows_delete(n->mdns)!=MATTER_OK) result=1;
    if(matter_udp_windows_delete(n->udp)!=MATTER_OK) result=1;
    if(n->server) { if(matter_server_delete(n->server)!=MATTER_OK) result=1; }
    else if(matter_root_delete(n->root)!=MATTER_OK) result=1;
    if(matter_resolver_windows_delete(n->resolver)!=MATTER_OK) result=1;
    if(matter_cluster_delete(n->eem)!=MATTER_OK) result=1;
    if(n->test_switch && matter_cluster_delete(n->test_switch)!=MATTER_OK) result=1;
    if(n->source && matter_cluster_delete(n->source)!=MATTER_OK) result=1;
    free(n->source_sim);
    for(unsigned i=0;i<HOST_METER_SERVICES_COUNT;++i) if(n->utilities[i] && matter_cluster_delete(n->utilities[i])!=MATTER_OK) result=1;
    if(matter_time_host_delete(n->clock)!=MATTER_OK) result=1;
    for(unsigned i=0;i<3;++i) {
        if(n->phase_epm[i] && matter_cluster_delete(n->phase_epm[i])!=MATTER_OK) result=1;
        if(n->phase_topology[i] && matter_cluster_delete(n->phase_topology[i])!=MATTER_OK) result=1;
    }
    if(matter_cluster_delete(n->epm)!=MATTER_OK) result=1;
    if(matter_cluster_delete(n->topology)!=MATTER_OK) result=1;
    if(matter_events_delete(n->events)!=MATTER_OK) result=1;
    if(matter_delete(n->owner)!=MATTER_OK) result=1;
    matter_discovery_delete(n->discovery); printf("STOPPED rx_packets=%llu result=%d\n",(unsigned long long)n->rx_packets,result);
    free(n); return result;
}

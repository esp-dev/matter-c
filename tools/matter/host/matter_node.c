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
#include "matter_gui_control.h"
#include "matter_switch_sim.h"
#include "matter_energy_sim.h"
#include "matter_store_file.h"
#include "codec/matter_tlv_writer.h"
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
#define HOST_PLUG_ENDPOINT 2
#define HOST_PLUG_POWER_MW UINT64_C(600000)
#define HOST_PLUG_MW_MS_PER_MWH UINT64_C(3600000)
#define HOST_PLUG_STATE_BYTES 32
#define HOST_POWER_ONLY_ENDPOINT 6
#define HOST_POWER_SENSOR_ONLY_ENDPOINT 1
#define HOST_POWER_ONLY_MW INT64_C(123000)
#define HOST_SENSOR_IMPORTED_MWH INT64_C(12345000)
#define HOST_SENSOR_EXPORTED_MWH INT64_C(2345000)
#define HOST_EXTENDED_DISCOVERY_SECONDS 900
#define HOST_PAIRING_HINT_POWER_CYCLE (UINT32_C(1)<<0)
#define HOST_PAIRING_HINT_ADMINISTRATOR (UINT32_C(1)<<2)

typedef struct { Matter_T owner; Matter_Mdns_Windows_T mdns; Matter_Discovery_T description; uint8_t index; } Operational;

typedef struct {
    Matter_T owner; Matter_Root_T root; Matter_Cluster_T topology,epm,eem,test_switch;
    bool switch_enabled,three_phase,wifi_sim_connected; uint16_t subscriptions_per_fabric;
    bool source_enabled; Matter_Cluster_T source;
    Matter_Source_Sim_T* source_sim;
    bool meter_services,clock_fabrics_seen; Matter_Time_Host_T clock;
    Matter_Cluster_T utilities[HOST_METER_SERVICES_COUNT]; uint32_t utility_versions[HOST_METER_SERVICES_COUNT],clock_fabric_revision;
    bool meter_id_test_active; /* Volatile; cleared with the Node on restart/reset. */
    Matter_Cluster_T phase_epm[3],phase_topology[3];
    Matter_Energy_Sim_T phase_energy_sim[3]; /* Independent, volatile PIXIT inputs. */
    Matter_Epm_Multi_Sample_T measurements[4];
    Matter_Epm_Measurement_T measurement_config[4];
    bool energy_test_enabled; Matter_Energy_Sim_T energy_sim;
    uint64_t boot_ms; /* Host clock origin of this simulated Node, not OS boot. */
    Matter_Events_T events; Matter_Udp_Windows_T udp; Matter_Mdns_Windows_T mdns;
    Matter_Discovery_T discovery; Matter_Mdns_Windows_Interface_T iface; uint8_t discovery_mac[6];
    Matter_Resolver_Windows_T resolver;
    Matter_Root_Config_T identity; Matter_Epm_Sample_T power; Matter_Eem_Sample_T energy;
    /* RAM cache; commissioned mode commits through the server store. */
    Matter_Eem_Checkpoint_T checkpoint; int64_t raw_base[2]; uint64_t high,rx_packets;
    Matter_Cluster_T plug_power,plug_energy,plug_topology;
    Matter_Energy_Sim_T plug_sim; Matter_Eem_Checkpoint_T plug_checkpoint;
    Matter_Store_File_T plug_file; Matter_Store_Blob_Port_T plug_blob;
    uint8_t plug_bytes[HOST_PLUG_STATE_BYTES]; bool plug_on,plug_fault,plug_ready;
    bool power_only_enabled,power_sensor_only,sensor_energy; Matter_Cluster_T power_only_epm,power_only_topology;
    Matter_Epm_Sample_T power_only_sample;
    bool gui_enabled,ota_control; Matter_Gui_Control_T gui;
    Matter_Server_T server; Operational operational[5]; uint16_t port,discriminator,advertised_discriminator; uint8_t random[8],cm_mode;
    uint8_t observed_cm_mode; bool discovery_stopping,discovery_rotate;
    uint64_t extended_duration_ms,extended_since_ms; bool extended_started;
} Node;
static uint64_t node_now(const Node* n) { return matter_host_now()-n->boot_ms; }
static Matter_Result_T network_snapshot(void* u,Matter_Diagnostics_Interface_T* out,size_t capacity,size_t* count) {
    Node* n=u; *count=1; if(!capacity) return MATTER_LIMIT_REACHED;
    Matter_Diagnostics_Interface_T* a=&out[0]; memset(a,0,sizeof(*a));
    int size=snprintf((char*)a->name,sizeof(a->name),"host-interface-%lu",(unsigned long)n->iface.index);
    if(size<0 || (size_t)size>=sizeof(a->name)) return MATTER_PORT_ERROR;
    a->name_size=(uint8_t)size; a->reachable4=a->reachable6=-1;
    /* The shared I/O snapshot does not expose the OS link type: leave Type
     * Unspecified rather than describing the simulated radio as this NIC. */
    memcpy(a->hardware+2,n->iface.mac,sizeof(n->iface.mac));
    for(unsigned i=0;i<n->iface.address_count;++i) {
        const Matter_Mdns_Host_Address_T* address=&n->iface.addresses[i];
        if(address->ipv4) {
            if(a->ipv4_count>=sizeof(a->ipv4)/sizeof(a->ipv4[0])) return MATTER_LIMIT_REACHED;
            memcpy(a->ipv4[a->ipv4_count++],address->bytes,4);
        } else {
            if(a->ipv6_count>=sizeof(a->ipv6)/sizeof(a->ipv6[0])) return MATTER_LIMIT_REACHED;
            memcpy(a->ipv6[a->ipv6_count++],address->bytes,16);
        }
    }
    if(!n->iface.address_count) {
        memcpy(a->ipv6[a->ipv6_count++],n->iface.ipv6,16);
        if(n->iface.has_ipv4) memcpy(a->ipv4[a->ipv4_count++],n->iface.ipv4,4);
    }
    for(unsigned i=0;i<sizeof(n->operational)/sizeof(n->operational[0]);++i)
        if(n->operational[i].mdns && matter_mdns_is_published(matter_mdns_windows_module(n->operational[i].mdns))) a->operational=true;
    return MATTER_OK;
}
static volatile sig_atomic_t interrupted;
static void stop_signal(int sig) { (void)sig; interrupted=1; }
static Matter_Result_T load(void* u,Matter_Root_Config_T* out) { *out=((Node*)u)->identity; return MATTER_OK; }
static Matter_Result_T store(void* u,const Matter_Root_Settings_T* in) { ((Node*)u)->identity.settings=*in; return MATTER_OK; }
static uint8_t deny(void* u,Matter_Exchange_Session_T s,const Matter_Im_Path_T* p,Matter_Im_Privilege_T v) {
    (void)u; (void)s; (void)p; (void)v; return MATTER_IM_UNSUPPORTED_ACCESS;
}
static Matter_Result_T power(void* u,Matter_Epm_Sample_T* out) { *out=((Node*)u)->power; return MATTER_OK; }
static Matter_Result_T energy(void* u,Matter_Eem_Sample_T* out) { *out=((Node*)u)->energy; return MATTER_OK; }
static Matter_Result_T power_only(void* u,Matter_Epm_Sample_T* out) { *out=((Node*)u)->power_only_sample; return MATTER_OK; }
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
    Node* n=u;
    /* Integrate the OLD state up to this transition, including sub-second use. */
    if(matter_energy_sim_sample(&n->plug_sim,node_now(n))!=MATTER_OK) n->plug_fault=true;
    n->plug_sim.normal_mw[0]=on?HOST_PLUG_POWER_MW:0; n->plug_on=on;
    printf("TEST_SWITCH endpoint=2 on=%u\n",on?1:0); matter_server_changed(n->server);
}
static Matter_Result_T plug_power(void* u,Matter_Epm_Sample_T* out) {
    Node* n=u; *out=(Matter_Epm_Sample_T){.active_mw=n->plug_on?(int64_t)HOST_PLUG_POWER_MW:0,
        .sampled_ms=n->plug_sim.last,.available=!n->plug_fault}; return MATTER_OK;
}
static Matter_Result_T plug_energy(void* u,Matter_Eem_Sample_T* out) {
    Node* n=u; *out=(Matter_Eem_Sample_T){.raw_mwh={n->plug_sim.raw[0],0},.generation=1,
        .sampled_ms=n->plug_sim.last,.available=!n->plug_fault}; return MATTER_OK;
}
static Matter_Result_T plug_load(void* u,Matter_Eem_Checkpoint_T* out) { *out=((Node*)u)->plug_checkpoint; return MATTER_OK; }
static Matter_Result_T plug_store(void* u,const Matter_Eem_Checkpoint_T* in) {
    Node* n=u;
    if(n->plug_file) {
        Matter_Tlv_Writer_T w; size_t size;
        if(matter_tlv_writer_init(&w,n->plug_bytes,sizeof(n->plug_bytes),1)!=MATTER_TLV_OK) return MATTER_PORT_ERROR;
        Matter_Tlv_Element_T e={.type=MATTER_TLV_STRUCTURE};
        if(matter_tlv_write(&w,&e,0)!=MATTER_TLV_OK) return MATTER_PORT_ERROR;
        const uint64_t fields[]={1,(uint64_t)in->raw_mwh[0],n->plug_sim.remainder[0]};
        for(unsigned i=0;i<3;++i) {
            e=(Matter_Tlv_Element_T){.type=MATTER_TLV_UNSIGNED,.tag={.control=1,.number=i},.unsigned_value=fields[i]};
            if(matter_tlv_write(&w,&e,0)!=MATTER_TLV_OK) return MATTER_PORT_ERROR;
        }
        e=(Matter_Tlv_Element_T){.type=MATTER_TLV_END};
        if(matter_tlv_write(&w,&e,0)!=MATTER_TLV_OK || matter_tlv_writer_finish(&w,&size)!=MATTER_TLV_OK) return MATTER_PORT_ERROR;
        Matter_Result_T r=n->plug_blob.replace(n->plug_blob.user,n->plug_bytes,size); if(r!=MATTER_OK) return r;
    }
    n->plug_checkpoint=*in; return MATTER_OK;
}
static bool plug_model(Node* n,const char* state,uint64_t now) {
    uint64_t remainder=0;
    if(state) {
        static const char suffix[]=".plug-energy"; size_t length=strlen(state);
        if(length>SIZE_MAX-sizeof(suffix)) return false;
        char* path=malloc(length+sizeof(suffix)); if(!path) return false;
        memcpy(path,state,length); memcpy(path+length,suffix,sizeof(suffix));
        n->plug_file=matter_store_file_new(path); free(path); if(!n->plug_file) return false;
        n->plug_blob=matter_store_file_port(n->plug_file); size_t size=0;
        Matter_Result_T r=n->plug_blob.read(n->plug_blob.user,n->plug_bytes,sizeof(n->plug_bytes),&size);
        if(r==MATTER_OK) {
            Matter_Tlv_Reader_T reader; Matter_Tlv_Element_T e; uint64_t fields[3]={0}; unsigned seen=0;
            if(!size || n->plug_bytes[0]!=0x15 || matter_tlv_init(&reader,n->plug_bytes,size,1)!=MATTER_TLV_OK ||
                matter_tlv_next(&reader,&e)!=MATTER_TLV_OK) return false;
            while(matter_tlv_next(&reader,&e)==MATTER_TLV_OK && e.type!=MATTER_TLV_END) {
                if(e.type!=MATTER_TLV_UNSIGNED || e.tag.control!=1 || e.tag.number>2 || (seen&(1u<<e.tag.number))) return false;
                seen|=1u<<e.tag.number; fields[e.tag.number]=e.unsigned_value;
            }
            if(seen!=7 || e.type!=MATTER_TLV_END || matter_tlv_next(&reader,&e)!=MATTER_TLV_DONE || fields[0]!=1 ||
                fields[1]>(uint64_t)MATTER_EEM_LIMIT || fields[2]>=HOST_PLUG_MW_MS_PER_MWH) return false;
            n->plug_checkpoint=(Matter_Eem_Checkpoint_T){.generation=1,.raw_mwh={(int64_t)fields[1],0},
                .total_mwh={(int64_t)fields[1],0},.initialized=true,.registers=true,.register_mask=3}; remainder=fields[2];
        } else if(r!=MATTER_OFFLINE) return false; /* Corrupt/unreadable state never silently resets. */
    }
    const uint64_t idle[]={0,0};
    if(matter_energy_sim_init_rates(&n->plug_sim,n->plug_checkpoint.raw_mwh,idle,now)!=MATTER_OK) return false;
    n->plug_sim.remainder[0]=remainder;
    uint32_t versions[3]; if(!matter_host_random(versions,sizeof(versions))) return false;
    Matter_Epm_Port_T pp={n,plug_power};
    Matter_Epm_Config_T pc={.range_count=1,.measured=false,.data_version=versions[0],.max_age_ms=3000};
    pc.ranges[0]=(Matter_Epm_Accuracy_Range_T){.min_mw=0,.max_mw=(int64_t)HOST_PLUG_POWER_MW,.fixed_max_mw=1,.fields=MATTER_EPM_FIXED_MAX};
    n->plug_power=matter_epm_new(&pp,&pc,now);
    Matter_Eem_Port_T pe={n,plug_energy,plug_load,plug_store};
    Matter_Eem_Config_T ec={.endpoint=HOST_PLUG_ENDPOINT,.fixed_max_mwh=1,.data_version=versions[1],.max_age_ms=3000,.events=n->events};
    n->plug_energy=matter_eem_new_registers(&pe,&ec,now);
    n->plug_topology=matter_power_topology_new(versions[2]);
    n->plug_ready=n->plug_power && n->plug_energy && n->plug_topology &&
        matter_root_add_device_type_at(n->root,HOST_PLUG_ENDPOINT,0x510,1)==MATTER_OK &&
        matter_root_attach_cluster_at(n->root,HOST_PLUG_ENDPOINT,n->plug_power)==MATTER_OK &&
        matter_root_attach_cluster_at(n->root,HOST_PLUG_ENDPOINT,n->plug_energy)==MATTER_OK &&
        matter_root_attach_cluster_at(n->root,HOST_PLUG_ENDPOINT,n->plug_topology)==MATTER_OK;
    return n->plug_ready;
}
static uint8_t test_event_trigger(void* u,uint64_t event) {
    Node* n=u;
    if(matter_server_reset_requested(n->server)) return MATTER_IM_FAILURE;
    /* Core 11.12.7.1: unknown EventTrigger -> INVALID_COMMAND; effects never persist. */
    if((event>>48)==UINT64_C(0x0b06)) {
        if(!n->meter_services) return MATTER_IM_INVALID_COMMAND;
        /* TH embeds the target endpoint in bits32..47 (MatterBaseTest
         * _update_legacy_test_event_triggers); PIXIT values are the low 32 bits. */
        uint64_t trigger_id=event&~(UINT64_C(0xffff)<<32);
        if(trigger_id==UINT64_C(0x0B06000000000000) || trigger_id==UINT64_C(0x0B06000000000001)) {
            bool set=trigger_id==UINT64_C(0x0B06000000000000);
            /* Repeating either trigger is a successful no-op; only a real change reports. */
            if(n->meter_id_test_active!=set) { n->meter_id_test_active=set; printf("MTRID_TEST event=%016llx action=%s\n",(unsigned long long)event,set?"attributes-value-set":"clear"); }
            return MATTER_IM_SUCCESS;
        }
        printf("MTRID_TEST event=%016llx status=%u\n",(unsigned long long)event,(unsigned)MATTER_IM_INVALID_COMMAND);
        return MATTER_IM_INVALID_COMMAND;
    }
    if(!n->energy_test_enabled) return MATTER_IM_INVALID_COMMAND;
    unsigned endpoint=(unsigned)((event>>32)&0xffff);
    Matter_Energy_Sim_T* target=&n->energy_sim;
    if(n->three_phase && endpoint>=3 && endpoint<=5) target=&n->phase_energy_sim[endpoint-3];
    else if(endpoint>1) return MATTER_IM_INVALID_COMMAND;
    /* Validate the target before normalizing the legacy energy helper's event. */
    uint8_t status=matter_energy_sim_trigger(target,event&~(UINT64_C(0xffff)<<32),node_now(n));
    printf("ENERGY_TEST event=%016llx status=%u\n",(unsigned long long)event,status); return status;
}
static Matter_Result_T multi_sample(void* u,Matter_Epm_Multi_Sample_T* out) { *out=*(Matter_Epm_Multi_Sample_T*)u; return MATTER_OK; }
static void identify_present(void* u,uint16_t seconds) { (void)u; printf("IDENTIFY seconds=%u presentation=simulation\n",seconds); }
static Matter_Result_T meter_identity(void* u,Matter_Meter_Id_Snapshot_T* out) {
    Node* n=u;
    /* CSA17 PIXIT.MTRID fake data covers every supported attribute 0..3. */
    if(n->meter_id_test_active) {
        static const char delivery[]="CSA17-POD",serial[]="CSA17-00000042",protocol[]="9.9";
        *out=(Matter_Meter_Id_Snapshot_T){.type_known=true,.meter_type=0}; /* Utility: differs from base Generic. */
        out->delivery.known=true; out->delivery.size=sizeof(delivery)-1; memcpy(out->delivery.data,delivery,sizeof(delivery)-1);
        out->serial.known=true; out->serial.size=sizeof(serial)-1; memcpy(out->serial.data,serial,sizeof(serial)-1);
        out->protocol.known=true; out->protocol.size=sizeof(protocol)-1; memcpy(out->protocol.data,protocol,sizeof(protocol)-1);
        return MATTER_OK;
    }
    *out=(Matter_Meter_Id_Snapshot_T){.type_known=true,.meter_type=2}; /* Generic synthetic meter; delivery unknown. */
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
static bool power_only_model(Node* n,uint64_t now,uint16_t endpoint) {
    uint32_t versions[3]; if(!matter_host_random(versions,sizeof(versions))) return false;
    Matter_Root_Endpoint_Config_T sensor={.endpoint=endpoint,.revision=1,.device_type=0x510,.data_version=versions[0]};
    Matter_Epm_Port_T port={n,power_only};
    Matter_Epm_Config_T config={.range_count=1,.measured=false,.data_version=versions[1],.max_age_ms=3000};
    config.ranges[0]=(Matter_Epm_Accuracy_Range_T){.min_mw=n->gui_enabled?-MATTER_GUI_POWER_LIMIT_MW:0,.max_mw=n->gui_enabled?MATTER_GUI_POWER_LIMIT_MW:HOST_POWER_ONLY_MW,.fixed_max_mw=1,.fields=MATTER_EPM_FIXED_MAX};
    n->power_only_epm=matter_epm_new(&port,&config,now);
    n->power_only_topology=matter_power_topology_new(versions[2]);
    return n->power_only_epm && n->power_only_topology && matter_root_add_endpoint(n->root,&sensor)==MATTER_OK &&
        matter_root_attach_cluster_at(n->root,endpoint,n->power_only_epm)==MATTER_OK &&
        matter_root_attach_cluster_at(n->root,endpoint,n->power_only_topology)==MATTER_OK;
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
    if(n->switch_enabled) c->configuration_version+=100; /* Metering on the existing plug endpoint. */
    if(n->power_only_enabled) c->configuration_version+=200; /* Additional independent sensor. */
    if(n->power_sensor_only) c->configuration_version+=400; /* Root and one power sensor only. */
    if(n->sensor_energy) c->configuration_version+=800; /* Add cumulative import/export to that sensor. */
    c->capabilities=(Matter_Root_Capabilities_T)MATTER_HOST_CAPABILITIES;
    c->capabilities.subscriptions=n->subscriptions_per_fabric;
    c->settings.location[0]='X'; c->settings.location[1]='X'; c->descriptor_version=versions[0]; c->basic_version=versions[1];
    if(credentials) {
        Matter_Server_Sim_Options_T options={.ota_public_key=ota_key,.wifi_connected=n->wifi_sim_connected,.network={n,network_snapshot},
            .unique_id=n->gui_enabled?&c->unique_id:NULL};
        n->server=matter_server_new_sim(credentials,state,c,pin,now,&options); if(!n->server) return false;
        n->root=matter_server_root(n->server);
    } else { Matter_Root_Port_T rp={n,load,deny,store}; n->root=matter_root_new(&rp); }
    if(!n->root) return false;
    if(n->power_sensor_only) {
        Matter_Events_Port_T events={n,event_load,event_store}; n->events=matter_events_new(&events);
        if(!n->events || matter_root_startup(n->root,n->events,now)!=MATTER_OK ||
            !power_only_model(n,now,HOST_POWER_SENSOR_ONLY_ENDPOINT)) return false;
        if(!n->sensor_energy) return true;
        Matter_Eem_Port_T port={n,energy,checkpoint_load,checkpoint_store};
        Matter_Eem_Config_T config={.endpoint=HOST_POWER_SENSOR_ONLY_ENDPOINT,.fixed_max_mwh=1,.data_version=versions[4],.max_age_ms=3000,.events=n->events};
        n->eem=matter_eem_new_registers(&port,&config,now); if(!n->eem) return false;
        const int64_t initial[]={HOST_SENSOR_IMPORTED_MWH,HOST_SENSOR_EXPORTED_MWH};
        const uint64_t rates[]={(uint64_t)HOST_POWER_ONLY_MW,0};
        if(matter_energy_sim_init_rates(&n->energy_sim,n->checkpoint.initialized?n->checkpoint.raw_mwh:initial,rates,now)!=MATTER_OK) return false;
        return matter_root_attach_cluster_at(n->root,HOST_POWER_SENSOR_ONLY_ENDPOINT,n->eem)==MATTER_OK;
    }
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
    if(n->energy_test_enabled) {
        if(n->three_phase) {
            const uint64_t rates[]={UINT64_C(551)*3600,UINT64_C(208)*3600},idle[]={0,0};
            const int64_t zero[]={0,0};
            if(matter_energy_sim_init_rates(&n->energy_sim,n->raw_base,rates,now)!=MATTER_OK) return false;
            for(unsigned i=0;i<3;++i) if(matter_energy_sim_init_rates(&n->phase_energy_sim[i],zero,idle,now)!=MATTER_OK) return false;
        } else if(matter_energy_sim_init(&n->energy_sim,n->raw_base,now)!=MATTER_OK) return false;
    }
    if(n->switch_enabled) {
        /* Explicit UI experiment; mandatory Groups/Scenes/Lighting remain absent. */
        Matter_Root_Endpoint_Config_T sw={.endpoint=2,.revision=5,.device_type=0x10a,.data_version=versions[5]};
        n->test_switch=matter_switch_sim_new(versions[6],switch_changed,n);
        if(!n->test_switch || matter_root_add_endpoint(n->root,&sw)!=MATTER_OK ||
            matter_root_attach_cluster_at(n->root,2,n->test_switch)!=MATTER_OK || !plug_model(n,state,now)) return false;
    }
    if(n->power_only_enabled && !power_only_model(n,now,HOST_POWER_ONLY_ENDPOINT)) return false;
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
    if(n->power_only_enabled) {
        n->power_only_sample=(Matter_Epm_Sample_T){.active_mw=n->gui_enabled?n->gui.power_mw:HOST_POWER_ONLY_MW,.sampled_ms=now,.available=true};
        bool ready; if(matter_epm_refresh(n->power_only_epm,now,&ready)!=MATTER_OK) return false;
    }
    if(n->power_sensor_only) {
        if(n->sensor_energy) {
            if(matter_energy_sim_sample(&n->energy_sim,now)!=MATTER_OK) return false;
            n->energy=(Matter_Eem_Sample_T){.raw_mwh={n->energy_sim.raw[0],n->energy_sim.raw[1]},
                .generation=n->checkpoint.initialized?n->checkpoint.generation:1,.sampled_ms=now,.available=true};
            bool ready; if(matter_eem_refresh(n->eem,now,&ready)!=MATTER_OK) return false;
        }
        matter_server_changed(n->server); return true;
    }
    if(n->switch_enabled) {
        bool ready;
        if(n->plug_fault || matter_energy_sim_sample(&n->plug_sim,now)!=MATTER_OK ||
            matter_epm_refresh(n->plug_power,now,&ready)!=MATTER_OK || matter_eem_refresh(n->plug_energy,now,&ready)!=MATTER_OK) return false;
    }
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
        if(!n->three_phase) n->power.active_mw=n->energy_sim.power;
        memcpy(n->energy.raw_mwh,n->energy_sim.raw,sizeof(n->energy.raw_mwh));
        if(n->three_phase) for(unsigned i=0;i<3;++i)
            if(matter_energy_sim_sample(&n->phase_energy_sim[i],now)!=MATTER_OK) return false;
    }
    if(n->source) {
        matter_source_sim_sample(n->source_sim,now,seconds,n->energy.raw_mwh[0],n->energy.raw_mwh[1]);
        const Matter_Source_Snapshot_T* source=&n->source_sim->snapshot;
        if(!source->online || now-source->sampled_ms>=3000) {
            n->energy.available=false; n->power.available=false;
            for(unsigned i=0;i<4;++i) n->measurements[i].available=0;
        }
    }
    if(n->three_phase && n->energy_test_enabled) {
        /* Targeted fake readings override the normal source's intentional outages.
         * STOP resumes that source; cumulative registers never roll back or reset.
         * Phase PIXITs inject only that EPM endpoint, not fabricated phase EEM. */
        if(n->energy_sim.mode) {
            int64_t p=n->energy_sim.power;
            n->measurements[0].values[0]=p; n->measurements[0].values[1]=0;
            n->measurements[0].values[2]=p<0?-p:p; n->measurements[0].values[3]=p<0?-10000:10000;
            n->measurements[0].available=15; n->power.active_mw=p; n->power.available=true; n->energy.available=true;
        }
        for(unsigned i=0;i<3;++i) if(n->phase_energy_sim[i].mode) {
            Matter_Energy_Sim_T* s=&n->phase_energy_sim[i]; Matter_Epm_Multi_Sample_T* m=&n->measurements[i+1];
            int64_t voltage=230000+(int64_t)(((now-s->epoch)/2000)%11)*10,p=s->power;
            m->values[0]=voltage; m->values[1]=p; m->values[2]=0;
            m->values[3]=(p<0?-p:p)*1000/voltage; m->available=15;
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
static bool discovery_wanted(Node* n,uint64_t now,uint8_t mode) {
    if(mode) { n->extended_started=false; return true; }
    if(!n->extended_started) { n->extended_started=true; n->extended_since_ms=now; }
    return n->extended_duration_ms==UINT64_MAX ||
        (n->extended_duration_ms && now-n->extended_since_ms<n->extended_duration_ms);
}
static Matter_Discovery_T commissionable_record(Node* n,uint16_t discriminator,uint8_t mode) {
    const Matter_Fabric_View_T* fabrics=matter_server_fabrics(n->server);
    uint32_t hint=fabrics && fabrics->count?HOST_PAIRING_HINT_ADMINISTRATOR:HOST_PAIRING_HINT_POWER_CYCLE;
    return matter_discovery_commissionable_with_hint(n->discovery_mac,n->random,discriminator,mode,n->port,hint);
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
    bool wanted=!stopping && n->server && discovery_wanted(n,now,mode);
    if(!stopping && n->server && (n->discovery_stopping || n->cm_mode!=mode || n->advertised_discriminator!=discriminator ||
        (wanted!=(n->mdns!=NULL)))) {
        /* Once removal starts it must drain, including close/reopen transitions
         * which return to the old mode/discriminator before goodbye completes. */
        n->discovery_stopping=true;
        if(n->mdns) {
            (void)matter_mdns_stop(matter_mdns_windows_module(n->mdns));
            (void)matter_mdns_process(matter_mdns_windows_module(n->mdns)); (void)matter_mdns_windows_poll(n->mdns,now);
            if(matter_mdns_windows_delete(n->mdns)!=MATTER_OK) return true;
            n->mdns=NULL;
        }
        matter_discovery_delete(n->discovery); n->discovery=NULL;
        if(n->discovery_rotate && !matter_host_random(n->random,sizeof(n->random))) return false;
        n->discovery_rotate=false;
        n->cm_mode=mode; n->advertised_discriminator=discriminator;
        if(wanted) {
            n->discovery=commissionable_record(n,discriminator,mode);
            if(!n->discovery) return false;
            n->mdns=matter_mdns_windows_new(n->owner,&n->iface,matter_discovery_record(n->discovery));
            if(!n->mdns || matter_mdns_start(matter_mdns_windows_module(n->mdns))!=MATTER_OK) return false;
        }
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
            a->index=index; a->owner=matter_new(NULL); a->description=matter_discovery_operational(n->discovery_mac,record->compressed_id,record->node_id,n->port);
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
    bool gui_control=false,ota_control=false; const char* instance_id=NULL;
    uint64_t extended_duration_ms=UINT64_C(1000)*HOST_EXTENDED_DISCOVERY_SECONDS;
    unsigned long subscriptions=MATTER_HOST_SUBS_PER_FABRIC;
    bool chip_validity=false,test_switch=false,test_power_only=false,power_sensor_only=false,sensor_energy=false,three_phase=false,source_registers=false,meter_services=false,wifi_sim_connected=false;
    Matter_Diagnostics_Test_Trigger_T trigger={.trigger=test_event_trigger}; bool test_events=false;
    for(int i=1;i<argc;++i) {
        if(!strcmp(argv[i],"--extended-discovery-seconds")) {
            if(++i==argc) return 2;
            if(!strcmp(argv[i],"unlimited")) extended_duration_ms=UINT64_MAX;
            else { unsigned long value; if(!number(argv[i],UINT32_MAX,&value)) return 2; extended_duration_ms=(uint64_t)value*1000; }
            continue;
        }
        if(!strcmp(argv[i],"--test-event-key")) { if(++i==argc || !test_key(argv[i],trigger.enable_key)) return 2; test_events=true; continue; }
        if(!strcmp(argv[i],"--three-phase")) { three_phase=true; continue; }
        if(!strcmp(argv[i],"--source-registers")) { source_registers=true; continue; }
        if(!strcmp(argv[i],"--meter-services")) { meter_services=true; continue; }
        if(!strcmp(argv[i],"--test-switch")) { test_switch=true; continue; }
        if(!strcmp(argv[i],"--test-power-only")) { test_power_only=true; continue; }
        if(!strcmp(argv[i],"--power-sensor-only")) { power_sensor_only=true; continue; }
        if(!strcmp(argv[i],"--ota-control")) { ota_control=true; continue; }
        if(!strcmp(argv[i],"--gui-control")) { gui_control=true; continue; }
        if(!strcmp(argv[i],"--instance-id")) { if(++i==argc) return 2; instance_id=argv[i]; continue; }
        if(!strcmp(argv[i],"--sensor-energy")) { sensor_energy=true; continue; }
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
        else if(!strcmp(argv[i],"--subscriptions-per-fabric")) { target=&subscriptions; max=10000; }
        if(!target || ++i==argc || !number(argv[i],max,target)) {
            fprintf(stderr,"Usage: matter-node --interface IPv6Index [--seconds 30] [--port 0] [--discriminator 3840] [--credentials DIR --state FILE --pin 20202021] [--subscriptions-per-fabric N] [--wifi-sim-connected] [--ota-file IMAGE] [--ota-sim-key RAW_PUBLIC_KEY] [--ota-sim-boot fail|hold] [--ota-control] [--operational-fixture] [--case-resumption-profile spec|chip] [--certificate-validity strict|chip] [--test-switch] [--test-power-only] [--power-sensor-only [--sensor-energy | --gui-control [--instance-id HEX16]]] [--three-phase [--source-registers] [--meter-services]] [--test-event-key HEX32]\n"
            "  --extended-discovery-seconds N|unlimited: CM0 announcements; default 900, 0 disables; active windows and operational discovery are unaffected.\n"
            "  --test-event-key: default profile routes energy triggers (legacy aggregate fixture);\n"
            "  with --three-phase --meter-services it enables targeted energy and Meter Identification change/reset triggers.\n"); return 2;
        }
    }
    if(!matter_host_transaction_capacity((uint16_t)subscriptions)) {
        fprintf(stderr,"Subscription budget must be at least 3 and fit MATTER_TRANSPORT_CAPACITY=%u\n",(unsigned)MATTER_TRANSPORT_CAPACITY); return 2;
    }
    if(ota_control && (!credentials || !ota_file)) { fputs("--ota-control requires credentials and --ota-file\n",stderr); return 2; }
    if(gui_control && (!power_sensor_only || sensor_energy || !credentials)) { fputs("--gui-control requires --power-sensor-only and credentials, without --sensor-energy\n",stderr); return 2; }
    if(gui_control && !instance_id) { fputs("--gui-control requires a persistent --instance-id HEX16\n",stderr); return 2; }
    if(instance_id && (!gui_control || strlen(instance_id)!=16 || strspn(instance_id,"0123456789abcdefABCDEF")!=16)) return 2;
    if(sensor_energy && !power_sensor_only) { fputs("--sensor-energy requires --power-sensor-only\n",stderr); return 2; }
    if(power_sensor_only && (test_switch || test_power_only || three_phase || source_registers || meter_services || test_events)) {
        fputs("--power-sensor-only excludes other measurement, switch and test-trigger profiles\n",stderr); return 2;
    }
    if(source_registers && !three_phase) { fputs("--source-registers requires --three-phase\n",stderr); return 2; }
    if(wifi_sim_connected && !credentials) { fputs("--wifi-sim-connected requires --credentials\n",stderr); return 2; }
    if(meter_services && (!three_phase || !credentials)) { fputs("--meter-services requires --three-phase and --credentials\n",stderr); return 2; }
    /* Explicit laboratory key enables energy and MTRID fixtures; never persisted. */
    if(test_events && !credentials) return 2;
    bool energy_test=test_events;
    if(test_events && three_phase && !meter_services) return 2;
    if(!index || (!seconds && !gui_control)) { fprintf(stderr,"Select an interface with a preferred link-local IPv6 address; seconds=1..86400.\n"); return 2; }
    if((ota_boot && !ota_key) || (ota_key && !ota_file) || (credentials && (!state || operational || !pin)) || (!credentials && (state || ota_file || ota_key || chip_validity))) return 2;
    setvbuf(stdout,NULL,_IONBF,0); signal(SIGINT,stop_signal); signal(SIGTERM,stop_signal);
    Node* n=calloc(1,sizeof(*n)); if(!n) return 1;
    n->switch_enabled=test_switch; n->three_phase=three_phase;
    n->power_only_enabled=test_power_only || power_sensor_only; n->power_sensor_only=power_sensor_only;
    n->sensor_energy=sensor_energy; n->gui_enabled=gui_control; n->ota_control=ota_control; n->gui.allow_ota_query=ota_control;
    n->wifi_sim_connected=wifi_sim_connected;
    n->extended_duration_ms=extended_duration_ms;
    n->source_enabled=source_registers;
    n->meter_services=meter_services;
    n->energy_test_enabled=energy_test; trigger.user=n;
    n->boot_ms=matter_host_now();
    int result=1; bool started=false; uint64_t start=node_now(n),now=start;
    if(matter_mdns_windows_interface((uint32_t)index,&n->iface)!=MATTER_OK) { fprintf(stderr,"Interface has no supported IPv6/MAC/multicast binding.\n"); goto done; }
    n->subscriptions_per_fabric=(uint16_t)subscriptions;
    n->owner=matter_new(NULL); if(!n->owner || matter_start(n->owner)!=MATTER_OK) goto done;
    started=true;
    /* Receive on every advertised IPv6 address; the port enforces iface via pktinfo. */
    Matter_Udp_Address_T bind={.port=(uint16_t)port};
    Matter_Udp_Listener_T listener={.user=n,.received=received,.sent=sent};
    n->udp=matter_udp_windows_new(n->owner,&bind,(uint32_t)index,&listener);
    if(!n->udp || matter_udp_start(matter_udp_windows_module(n->udp))!=MATTER_OK || matter_udp_windows_local(n->udp,&bind)!=MATTER_OK) goto done;
    if(!matter_host_random(n->random,8)) goto done;
    if(instance_id) for(unsigned i=0;i<sizeof(n->random);++i) {
        char hex[3]={instance_id[i*2],instance_id[i*2+1],0}; n->random[i]=(uint8_t)strtoul(hex,NULL,16);
    }
    memcpy(n->discovery_mac,n->iface.mac,sizeof(n->discovery_mac));
    if(n->power_sensor_only) {
        /* Separate simulated nodes must not contend for the physical NIC's
         * shared host name when their advertised address snapshots differ.
         * This locally assigned host label changes no interface/MAC/address. */
        memcpy(n->discovery_mac,n->random,sizeof(n->discovery_mac));
        n->discovery_mac[0]=(uint8_t)((n->discovery_mac[0]|2u)&~1u);
    }
    n->port=bind.port; n->discriminator=(uint16_t)disc;
    /* Explicit fixture identity from Core4.3.2 examples, never a commissioned fabric. */
    static const uint8_t fabric[]={0x87,0xe1,0xb0,4,0xe2,0x35,0xa1,0x30};
    n->discovery=operational?matter_discovery_operational(n->discovery_mac,fabric,1,bind.port):
        matter_discovery_commissionable(n->discovery_mac,n->random,(uint16_t)disc,0,bind.port);
    if(!n->discovery || !model(n,now,credentials,state,(uint32_t)pin,ota_key)) goto done;
    if(n->server) {
        if(test_events && matter_server_set_test_trigger(n->server,&trigger)!=MATTER_OK) goto done;
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
        n->discovery=commissionable_record(n,n->advertised_discriminator,n->cm_mode);
        if(!n->discovery) goto done;
    }
    if(!n->server || discovery_wanted(n,now,n->cm_mode)) {
        n->mdns=matter_mdns_windows_new(n->owner,&n->iface,matter_discovery_record(n->discovery));
        if(!n->mdns || matter_mdns_start(matter_mdns_windows_module(n->mdns))!=MATTER_OK) goto done;
    }
    if(matter_server_ota_trial(n->server) && ota_boot) {
        puts("OTA_SIM_TRIAL_WAIT");
        if(!strcmp(ota_boot,"hold")) while(!interrupted && node_now(n)-start<seconds*1000) matter_host_sleep(10);
        puts("OTA_SIM_BOOT_FAILED"); result=0; goto done;
    }
    if(matter_server_ota_boot_ready(n->server)!=MATTER_OK) goto done;
    const Matter_Mdns_Record_T* record=matter_discovery_record(n->discovery);
    printf("NODE instance=%s service=%s.%s.local. host=%s.local. port=%u interface=%lu mode=%s\n",
        record->instance,record->service,record->protocol,record->hostname,bind.port,index,operational?"operational-fixture":n->cm_mode?"CM1":"CM0");
    printf("SIMULATION %s.\n",n->power_sensor_only?(n->sensor_energy?"Root and synthetic power/energy sensor, no On/Off":"Root and synthetic power sensor only, no On/Off or EEM"):n->server?"PASE/CASE/IM, durable fabrics/EEM/event high-water; simulated source resumes at saved raw; development attestation":"discovery only, closed commissioning, volatile EPM/EEM");
    if(n->three_phase) puts("THREE_PHASE aggregate=1 phases=3,4,5 energy=physical-registers phase-energy=absent L3-unavailable=15..19s-of-20s synthetic-only");
    if(n->source) printf("SOURCE_REGISTERS endpoint=1 cluster=%08lx channels=%lu schema=1 synthetic-only\n",(unsigned long)matter_cluster_id(n->source),(unsigned long)n->source_sim->count);
    if(n->switch_enabled) puts("TEST_SWITCH endpoint=2 on=0 profile=incomplete-ui-demo state=volatile energy=independent-600W-on-0W-off cumulative-import-export-persisted-with-state");
    if(n->power_only_enabled) printf("TEST_POWER_ONLY endpoint=%u power_mW=%lld synthetic-only onoff=absent energy=%s\n",
        (unsigned)(n->power_sensor_only?HOST_POWER_SENSOR_ONLY_ENDPOINT:HOST_POWER_ONLY_ENDPOINT),(long long)HOST_POWER_ONLY_MW,n->sensor_energy?"cumulative-import-export":"absent");
    if(energy_test) printf("ENERGY_TEST enabled=1 laboratory-only mode=normal key=not-persisted measurements=volatile endpoints=%s\n",three_phase?"1,3,4,5":"1");
    if(test_events && three_phase) puts("MTRID_TEST enabled=1 endpoint=1 key=not-persisted identity=volatile clear=base-snapshot");
    bool announced=n->mdns==NULL; uint64_t next_sample=now,next_status=now;
    if(announced) puts("READY commissioning_discovery=disabled; operational discovery and CASE remain enabled");
    while(!interrupted && (now=node_now(n),(!seconds || now-start<seconds*1000))) {
        if(n->gui_enabled || n->ota_control) {
            uint64_t generation=n->gui.generation,queries=n->gui.query_generation;
            if(!matter_gui_control_poll(&n->gui)) { fputs("GUI control pipe failed\n",stderr); goto done; }
            if(n->gui.stop) break;
            if(queries!=n->gui.query_generation) printf("OTA_LOCAL_QUERY result=%d\n",matter_server_ota_request_query(n->server));
            if(generation!=n->gui.generation) { next_sample=now; next_status=now; }
        }
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
        if(n->gui_enabled && now>=next_status) {
            const Matter_Fabric_View_T* fabrics=matter_server_fabrics(n->server);
            uint16_t discriminator=n->discriminator;
            uint8_t mode=matter_server_commissioning_mode(n->server,&discriminator);
            bool published=matter_mdns_is_published(matter_mdns_windows_module(n->mdns));
            if(!mode) for(unsigned i=0;i<sizeof(n->operational)/sizeof(n->operational[0]);++i)
                published|=matter_mdns_is_published(matter_mdns_windows_module(n->operational[i].mdns));
            printf("GUI_STATUS {\"commissioning\":%u,\"fabrics\":%u,\"published\":%s,\"power_mw\":%lld,\"generation\":%llu}\n",
                mode,fabrics?fabrics->count:0,published?"true":"false",
                (long long)n->gui.power_mw,(unsigned long long)n->gui.generation);
            next_status=now+500;
        }
        matter_host_sleep(10); /* This executable owns scheduling; the library never sleeps. */
    }
    result=(announced || ((n->gui_enabled || n->ota_control) && n->gui.stop))?0:1;
done:
    if(n->server) {
        while(matter_server_stop(n->server,node_now(n))==MATTER_PENDING) {
            if(n->resolver) (void)matter_resolver_windows_poll(n->resolver,node_now(n));
            (void)matter_udp_windows_poll(n->udp); (void)matter_server_process(n->server,node_now(n)); matter_host_sleep(1);
        }
    }
    if(n->plug_ready && !n->plug_fault) {
        /* Retain the final partial second and fractional mWh across clean
         * restart; never count powered-off time while this process is absent. */
        Matter_Eem_Checkpoint_T saved=n->plug_checkpoint;
        if(matter_energy_sim_sample(&n->plug_sim,node_now(n))!=MATTER_OK) result=1;
        else {
            saved=(Matter_Eem_Checkpoint_T){.generation=1,.raw_mwh={n->plug_sim.raw[0],0},.total_mwh={n->plug_sim.raw[0],0},
                .initialized=true,.registers=true,.register_mask=3};
            if(plug_store(n,&saved)!=MATTER_OK) result=1;
        }
    }
    for(;;) {
        (void)advertisements(n,node_now(n),true); bool pending=false;
        for(unsigned i=0;i<5;++i) pending|=n->operational[i].owner!=NULL;
        if(!pending) break;
        matter_host_sleep(10);
    }
    if(started) {
        (void)matter_stop(n->owner);
        while(matter_get_state(n->owner)==MATTER_STATE_STOPPING) {
            if(n->mdns) {
                (void)matter_mdns_process(matter_mdns_windows_module(n->mdns));
                (void)matter_mdns_windows_poll(n->mdns,node_now(n));
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
    if(n->eem && matter_cluster_delete(n->eem)!=MATTER_OK) result=1;
    if(n->test_switch && matter_cluster_delete(n->test_switch)!=MATTER_OK) result=1;
    if(n->plug_power && matter_cluster_delete(n->plug_power)!=MATTER_OK) result=1;
    if(n->plug_energy && matter_cluster_delete(n->plug_energy)!=MATTER_OK) result=1;
    if(n->plug_topology && matter_cluster_delete(n->plug_topology)!=MATTER_OK) result=1;
    if(n->plug_file && matter_store_file_delete(n->plug_file)!=MATTER_OK) result=1;
    if(n->power_only_epm && matter_cluster_delete(n->power_only_epm)!=MATTER_OK) result=1;
    if(n->power_only_topology && matter_cluster_delete(n->power_only_topology)!=MATTER_OK) result=1;
    if(n->source && matter_cluster_delete(n->source)!=MATTER_OK) result=1;
    free(n->source_sim);
    for(unsigned i=0;i<HOST_METER_SERVICES_COUNT;++i) if(n->utilities[i] && matter_cluster_delete(n->utilities[i])!=MATTER_OK) result=1;
    if(matter_time_host_delete(n->clock)!=MATTER_OK) result=1;
    for(unsigned i=0;i<3;++i) {
        if(n->phase_epm[i] && matter_cluster_delete(n->phase_epm[i])!=MATTER_OK) result=1;
        if(n->phase_topology[i] && matter_cluster_delete(n->phase_topology[i])!=MATTER_OK) result=1;
    }
    if(n->epm && matter_cluster_delete(n->epm)!=MATTER_OK) result=1;
    if(n->topology && matter_cluster_delete(n->topology)!=MATTER_OK) result=1;
    if(matter_events_delete(n->events)!=MATTER_OK) result=1;
    if(matter_delete(n->owner)!=MATTER_OK) result=1;
    matter_discovery_delete(n->discovery); printf("STOPPED rx_packets=%llu result=%d\n",(unsigned long long)n->rx_packets,result);
    free(n); return result;
}

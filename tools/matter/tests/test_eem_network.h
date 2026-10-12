#ifdef MATTER_TEST_HOST_UDP
#include "test_eem_fixture.h"
typedef struct {
    AclNetwork acl; EemFixture* source; EpmFixture* power_source; Matter_Cluster_T topology;
    bool deny; uint64_t sampled[3]; unsigned attrs,events;
} EemNetwork;
static uint8_t eem_access(void* u,Matter_Exchange_Session_T token,const Matter_Im_Path_T* p,Matter_Im_Privilege_T privilege) {
    EemNetwork* h=u; return h->deny?MATTER_IM_UNSUPPORTED_ACCESS:acl_access(&h->acl,token,p,privilege);
}
static void eem_request(RootFixture* r,bool attributes,uint64_t minimum,uint32_t event) {
    ROOT_CHECK(matter_tlv_writer_init(&r->writer,r->request,sizeof(r->request),6)==MATTER_TLV_OK);
    root_put(r,MATTER_TLV_STRUCTURE,-1,0,NULL,0);
    if(attributes) {
        root_put(r,MATTER_TLV_ARRAY,0,0,NULL,0); root_put(r,MATTER_TLV_LIST,-1,0,NULL,0);
        root_put(r,MATTER_TLV_UNSIGNED,2,1,NULL,0); root_put(r,MATTER_TLV_UNSIGNED,3,0x91,NULL,0);
        root_put(r,MATTER_TLV_END,-1,0,NULL,0); root_put(r,MATTER_TLV_END,-1,0,NULL,0);
    }
    root_put(r,MATTER_TLV_ARRAY,1,0,NULL,0); root_put(r,MATTER_TLV_LIST,-1,0,NULL,0);
    root_put(r,MATTER_TLV_UNSIGNED,1,1,NULL,0); root_put(r,MATTER_TLV_UNSIGNED,2,0x91,NULL,0); root_put(r,MATTER_TLV_UNSIGNED,3,event,NULL,0);
    root_put(r,MATTER_TLV_END,-1,0,NULL,0); root_put(r,MATTER_TLV_END,-1,0,NULL,0);
    root_put(r,MATTER_TLV_ARRAY,2,0,NULL,0); root_put(r,MATTER_TLV_STRUCTURE,-1,0,NULL,0);
    root_put(r,MATTER_TLV_UNSIGNED,1,minimum,NULL,0); root_put(r,MATTER_TLV_END,-1,0,NULL,0); root_put(r,MATTER_TLV_END,-1,0,NULL,0);
    root_put(r,MATTER_TLV_BOOL,3,1,NULL,0); root_put(r,MATTER_TLV_UNSIGNED,255,13,NULL,0); root_put(r,MATTER_TLV_END,-1,0,NULL,0);
    ROOT_CHECK(matter_tlv_writer_finish(&r->writer,&r->request_size)==MATTER_TLV_OK);
}
static size_t eem_normalize(RootFixture* r,const uint8_t* data,size_t start) {
    ROOT_CHECK(matter_tlv_skip_container(&r->reader)==MATTER_TLV_OK);
    size_t size=r->reader.offset-start; ROOT_CHECK(size>2 && size-1<=sizeof(r->request));
    r->request[0]=data[start]&31; memcpy(r->request+1,data+start+2,size-2); return size-1;
}
static bool eem_report(EemNetwork* h,unsigned* attr_seen,uint64_t minimum,uint8_t error,bool updated) {
    RootFixture* r=h->acl.root; Peer* a=&h->acl.net->link->a; const uint8_t* data=a->im_received.data;
    ROOT_CHECK(matter_tlv_init(&r->reader,data,a->im_received.size,8)==MATTER_TLV_OK);
    unsigned depth=0,parent[8]={0},direction_mask=0,errors=0; uint32_t attr=0,version=0; uint64_t event_no=UINT64_MAX;
    bool more=false,suppress=false; Matter_Tlv_Result_T result;
    while((result=matter_tlv_next(&r->reader,&r->token))==MATTER_TLV_OK) {
        Matter_Tlv_Element_T* e=&r->token;
        if(e->type==MATTER_TLV_END) { ROOT_CHECK(depth); --depth; continue; }
        if(depth==1 && e->tag.number==3) more=e->unsigned_value!=0;
        if(depth==1 && e->tag.number==4) suppress=e->unsigned_value!=0;
        if(depth==4 && parent[1]==1 && e->tag.number==0) version=(uint32_t)e->unsigned_value;
        if(depth==5 && parent[1]==1 && e->tag.number==2) ROOT_CHECK(e->unsigned_value==1);
        if(depth==5 && parent[1]==1 && e->tag.number==3) ROOT_CHECK(e->unsigned_value==0x91);
        if(depth==5 && parent[1]==1 && e->tag.number==4) attr=(uint32_t)e->unsigned_value;
        if(depth==4 && parent[1]==1 && e->tag.number==2) {
            ROOT_CHECK(version==102); unsigned bit=attr<3?attr:attr==0xfff8?3:attr==0xfff9?4:attr==0xfffb?5:attr==0xfffc?6:7;
            ROOT_CHECK(!(*attr_seen&(1u<<bit))); *attr_seen|=1u<<bit; ++h->attrs;
            if(e->type==MATTER_TLV_STRUCTURE || e->type==MATTER_TLV_ARRAY) {
                size_t n=eem_normalize(r,data,e->offset);
                if(!attr) ROOT_CHECK(n==sizeof(eem_accuracy) && !memcmp(r->request,eem_accuracy,n));
                else if(attr<=2) eem_measurement(r->request,n,attr==1?1250:500,h->sampled[1],true,100);
                else if(attr==0xfffb) { static const uint8_t ids[]={0x16,4,0,4,1,4,2,5,0xf8,0xff,5,0xf9,0xff,5,0xfb,0xff,5,0xfc,0xff,5,0xfd,0xff,0x18}; ROOT_CHECK(n==sizeof(ids) && !memcmp(r->request,ids,n)); }
                else ROOT_CHECK(n==2 && r->request[0]==0x16 && r->request[1]==0x18);
                continue;
            }
            ROOT_CHECK(e->type==MATTER_TLV_UNSIGNED && e->unsigned_value==(attr==0xfffc?7:2));
        }
        if(parent[1]==2 && depth==5 && parent[4]==0) {
            if(e->tag.number==1) ROOT_CHECK(e->unsigned_value==1);
            if(e->tag.number==2) ROOT_CHECK(e->unsigned_value==0x91);
            if(e->tag.number==3) ROOT_CHECK(e->unsigned_value==(error==MATTER_IM_UNSUPPORTED_EVENT?1u:0u));
        }
        if(parent[1]==2 && depth==4 && e->tag.number==1 && e->type==MATTER_TLV_UNSIGNED) {
            event_no=e->unsigned_value; ROOT_CHECK(!error && event_no==minimum+h->events && event_no<3); ++h->events;
        }
        if(parent[1]==2 && depth==4 && e->tag.number==2) ROOT_CHECK(e->unsigned_value==1);
        if(parent[1]==2 && depth==4 && e->tag.number==4) ROOT_CHECK(e->unsigned_value==h->sampled[event_no]);
        if(parent[1]==2 && depth==5 && parent[4]==7) {
            unsigned direction=e->tag.number; ROOT_CHECK(direction<2 && e->type==MATTER_TLV_STRUCTURE && event_no<3);
            ROOT_CHECK(!(direction_mask&(1u<<direction))); direction_mask|=1u<<direction;
            size_t n=eem_normalize(r,data,e->offset);
            int64_t value=event_no?(direction?500:1250):0; if(event_no==2) { ROOT_CHECK(updated); value+=10; }
            eem_measurement(r->request,n,value,h->sampled[event_no],event_no!=0,100); continue;
        }
        if(error && parent[1]==2 && depth==5 && parent[4]==1) { ROOT_CHECK(e->tag.number==0 && e->unsigned_value==error); ++errors; }
        if(e->type==MATTER_TLV_ARRAY || e->type==MATTER_TLV_STRUCTURE || e->type==MATTER_TLV_LIST) { ROOT_CHECK(depth<8); parent[depth++]=e->tag.number; }
    }
    ROOT_CHECK(result==MATTER_TLV_DONE && !depth && more!=suppress && errors==(error?1u:0u));
    if(event_no!=UINT64_MAX) ROOT_CHECK(direction_mask==3);
    return more;
}
static bool eem_read_network(EemNetwork* h,bool attributes,uint64_t minimum,unsigned expected,uint8_t error,bool loss) {
    bool ok=false; AclNetwork* n=&h->acl; PaseFixture* f=n->net; Peer* a=&f->link->a; Peer* b=&f->link->b;
    Matter_Root_Case_Read_Binding_T binding; Matter_Im_Read_Port_T port; Matter_Im_Read_Fabric_Port_T fabric;
    CHECK(fab_exchange(f) && matter_root_case_read_port(n->root->root,b->secure_token,b->secure,&binding,&port,&fabric)==MATTER_OK);
    Matter_Im_Read_Config_T config={{b->secure_token,a->key.exchange_id,false},30000,180,false};
    b->im=matter_im_read_new_case(&port,&fabric,&config,++n->now); CHECK(b->im);
    Matter_Im_Read_Events_Port_T ep={n->root->root,h->source->config.events,matter_root_event_describe};
    CHECK(matter_im_read_bind_events(b->im,&ep)==MATTER_OK);
    eem_request(n->root,attributes,minimum,error==MATTER_IM_UNSUPPORTED_EVENT?1:0);
    CHECK(sub_host_packet(f,a,b,2,n->root->request,n->root->request_size,n->now) && im_ack_transfer(b,a,n->now+=200));
    unsigned seen=0,chunks=0; h->attrs=h->events=0;
    for(unsigned step=0;step<40;++step) {
        CHECK(matter_im_read_process(b->im,n->now)==MATTER_PENDING);
        Matter_Im_Read_Message_T out; if(matter_im_read_output(b->im,&out)!=MATTER_OK) continue;
        CHECK(out.opcode==5 && im_host_send(f,b,5,out.data,out.size,n->now) && matter_im_read_sent(b->im)==MATTER_OK && tick(b,n->now)); network_poll(b);
        CHECK(network_take(b) && network_receive(a));
        if(loss && !chunks) {
            f->link->delayed_data=a->inbox; a->inbox_full=false;
            uint64_t retry; CHECK(matter_retransmission_sender_deadline(b->tx,&retry)==MATTER_OK);
            n->now+=1000; if(n->now<retry) n->now=retry;
            h->sampled[2]=n->now; h->source->sample.sampled_ms=n->now; h->source->sample.raw_mwh[0]+=10; h->source->sample.raw_mwh[1]+=10; bool ready;
            CHECK(matter_eem_refresh(h->source->cluster,n->now,&ready)==MATTER_OK && ready);
            CHECK(tick(b,n->now)); complete_resolver(b); network_poll(b);
            CHECK(network_take(b) && network_receive(a) && a->inbox.size==f->link->delayed_data.size && !memcmp(a->inbox.data,f->link->delayed_data.data,a->inbox.size));
        }
        CHECK(network_admit(a,n->now) && tick(a,n->now));
        bool more=eem_report(h,&seen,minimum,error,!attributes); ++chunks;
        CHECK(im_ack_transfer(a,b,n->now+=200)); if(!more) break;
        CHECK(sub_host_packet(f,a,b,1,sub_success,sizeof(sub_success),n->now) && im_ack_transfer(b,a,n->now+=200));
    }
    CHECK(h->events==expected && seen==(attributes?255u:0u) && matter_im_read_state(b->im)==MATTER_IM_READ_COMPLETE);
    if(loss) CHECK(chunks>=3);
    CHECK(matter_im_read_delete(b->im)==MATTER_OK); b->im=NULL; a->im_client=false; ok=true;
done: return ok;
}
#include "test_eem_subscribe_network.h"
static bool network_eem(void) {
    bool ok=false; EemNetwork* h=calloc(1,sizeof(*h)); REQUIRE(h); AclNetwork* n=&h->acl;
    n->net=setup(false,false); PaseFixture* f=n->net; Matter_Credentials_Port_T cp;
    CHECK(matter_crypto_mbedtls_credentials(f->crypto,&cp)==MATTER_OK); n->admin=case_fixture(&f->port,&cp);
    Matter_Acl_Port_T ap=matter_fabric_host_acl_port(n->admin->fabrics[1]->host); n->acl=matter_acl_new(&ap); CHECK(n->acl);
    n->root=root_fixture(); Matter_Root_Port_T rp={h,acl_load,eem_access,acl_store_root}; n->root->root=matter_root_new(&rp); CHECK(n->root->root);
    CHECK(matter_root_attach_acl(n->root->root,n->acl)==MATTER_OK);
    Matter_Root_Endpoint_Config_T config={1,1,0x0510,12}; CHECK(matter_root_add_endpoint(n->root->root,&config)==MATTER_OK);
    h->topology=matter_power_topology_new(50); CHECK(h->topology && matter_root_attach_cluster_at(n->root->root,1,h->topology)==MATTER_OK);
    h->power_source=epm_fixture(); h->power_source->cluster=epm_create(h->power_source,0);
    CHECK(h->power_source->cluster && matter_root_attach_cluster_at(n->root->root,1,h->power_source->cluster)==MATTER_OK);
    h->source=eem_fixture(); h->source->cluster=eem_create(h->source,0); CHECK(h->source->cluster && matter_root_attach_cluster_at(n->root->root,1,h->source->cluster)==MATTER_OK);
    Matter_Im_Value_T v; Matter_Cluster_Request_T q={0}; Matter_Cluster_T descriptor=matter_root_cluster_at(n->root->root,1,0x1d);
    static const uint8_t servers[]={0x16,4,0x1d,4,0x9c,4,0x90,4,0x91,0x18};
    CHECK(!matter_cluster_read(descriptor,1,&q,&v) && v.size==sizeof(servers) && !memcmp(v.data,servers,sizeof(servers)));
    Matter_Event_Path_T missing={1,0x91,999}; Matter_Im_Attribute_T meta;
    CHECK(matter_root_event_describe(n->root->root,&missing,&meta)==MATTER_IM_UNSUPPORTED_EVENT);
    missing.endpoint=2; CHECK(matter_root_event_describe(n->root->root,&missing,&meta)==MATTER_IM_UNSUPPORTED_ENDPOINT);
    missing.endpoint=1; missing.cluster=0xffff; CHECK(matter_root_event_describe(n->root->root,&missing,&meta)==MATTER_IM_UNSUPPORTED_CLUSTER);
    CHECK(acl_handshake(n,0,n->admin->session)); bool ready;
    h->sampled[0]=n->now; h->source->sample=(Matter_Eem_Sample_T){.raw_mwh={1000000,2000000},.generation=1,.sampled_ms=n->now,.available=true};
    CHECK(matter_eem_refresh(h->source->cluster,n->now,&ready)==MATTER_OK && ready);
    n->now+=1000; h->sampled[1]=n->now; h->source->sample.sampled_ms=n->now; h->source->sample.utc_known=true; h->source->sample.epoch_s=100;
    h->source->sample.raw_mwh[0]+=1250; h->source->sample.raw_mwh[1]+=500;
    CHECK(matter_eem_refresh(h->source->cluster,n->now,&ready)==MATTER_OK && ready);
    CHECK(eem_read_network(h,true,0,2,0,true));
    CHECK(eem_read_network(h,false,1,2,0,false));
    CHECK(eem_read_network(h,false,3,0,0,false));
    CHECK(eem_read_network(h,false,0,0,MATTER_IM_UNSUPPORTED_EVENT,false));
    CHECK(eem_subscribe_network(h));
    h->deny=true; CHECK(eem_read_network(h,false,0,0,MATTER_IM_UNSUPPORTED_ACCESS,false));
    puts("PASS EEM CASE IPv6: complete EP1 model, Accuracy/import/export, UTC/system, mixed attribute/event chunks, EventMin, immutable ciphertext during new measurement, unsupported/denied events"); ok=true;
done:
    if(f->link) cleanup(f->link);
    f->link=NULL;
    if(n->root) root_release(n->root);
    if(h->topology) REQUIRE(matter_cluster_delete(h->topology)==MATTER_OK);
    if(h->power_source) { REQUIRE(matter_cluster_delete(h->power_source->cluster)==MATTER_OK); free(h->power_source); }
    if(h->source) eem_free(h->source);
    if(n->acl) REQUIRE(matter_acl_delete(n->acl)==MATTER_OK);
    if(n->admin) case_free(n->admin);
    dispose(f); free(h); return ok;
}
#endif

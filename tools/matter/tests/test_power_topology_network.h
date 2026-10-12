#ifdef MATTER_TEST_HOST_UDP
#include "clusters/matter_power_topology.h"
typedef struct { AclNetwork acl; bool deny; uint64_t seen; unsigned errors; } PowerNetwork;
static uint8_t power_access(void* u,Matter_Exchange_Session_T token,const Matter_Im_Path_T* p,Matter_Im_Privilege_T privilege) {
    PowerNetwork* h=u;
    if(h->deny && p->endpoint==1) return MATTER_IM_UNSUPPORTED_ACCESS;
    return acl_access(&h->acl,token,p,privilege);
}
static void power_request(RootFixture* r,int ep,int cluster,int attr,int filter_ep,int filter_cluster,uint32_t version) {
    ROOT_CHECK(matter_tlv_writer_init(&r->writer,r->request,sizeof(r->request),6)==MATTER_TLV_OK);
    root_put(r,MATTER_TLV_STRUCTURE,-1,0,NULL,0); root_put(r,MATTER_TLV_ARRAY,0,0,NULL,0);
    root_put(r,MATTER_TLV_LIST,-1,0,NULL,0);
    if(ep>=0) root_put(r,MATTER_TLV_UNSIGNED,2,(unsigned)ep,NULL,0);
    if(cluster>=0) root_put(r,MATTER_TLV_UNSIGNED,3,(unsigned)cluster,NULL,0);
    if(attr>=0) root_put(r,MATTER_TLV_UNSIGNED,4,(unsigned)attr,NULL,0);
    root_put(r,MATTER_TLV_END,-1,0,NULL,0); root_put(r,MATTER_TLV_END,-1,0,NULL,0);
    if(filter_ep>=0) {
        root_put(r,MATTER_TLV_ARRAY,4,0,NULL,0); root_put(r,MATTER_TLV_STRUCTURE,-1,0,NULL,0);
        root_put(r,MATTER_TLV_LIST,0,0,NULL,0); root_put(r,MATTER_TLV_UNSIGNED,1,(unsigned)filter_ep,NULL,0);
        root_put(r,MATTER_TLV_UNSIGNED,2,(unsigned)filter_cluster,NULL,0); root_put(r,MATTER_TLV_END,-1,0,NULL,0);
        root_put(r,MATTER_TLV_UNSIGNED,1,version,NULL,0); root_put(r,MATTER_TLV_END,-1,0,NULL,0);
        root_put(r,MATTER_TLV_END,-1,0,NULL,0);
    }
    root_put(r,MATTER_TLV_BOOL,3,1,NULL,0); root_put(r,MATTER_TLV_UNSIGNED,255,13,NULL,0);
    root_put(r,MATTER_TLV_END,-1,0,NULL,0);
    ROOT_CHECK(matter_tlv_writer_finish(&r->writer,&r->request_size)==MATTER_TLV_OK);
}
/* Independent literal values: no comparison against the server's read callback. */
static void power_wire_value(RootFixture* r,unsigned ep,uint32_t cluster,uint32_t attr,const Matter_Im_Value_T* v) {
    ROOT_CHECK(ep<=1 && (cluster==0x1d || (ep==1 && cluster==0x9c)));
    if(attr==0xfffc || attr==0xfffd) {
        uint64_t n=attr==0xfffc?(cluster==0x9c?2:0):(cluster==0x9c?1:3);
        ROOT_CHECK(v->type==MATTER_TLV_UNSIGNED && v->unsigned_value==n); return;
    }
    static const uint8_t empty[]={0x16,0x18},parts[]={0x16,4,1,0x18};
    static const uint8_t device[]={0x16,0x15,0x25,0,0x10,5,0x24,1,1,0x18,0x18};
    static const uint8_t root_device[]={0x16,0x15,0x24,0,0x16,0x24,1,5,0x18,0x18};
    static const uint8_t servers[]={0x16,4,0x1d,4,0x9c,0x18},root_servers[]={0x16,4,0x1d,4,0x28,4,0x1f,0x18};
    const uint8_t* bytes=empty; size_t n=sizeof(empty);
    if(attr==0) { bytes=ep?device:root_device; n=ep?sizeof(device):sizeof(root_device); }
    if(attr==1) { bytes=ep?servers:root_servers; n=ep?sizeof(servers):sizeof(root_servers); }
    if(attr==3 && !ep) { bytes=parts; n=sizeof(parts); }
    if(attr==0xfffb) {
        n=0; r->expected[n++]=0x16;
        for(unsigned i=cluster==0x9c?4:0;i<9;++i) {
            uint32_t id=root_descriptor_ids[i]; r->expected[n++]=id>255?5:4; r->expected[n++]=(uint8_t)id;
            if(id>255) r->expected[n++]=(uint8_t)(id>>8);
        }
        r->expected[n++]=0x18; bytes=r->expected;
    }
    ROOT_CHECK(v->type==MATTER_TLV_ARRAY && v->size==n && !memcmp(v->data,bytes,n));
}
static bool power_report(PowerNetwork* h,const uint8_t* data,size_t size,uint8_t expected_status,int expected_ep,int expected_cluster,int expected_attr) {
    RootFixture* r=h->acl.root; unsigned depth=0,ep=0; uint32_t cluster=0,attr=0,version=0;
    bool more=false,suppress=false,status=false; Matter_Tlv_Result_T result;
    ROOT_CHECK(matter_tlv_init(&r->reader,data,size,8)==MATTER_TLV_OK);
    while((result=matter_tlv_next(&r->reader,&r->token))==MATTER_TLV_OK) {
        Matter_Tlv_Element_T* e=&r->token;
        if(e->type==MATTER_TLV_END) { ROOT_CHECK(depth); --depth; continue; }
        if(depth==3) status=e->tag.number==0;
        if(!status && depth==4 && e->tag.number==0) version=(uint32_t)e->unsigned_value;
        if(depth==5 && e->tag.number==2) ep=(unsigned)e->unsigned_value;
        if(depth==5 && e->tag.number==3) cluster=(uint32_t)e->unsigned_value;
        if(depth==5 && e->tag.number==4) attr=(uint32_t)e->unsigned_value;
        if(depth==5 && e->tag.number==5) ROOT_CHECK(false);
        if(status && depth==5 && e->tag.number==0) {
            ROOT_CHECK(expected_status && e->unsigned_value==expected_status && ep==(unsigned)expected_ep &&
                cluster==(unsigned)expected_cluster && attr==(unsigned)expected_attr); ++h->errors;
        }
        if(!status && depth==4 && e->tag.number==2) {
            ROOT_CHECK(!expected_status && version==(cluster==0x9c?50:13));
            Matter_Im_Value_T v={.type=e->type,.unsigned_value=e->unsigned_value,.data=e->data,.size=e->size};
            if(e->type==MATTER_TLV_ARRAY) {
                size_t start=e->offset; ROOT_CHECK(matter_tlv_skip_container(&r->reader)==MATTER_TLV_OK);
                size_t bytes=r->reader.offset-start; ROOT_CHECK(bytes>1 && bytes-1<=sizeof(r->request));
                r->request[0]=data[start]&31; memcpy(r->request+1,data+start+2,bytes-2); v.data=r->request; v.size=bytes-1;
            }
            power_wire_value(r,ep,cluster,attr,&v);
            unsigned i=0; while(i<9 && root_descriptor_ids[i]!=attr) ++i; ROOT_CHECK(i<9);
            unsigned bit=ep?cluster==0x9c?18+i-4:9+i:i;
            ROOT_CHECK(!(h->seen&(UINT64_C(1)<<bit))); h->seen|=UINT64_C(1)<<bit; continue;
        }
        if(depth==1 && e->tag.number==3) more=e->unsigned_value!=0;
        if(depth==1 && e->tag.number==4) suppress=e->unsigned_value!=0;
        if(e->type==MATTER_TLV_STRUCTURE || e->type==MATTER_TLV_ARRAY || e->type==MATTER_TLV_LIST) ++depth;
    }
    ROOT_CHECK(result==MATTER_TLV_DONE && !depth && more!=suppress); return more;
}
static bool power_read_network(PowerNetwork* h,int ep,int cluster,int attr,int filter_ep,int filter_cluster,uint32_t version,uint64_t seen,uint8_t status,bool loss) {
    bool ok=false; AclNetwork* n=&h->acl; PaseFixture* f=n->net; Peer* a=&f->link->a; Peer* b=&f->link->b;
    Matter_Root_Case_Read_Binding_T binding; Matter_Im_Read_Port_T port; Matter_Im_Read_Fabric_Port_T fabric;
    CHECK(fab_exchange(f) && matter_root_case_read_port(n->root->root,b->secure_token,b->secure,&binding,&port,&fabric)==MATTER_OK);
    Matter_Im_Read_Config_T config={{b->secure_token,a->key.exchange_id,false},30000,180,false};
    b->im=matter_im_read_new_case(&port,&fabric,&config,++n->now); CHECK(b->im);
    power_request(n->root,ep,cluster,attr,filter_ep,filter_cluster,version); h->seen=0; h->errors=0;
    CHECK(im_host_send(f,a,2,n->root->request,n->root->request_size,n->now) && tick(a,n->now)); network_poll(a);
    CHECK(network_take(a) && network_receive(b) && network_admit(b,n->now) && tick(b,n->now));
    CHECK(im_ack_transfer(b,a,n->now+=200) && matter_im_read_process(b->im,n->now)==MATTER_PENDING);
    unsigned chunks=0;
    for(unsigned step=0;step<40;++step) {
        CHECK(matter_im_read_process(b->im,n->now)==MATTER_PENDING);
        Matter_Im_Read_Message_T out; if(matter_im_read_output(b->im,&out)!=MATTER_OK) continue;
        CHECK(out.opcode==5);
        CHECK(im_host_send(f,b,5,out.data,out.size,n->now) && matter_im_read_sent(b->im)==MATTER_OK && tick(b,n->now)); network_poll(b);
        CHECK(network_take(b) && network_receive(a));
        if(loss && !chunks) {
            f->link->delayed_ack=a->inbox; a->inbox_full=false;
            CHECK(matter_retransmission_sender_deadline(b->tx,&n->now)==MATTER_OK && tick(b,n->now)); complete_resolver(b); network_poll(b);
            CHECK(network_take(b) && network_receive(a) && a->inbox.size==f->link->delayed_ack.size &&
                !memcmp(a->inbox.data,f->link->delayed_ack.data,a->inbox.size));
        }
        CHECK(network_admit(a,n->now) && tick(a,n->now));
        bool more=power_report(h,a->im_received.data,a->im_received.size,status,ep,cluster,attr);
        CHECK(im_ack_transfer(a,b,n->now+=200));
        ++chunks;
        if(!more) break;
        static const uint8_t success[]={0x15,0x24,0,0,0x24,255,13,0x18};
        CHECK(im_host_send(f,a,1,success,sizeof(success),n->now) && tick(a,n->now)); network_poll(a);
        CHECK(network_take(a) && network_receive(b) && network_admit(b,n->now) && tick(b,n->now));
        CHECK(im_ack_transfer(b,a,n->now+=200) && matter_im_read_process(b->im,n->now)==MATTER_PENDING);
    }
    CHECK(h->seen==seen && h->errors==(status?1u:0u) && matter_im_read_state(b->im)==MATTER_IM_READ_COMPLETE);
    if(loss) CHECK(chunks>1);
    CHECK(matter_im_read_delete(b->im)==MATTER_OK); b->im=NULL; a->im_client=false; ok=true;
done: return ok;
}
static bool network_power_topology(void) {
    bool ok=false; PowerNetwork* h=calloc(1,sizeof(*h)); REQUIRE(h); AclNetwork* n=&h->acl;
    n->net=setup(false,false); PaseFixture* f=n->net; Matter_Cluster_T power=NULL;
    Matter_Credentials_Port_T cp; CHECK(matter_crypto_mbedtls_credentials(f->crypto,&cp)==MATTER_OK);
    n->admin=case_fixture(&f->port,&cp); Matter_Acl_Port_T ap=matter_fabric_host_acl_port(n->admin->fabrics[1]->host);
    n->acl=matter_acl_new(&ap); CHECK(n->acl); n->root=root_fixture();
    Matter_Root_Port_T rp={h,acl_load,power_access,acl_store_root}; n->root->root=matter_root_new(&rp); CHECK(n->root->root);
    CHECK(matter_root_attach_acl(n->root->root,n->acl)==MATTER_OK);
    Matter_Root_Endpoint_Config_T config={1,1,0x0510,12}; CHECK(matter_root_add_endpoint(n->root->root,&config)==MATTER_OK);
    power=matter_power_topology_new(50); CHECK(power && matter_root_attach_cluster_at(n->root->root,1,power)==MATTER_OK);
    CHECK(acl_handshake(n,0,n->admin->session));
    CHECK(power_read_network(h,0,0x1d,3,-1,0,0,UINT64_C(1)<<3,0,false));
    CHECK(power_read_network(h,1,-1,-1,-1,0,0,UINT64_C(0x3fff)<<9,0,true));
    /* Both Descriptor instances have version 13: the endpoint is part of the filter. */
    CHECK(power_read_network(h,-1,0x1d,-1,0,0x1d,13,UINT64_C(0x1ff)<<9,0,false));
    CHECK(power_read_network(h,1,-1,-1,1,0x9c,50,UINT64_C(0x1ff)<<9,0,false));
    CHECK(power_read_network(h,1,0x9c,-1,1,0x9c,50,0,0,false));
    CHECK(power_read_network(h,2,0x9c,0xfffc,-1,0,0,0,MATTER_IM_UNSUPPORTED_ENDPOINT,false));
    CHECK(power_read_network(h,0,0x9c,0xfffc,-1,0,0,0,MATTER_IM_UNSUPPORTED_CLUSTER,false));
    CHECK(power_read_network(h,1,0x9c,0,-1,0,0,0,MATTER_IM_UNSUPPORTED_ATTRIBUTE,false));
    h->deny=true;
    CHECK(power_read_network(h,1,0x9c,0xfffc,-1,0,0,0,MATTER_IM_UNSUPPORTED_ACCESS,false));
    CHECK(power_read_network(h,1,-1,-1,-1,0,0,0,0,false));
    puts("PASS Power Topology CASE IPv6: EP1 literal values, root PartsList, wildcard chunks, identical encrypted retry, endpoint-scoped filters, path errors and access"); ok=true;
done:
    if(f->link) cleanup(f->link);
    f->link=NULL;
    if(n->root) root_release(n->root);
    if(power) REQUIRE(matter_cluster_delete(power)==MATTER_OK);
    if(n->acl) REQUIRE(matter_acl_delete(n->acl)==MATTER_OK);
    if(n->admin) case_free(n->admin);
    dispose(f); free(h); return ok;
}
#endif

#ifdef MATTER_TEST_HOST_UDP
#include "test_epm_fixture.h"
typedef struct {
    Matter_Root_Case_Read_Binding_T binding; unsigned reserves,releases;
} EpmSubscription;
typedef struct {
    AclNetwork acl; EpmFixture* source; Matter_Cluster_T power;
    EpmSubscription subscription; bool deny;
} EpmNetwork;
static uint8_t epm_access(void* u,Matter_Exchange_Session_T token,const Matter_Im_Path_T* p,Matter_Im_Privilege_T privilege) {
    EpmNetwork* h=u; return h->deny?MATTER_IM_UNSUPPORTED_ACCESS:acl_access(&h->acl,token,p,privilege);
}
static uint8_t epm_reserve(void* u,Matter_Exchange_Session_T session,bool keep,uint32_t* id) {
    EpmSubscription* s=u; Matter_Secure_Identity_T identity;
    ROOT_CHECK(session==s->binding.base.session && keep && !s->reserves &&
        matter_secure_identity(s->binding.secure,&identity)==MATTER_OK && identity.fabric_index==1);
    ++s->reserves; *id=42; return 0; /* One subscriber in this fixture's owner registry. */
}
static void epm_release(void* u,uint32_t id) { EpmSubscription* s=u; ROOT_CHECK(id==42 && !s->releases); ++s->releases; }
/* Parse actual client RX, compare against literal Accuracy and independent values. */
static bool epm_report(EpmNetwork* h,bool subscription,bool available,int64_t power,uint32_t version,unsigned* seen,uint8_t status) {
    RootFixture* r=h->acl.root; Peer* a=&h->acl.net->link->a; const uint8_t* data=a->im_received.data;
    ROOT_CHECK(matter_tlv_init(&r->reader,data,a->im_received.size,8)==MATTER_TLV_OK);
    unsigned depth=0; uint32_t cluster=0,attr=0,dv=0; bool more=false,suppress=false; unsigned errors=0;
    Matter_Tlv_Result_T result;
    while((result=matter_tlv_next(&r->reader,&r->token))==MATTER_TLV_OK) {
        Matter_Tlv_Element_T* e=&r->token;
        if(e->type==MATTER_TLV_END) { ROOT_CHECK(depth); --depth; continue; }
        if(depth==4 && e->tag.number==0 && !status) dv=(uint32_t)e->unsigned_value;
        if(depth==5 && e->tag.number==2) ROOT_CHECK(e->unsigned_value==1);
        if(depth==5 && e->tag.number==3) cluster=(uint32_t)e->unsigned_value;
        if(depth==5 && e->tag.number==4) attr=(uint32_t)e->unsigned_value;
        if(depth==5 && e->tag.number==5) ROOT_CHECK(false);
        if(status && depth==5 && e->tag.number==0) { ROOT_CHECK(cluster==0x90 && attr==8 && e->unsigned_value==status); ++errors; }
        if(!status && depth==4 && e->tag.number==2) {
            Matter_Im_Value_T v={.type=e->type,.unsigned_value=e->unsigned_value,.signed_value=e->signed_value,.data=e->data,.size=e->size,.data_version=dv};
            if(e->type==MATTER_TLV_ARRAY) {
                size_t start=e->offset; ROOT_CHECK(matter_tlv_skip_container(&r->reader)==MATTER_TLV_OK);
                size_t bytes=r->reader.offset-start; ROOT_CHECK(bytes>1 && bytes-1<=sizeof(r->request));
                r->request[0]=data[start]&31; memcpy(r->request+1,data+start+2,bytes-2); v.data=r->request; v.size=bytes-1;
            }
            unsigned i=0;
            if(cluster==0x1d) {
                static const uint8_t servers[]={0x16,4,0x1d,4,0x9c,4,0x90,0x18};
                ROOT_CHECK(attr==1 && v.type==MATTER_TLV_ARRAY && v.size==sizeof(servers) && !memcmp(v.data,servers,sizeof(servers)) && dv==14); i=9;
            } else {
                ROOT_CHECK(cluster==0x90); epm_expect(attr,&v,available,power,version);
                while(i<9 && epm_ids[i]!=attr) ++i;
                ROOT_CHECK(i<9);
            }
            ROOT_CHECK(!(*seen&(1u<<i))); *seen|=1u<<i; continue;
        }
        if(subscription && depth==1 && e->tag.number==0) ROOT_CHECK(e->unsigned_value==42);
        if(depth==1 && e->tag.number==3) more=e->unsigned_value!=0;
        if(depth==1 && e->tag.number==4) suppress=e->unsigned_value!=0;
        if(e->type==MATTER_TLV_ARRAY || e->type==MATTER_TLV_STRUCTURE || e->type==MATTER_TLV_LIST) ++depth;
    }
    ROOT_CHECK(result==MATTER_TLV_DONE && !depth && errors==(status?1u:0u));
    ROOT_CHECK(subscription?(!more && !suppress):(more!=suppress)); return more;
}
static bool epm_read_network(EpmNetwork* h,int attr,int filter,bool available,int64_t value,uint32_t version,bool loss) {
    bool ok=false; AclNetwork* n=&h->acl; PaseFixture* f=n->net; Peer* a=&f->link->a; Peer* b=&f->link->b;
    Matter_Root_Case_Read_Binding_T binding; Matter_Im_Read_Port_T port; Matter_Im_Read_Fabric_Port_T fabric;
    CHECK(fab_exchange(f) && matter_root_case_read_port(n->root->root,b->secure_token,b->secure,&binding,&port,&fabric)==MATTER_OK);
    Matter_Im_Read_Config_T config={{b->secure_token,a->key.exchange_id,false},30000,180,false};
    b->im=matter_im_read_new_case(&port,&fabric,&config,++n->now); CHECK(b->im);
    power_request(n->root,1,attr==-2?0x1d:0x90,attr==-2?1:attr,filter<0?-1:1,0x90,(uint32_t)filter);
    CHECK(sub_host_packet(f,a,b,2,n->root->request,n->root->request_size,n->now) && im_ack_transfer(b,a,n->now+=200));
    unsigned seen=0,chunks=0;
    for(unsigned step=0;step<40;++step) {
        CHECK(matter_im_read_process(b->im,n->now)==MATTER_PENDING);
        Matter_Im_Read_Message_T out; if(matter_im_read_output(b->im,&out)!=MATTER_OK) continue;
        CHECK(out.opcode==5 && im_host_send(f,b,5,out.data,out.size,n->now) && matter_im_read_sent(b->im)==MATTER_OK && tick(b,n->now)); network_poll(b);
        CHECK(network_take(b) && network_receive(a));
        if(loss && !chunks) {
            f->link->delayed_data=a->inbox; a->inbox_full=false;
            /* Snapshot stays immutable when application publishes a newer sample. */
            h->source->sample=(Matter_Epm_Sample_T){-1000,n->now,true}; bool ready;
            CHECK(matter_epm_refresh(h->source->cluster,n->now,&ready)==MATTER_OK);
            CHECK(matter_retransmission_sender_deadline(b->tx,&n->now)==MATTER_OK && tick(b,n->now)); complete_resolver(b); network_poll(b);
            CHECK(network_take(b) && network_receive(a) && a->inbox.size==f->link->delayed_data.size && !memcmp(a->inbox.data,f->link->delayed_data.data,a->inbox.size));
        }
        CHECK(network_admit(a,n->now) && tick(a,n->now));
        bool more=epm_report(h,false,available,value,version,&seen,0); ++chunks;
        CHECK(im_ack_transfer(a,b,n->now+=200)); if(!more) break;
        CHECK(sub_host_packet(f,a,b,1,sub_success,sizeof(sub_success),n->now) && im_ack_transfer(b,a,n->now+=200));
    }
    unsigned expected=filter==(int)version?0:attr==-1?511:attr==-2?512:8;
    CHECK(seen==expected && matter_im_read_state(b->im)==MATTER_IM_READ_COMPLETE);
    if(loss) CHECK(chunks>1);
    CHECK(matter_im_read_delete(b->im)==MATTER_OK); b->im=NULL; a->im_client=false; ok=true;
done: return ok;
}
static bool epm_sub_status(EpmNetwork* h) {
    AclNetwork* n=&h->acl; PaseFixture* f=n->net; Peer* a=&f->link->a; Peer* b=&f->link->b;
    return im_ack_transfer(a,b,n->now+=200) && sub_host_packet(f,a,b,1,sub_success,sizeof(sub_success),n->now) &&
        im_ack_transfer(b,a,n->now+=200);
}
static bool epm_subscribe_network(EpmNetwork* h) {
    bool ok=false; AclNetwork* n=&h->acl; PaseFixture* f=n->net; Peer* a=&f->link->a; Peer* b=&f->link->b;
    Matter_Im_Subscribe_Port_T p={.reserve=epm_reserve,.release=epm_release}; Matter_Im_Read_Fabric_Port_T resolver;
    CHECK(fab_exchange(f) && matter_root_case_read_port(n->root->root,b->secure_token,b->secure,&h->subscription.binding,&p.attributes,&resolver)==MATTER_OK);
    Matter_Im_Subscribe_Config_T c={{b->secure_token,a->key.exchange_id,false},10000,128,false};
    b->sub=matter_im_subscribe_new_case(&p,&resolver,&c,++n->now); CHECK(b->sub);
    memcpy(n->root->request,sub_request,sizeof(sub_request)); n->root->request[5]=1; n->root->request[14]=1; n->root->request[17]=0x90; n->root->request[20]=8;
    h->source->sample=(Matter_Epm_Sample_T){1000,n->now,true}; bool ready;
    CHECK(matter_epm_refresh(h->source->cluster,n->now,&ready)==MATTER_OK); uint32_t version;
    CHECK(matter_cluster_version(h->source->cluster,&version)==MATTER_OK);
    CHECK(sub_host_packet(f,a,b,3,n->root->request,sizeof(sub_request),n->now) && im_ack_transfer(b,a,n->now+=200));
    CHECK(matter_im_subscribe_process(b->sub,n->now)==MATTER_PENDING && sub_host_output(f,&n->now,false)); unsigned seen=0;
    (void)epm_report(h,true,true,1000,version,&seen,0); CHECK(seen==8 && epm_sub_status(h));
    CHECK(matter_im_subscribe_process(b->sub,n->now)==MATTER_PENDING && sub_host_output(f,&n->now,false));
    CHECK(a->im_received.size==sizeof(sub_response) && !memcmp(a->im_received.data,sub_response,sizeof(sub_response)));
    CHECK(im_ack_transfer(a,b,n->now+=200) && matter_im_subscribe_state(b->sub)==MATTER_IM_SUB_IDLE);
    for(unsigned mode=0;mode<4;++mode) {
        n->now+=1000;
        if(mode==0) h->source->sample=(Matter_Epm_Sample_T){-1000,n->now,true};
        if(mode==1) h->source->sample=(Matter_Epm_Sample_T){0,n->now,true};
        if(mode==2) h->source->error=MATTER_PORT_ERROR;
        if(mode==3) { h->source->error=MATTER_OK; h->source->sample=(Matter_Epm_Sample_T){500,n->now,true}; }
        CHECK(matter_epm_refresh(h->source->cluster,n->now,&ready)==(mode==2?MATTER_PORT_ERROR:MATTER_OK) && ready);
        CHECK(matter_im_subscribe_changed(b->sub)==MATTER_OK && matter_cluster_version(h->source->cluster,&version)==MATTER_OK);
        CHECK(matter_im_subscribe_process(b->sub,n->now)==MATTER_PENDING && sub_host_exchange(f,n->now));
        CHECK(matter_im_subscribe_process(b->sub,n->now)==MATTER_PENDING && sub_host_output(f,&n->now,mode==0));
        seen=0; (void)epm_report(h,true,mode!=2,mode==0?-1000:mode==3?500:0,version,&seen,0); CHECK(seen==8);
        CHECK(epm_sub_status(h) && matter_im_subscribe_process(b->sub,n->now)==MATTER_PENDING && matter_im_subscribe_state(b->sub)==MATTER_IM_SUB_IDLE);
    }
    /* ACL revocation must also be enforced on an unchanged heartbeat. */
    uint64_t deadline; CHECK(matter_im_subscribe_deadline(b->sub,&deadline)==MATTER_OK); n->now=deadline; h->deny=true;
    CHECK(matter_im_subscribe_process(b->sub,n->now)==MATTER_PENDING && sub_host_exchange(f,n->now));
    CHECK(matter_im_subscribe_process(b->sub,n->now)==MATTER_PENDING && sub_host_output(f,&n->now,false));
    seen=0; (void)epm_report(h,true,false,0,0,&seen,MATTER_IM_UNSUPPORTED_ACCESS); CHECK(!seen && epm_sub_status(h));
    CHECK(matter_im_subscribe_process(b->sub,n->now)==MATTER_PORT_ERROR && h->subscription.reserves==1 && h->subscription.releases==1);
    CHECK(matter_im_subscribe_delete(b->sub)==MATTER_OK); b->sub=NULL; a->im_client=false; ok=true;
done: return ok;
}
static bool network_epm(void) {
    bool ok=false; EpmNetwork* h=calloc(1,sizeof(*h)); REQUIRE(h); AclNetwork* n=&h->acl;
    n->net=setup(false,false); PaseFixture* f=n->net; Matter_Credentials_Port_T cp;
    CHECK(matter_crypto_mbedtls_credentials(f->crypto,&cp)==MATTER_OK); n->admin=case_fixture(&f->port,&cp);
    Matter_Acl_Port_T ap=matter_fabric_host_acl_port(n->admin->fabrics[1]->host); n->acl=matter_acl_new(&ap); CHECK(n->acl);
    n->root=root_fixture(); Matter_Root_Port_T rp={h,acl_load,epm_access,acl_store_root}; n->root->root=matter_root_new(&rp); CHECK(n->root->root);
    CHECK(matter_root_attach_acl(n->root->root,n->acl)==MATTER_OK);
    Matter_Root_Endpoint_Config_T config={1,1,0x0510,12}; CHECK(matter_root_add_endpoint(n->root->root,&config)==MATTER_OK);
    h->power=matter_power_topology_new(50); CHECK(h->power && matter_root_attach_cluster_at(n->root->root,1,h->power)==MATTER_OK);
    h->source=epm_fixture(); h->source->cluster=epm_create(h->source,0); CHECK(h->source->cluster && matter_root_attach_cluster_at(n->root->root,1,h->source->cluster)==MATTER_OK);
    CHECK(acl_handshake(n,0,n->admin->session));
    bool ready; h->source->sample=(Matter_Epm_Sample_T){1000,n->now,true}; CHECK(matter_epm_refresh(h->source->cluster,n->now,&ready)==MATTER_OK);
    CHECK(epm_read_network(h,-2,-1,true,1000,101,false));
    CHECK(epm_read_network(h,-1,-1,true,1000,101,true)); /* Changes to -1000 during retry. */
    CHECK(epm_read_network(h,8,-1,true,-1000,102,false));
    CHECK(epm_read_network(h,-1,102,true,-1000,102,false));
    n->now+=3000; CHECK(matter_epm_refresh(h->source->cluster,n->now,&ready)==MATTER_OK);
    CHECK(epm_read_network(h,8,102,false,0,103,false));
    CHECK(epm_subscribe_network(h));
    puts("PASS EPM CASE IPv6: Descriptor, literal Accuracy/chunks, signed mW/null, filters/stale, immutable retry across refresh, Subscribe updates/recovery and ACL heartbeat revocation"); ok=true;
done:
    if(f->link) cleanup(f->link);
    f->link=NULL;
    if(n->root) root_release(n->root);
    if(h->power) REQUIRE(matter_cluster_delete(h->power)==MATTER_OK);
    if(h->source) { if(h->source->cluster) REQUIRE(matter_cluster_delete(h->source->cluster)==MATTER_OK); free(h->source); }
    if(n->acl) REQUIRE(matter_acl_delete(n->acl)==MATTER_OK);
    if(n->admin) case_free(n->admin);
    dispose(f); free(h); return ok;
}
#endif

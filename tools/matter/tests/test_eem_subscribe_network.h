/* Included after the EEM Read network fixture. Real secure/MRP path throughout. */
typedef struct {
    EpmSubscription owner; EemNetwork* host;
    uint64_t first_event; uint32_t version; int64_t imported,exported; uint64_t sampled;
    bool available; unsigned attrs,events,errors;
    struct { int64_t imported,exported; uint64_t sampled; } history[4];
} EemSubNetwork;
static void eem_sub_request(RootFixture* r,uint64_t minimum) {
    ROOT_CHECK(matter_tlv_writer_init(&r->writer,r->request,sizeof(r->request),6)==MATTER_TLV_OK);
    root_put(r,MATTER_TLV_STRUCTURE,-1,0,NULL,0); root_put(r,MATTER_TLV_BOOL,0,1,NULL,0);
    root_put(r,MATTER_TLV_UNSIGNED,1,5,NULL,0); root_put(r,MATTER_TLV_UNSIGNED,2,10,NULL,0);
    root_put(r,MATTER_TLV_ARRAY,3,0,NULL,0);
    for(unsigned attr=1;attr<=2;++attr) {
        root_put(r,MATTER_TLV_LIST,-1,0,NULL,0); root_put(r,MATTER_TLV_UNSIGNED,2,1,NULL,0);
        root_put(r,MATTER_TLV_UNSIGNED,3,0x91,NULL,0); root_put(r,MATTER_TLV_UNSIGNED,4,attr,NULL,0); root_put(r,MATTER_TLV_END,-1,0,NULL,0);
    }
    root_put(r,MATTER_TLV_END,-1,0,NULL,0); root_put(r,MATTER_TLV_ARRAY,4,0,NULL,0); root_put(r,MATTER_TLV_LIST,-1,0,NULL,0);
    root_put(r,MATTER_TLV_UNSIGNED,1,1,NULL,0); root_put(r,MATTER_TLV_UNSIGNED,2,0x91,NULL,0); root_put(r,MATTER_TLV_UNSIGNED,3,0,NULL,0);
    root_put(r,MATTER_TLV_BOOL,4,1,NULL,0); root_put(r,MATTER_TLV_END,-1,0,NULL,0); root_put(r,MATTER_TLV_END,-1,0,NULL,0);
    root_put(r,MATTER_TLV_ARRAY,5,0,NULL,0); root_put(r,MATTER_TLV_STRUCTURE,-1,0,NULL,0); root_put(r,MATTER_TLV_UNSIGNED,1,minimum,NULL,0);
    root_put(r,MATTER_TLV_END,-1,0,NULL,0); root_put(r,MATTER_TLV_END,-1,0,NULL,0);
    root_put(r,MATTER_TLV_BOOL,7,1,NULL,0); root_put(r,MATTER_TLV_UNSIGNED,255,13,NULL,0); root_put(r,MATTER_TLV_END,-1,0,NULL,0);
    ROOT_CHECK(matter_tlv_writer_finish(&r->writer,&r->request_size)==MATTER_TLV_OK);
}
static bool eem_sub_report(EemSubNetwork* s,uint64_t first) {
    EemNetwork* h=s->host; RootFixture* r=h->acl.root; Peer* a=&h->acl.net->link->a;
    const uint8_t* data=a->im_received.data; ROOT_CHECK(matter_tlv_init(&r->reader,data,a->im_received.size,8)==MATTER_TLV_OK);
    unsigned depth=0,parent[8]={0}; uint32_t attr=0; uint64_t event_no=UINT64_MAX; bool more=false,suppress=true; Matter_Tlv_Result_T result;
    while((result=matter_tlv_next(&r->reader,&r->token))==MATTER_TLV_OK) {
        Matter_Tlv_Element_T* e=&r->token;
        if(e->type==MATTER_TLV_END) { ROOT_CHECK(depth); --depth; continue; }
        if(depth==1 && e->tag.number==0) ROOT_CHECK(e->unsigned_value==42);
        if(depth==1 && e->tag.number==3) more=e->unsigned_value!=0;
        if(depth==1 && e->tag.number==4) suppress=e->unsigned_value!=0;
        if(parent[1]==1 && depth==4 && !e->tag.number && parent[3]==1) ROOT_CHECK(e->unsigned_value==s->version);
        if(parent[1]==1 && depth==5 && e->tag.number==4) attr=(uint32_t)e->unsigned_value;
        if(parent[1]==1 && depth==4 && e->tag.number==2) {
            ROOT_CHECK((attr==1 || attr==2) && e->type==(s->available?MATTER_TLV_STRUCTURE:MATTER_TLV_NULL)); ++s->attrs;
            if(s->available) { size_t size=eem_normalize(r,data,e->offset); eem_measurement(r->request,size,attr==1?s->imported:s->exported,s->sampled,true,100); continue; }
        }
        if(parent[1]==2 && depth==4 && e->tag.number==1 && e->type==MATTER_TLV_UNSIGNED) {
            event_no=e->unsigned_value; ROOT_CHECK(event_no==first+s->events && event_no>=s->first_event && event_no-s->first_event<4); ++s->events;
        }
        if(parent[1]==2 && depth==4 && e->tag.number==2) ROOT_CHECK(e->unsigned_value==1);
        if(parent[1]==2 && depth==4 && e->tag.number==4) ROOT_CHECK(e->unsigned_value==s->history[event_no-s->first_event].sampled);
        if(parent[1]==2 && depth==5 && parent[4]==7) {
            ROOT_CHECK(e->tag.number<2 && e->type==MATTER_TLV_STRUCTURE); unsigned direction=e->tag.number,index=(unsigned)(event_no-s->first_event);
            size_t size=eem_normalize(r,data,e->offset);
            eem_measurement(r->request,size,direction?s->history[index].exported:s->history[index].imported,s->history[index].sampled,true,100); continue;
        }
        if(depth==5 && parent[3]==0 && parent[4]==1 && !e->tag.number) { ROOT_CHECK(e->unsigned_value==MATTER_IM_UNSUPPORTED_ACCESS); ++s->errors; }
        if(e->type==MATTER_TLV_ARRAY || e->type==MATTER_TLV_STRUCTURE || e->type==MATTER_TLV_LIST) { ROOT_CHECK(depth<8); parent[depth++]=e->tag.number; }
    }
    ROOT_CHECK(result==MATTER_TLV_DONE && !depth && !suppress); return more;
}
static bool eem_sub_sample(EemSubNetwork* s,unsigned history,int64_t imported,int64_t exported,bool notify) {
    AclNetwork* n=&s->host->acl; EemFixture* f=s->host->source;
    f->sample.sampled_ms=n->now; f->sample.raw_mwh[0]=1000000+imported; f->sample.raw_mwh[1]=2000000+exported; f->sample.available=true;
    s->history[history].sampled=n->now; s->history[history].imported=imported; s->history[history].exported=exported;
    bool ready; if(matter_eem_refresh(f->cluster,n->now,&ready)!=MATTER_OK || !ready) return false;
    return !notify || (matter_im_subscribe_changed(n->net->link->b.sub)==MATTER_OK && matter_im_subscribe_events_changed(n->net->link->b.sub)==MATTER_OK);
}
static bool eem_sub_transaction(EemSubNetwork* s,uint64_t first,bool prime,bool loss,bool revoke) {
    bool ok=false; AclNetwork* n=&s->host->acl; PaseFixture* f=n->net; Peer* a=&f->link->a; Peer* b=&f->link->b;
    s->attrs=s->events=s->errors=0;
    for(unsigned chunk=0;chunk<20;++chunk) {
        CHECK(matter_im_subscribe_process(b->sub,n->now)==MATTER_PENDING);
        Matter_Im_Subscribe_Message_T out; CHECK(matter_im_subscribe_output(b->sub,&out)==MATTER_OK && out.opcode==5);
        CHECK(im_host_send(f,b,5,out.data,out.size,n->now) && tick(b,n->now)); network_poll(b); CHECK(network_take(b) && network_receive(a));
        if(loss && !chunk) {
            f->link->delayed_data=a->inbox; a->inbox_full=false; uint64_t retry;
            CHECK(matter_retransmission_sender_deadline(b->tx,&retry)==MATTER_OK); n->now+=1000; if(n->now<retry) n->now=retry;
            CHECK(eem_sub_sample(s,1,1410,770,true));
            CHECK(tick(b,n->now)); complete_resolver(b); network_poll(b);
            CHECK(network_take(b) && network_receive(a) && a->inbox.size==f->link->delayed_data.size && !memcmp(a->inbox.data,f->link->delayed_data.data,a->inbox.size));
        }
        CHECK(network_admit(a,n->now) && tick(a,n->now)); bool more=eem_sub_report(s,first);
        if(revoke && !chunk) s->host->deny=true;
        /* Alternate IM-before-MRP and MRP-before-IM for every chunk. */
        if(chunk%2) CHECK(im_ack_transfer(a,b,n->now+=200));
        CHECK(sub_host_packet(f,a,b,1,sub_success,sizeof(sub_success),++n->now));
        if(!(chunk%2)) {
            CHECK(matter_im_subscribe_process(b->sub,n->now)==MATTER_PENDING && matter_im_subscribe_state(b->sub)==MATTER_IM_SUB_IN_FLIGHT);
            CHECK(im_ack_transfer(a,b,n->now+=200));
        }
        CHECK(im_ack_transfer(b,a,n->now+=200));
        if(!more) break;
    }
    if(revoke) { CHECK(matter_im_subscribe_process(b->sub,n->now)==MATTER_PORT_ERROR && s->owner.releases==1); ok=true; goto done; }
    CHECK(matter_im_subscribe_process(b->sub,n->now)==MATTER_PENDING);
    if(prime) {
        CHECK(sub_host_output(f,&n->now,false)); static const uint8_t response[]={0x15,0x24,0,42,0x24,2,10,0x24,255,13,0x18};
        CHECK(a->im_received.size==sizeof(response) && !memcmp(a->im_received.data,response,sizeof(response)) && im_ack_transfer(a,b,n->now+=200));
    }
    CHECK(matter_im_subscribe_state(b->sub)==MATTER_IM_SUB_IDLE); ok=true;
done: return ok;
}
static bool eem_sub_next(EemSubNetwork* s) {
    AclNetwork* n=&s->host->acl; Matter_Im_Subscribe_T sub=n->net->link->b.sub; uint64_t due;
    if(matter_im_subscribe_deadline(sub,&due)!=MATTER_OK) return false;
    if(due>n->now) {
        if(matter_im_subscribe_process(sub,due-1)!=MATTER_PENDING || matter_im_subscribe_state(sub)!=MATTER_IM_SUB_IDLE) return false;
        n->now=due;
    }
    return matter_im_subscribe_process(sub,n->now)==MATTER_PENDING && sub_host_exchange(n->net,n->now);
}
static bool eem_subscribe_network(EemNetwork* h) {
    bool ok=false; EemSubNetwork* s=calloc(1,sizeof(*s)); REQUIRE(s); s->host=h;
    AclNetwork* n=&h->acl; PaseFixture* f=n->net; Peer* a=&f->link->a; Peer* b=&f->link->b;
    CHECK(matter_events_position(h->source->config.events,&s->first_event)==MATTER_OK && s->first_event==3);
    n->now+=1000; CHECK(eem_sub_sample(s,0,1360,710,false)); s->sampled=n->now; s->imported=1360; s->exported=710; s->version=104; s->available=true;
    Matter_Im_Subscribe_Port_T p={.reserve=epm_reserve,.release=epm_release}; Matter_Im_Read_Fabric_Port_T resolver;
    CHECK(fab_exchange(f) && matter_root_case_read_port(n->root->root,b->secure_token,b->secure,&s->owner.binding,&p.attributes,&resolver)==MATTER_OK);
    Matter_Im_Subscribe_Config_T c={{b->secure_token,a->key.exchange_id,false},30000,80,false}; b->sub=matter_im_subscribe_new_case(&p,&resolver,&c,n->now); CHECK(b->sub);
    Matter_Im_Read_Events_Port_T ep={n->root->root,h->source->config.events,matter_root_event_describe}; CHECK(matter_im_subscribe_bind_events(b->sub,&ep)==MATTER_OK);
    eem_sub_request(n->root,s->first_event);
    CHECK(sub_host_packet(f,a,b,3,n->root->request,n->root->request_size,n->now) && im_ack_transfer(b,a,n->now+=200));
    CHECK(eem_sub_transaction(s,3,true,true,false) && s->attrs==2 && s->events==1);
    CHECK(eem_sub_next(s)); s->sampled=s->history[1].sampled; s->imported=1410; s->exported=770; s->version=105;
    CHECK(eem_sub_transaction(s,4,false,false,false) && s->attrs==2 && s->events==1);
    /* Temporary unavailability reports null, preserves totals and emits no fake event. */
    n->now+=1000; h->source->sample.available=false; bool ready;
    CHECK(matter_eem_refresh(h->source->cluster,n->now,&ready)==MATTER_OK && ready && matter_im_subscribe_changed(b->sub)==MATTER_OK);
    CHECK(eem_sub_next(s)); s->available=false; s->version=106;
    CHECK(eem_sub_transaction(s,5,false,false,false) && s->attrs==2 && !s->events);
    n->now+=1000; CHECK(eem_sub_sample(s,2,1410,770,true)); s->sampled=n->now; s->available=true; s->version=107;
    CHECK(eem_sub_next(s) && eem_sub_transaction(s,5,false,false,false) && s->attrs==2 && s->events==1);
    CHECK(eem_sub_next(s) && eem_sub_transaction(s,6,false,false,false) && !s->attrs && !s->events); /* No repeated event on max heartbeat. */
    n->now+=1000; CHECK(eem_sub_sample(s,3,1411,771,true)); s->sampled=n->now; s->imported=1411; s->exported=771; s->version=108;
    CHECK(eem_sub_next(s) && eem_sub_transaction(s,6,false,false,true) && s->attrs==1 && !s->events && s->errors==2);
    CHECK(s->owner.reserves==1 && s->owner.releases==1); ok=true;
    puts("PASS EEM Subscribe CASE IPv6: two structures/events, prime and update chunks, mid-flight new measurement, exact encrypted retry, min/max heartbeat, null/recovery, cursor and ACL revocation");
done:
    if(b->sub) { REQUIRE(matter_im_subscribe_delete(b->sub)==MATTER_OK); b->sub=NULL; }
    a->im_client=false; free(s); return ok;
}

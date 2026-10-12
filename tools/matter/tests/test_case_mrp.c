/* Core1.6.1 4.12.2/4.12.5 and 4.14.2. Deterministic packet faults,
 * real RX/ACK/MRP, crypto and CASE; no sockets or wall-clock sleeps. */
#define MATTER_TEST_PASE 1
#define main mrp_regression_main
#include "test_mrp_pair.c"
#undef main
#include "crypto/matter_crypto_mbedtls.h"
#include "test_opcreds_fixture.h"
#include "test_fabric_fixture.h"
#include "test_case_fixture.h"
#include "test_im_vectors.h"

typedef struct {
    Matter_Case_Port_T original; unsigned saves;
} Cache;
typedef struct {
    CaseFixture* cases; Pair* pair; Cache cache[2]; bool taken[2];
    Packet immutable, ack, previous[2], plain;
    uint64_t now; unsigned reads,probes;
} Faults;
static Matter_Result_T cache_load(void* u,unsigned n,Matter_Case_Fabric_T* f) { Cache* c=u; return c->original.load(c->original.user,n,f); }
static Matter_Result_T cache_valid(void* u,uint8_t i,uint32_t r) { Cache* c=u; return c->original.valid(c->original.user,i,r); }
static Matter_Result_T cache_sign(void* u,uint8_t i,const uint8_t* p,size_t n,uint8_t s[64]) { Cache* c=u; return c->original.sign(c->original.user,i,p,n,s); }
static Matter_Result_T cache_find(void* u,uint8_t i,uint64_t peer,const uint8_t* id,Matter_Case_Resumption_T* r) { Cache* c=u; return c->original.resume_find(c->original.user,i,peer,id,r); }
static Matter_Result_T cache_save(void* u,const Matter_Case_Resumption_T* r) { Cache* c=u; ++c->saves; return c->original.resume_save(c->original.user,r); }
static Peer* side(Faults* f,unsigned i) { return i?&f->pair->b:&f->pair->a; }
static void handoff(Faults* f,unsigned i) {
    Matter_Case_T s=f->cases->session[i];
    if(!f->taken[i] && matter_case_state(s)==MATTER_CASE_COMPLETE) {
        f->cases->secure[i]=matter_secure_new_case(&f->cases->crypto,s,f->now); REQUIRE(f->cases->secure[i]);
        REQUIRE(matter_case_take_keys(s,&f->cases->keys[i])==MATTER_INVALID_STATE);
        f->taken[i]=true;
    }
}
static void open_attempt(Faults* f,const Matter_Credentials_Port_T* cp,unsigned profile) {
    f->pair=create(); REQUIRE(f->pair); f->now=0; f->reads=f->probes=0;
    for(unsigned i=0;i<2;++i) {
        if(f->cases->secure[i]) { REQUIRE(matter_secure_close(f->cases->secure[i])==MATTER_OK && matter_secure_delete(f->cases->secure[i])==MATTER_OK); f->cases->secure[i]=NULL; }
        REQUIRE(matter_case_delete(f->cases->session[i])==MATTER_OK);
        f->cases->config[i].local_session_id+=2;
        f->cases->config[i].resumption_profile=(Matter_Case_Resumption_Profile_T)profile;
        f->cases->session[i]=matter_case_new(&f->cases->crypto,cp,&f->cases->ports[i],&f->cases->config[i],0);
        REQUIRE(f->cases->session[i]); f->taken[i]=false; f->previous[i].size=0;
        Peer* p=side(f,i); p->case_session=f->cases->session[i]; REQUIRE(matter_rx_register(p->rx,0,0)==MATTER_OK);
    }
}
static void close_attempt(Faults* f) {
    /* Cleanup checks every RX/TX/ACK/session/resolver pin and dependency. */
    if(!f->pair) return;
    for(unsigned i=0;i<2;++i) side(f,i)->case_session=NULL;
    cleanup(f->pair); f->pair=NULL;
}
static void queue_case(Peer* p) {
    Matter_Pase_Message_T m; REQUIRE(matter_case_output(p->case_session,&m)==MATTER_OK && !p->tx_pins);
    if(!p->handle) { REQUIRE(matter_rx_initiate(p->rx,p->session,&p->handle)==MATTER_OK); REQUIRE(matter_rx_get(p->rx,p->handle,&p->key)==MATTER_OK); }
    Matter_Protocol_Header_T h={.exchange_id=p->key.exchange_id,.opcode=m.opcode,
        .exchange_flags=MATTER_PROTOCOL_RELIABLE|(p->key.initiator?MATTER_PROTOCOL_INITIATOR:0)};
    Matter_Unsecured_Prepared_T packet;
    REQUIRE(matter_unsecured_prepare(p->sessions,p->session,&p->outgoing,&h,m.data,m.size,p->outbound.data,sizeof(p->outbound.data),&packet)==MATTER_OK);
    p->outbound.size=packet.size;
    REQUIRE(matter_retransmission_sender_add(p->tx,&p->key,packet.counter,p->outbound.data,packet.size,&p->message_id)==MATTER_OK);
    p->pase_final=m.opcode==0x40; REQUIRE(matter_case_sent(p->case_session)==MATTER_OK);
}
/* 0 normal, 1 drop first data, 2 duplicate data, 3 drop first ACK,
 * 4 duplicate ACK, 5 replay previous data after advancing CASE,
 * 6 drop all data, 7 drop all ACK. Only 6/7 exhaust MRP. */
static Matter_Result_T probe_received(void* u,const Matter_Secure_Received_T* m) {
    Faults* f=u; REQUIRE(m->protocol.protocol_id==1);
    if(!m->duplicate) { REQUIRE(m->size==1 && m->payload[0]==0x15); ++f->probes; }
    return MATTER_OK;
}
static void probe_before_ack(Faults* f,unsigned sender) {
    if(f->probes || !f->taken[0] || !f->taken[1]) return;
    static const uint8_t plain[]={1,2,0x34,0x12,1,0,0x15};
    REQUIRE(matter_secure_seal(f->cases->secure[1-sender],plain,sizeof(plain),f->now,f->plain.data,sizeof(f->plain.data),&f->plain.size)==MATTER_OK);
    f->plain.data[f->plain.size-1]^=1;
    REQUIRE(matter_secure_receive(f->cases->secure[sender],f->plain.data,f->plain.size,f->now,probe_received,f)==MATTER_PORT_ERROR && !f->probes);
    f->plain.data[f->plain.size-1]^=1;
    REQUIRE(matter_secure_receive(f->cases->secure[sender],f->plain.data,f->plain.size,f->now,probe_received,f)==MATTER_OK && f->probes==1);
    REQUIRE(matter_secure_receive(f->cases->secure[sender],f->plain.data,f->plain.size,f->now,probe_received,f)==MATTER_OK && f->probes==1);
}
static bool transfer(Faults* f,unsigned from,unsigned fault,bool handshake) {
    Peer* p=side(f,from); Peer* q=side(f,1-from);
    unsigned delivered=q->deliveries, notified=p->notifications;
    REQUIRE(tick(p,f->now) && p->retained); f->immutable=p->wire;
    if(handshake) handoff(f,from); /* Sender activates before final ACK. */
    for(unsigned attempt=0;attempt<8;++attempt) {
        REQUIRE(p->wire.size==f->immutable.size && !memcmp(p->wire.data,f->immutable.data,p->wire.size));
        REQUIRE(complete_tx(p,MATTER_RETRANSMISSION_SENT));
        if(fault!=6 && !(fault==1 && !attempt)) {
            REQUIRE(receive_packet(q,&f->immutable,f->now)==MATTER_OK && tick(q,f->now));
            REQUIRE(q->deliveries==delivered+1);
            if(handshake) {
                Matter_Result_T r=matter_case_process(q->case_session,f->now); REQUIRE(r==MATTER_PENDING || r==MATTER_OK);
                handoff(f,1-from);
                probe_before_ack(f,from); /* Authenticated RX while final MRP is pending. */
            }
            if(fault==2 || (fault==5 && f->previous[from].size)) {
                REQUIRE(receive_packet(q,fault==2?&f->immutable:&f->previous[from],f->now)==MATTER_OK && tick(q,f->now));
                REQUIRE(q->deliveries==delivered+1);
            }
            f->now+=200; REQUIRE(tick(q,f->now) && q->retained_ack); f->ack=q->wire;
            REQUIRE(complete_ack(q,MATTER_OPERATION_SUCCEEDED));
            if(fault!=7 && !(fault==3 && !attempt)) {
                REQUIRE(receive_packet(p,&f->ack,f->now)==MATTER_OK && tick(p,f->now));
                if(fault==4) REQUIRE(receive_packet(p,&f->ack,f->now)==MATTER_OK && tick(p,f->now));
                /* A late old reliable packet can force its own immediate ACK
                 * ahead of the pending ACK for the current message. */
                for(unsigned drain=0;fault==5 && p->tx_pins && drain<2;++drain) {
                    f->now+=200; REQUIRE(tick(q,f->now) && q->retained_ack); f->ack=q->wire;
                    REQUIRE(complete_ack(q,MATTER_OPERATION_SUCCEEDED));
                    REQUIRE(receive_packet(p,&f->ack,f->now)==MATTER_OK && tick(p,f->now));
                }
                if(p->notifications!=notified+1 || p->tx_pins) fprintf(stderr,"from=%u fault=%u handshake=%u attempt=%u notifications=%u before=%u pins=%u outcome=%u\n",from,fault,handshake,attempt,p->notifications,notified,p->tx_pins,p->outcome);
                REQUIRE(p->notifications==notified+1 && p->outcome==MATTER_RETRANSMISSION_ACKNOWLEDGED && !p->tx_pins);
                if(handshake) handoff(f,from);
                f->previous[from]=f->immutable; return true;
            }
        }
        REQUIRE(matter_retransmission_sender_deadline(p->tx,&f->now)==MATTER_OK && tick(p,f->now));
        complete_resolver(p);
        if(p->notifications!=notified) {
            REQUIRE((fault==6 || fault==7) && p->notifications==notified+1 && !p->tx_pins && !p->retained);
            REQUIRE(p->outcome==MATTER_RETRANSMISSION_TIMEOUT); return false;
        }
        REQUIRE(p->retained);
    }
    abort();
}
static bool handshake(Faults* f,bool resumed,unsigned fault) {
    unsigned before[2]={f->cache[0].saves,f->cache[1].saves};
    unsigned count=resumed?3:4;
    REQUIRE(matter_case_process(f->cases->session[0],0)==MATTER_PENDING);
    for(unsigned step=0;step<count;++step) {
        unsigned from=step%2; Peer* p=side(f,from); Matter_Pase_Message_T m;
        REQUIRE(matter_case_output(p->case_session,&m)==MATTER_OK);
        REQUIRE(m.opcode==(step==0?0x30:step==1?(resumed?0x33:0x31):step==2?(resumed?0x40:0x32):0x40));
        queue_case(p);
        bool success=transfer(f,from,(fault<6 || step+1==count)?fault:0,true);
        if(!success) {
            REQUIRE(matter_case_state(p->case_session)==MATTER_CASE_COMPLETE && f->taken[from]);
            REQUIRE(matter_case_take_keys(p->case_session,&f->cases->keys[from])==MATTER_INVALID_STATE);
            REQUIRE(f->cache[from].saves==before[from]+1);
            REQUIRE(f->cache[1-from].saves==before[1-from]+(fault==7));
            return false;
        }
    }
    for(unsigned i=0;i<2;++i) REQUIRE(f->taken[i] && f->cache[i].saves==before[i]+1);
    return true;
}
/* Exercise real IM and encrypted MRP after the resulting CASE grant. */
static Matter_Im_Status_T authorize(void* u,Matter_Exchange_Session_T s,const Matter_Im_Path_T* p,Matter_Im_Privilege_T v) { (void)u;(void)s;(void)p;return v==MATTER_IM_VIEW?MATTER_IM_SUCCESS:MATTER_IM_UNSUPPORTED_ACCESS; }
static Matter_Im_Status_T describe(void* u,const Matter_Im_Path_T* p,Matter_Im_Attribute_T* a) { (void)u;if(p->endpoint || p->cluster!=0x28 || p->attribute!=2) return MATTER_IM_UNSUPPORTED_ATTRIBUTE; *a=(Matter_Im_Attribute_T){MATTER_IM_VIEW,false};return MATTER_IM_SUCCESS; }
static Matter_Im_Status_T read_value(void* u,const Matter_Im_Path_T* p,bool filtered,Matter_Im_Value_T* v) { Faults* f=u;(void)p;REQUIRE(filtered);++f->reads;*v=(Matter_Im_Value_T){.type=MATTER_TLV_UNSIGNED,.unsigned_value=0xfff1,.data_version=7};return MATTER_IM_SUCCESS; }
static Matter_Result_T fabric_index(void* u,Matter_Exchange_Session_T s,uint8_t* i) { (void)u;(void)s;*i=1;return MATTER_OK; }
static void queue_im(Faults* f,Peer* p,uint8_t opcode,const uint8_t* data,size_t size) {
    Matter_Protocol_Header_T h={.protocol_id=1,.opcode=opcode,.exchange_id=p->key.exchange_id,
        .exchange_flags=MATTER_PROTOCOL_RELIABLE|(p->key.initiator?MATTER_PROTOCOL_INITIATOR:0)};
    size_t n; REQUIRE(matter_protocol_header_write(&h,f->plain.data,sizeof(f->plain.data),&n)==MATTER_MESSAGE_OK);
    REQUIRE(size<=sizeof(f->plain.data)-n); memcpy(f->plain.data+n,data,size);
    Matter_Secure_Prepared_T packet;
    REQUIRE(matter_secure_channel_prepare(p->channel,f->plain.data,n+size,f->now,p->outbound.data,sizeof(p->outbound.data),&packet)==MATTER_OK);
    p->outbound.size=packet.size;
    REQUIRE(matter_retransmission_sender_add(p->tx,&p->key,packet.counter,p->outbound.data,packet.size,&p->message_id)==MATTER_OK);
}
static void read_after(Faults* f) {
    Peer* a=side(f,0); Peer* b=side(f,1);
    for(unsigned i=0;i<2;++i) {
        Peer* p=side(f,i); REQUIRE(matter_rx_close(p->rx,p->handle)==MATTER_OK); p->handle=0; p->case_session=NULL;
        p->secure=f->cases->secure[i]; f->cases->secure[i]=NULL; REQUIRE(p->secure);
        p->session=p->secure_token=20001+i; p->channel=matter_secure_channel_new(p->secure,p->session,&p->path); REQUIRE(p->channel);
        REQUIRE(matter_rx_register(p->rx,0,1)==MATTER_OK);
    }
    a->im_client=true; REQUIRE(matter_rx_initiate(a->rx,a->session,&a->handle)==MATTER_OK && matter_rx_get(a->rx,a->handle,&a->key)==MATTER_OK);
    Matter_Im_Read_Port_T port={f,authorize,describe,read_value,NULL,NULL}; Matter_Im_Read_Fabric_Port_T fabric={fabric_index};
    Matter_Im_Read_Config_T cfg={{b->session,a->key.exchange_id,false},10000,512,false};
    b->im=matter_im_read_new_case(&port,&fabric,&cfg,f->now); REQUIRE(b->im);
    queue_im(f,a,2,im_request,sizeof(im_request)); REQUIRE(transfer(f,0,3,false));
    REQUIRE(matter_im_read_process(b->im,f->now)==MATTER_PENDING);
    Matter_Im_Read_Message_T m; REQUIRE(matter_im_read_output(b->im,&m)==MATTER_OK);
    queue_im(f,b,m.opcode,m.data,m.size); REQUIRE(matter_im_read_sent(b->im)==MATTER_OK && transfer(f,1,1,false));
    REQUIRE(f->reads==1 && a->im_received.size==sizeof(im_report) && !memcmp(a->im_received.data,im_report,sizeof(im_report)));
    REQUIRE(matter_im_read_delete(b->im)==MATTER_OK); b->im=NULL;
    /* Normal fixture shutdown drains first, then closes/deletes secure owners. */
    for(unsigned i=0;i<2;++i) { Peer* p=side(f,i); REQUIRE(matter_secure_channel_retire(p->channel,p->rx,p->tx)==MATTER_OK); }
    close_attempt(f);
}
int main(void) {
    Matter_Crypto_Mbedtls_T backend=matter_crypto_mbedtls_new(NULL); REQUIRE(backend);
    Matter_Crypto_Port_T crypto; Matter_Credentials_Port_T cp;
    REQUIRE(matter_crypto_mbedtls_port(backend,&crypto)==MATTER_OK && matter_crypto_mbedtls_credentials(backend,&cp)==MATTER_OK);
    for(unsigned profile=0;profile<2;++profile) for(unsigned resumed=0;resumed<2;++resumed) for(unsigned fault=0;fault<8;++fault) {
        printf("CASE profile=%u resume=%u fault=%u\n",profile,resumed,fault); fflush(stdout);
        Faults* f=calloc(1,sizeof(*f)); REQUIRE(f); f->cases=case_fixture(&crypto,&cp);
        for(unsigned i=0;i<2;++i) { Cache* c=&f->cache[i];c->original=f->cases->ports[i];f->cases->ports[i]=(Matter_Case_Port_T){c,c->original.capacity,cache_load,cache_valid,cache_sign,cache_find,cache_save}; }
        if(resumed) { open_attempt(f,&cp,profile); REQUIRE(handshake(f,false,0)); close_attempt(f); }
        open_attempt(f,&cp,profile); REQUIRE(handshake(f,resumed,fault)==(fault<6));
        if(fault>=6) {
            if(fault==7) read_after(f); /* Lost ACK cannot revoke an active session. */
            close_attempt(f); open_attempt(f,&cp,profile);
            /* Lost final data leaves asymmetric cache -> full CASE fallback.
             * Lost ACK leaves both authenticated peers with the new ID. */
            REQUIRE(handshake(f,fault==7,0));
        }
        read_after(f); case_free(f->cases); memset(f,0,sizeof(*f)); free(f);
    }
    REQUIRE(matter_crypto_mbedtls_delete(backend)==MATTER_OK);
    puts("PASS CASE/MRP 32 scenarios: two profiles/full/resume, data/ACK loss/duplicates/stale data, exhaustion, one-shot cache, recovery and encrypted Read");
    return 0;
}

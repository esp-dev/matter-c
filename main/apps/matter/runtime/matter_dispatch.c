#include "matter_dispatch.h"
#include "matter_host_limits.h"
#include "transport/matter_unsecured_rx.h"
#include "transport/matter_unsecured_prepare.h"
#include "transport/matter_unsecured_tx.h"
#include "transport/matter_secure_channel.h"
#include "model/matter_im_subscribe.h"
#include <stdlib.h>
#include <string.h>

enum { CONNECTIONS=MATTER_HOST_CONNECTIONS, TRANSACTIONS=MATTER_HOST_TRANSACTIONS, ROUTES=8, PACKET=1232 };
typedef char TransportBudget[(MATTER_TRANSPORT_CAPACITY>=MATTER_HOST_TRANSACTIONS)?1:-1];
typedef enum { NONE, READ, SUBSCRIBE, WRITE, INVOKE, TIMED, HANDSHAKE, REJECT, CLIENT } Admission;
typedef struct { Matter_Exchange_Session_T token; Matter_Udp_Path_T path; uint64_t touched; } Route;
typedef struct {
    Matter_Exchange_Session_T token; Matter_Secure_T secure;
    Matter_Secure_Channel_T channel; bool operational,retiring;
    uint8_t fabric_index; uint64_t peer_node;
    bool reserved,rotating; uint8_t reserved_fabric; uint64_t credential_revision; Matter_Exchange_Handle_T rotation_reply;
    Matter_Exchange_Handle_T removal_reply; uint64_t removal_deadline;
    uint64_t resolve_id,resolve_deadline;
    bool resolve_pin,resolve_cancelled,resolve_ready,resolved;
    Matter_Resolver_Answer_T answer;
    Matter_Pase_Intervals_T discovered_intervals;
} Connection;
typedef struct {
    struct Matter_Dispatch* owner;
    Matter_Exchange_Handle_T handle; Matter_Exchange_Info_T key;
    Matter_Pase_T pase; Matter_Case_T case_attempt;
    Matter_Im_Read_T read; Matter_Im_Invoke_T invoke; Matter_Im_Write_T write; Matter_Im_Subscribe_T sub;
    Matter_Root_Invoke_Binding_T read_pase;
    Matter_Root_Case_Read_Binding_T read_case;
    Matter_Root_Async_Invoke_Binding_T invoke_pase;
    Matter_Root_Case_Invoke_Binding_T invoke_case;
    Matter_Root_Case_Write_Binding_T write_case;
    Matter_Im_Read_Port_T sub_read; Matter_Im_Read_Fabric_Port_T sub_fabric;
    Admission admission; uint8_t fabric_index; uint32_t subscription_id;
    bool im_busy,draining,delivery_shared;
    uint64_t message; size_t size; uint8_t packet[PACKET];
    uint32_t received_counter; bool has_ack;
    uint8_t timed_target; /* TimedRequest does not yet identify Invoke vs Write. */
    Connection* slot; /* Reserved before successful handshake response, released on every exit. */
    bool busy_reply; uint64_t busy_deadline;
    bool pending,notified,acknowledged,sent,final,closing,operational;
    bool outbound,expiry_reply; /* Only the Invoke which synchronously expired fail-safe. */
    bool im_packet,im_counted,sub_response,sub_established;
} Transaction;
struct Matter_Dispatch {
    Matter_Dispatch_Config_T config; Matter_Udp_T udp; Matter_Rx_T rx;
    Matter_Retransmission_Sender_T tx; Matter_Unsecured_T unsecured;
    Matter_Unsecured_Rx_T ingress; Matter_Unsecured_Tx_T transport;
    Matter_Counter_T counter; Route routes[ROUTES]; Connection connections[CONNECTIONS];
    Transaction transactions[TRANSACTIONS];
    Matter_Udp_Path_T received_path; uint8_t inbox[PACKET],plain[PACKET],ack[PACKET],delivery[PACKET];
    size_t inbox_size; Matter_Rx_Decision_T decision;
    bool queued,delivered,ack_waiting,stopping,stopped,started;
    uint64_t now,request,producer,next_token; uint32_t next_subscription; uint16_t next_id;
    Connection* sending; Matter_Exchange_Session_T ack_token;
    bool completion; Matter_Operation_Result_T outcome;
    bool control; Transaction* control_transaction; /* Non-MRP Busy/CloseSession completion. */
    Transaction* sending_message; /* Pinned by pending MRP send until completion. */
    uint32_t im_sent,subscriptions_established;
    struct {
        uint64_t serial,id,node,resolve,deadline,revision; uint8_t fabric;
        Matter_Im_Client_T client; Matter_Bdx_T bdx; Matter_Exchange_Session_T session;
        bool cancelled,resolve_cancelled,failed,invoked;
        Matter_Udp_Path_T path;
    } outgoing;
};
static void delivery_slot(Transaction*);
static bool handoff(Transaction*);
static void outgoing_process(Matter_Dispatch_T);
static Connection* connection(Matter_Dispatch_T d,Matter_Exchange_Session_T token) {
    for(unsigned i=0;i<CONNECTIONS;++i) if(d->connections[i].token==token) return &d->connections[i];
    return NULL;
}
Matter_Secure_T matter_dispatch_session(Matter_Dispatch_T d,Matter_Exchange_Session_T token) {
    Connection* c=d?connection(d,token):NULL; return c && !c->retiring && !c->removal_reply?c->secure:NULL;
}
static Transaction* transaction(Matter_Dispatch_T d,const Matter_Exchange_Info_T* k) {
    for(unsigned i=0;i<TRANSACTIONS;++i) { Transaction* t=&d->transactions[i];
        if(t->handle && t->key.session==k->session && t->key.exchange_id==k->exchange_id && t->key.initiator==k->initiator) return t;
    } return NULL;
}
static void clear_connection(Connection* c) {
    /* The handshake owns its reservation until handoff or dispose, including
     * failed channel allocation and retirement of the previous incarnation. */
    bool reserved=c->reserved; uint8_t fabric=c->reserved_fabric;
    memset(c,0,sizeof(*c)); c->reserved=reserved; c->reserved_fabric=fabric;
}
/* Only idle CASE sessions are reclaimable. PASE remains owned by fail-safe;
 * live subscriptions, exchanges, ACK/MRP references and borrowed I/O protect a slot. */
static bool idle(Matter_Dispatch_T d,Connection* c,Matter_Secure_Info_T* info) {
    if(!c->token || !c->operational || c->retiring || c->reserved || d->sending==c ||
        matter_secure_info(c->secure,info)!=MATTER_OK || info->closing || info->pins!=1) return false;
    for(unsigned i=0;i<TRANSACTIONS;++i)
        if(d->transactions[i].handle && d->transactions[i].key.session==c->token) return false;
    return true;
}
static Connection* available(Matter_Dispatch_T d) {
    Connection* oldest=NULL; uint64_t timestamp=UINT64_MAX;
    for(unsigned i=0;i<CONNECTIONS;++i) {
        Connection* c=&d->connections[i]; Matter_Secure_Info_T info;
        if(!c->token && !c->reserved) return c;
        if(idle(d,c,&info)) {
            uint64_t used=info.last_sent_ms>info.last_received_ms?info.last_sent_ms:info.last_received_ms;
            if(!oldest || used<timestamp) { oldest=c; timestamp=used; }
        }
    }
    return oldest;
}
/* The index is selected by authenticated CASE before the success response.
 * Never evict another fabric, even when its sessions happen to be idle. */
static Connection* available_for(Matter_Dispatch_T d,uint8_t fabric) {
    unsigned count=0; Connection* empty=NULL; Connection* oldest=NULL; uint64_t timestamp=UINT64_MAX;
    for(unsigned i=0;i<CONNECTIONS;++i) {
        Connection* c=&d->connections[i];
        if(!c->token && !c->reserved) { if(!empty) empty=c; continue; }
        uint8_t index=c->reserved?c->reserved_fabric:(c->operational?c->fabric_index:0);
        if(index!=fabric) continue;
        ++count; Matter_Secure_Info_T info;
        if(fabric && idle(d,c,&info)) {
            uint64_t used=info.last_sent_ms>info.last_received_ms?info.last_sent_ms:info.last_received_ms;
            if(!oldest || used<timestamp) { oldest=c; timestamp=used; }
        }
    }
    return count<(fabric?MATTER_HOST_CASE_PER_FABRIC:1)?empty:oldest;
}
static bool reserve_for(Transaction* t,uint8_t fabric) {
    Matter_Dispatch_T d=t->owner;
    if(t->slot) return !t->slot->token;
    Connection* c=available_for(d,fabric); if(!c) return false;
    if(c->token) {
        if(d->request) return false;
        Matter_Result_T r=matter_secure_channel_send_close(c->channel,d->rx,d->udp,d->now,&d->request);
        if(r!=MATTER_PENDING) return false;
        d->sending=c; d->control=true; d->control_transaction=NULL; d->ack_token=0;
        c->retiring=true;
    }
    c->reserved=true; c->reserved_fabric=fabric; t->slot=c; return !c->token;
}
static bool reserve_session(Transaction* t) {
    return reserve_for(t,t->case_attempt?matter_case_fabric_index(t->case_attempt):0);
}
static void reconcile(Matter_Dispatch_T d) {
    bool reset=d->config.fabric_live && !d->config.fabric_live(d->config.user,0);
    for(unsigned i=0;i<CONNECTIONS;++i) {
        Connection* c=&d->connections[i];
        if(c->token && (reset || (c->operational && d->config.fabric_live && !d->config.fabric_live(d->config.user,c->fabric_index)))) {
            bool waiting=false;
            for(unsigned j=0;j<TRANSACTIONS;++j) {
                Transaction* t=&d->transactions[j];
                if(c->removal_reply && t->handle==c->removal_reply && t->key.session==c->token &&
                    !t->closing && !t->notified && d->now<c->removal_deadline) waiting=true;
            }
            if(!waiting) c->retiring=true;
        }
        if(c->removal_reply) continue;
        if(!c->token || !c->operational || c->retiring || !d->config.credential_revision) continue;
        Matter_Exchange_Session_T invoker=0;
        uint64_t revision=d->config.credential_revision(d->config.user,c->fabric_index,&invoker);
        if(revision==c->credential_revision) continue;
        if(!c->rotating) {
            c->rotating=true;
            /* Root processes the pending credential operation before dispatcher
             * polling. Only the unique pending OC Invoke may deliver its reply. */
            for(unsigned j=0;j<TRANSACTIONS;++j) {
                Transaction* t=&d->transactions[j];
                if(invoker==c->token && t->handle && t->key.session==invoker && !t->closing && t->invoke &&
                    t->invoke_case.pending==matter_root_cluster(d->config.root,0x3e)) c->rotation_reply=t->handle;
            }
        }
        bool waiting=false;
        for(unsigned j=0;j<TRANSACTIONS;++j) {
            Transaction* t=&d->transactions[j];
            if(t->handle && t->handle==c->rotation_reply && t->key.session==c->token && !t->closing && !t->notified) waiting=true;
        }
        if(!waiting) c->retiring=true;
    }
    for(unsigned i=0;i<TRANSACTIONS;++i) {
        Transaction* t=&d->transactions[i]; if(!t->handle) continue;
        Connection* c=connection(d,t->key.session); uint8_t index=matter_case_fabric_index(t->case_attempt);
        bool removal=c && !c->retiring && c->removal_reply==t->handle;
        if((reset && !removal) || (c && (c->retiring || (c->removal_reply && !removal) || (c->rotating && t->handle!=c->rotation_reply))) || (index && d->config.fabric_live && !d->config.fabric_live(d->config.user,index))) t->closing=true;
    }
}
static void resolve_process(Matter_Dispatch_T d) {
    Matter_Resolver_Port_T* p=&d->config.resolver;
    for(unsigned i=0;i<CONNECTIONS;++i) {
        Connection* c=&d->connections[i]; if(!c->resolve_pin) continue;
        if(c->resolve_id) {
            if((c->retiring || d->stopping || d->now>=c->resolve_deadline) && !c->resolve_cancelled) {
                p->cancel(p->user,c->resolve_id); c->resolve_cancelled=true;
            }
            Matter_Operation_Result_T outcome; Matter_Resolver_Answer_T answer;
            if(p->take(p->user,c->resolve_id,&outcome,&answer)!=MATTER_OK) continue;
            c->resolve_id=0;
            if(outcome==MATTER_OPERATION_SUCCEEDED && !c->resolve_cancelled &&
                answer.idle_ms<=3600000 && answer.active_ms<=3600000 && answer.active_threshold_ms<=65535) {
                c->answer=answer; c->resolve_ready=true;
            }
        }
        if(c->resolve_ready && !c->retiring && !d->stopping && d->now<c->resolve_deadline) {
            Matter_Result_T r=matter_secure_channel_route(c->channel,&c->answer.peer);
            if(r==MATTER_BUSY) continue; /* Accepted TX still owns the old path. */
            if(r==MATTER_OK) {
                c->resolved=true;
                c->discovered_intervals=(Matter_Pase_Intervals_T){c->answer.idle_ms,c->answer.active_ms,c->answer.active_threshold_ms};
            }
        }
        c->resolve_ready=c->resolve_pin=false; (void)matter_secure_release(c->secure);
    }
}
static Route* route(Matter_Dispatch_T d,Matter_Exchange_Session_T token) {
    for(unsigned i=0;i<ROUTES;++i) if(d->routes[i].token==token) return &d->routes[i];
    return NULL;
}
static Matter_Result_T retain(void* u,Matter_Exchange_Session_T token) {
    Matter_Dispatch_T d=u; Connection* c=connection(d,token);
    return c?matter_secure_retain(c->secure):matter_unsecured_pin(d->unsecured,token);
}
static void release(void* u,Matter_Exchange_Session_T token) {
    Matter_Dispatch_T d=u; Connection* c=connection(d,token);
    if(c) (void)matter_secure_release(c->secure); else (void)matter_unsecured_unpin(d->unsecured,token);
}
static void detach(void* u) { (void)u; }
static Matter_Result_T random32(void* u,uint32_t* out) {
    Matter_Dispatch_T d=u; Matter_Result_T r=d->config.crypto.random(d->config.crypto.user,(uint8_t*)out,sizeof(*out));
    if(r==MATTER_OK) *out&=0x0fffffff;
    return r;
}
static Matter_Result_T random16(void* u,uint16_t* out) {
    Matter_Dispatch_T d=u; return d->config.crypto.random(d->config.crypto.user,(uint8_t*)out,sizeof(*out));
}
static Matter_Result_T tx_route(void* u,Matter_Exchange_Session_T token,Matter_Udp_Path_T* out) {
    Route* r=route(u,token); if(!r) return MATTER_PORT_ERROR; *out=r->path; return MATTER_OK;
}
static Matter_Result_T process_ack(void* u,const Matter_Exchange_Info_T* k,uint32_t counter) {
    return matter_retransmission_sender_ack(((Matter_Dispatch_T)u)->tx,k,counter);
}
static Matter_Result_T drained(void* u,const Matter_Exchange_Info_T* k) {
    return matter_retransmission_sender_drained(((Matter_Dispatch_T)u)->tx,k);
}
static Matter_Result_T dependencies(void* u) {
    Matter_Dispatch_T d=u;
    if(matter_retransmission_sender_stop(d->tx)!=MATTER_OK || d->request) return MATTER_PENDING;
    if(matter_unsecured_tx_close(d->transport)!=MATTER_OK) return MATTER_PENDING;
    (void)matter_unsecured_rx_stop(d->ingress); d->stopped=true; return MATTER_OK;
}
static void delivered(void* u,const Matter_Rx_Decision_T* in) {
    Matter_Dispatch_T d=u;
    if(d->delivered || in->payload_size>sizeof(d->delivery)) return;
    d->decision=*in; memcpy(d->delivery,in->payload,in->payload_size);
    d->decision.payload=d->delivery; d->delivered=true;
}
static Matter_Result_T tx_retain(void* u,const Matter_Exchange_Info_T* k,const uint8_t* bytes,size_t size) {
    Transaction* t=transaction(u,k);
    if(!t || t->closing || bytes!=t->packet || size!=t->size) return MATTER_PORT_ERROR;
    return retain(u,k->session);
}
static void tx_release(void* u,const Matter_Exchange_Info_T* k,const uint8_t* bytes,size_t size) {
    (void)bytes; (void)size; Transaction* t=transaction(u,k);
    if(t) t->pending=false;
    release(u,k->session);
}
static Matter_Result_T ready(void* u) {
    Matter_Dispatch_T d=u; return d->request || d->ack_waiting?MATTER_WOULD_BLOCK:MATTER_OK;
}
static Matter_Result_T parameters(void* u,const Matter_Retransmission_Message_T* m,uint8_t attempt,Matter_Retransmission_Parameters_T* out) {
    (void)attempt; Matter_Dispatch_T d=u; Connection* c=connection(d,m->exchange.session);
    if(c) {
        if(!c->resolved) return matter_secure_channel_parameters(c->channel,d->now,out);
        Matter_Secure_Info_T info; Matter_Result_T r=matter_secure_info(c->secure,&info); if(r!=MATTER_OK) return r;
        if(info.closing) return MATTER_INVALID_STATE;
        if(d->now<info.last_received_ms) return MATTER_INVALID_ARGUMENT;
        *out=(Matter_Retransmission_Parameters_T){c->discovered_intervals.idle_ms,c->discovered_intervals.active_ms,d->now-info.last_received_ms<c->discovered_intervals.active_threshold_ms};
        return MATTER_OK;
    }
    Transaction* t=transaction(d,&m->exchange); Matter_Pase_Intervals_T p={500,300,4000};
    if(t && t->pase) (void)matter_pase_peer_intervals(t->pase,&p);
    if(t && t->case_attempt) (void)matter_case_peer_intervals(t->case_attempt,&p);
    *out=(Matter_Retransmission_Parameters_T){p.idle_ms,p.active_ms,true}; return MATTER_OK;
}
static Matter_Result_T rediscover(void* u,const Matter_Retransmission_Message_T* m) {
    Matter_Dispatch_T d=u; Connection* c=connection(d,m->exchange.session);
    /* The removed fabric no longer has a DNS identity. Its final reply retries
     * only on the authenticated request's cached route. */
    if(!c || !c->operational || c->retiring || c->removal_reply || c->resolve_pin || !d->config.resolver.start) return MATTER_OK;
    Matter_Resolver_Query_T query={.node_id=c->peer_node}; Matter_Udp_Path_T path;
    if(d->config.compressed_fabric(d->config.user,c->fabric_index,query.compressed_fabric)!=MATTER_OK ||
        matter_secure_channel_path(c->channel,&path)!=MATTER_OK || matter_secure_retain(c->secure)!=MATTER_OK) return MATTER_PORT_ERROR;
    query.interface_id=path.interface_id;
    c->resolve_pin=true; c->resolve_cancelled=false;
    c->resolve_deadline=d->now>UINT64_MAX-5000?UINT64_MAX:d->now+5000;
    if(d->config.resolver.start(d->config.resolver.user,&query,&c->resolve_id)!=MATTER_PENDING) {
        /* Terminal local discovery failure: keep cached route and bounded MRP,
         * rather than indefinitely blocking first retry on an offline resolver. */
        c->resolve_pin=false; (void)matter_secure_release(c->secure);
    }
    return MATTER_OK; /* Resolution runs alongside the retransmission. */
}
static Matter_Retransmission_Submission_T send_message(void* u,const Matter_Retransmission_Request_T* r) {
    Matter_Dispatch_T d=u; Transaction* t=transaction(d,&r->message.exchange);
    if(d->request || !t) return MATTER_RETRANSMISSION_REJECTED_RETRYABLE;
    if(t->closing) return MATTER_RETRANSMISSION_REJECTED_FATAL;
    Connection* c=connection(d,r->message.exchange.session);
    if(c && (c->retiring || (c->removal_reply && c->removal_reply!=t->handle))) return MATTER_RETRANSMISSION_REJECTED_FATAL;
    Matter_Result_T result=c?matter_secure_channel_send(c->channel,d->udp,r->message.data,r->message.size,&d->request):
        matter_unsecured_tx_send(d->transport,r->message.exchange.session,r->message.data,r->message.size,&d->request);
    if(result!=MATTER_PENDING) return result==MATTER_BUSY || result==MATTER_WOULD_BLOCK?
        MATTER_RETRANSMISSION_REJECTED_RETRYABLE:MATTER_RETRANSMISSION_REJECTED_FATAL;
    d->sending=c; d->producer=r->id; d->ack_token=0; d->sending_message=t;
    if(!t->sent) {
        t->sent=true;
        if(t->case_attempt) {
            (void)matter_case_sent(t->case_attempt);
            if(matter_case_state(t->case_attempt)==MATTER_CASE_COMPLETE && !handoff(t)) t->closing=true;
        }
        if(t->invoke) (void)matter_im_invoke_sent_at(t->invoke,d->now);
        if(t->write) (void)matter_im_write_sent_at(t->write,d->now);
        if(t->sub) (void)matter_im_subscribe_sent_at(t->sub,d->now);
        if(t->outbound && !t->case_attempt) {
            if(d->outgoing.bdx) (void)matter_bdx_sent(d->outgoing.bdx,d->now);
            else (void)matter_im_client_sent(d->outgoing.client);
        }
        delivery_slot(t);
    }
    return MATTER_RETRANSMISSION_SUBMITTED;
}
static void cancel_send(void* u,uint64_t id) { (void)u; (void)id; /* UDP owes actual completion. */ }
static void finished(void* u,const Matter_Retransmission_Result_T* result) {
    Transaction* t=transaction(u,&result->message.exchange); if(!t) return;
    t->notified=true; t->acknowledged=result->outcome==MATTER_RETRANSMISSION_ACKNOWLEDGED;
}
static Matter_Result_T send_ack(void* u,uint64_t id,const Matter_Ack_Message_T* m) {
    Matter_Dispatch_T d=u; d->ack_waiting=true; if(d->request) return MATTER_WOULD_BLOCK;
    Connection* c=connection(d,m->exchange.session); Matter_Result_T r;
    Transaction* t=transaction(d,&m->exchange);
    if(c && (c->retiring || (c->removal_reply && (!t || c->removal_reply!=t->handle)))) return MATTER_PORT_ERROR;
    if(c) r=matter_secure_channel_send_ack(c->channel,d->udp,m,d->now,&d->request);
    else {
        Matter_Unsecured_Prepared_T out;
        r=matter_unsecured_prepare_encoded(d->unsecured,m->exchange.session,&d->counter,m->data,m->size,d->ack,sizeof(d->ack),&out);
        if(r!=MATTER_OK) return r;
        r=matter_unsecured_tx_send(d->transport,m->exchange.session,d->ack,out.size,&d->request);
    }
    if(r!=MATTER_PENDING) return r==MATTER_BUSY?MATTER_WOULD_BLOCK:r;
    d->sending=c; d->producer=id; d->ack_token=m->exchange.session; return MATTER_OK;
}
static bool same_path(const Matter_Udp_Path_T* a,const Matter_Udp_Path_T* b) {
    return a->interface_id==b->interface_id && a->peer.port==b->peer.port && a->local.port==b->local.port &&
        !memcmp(a->peer.address,b->peer.address,16) && !memcmp(a->local.address,b->local.address,16);
}
static Matter_Result_T admit(void* u,const Matter_Unsecured_Rx_Message_T* m,bool* create) {
    Matter_Dispatch_T d=u; const Matter_Protocol_Header_T* h=&m->protocol;
    if(h->vendor_id || h->protocol_id) return MATTER_INVALID_ARGUMENT;
    Route* r=m->session?route(d,m->session):NULL;
    if(r && !same_path(&r->path,&m->datagram->path)) return MATTER_INVALID_ARGUMENT;
    bool ack=h->opcode==0x10 && !m->payload_size && (h->exchange_flags&MATTER_PROTOCOL_ACK) && !(h->exchange_flags&MATTER_PROTOCOL_RELIABLE);
    if(ack) return r?MATTER_OK:MATTER_INVALID_STATE;
    if(!(h->exchange_flags&MATTER_PROTOCOL_RELIABLE)) return MATTER_INVALID_ARGUMENT;
    Matter_Exchange_Info_T k={m->session,h->exchange_id,!(h->exchange_flags&MATTER_PROTOCOL_INITIATOR)}; Transaction* t=transaction(d,&k);
    if(t && !t->closing) return ((t->pase && ((h->opcode>=0x20 && h->opcode<=0x24)||h->opcode==0x40)) ||
        (t->case_attempt && ((h->opcode>=0x30 && h->opcode<=0x33)||h->opcode==0x40)))?MATTER_OK:MATTER_INVALID_ARGUMENT;
    /* Completed handshake exchanges are gone, but their unsecured reception
     * window/route still remembers duplicates. Admit control-only RX so MRP
     * can repeat a lost final ACK without constructing another CASE/PASE. */
    if(r && ((h->opcode>=0x20 && h->opcode<=0x24) || (h->opcode>=0x30 && h->opcode<=0x33) || h->opcode==0x40)) {
        bool duplicate=false;
        if(matter_unsecured_pin(d->unsecured,m->session)==MATTER_OK) {
            Matter_Result_T result=matter_unsecured_classify(d->unsecured,m->session,m->message.message_counter,&duplicate);
            (void)matter_unsecured_unpin(d->unsecured,m->session);
            if(result==MATTER_OK && duplicate) { *create=false; return MATTER_OK; }
        }
    }
    if(d->stopping || (d->config.fabric_live && !d->config.fabric_live(d->config.user,0)) || k.initiator || (h->opcode!=0x20 && h->opcode!=0x30)) return MATTER_INVALID_STATE;
    if(!r) {
        Route* oldest=NULL;
        for(unsigned i=0;i<ROUTES;++i) {
            Route* candidate=&d->routes[i]; Matter_Unsecured_Info_T info;
            if(!candidate->token) { oldest=candidate; break; }
            if(matter_unsecured_get(d->unsecured,candidate->token,&info)==MATTER_OK && !info.pins &&
                (!oldest || candidate->touched<oldest->touched)) oldest=candidate;
        }
        if(!oldest) return MATTER_WOULD_BLOCK;
        if(oldest->token) {
            if(matter_unsecured_remove(d->unsecured,oldest->token)!=MATTER_OK) return MATTER_WOULD_BLOCK;
            memset(oldest,0,sizeof(*oldest));
        }
    }
    bool free=false; for(unsigned i=0;i<TRANSACTIONS;++i) free|=!d->transactions[i].handle;
    if(!free) return MATTER_WOULD_BLOCK;
    *create=true; return MATTER_OK;
}
static void accepted(void* u,const Matter_Unsecured_Rx_Message_T* m,bool duplicate) {
    (void)duplicate; Matter_Dispatch_T d=u; Route* r=route(d,m->session);
    if(!r) for(unsigned i=0;i<ROUTES;++i) if(!d->routes[i].token) { r=&d->routes[i]; break; }
    if(r) { r->token=m->session; r->path=m->datagram->path; r->touched=d->now; }
}
void matter_dispatch_received(void* u,const Matter_Udp_Datagram_T* data) {
    Matter_Dispatch_T d=u; if(!d || d->queued || data->size>sizeof(d->inbox)) return;
    memcpy(d->inbox,data->data,data->size); d->inbox_size=data->size; d->received_path=data->path; d->queued=true;
}
void matter_dispatch_sent(void* u,uint64_t request,Matter_Operation_Result_T outcome) {
    Matter_Dispatch_T d=u; if(!d || request!=d->request || d->completion) return;
    d->completion=true; d->outcome=outcome;
}
static void count_sent(Matter_Dispatch_T d,Transaction* t,Matter_Operation_Result_T outcome) {
    if(!t || outcome!=MATTER_OPERATION_SUCCEEDED || !t->im_packet || t->im_counted) return;
    t->im_counted=true;
    if(d->im_sent<UINT32_MAX) ++d->im_sent;
    if(t->sub_response && !t->sub_established && t->subscription_id && !t->closing) {
        t->sub_established=true;
        if(d->subscriptions_established<UINT32_MAX) ++d->subscriptions_established;
    }
}
Matter_Dispatch_Load_T matter_dispatch_load(Matter_Dispatch_T d,uint8_t fabric) {
    Matter_Dispatch_Load_T load={0}; if(!d) return load;
    load.sent=d->im_sent; load.received=matter_rx_im_received(d->rx); load.established=d->subscriptions_established;
    for(unsigned i=0;i<TRANSACTIONS;++i) {
        Transaction* t=&d->transactions[i]; Connection* c=connection(d,t->key.session);
        if(!t->handle || !t->subscription_id || !t->sub_established || t->closing || !c || c->retiring || c->removal_reply) continue;
        if(c->operational && d->config.fabric_live && !d->config.fabric_live(d->config.user,c->fabric_index)) continue;
        if(load.current<UINT16_MAX) ++load.current;
        if(fabric && t->fabric_index==fabric && load.current_for_fabric<UINT16_MAX) ++load.current_for_fabric;
    }
    return load;
}
static Matter_Result_T take_completion(Matter_Dispatch_T d) {
    if(!d->completion) return MATTER_OK;
    Matter_Result_T r;
    if(d->sending) {
        Matter_Secure_Channel_Result_T out;
        r=matter_secure_channel_complete(d->sending->channel,d->request,d->outcome);
        if(r==MATTER_OK) r=matter_secure_channel_take(d->sending->channel,&out);
    } else {
        Matter_Unsecured_Tx_Result_T out;
        r=matter_unsecured_tx_complete(d->transport,d->request,d->outcome);
        if(r==MATTER_OK) r=matter_unsecured_tx_take(d->transport,&out);
    }
    if(r!=MATTER_OK) return r;
    count_sent(d,d->sending_message,d->outcome); d->sending_message=NULL;
    if(d->sending && d->sending->rotating && d->outcome!=MATTER_OPERATION_SUCCEEDED) d->sending->retiring=true;
    d->request=0; d->completion=false; d->sending=NULL;
    if(d->control) {
        if(d->control_transaction) { d->control_transaction->pending=false; d->control_transaction->closing=true; }
        d->control=false; d->control_transaction=NULL; d->ack_token=0; return MATTER_OK;
    }
    if(d->ack_token) r=matter_rx_complete(d->rx,d->producer,d->outcome);
    else r=matter_retransmission_sender_complete(d->tx,d->producer,d->outcome==MATTER_OPERATION_SUCCEEDED?MATTER_RETRANSMISSION_SENT:MATTER_RETRANSMISSION_FATAL);
    d->ack_token=0; return r;
}
/* Subscription callbacks wrap a per-handler Root binding without changing its
 * user pointer or caching authorization/fabric state globally. */
static Matter_Im_Status_T sub_authorize(void* u,Matter_Exchange_Session_T s,const Matter_Im_Path_T* p,Matter_Im_Privilege_T v) {
    Transaction* t=u; return t->sub_read.authorize(t->sub_read.user,s,p,v);
}
static Matter_Im_Status_T sub_describe(void* u,const Matter_Im_Path_T* p,Matter_Im_Attribute_T* a) {
    Transaction* t=u; return t->sub_read.describe(t->sub_read.user,p,a);
}
static Matter_Im_Status_T sub_read(void* u,const Matter_Im_Path_T* p,bool filtered,Matter_Im_Value_T* v) {
    Transaction* t=u; return t->sub_read.read(t->sub_read.user,p,filtered,v);
}
static Matter_Result_T sub_enumerate(void* u,const Matter_Im_Selector_T* q,const Matter_Im_Path_T* after,Matter_Im_Path_T* next,bool* found) {
    Transaction* t=u; return t->sub_read.enumerate(t->sub_read.user,q,after,next,found);
}
static Matter_Result_T sub_version(void* u,const Matter_Im_Path_T* p,uint32_t* version) {
    Transaction* t=u; return t->sub_read.version(t->sub_read.user,p,version);
}
static Matter_Result_T sub_index(void* u,Matter_Exchange_Session_T s,uint8_t* index) {
    Transaction* t=u; return t->sub_fabric.index(t->sub_read.user,s,index);
}
static uint8_t reserve(void* u,Matter_Exchange_Session_T s,bool keep,uint32_t* id) {
    Transaction* t=u; Matter_Dispatch_T d=t->owner;
    Connection* subscriber=connection(d,s);
    if(!subscriber || subscriber->retiring) return MATTER_IM_FAILURE;
    if(d->next_subscription==UINT32_MAX) return MATTER_IM_RESOURCE_EXHAUSTED;
    if(!keep) for(unsigned i=0;i<TRANSACTIONS;++i) {
        Transaction* other=&d->transactions[i]; Connection* peer=connection(d,other->key.session);
        bool same=other->key.session==s;
        if(subscriber->operational && peer && peer->operational)
            same=subscriber->fabric_index==peer->fabric_index && subscriber->peer_node==peer->peer_node;
        if(other!=t && other->sub && same) other->closing=true;
    }
    unsigned count=0;
    for(unsigned i=0;i<TRANSACTIONS;++i) {
        Transaction* other=&d->transactions[i];
        if(other!=t && other->subscription_id && !other->closing && other->fabric_index==t->fabric_index) ++count;
    }
    if(count>=MATTER_HOST_SUBS_PER_FABRIC) return MATTER_IM_RESOURCE_EXHAUSTED;
    *id=t->subscription_id=++d->next_subscription; return MATTER_IM_SUCCESS;
}
static void unreserve(void* u,uint32_t id) {
    Transaction* t=u; if(t->subscription_id==id) { t->subscription_id=0; t->sub_established=false; }
}
static Admission admission(uint16_t protocol,uint8_t opcode) {
    if(!protocol && (opcode==0x20 || opcode==0x30)) return HANDSHAKE;
    if(protocol!=1) return NONE;
    switch(opcode) {
        case 2: return READ; case 3: return SUBSCRIBE; case 6: return WRITE;
        case 8: return INVOKE; case 10: return TIMED; default: return NONE;
    }
}
/* Count even closing handlers: they still own memory/exchanges until drain.
 * A separate replacement slot lets KeepSubscriptions=false reach reserve(). */
static bool admit_work(Matter_Dispatch_T d,Admission kind,uint8_t fabric) {
    unsigned reads=0,subs=0,writes=0,invokes=0,handshakes=0,rejections=0;
    for(unsigned i=0;i<TRANSACTIONS;++i) {
        Transaction* t=&d->transactions[i]; if(!t->handle || t->draining) continue;
        if(t->fabric_index==fabric) { reads+=t->admission==READ; subs+=t->admission==SUBSCRIBE; }
        writes+=t->admission==WRITE || t->admission==TIMED;
        invokes+=t->admission==INVOKE || t->admission==TIMED;
        handshakes+=t->admission==HANDSHAKE; rejections+=t->admission==REJECT;
    }
    switch(kind) {
        case READ: return !reads;
        case SUBSCRIBE: return subs<MATTER_HOST_SUBS_PER_FABRIC+1;
        case WRITE: return writes<MATTER_HOST_WRITES;
        case INVOKE: return invokes<MATTER_HOST_INVOKES;
        case TIMED: return writes<MATTER_HOST_WRITES && invokes<MATTER_HOST_INVOKES;
        case HANDSHAKE: return handshakes<MATTER_HOST_HANDSHAKES;
        case REJECT: return rejections<MATTER_HOST_REJECTIONS;
        default: return false;
    }
}
static void delivery_slot(Transaction* t) {
    if(t->draining || !t->sent) return;
    bool read=t->admission==READ, write=t->admission==WRITE || t->admission==TIMED;
    bool invoke=t->admission==INVOKE || t->admission==TIMED;
    if(!(read || write || invoke) || (read && !matter_im_read_awaiting_delivery(t->read)) ||
        (write && !matter_im_write_awaiting_delivery(t->write)) ||
        (invoke && !matter_im_invoke_awaiting_delivery(t->invoke))) return;
    bool occupied=false; unsigned shared=0;
    for(unsigned i=0;i<TRANSACTIONS;++i) {
        Transaction* other=&t->owner->transactions[i];
        if(!other->handle || !other->draining) continue;
        if(other->delivery_shared) { ++shared; continue; }
        if((read && other->admission==READ && other->fabric_index==t->fabric_index) ||
            (write && (other->admission==WRITE || other->admission==TIMED)) ||
            (invoke && (other->admission==INVOKE || other->admission==TIMED))) occupied=true;
    }
    /* A controller pipelines sequential commands before its delayed standalone
     * ACK. Shared burst capacity supplements, never consumes, reserved tails. */
    if(occupied && shared>=MATTER_HOST_DELIVERY_BURST) return;
    t->draining=true; t->delivery_shared=occupied;
}
static void busy(Transaction* t,bool secure) {
    t->admission=REJECT; t->im_busy=secure; t->busy_reply=!secure;
    t->busy_deadline=t->owner->now>UINT64_MAX-30000?UINT64_MAX:t->owner->now+30000;
}
static void reject_work(Transaction* t,bool reply,bool secure) {
    if(!admit_work(t->owner,REJECT,0)) {
        /* No handler or borrowed TX exists yet. RX owns the remaining ACK/drain. */
        (void)matter_rx_close(t->owner->rx,t->handle); memset(t,0,sizeof(*t)); return;
    }
    if(reply) busy(t,secure);
    else { t->admission=REJECT; t->closing=true; }
}
static bool create_handler(Matter_Dispatch_T d,Transaction* t,uint8_t opcode) {
    Connection* c=connection(d,t->key.session); if(!c || c->retiring || c->rotating || c->removal_reply) return false;
    t->operational=c->operational;
    Matter_Im_Read_Config_T config={t->key,30000,1024,!c->operational};
    Matter_Im_Read_Port_T read; Matter_Im_Read_Fabric_Port_T fabric; Matter_Im_Write_Port_T write;
    if(opcode==2 || opcode==3) {
        Matter_Result_T r=c->operational?matter_root_case_read_port(d->config.root,c->token,c->secure,&t->read_case,&read,&fabric):
            matter_root_fabric_read_port(d->config.root,c->token,&t->read_pase,&read,&fabric);
        if(r!=MATTER_OK) return false;
        if(opcode==2) t->read=c->operational?matter_im_read_new_case(&read,&fabric,&config,d->now):matter_im_read_new_fabric(&read,&fabric,&config,d->now);
        else {
            t->sub_read=read; t->sub_fabric=fabric;
            Matter_Im_Subscribe_Port_T port={{t,sub_authorize,sub_describe,sub_read,
                read.enumerate?sub_enumerate:NULL,read.version?sub_version:NULL},reserve,unreserve};
            Matter_Im_Read_Fabric_Port_T resolver={sub_index};
            t->sub=c->operational?matter_im_subscribe_new_case(&port,&resolver,&config,d->now):matter_im_subscribe_new(&port,&config,d->now);
        }
        if(d->config.events) {
            Matter_Im_Read_Events_Port_T events={d->config.root,d->config.events,matter_root_event_describe};
            if(t->read && matter_im_read_bind_events(t->read,&events)!=MATTER_OK) return false;
            if(t->sub && matter_im_subscribe_bind_events(t->sub,&events)!=MATTER_OK) return false;
            if(t->read && matter_im_read_bind_event_enumerator(t->read,matter_root_event_enumerate)!=MATTER_OK) return false;
            if(t->sub && matter_im_subscribe_bind_event_enumerator(t->sub,matter_root_event_enumerate)!=MATTER_OK) return false;
        }
        return t->read || t->sub;
    }
    if(opcode==6) {
        if(c->operational) {
            if(matter_root_case_write_port(d->config.root,c->token,c->secure,&t->write_case,&write,&fabric)!=MATTER_OK) return false;
            t->write=matter_im_write_new_case(&write,&fabric,&config,d->now);
        } else {
            if(matter_root_ports(d->config.root,&read,&write)!=MATTER_OK) return false;
            t->write=matter_im_write_new(&write,&config,d->now);
        }
        return t->write!=NULL;
    }
    if(opcode==8 || opcode==10) {
        Matter_Im_Invoke_Port_T invoke; Matter_Im_Invoke_Async_Port_T async;
        Matter_Result_T r=c->operational?matter_root_case_invoke_port(d->config.root,c->token,c->secure,&t->invoke_case,&invoke,&async,&fabric):
            matter_root_async_invoke_port(d->config.root,c->token,&t->invoke_pase,&invoke,&async);
        if(r!=MATTER_OK) return false;
        /* AddNOC associates a previously fabricless PASE session during this
         * command. Bootstrap Invoke has no fabric-scoped authority; CASE uses
         * the immutable live resolver. PASE Read resolves its post-AddNOC index. */
        uint8_t index=0;
        if(!c->operational) { fabric.index=matter_root_invoke_fabric; (void)fabric.index(invoke.user,c->token,&index); }
        t->invoke=c->operational?matter_im_invoke_new_case(&invoke,&async,&fabric,&config,d->now):
            index?matter_im_invoke_new_fabric(&invoke,&async,&fabric,&config,d->now):matter_im_invoke_new_async(&invoke,&async,&config,d->now);
        return t->invoke && (opcode!=10 || create_handler(d,t,6));
    }
    return false;
}
static void dispatch(Matter_Dispatch_T d) {
    const Matter_Rx_Decision_T* in=&d->decision;
    Matter_Exchange_Info_T key={in->session,in->header.exchange_id,!(in->header.exchange_flags&MATTER_PROTOCOL_INITIATOR)};
    Transaction* t=transaction(d,&key);
    Connection* revoked=connection(d,key.session);
    /* RX still authenticates/processes MRP ACKs and duplicates, but no IM work
     * may be executed on the reply-only session, even on its existing exchange. */
    if(revoked && revoked->removal_reply) {
        if(!t) (void)matter_rx_close(d->rx,in->exchange);
        return;
    }
    if(!t) {
        for(unsigned i=0;i<TRANSACTIONS;++i) if(!d->transactions[i].handle) { t=&d->transactions[i]; break; }
        if(!t) { (void)matter_rx_close(d->rx,in->exchange); return; }
        t->owner=d; t->key=key; t->handle=in->exchange;
        Connection* c=connection(d,key.session);
        t->fabric_index=c && c->operational?c->fabric_index:0;
        Admission kind=admission(in->header.protocol_id,in->header.opcode);
        if(in->header.vendor_id || key.initiator || !(in->header.exchange_flags&MATTER_PROTOCOL_RELIABLE) ||
            kind==NONE || (in->header.protocol_id==1 && !c) || (!in->header.protocol_id && c)) {
            reject_work(t,false,false); return;
        }
        if(!admit_work(d,kind,t->fabric_index) || (kind==HANDSHAKE && !available(d))) {
            t->received_counter=in->message_counter; t->has_ack=true;
            reject_work(t,true,in->header.protocol_id==1); return;
        }
        t->admission=kind; /* Includes partial construction/failure until disposal. */
        if(in->header.protocol_id==0 && d->next_id) {
            uint16_t id=d->next_id++;
            if(in->header.opcode==0x20 && d->config.pase) t->pase=d->config.pase(d->config.user,id,d->now);
            else if(in->header.opcode==0x30 && d->config.fabrics.load) {
                Matter_Case_Config_T c={.responder=true,.local_session_id=id,.timeout_ms=30000,.time=d->config.time,.resumption_profile=d->config.resumption_profile};
                t->case_attempt=matter_case_new(&d->config.crypto,&d->config.credentials,&d->config.fabrics,&c,d->now);
            }
            t->closing=!t->pase && !t->case_attempt;
        } else if(in->header.protocol_id!=1 || !create_handler(d,t,in->header.opcode)) t->closing=true;
    }
    if(t->closing) return;
    if(t->im_busy || t->busy_reply) return; /* Retransmits must not restart admission. */
    if(in->header.exchange_flags&MATTER_PROTOCOL_RELIABLE) { t->received_counter=in->message_counter; t->has_ack=true; }
    Matter_Result_T r=MATTER_INVALID_ARGUMENT;
    if(t->outbound && !t->case_attempt && d->outgoing.bdx && !in->header.vendor_id &&
        in->action==MATTER_RX_EXISTING && !(in->header.exchange_flags&MATTER_PROTOCOL_INITIATOR) &&
        (in->header.exchange_flags&MATTER_PROTOCOL_RELIABLE)) {
        r=matter_bdx_receive(d->outgoing.bdx,in->header.protocol_id,in->header.opcode,in->payload,in->payload_size,d->now);
    } else if(!in->header.vendor_id && !in->header.protocol_id) {
        if(t->pase) r=matter_pase_receive(t->pase,in->header.opcode,in->payload,in->payload_size);
        if(t->case_attempt) r=matter_case_receive(t->case_attempt,in->header.opcode,in->payload,in->payload_size);
    } else if(!in->header.vendor_id && in->header.protocol_id==1) {
        if(t->outbound && !t->case_attempt && in->action==MATTER_RX_EXISTING &&
            !(in->header.exchange_flags&MATTER_PROTOCOL_INITIATOR) && (in->header.exchange_flags&MATTER_PROTOCOL_RELIABLE))
            r=matter_im_client_receive(d->outgoing.client,in->header.opcode,in->payload,in->payload_size);
        if(t->invoke && t->write && (in->header.opcode==6 || in->header.opcode==8)) t->timed_target=in->header.opcode;
        if(t->read) r=matter_im_read_receive(t->read,in);
        if(t->write && t->timed_target!=8) r=matter_im_write_receive_at(t->write,in,d->now);
        if(t->invoke && t->timed_target!=6) r=matter_im_invoke_receive_at(t->invoke,in,d->now);
        if(t->sub) r=matter_im_subscribe_receive(t->sub,in);
    }
    if(r!=MATTER_OK) t->closing=true;
}
static void confirm(Transaction* t) {
    if(!t->notified) return;
    Connection* c=connection(t->owner,t->key.session);
    if(c && ((c->rotating && c->rotation_reply==t->handle) || c->removal_reply==t->handle)) c->retiring=true;
    t->notified=false; if(!t->acknowledged || t->im_busy) {
        if(t->outbound) t->owner->outgoing.failed=true;
        t->closing=true; return;
    }
    uint64_t now=t->owner->now; Matter_Result_T r=MATTER_OK;
    if(t->read) r=matter_im_read_confirm(t->read,now);
    if(t->write) r=matter_im_write_confirm(t->write,now);
    if(t->invoke) r=matter_im_invoke_confirm(t->invoke,now);
    if(t->sub) r=matter_im_subscribe_confirm(t->sub,now);
    if(t->final && t->pase) r=matter_pase_confirm_delivery(t->pase,now);
    if(t->final && t->case_attempt) r=matter_case_confirm_delivery(t->case_attempt,now);
    if(r!=MATTER_OK) t->closing=true;
}
static bool handoff(Transaction* t) {
    Matter_Dispatch_T d=t->owner; Connection* c=t->slot; Route* r=route(d,t->key.session);
    if(!c || c->token || !r || d->next_token==UINT64_MAX) return false;
    c->secure=t->pase?matter_secure_new(&d->config.crypto,t->pase,d->now):matter_secure_new_case(&d->config.crypto,t->case_attempt,d->now);
    if(!c->secure) return false;
    c->token=d->next_token++; c->operational=t->case_attempt!=NULL;
    if(c->operational) { Matter_Secure_Identity_T id; if(matter_secure_identity(c->secure,&id)==MATTER_OK) { c->fabric_index=id.fabric_index; c->peer_node=id.peer_node_id; } }
    if(c->operational && d->config.credential_revision) {
        Matter_Exchange_Session_T ignored; c->credential_revision=d->config.credential_revision(d->config.user,c->fabric_index,&ignored);
    }
    c->channel=matter_secure_channel_new(c->secure,c->token,&r->path);
    if(!c->channel) { (void)matter_secure_close(c->secure); (void)matter_secure_delete(c->secure); clear_connection(c); return false; }
    if(t->outbound) d->outgoing.session=c->token;
    c->reserved=false; t->slot=NULL; return true;
}
static void dispose(Transaction* t) {
    if(t->outbound) {
        uint8_t status; const uint8_t* body; size_t size; uint64_t bytes;
        if((t->case_attempt && !t->owner->outgoing.session) || (!t->case_attempt &&
            (t->owner->outgoing.bdx?matter_bdx_result(t->owner->outgoing.bdx,&bytes):
            matter_im_client_result(t->owner->outgoing.client,&status,&body,&size))!=MATTER_OK)) t->owner->outgoing.failed=true;
    }
    if(t->slot) t->slot->reserved=false;
    (void)matter_pase_delete(t->pase); (void)matter_case_delete(t->case_attempt);
    if(t->read) { (void)matter_im_read_cancel(t->read); (void)matter_im_read_delete(t->read); }
    if(t->invoke) { (void)matter_im_invoke_cancel(t->invoke); (void)matter_im_invoke_delete(t->invoke); }
    if(t->write) { (void)matter_im_write_cancel(t->write); (void)matter_im_write_delete(t->write); }
    if(t->sub) { (void)matter_im_subscribe_cancel(t->sub); (void)matter_im_subscribe_delete(t->sub); }
    memset(t,0,sizeof(*t));
}
static void process_transaction(Transaction* t) {
    Matter_Dispatch_T d=t->owner; confirm(t);
    delivery_slot(t);
    if((t->busy_reply || t->im_busy) && d->now>=t->busy_deadline) t->closing=true;
    if(!t->pending && t->invoke && t->write && t->timed_target) {
        if(t->timed_target==6) { (void)matter_im_invoke_cancel(t->invoke); (void)matter_im_invoke_delete(t->invoke); t->invoke=NULL; }
        else { (void)matter_im_write_cancel(t->write); (void)matter_im_write_delete(t->write); t->write=NULL; }
        t->admission=t->timed_target==6?WRITE:INVOKE;
    }
    if(t->closing) {
        if(t->pending) { if(!t->busy_reply) (void)matter_retransmission_sender_cancel(d->tx,t->message); return; }
        if(matter_rx_close(d->rx,t->handle)==MATTER_PENDING) return;
        Matter_Exchange_Info_T ignored;
        if(matter_rx_get(d->rx,t->handle,&ignored)==MATTER_OK) return;
        dispose(t); return;
    }
    /* Cleanup gates Root providers, not the authority of an unrelated retained
     * CASE fabric. Queue its IM work until rollback finishes. Retired sessions
     * take the closing path above; the expiry response must still drain. */
    Matter_Root_Fail_Safe_State_T state;
    if(t->operational && !t->expiry_reply && matter_root_fail_safe_state(d->config.root,&state)==MATTER_OK &&
        state==MATTER_ROOT_FAIL_SAFE_CLEANUP) return;
    if(t->busy_reply) {
        if(d->request || t->pending) return;
        /* Core 4.11.1.5: unencrypted BUSY, R=0, same exchange, retry after 500ms.
         * Piggyback ACK is allowed; packet lives until actual UDP completion. */
        const uint8_t busy[10]={8,0,0,0,0,0,4,0,0xf4,1}; size_t n;
        Matter_Protocol_Header_T h={.opcode=0x40,.exchange_id=t->key.exchange_id,
            .exchange_flags=MATTER_PROTOCOL_ACK,.acknowledged_message_counter=t->received_counter};
        Matter_Unsecured_Prepared_T p;
        if(matter_protocol_header_write(&h,d->plain,sizeof(d->plain),&n)!=MATTER_MESSAGE_OK) { t->closing=true; return; }
        memcpy(d->plain+n,busy,sizeof(busy));
        Matter_Result_T r=matter_unsecured_prepare_encoded(d->unsecured,t->key.session,&d->counter,d->plain,n+sizeof(busy),t->packet,sizeof(t->packet),&p);
        if(r==MATTER_OK) r=matter_unsecured_tx_send(d->transport,t->key.session,t->packet,p.size,&d->request);
        if(r==MATTER_PENDING) { d->control=true; d->control_transaction=t; d->sending=NULL; d->ack_token=0; t->pending=true; }
        else if(r!=MATTER_BUSY && r!=MATTER_WOULD_BLOCK) t->closing=true;
        return;
    }
    Matter_Result_T r=MATTER_OK; Matter_Im_Read_Message_T out={0}; Matter_Pase_Message_T hs={0};
    /* StatusResponse {Status=BUSY(0x9c), InteractionModelRevision=13}. Reliable
     * encrypted TX uses the normal MRP lifecycle and bounded rejection slots. */
    static const uint8_t im_busy[]={0x15,0x24,0,0x9c,0x24,0xff,MATTER_IM_REVISION,0x18};
    if(t->im_busy) out=(Matter_Im_Read_Message_T){im_busy,sizeof(im_busy),1};
    if(t->pase) { r=matter_pase_process(t->pase,d->now); if(matter_pase_state(t->pase)==MATTER_PASE_COMPLETE) { (void)handoff(t); t->closing=true; return; }
        if(matter_pase_output(t->pase,&hs)==MATTER_OK) out=(Matter_Im_Read_Message_T){hs.data,hs.size,hs.opcode}; }
    if(t->case_attempt) { r=matter_case_process(t->case_attempt,d->now); if(matter_case_state(t->case_attempt)==MATTER_CASE_COMPLETE) {
            /* Activate after first transport submission, not its ACK. Keep the
             * final immutable MRP packet alive while secure IM runs separately.
             * slot becomes NULL on handoff, so retries cannot install twice. */
            if(t->final && !t->sent) return;
            if(t->slot && !handoff(t)) { t->closing=true; return; }
            t->closing=!t->pending; return;
        }
        if(matter_case_output(t->case_attempt,&hs)==MATTER_OK) out=(Matter_Im_Read_Message_T){hs.data,hs.size,hs.opcode}; }
    if(t->read) { r=matter_im_read_process(t->read,d->now); (void)matter_im_read_output(t->read,&out); if(matter_im_read_state(t->read)==MATTER_IM_READ_COMPLETE) t->closing=true; }
    if(t->write) { r=matter_im_write_process(t->write,d->now); (void)matter_im_write_output(t->write,&out); if(matter_im_write_state(t->write)==MATTER_IM_WRITE_COMPLETE) t->closing=true; }
    if(t->invoke) {
        Connection* c=connection(d,t->key.session);
        bool live=c && c->operational && d->config.fabric_live && d->config.fabric_live(d->config.user,c->fabric_index);
        Matter_Root_Fail_Safe_State_T before,after;
        bool armed=matter_root_fail_safe_state(d->config.root,&before)==MATTER_OK && before==MATTER_ROOT_FAIL_SAFE_ARMED;
        r=matter_im_invoke_process(t->invoke,d->now); (void)matter_im_invoke_output(t->invoke,&out);
        /* ArmFailSafe(0) expires synchronously, but cleanup runs at the next
         * owner process pass. Capture causality before cleanup retires PASE or
         * the pending fabric. An unrelated pending Invoke gets no exemption. */
        if(armed && out.data && out.opcode==9 &&
            matter_root_fail_safe_state(d->config.root,&after)==MATTER_OK && after==MATTER_ROOT_FAIL_SAFE_CLEANUP)
            t->expiry_reply=true;
        /* RemoveFabric is synchronous in the owner: capture only the exchange
         * which actually revoked its own live identity, never an unrelated
         * Invoke pending when another caller removes a fabric or resets it. */
        if(live && !d->config.fabric_live(d->config.user,c->fabric_index) && out.data && out.opcode==9) {
            c->removal_reply=t->handle;
            c->removal_deadline=d->now>UINT64_MAX-30000?UINT64_MAX:d->now+30000;
        }
        if(matter_im_invoke_state(t->invoke)==MATTER_IM_INVOKE_COMPLETE) t->closing=true;
    }
    if(t->sub) {
        r=matter_im_subscribe_process(t->sub,d->now);
        if(matter_im_subscribe_state(t->sub)==MATTER_IM_SUB_NEED_EXCHANGE && !t->pending) {
            Matter_Exchange_Info_T ignored; (void)matter_rx_close(d->rx,t->handle);
            if(matter_rx_get(d->rx,t->handle,&ignored)!=MATTER_OK && matter_rx_initiate(d->rx,t->key.session,&t->handle)==MATTER_OK &&
                matter_rx_get(d->rx,t->handle,&t->key)==MATTER_OK) { t->has_ack=false; r=matter_im_subscribe_bind_report(t->sub,&t->key,d->now); }
        }
        (void)matter_im_subscribe_output(t->sub,&out);
    }
    Matter_Bdx_Message_T bdx_out={0};
    if(t->outbound && !t->case_attempt && d->outgoing.bdx) {
        uint64_t bytes; r=matter_bdx_process(d->outgoing.bdx,d->now);
        if(matter_bdx_result(d->outgoing.bdx,&bytes)!=MATTER_PENDING) { if(!t->pending) t->closing=true; }
        else if(matter_bdx_output(d->outgoing.bdx,&bdx_out)==MATTER_OK)
            out=(Matter_Im_Read_Message_T){bdx_out.data,bdx_out.size,bdx_out.opcode};
    }
    if(t->outbound && !t->case_attempt && !d->outgoing.bdx) {
        uint8_t status; const uint8_t* body; size_t size;
        if(matter_im_client_result(d->outgoing.client,&status,&body,&size)==MATTER_OK) {
            /* A validated reply may require our reliable StatusResponse. Keep
             * its immutable MRP packet until ACK/failure, not just first send. */
            if(!t->pending) t->closing=true;
        }
        else (void)matter_im_client_output(d->outgoing.client,&out);
    }
    if(r!=MATTER_OK && r!=MATTER_PENDING && r!=MATTER_WOULD_BLOCK) { t->closing=true; return; }
    reconcile(d); /* Only the captured removal/rotation response may drain. */
    if(t->closing || t->pending || !out.data) return;
    if(t->pase || t->case_attempt) {
        static const uint8_t success[8]={0};
        bool authenticated=(out.opcode==0x40 && out.size==8 && !memcmp(out.data,success,8)) ||
            (t->case_attempt && out.opcode==0x33);
        if(authenticated && !reserve_session(t)) {
            if(!t->slot && !available_for(d,t->case_attempt?matter_case_fabric_index(t->case_attempt):0)) {
                /* Authentication succeeded but this fabric's protected quota
                 * is full. Do not wait silently for a handshake timeout. */
                if(admit_work(d,REJECT,0)) busy(t,false); else t->closing=true;
            }
            return;
        }
    }
    Matter_Protocol_Header_T h={.protocol_id=(t->pase || t->case_attempt)?0:bdx_out.data?bdx_out.protocol:1,.opcode=out.opcode,.exchange_id=t->key.exchange_id,
        .exchange_flags=MATTER_PROTOCOL_RELIABLE|(t->key.initiator?MATTER_PROTOCOL_INITIATOR:0)|
            (t->has_ack?MATTER_PROTOCOL_ACK:0),.acknowledged_message_counter=t->received_counter};
    size_t n; if(matter_protocol_header_write(&h,d->plain,sizeof(d->plain),&n)!=MATTER_MESSAGE_OK || out.size>sizeof(d->plain)-n) { t->closing=true; return; }
    memcpy(d->plain+n,out.data,out.size); n+=out.size; uint32_t counter; Connection* c=connection(d,t->key.session);
    if(c) { Matter_Secure_Prepared_T p; r=matter_secure_channel_prepare(c->channel,d->plain,n,d->now,t->packet,sizeof(t->packet),&p); t->size=r==MATTER_OK?p.size:0; counter=r==MATTER_OK?p.counter:0; }
    else { Matter_Unsecured_Prepared_T p; r=matter_unsecured_prepare_encoded(d->unsecured,t->key.session,&d->counter,d->plain,n,t->packet,sizeof(t->packet),&p); t->size=r==MATTER_OK?p.size:0; counter=r==MATTER_OK?p.counter:0; }
    if(r!=MATTER_OK) { t->closing=true; return; }
    r=matter_retransmission_sender_add(d->tx,&t->key,counter,t->packet,t->size,&t->message);
    if(r!=MATTER_OK) { t->closing=true; return; }
    t->pending=true; t->sent=false; t->final=out.opcode==0x40;
    t->im_packet=h.protocol_id==1; t->im_counted=false; t->sub_response=t->sub && out.opcode==4;
    if(t->pase) (void)matter_pase_sent(t->pase);
    if(t->read) (void)matter_im_read_sent(t->read);
}
static bool keep_expiry_reply(Matter_Dispatch_T d,Connection* c) {
    if(c->retiring) return false;
    for(unsigned i=0;i<TRANSACTIONS;++i) {
        Transaction* t=&d->transactions[i];
        if(!t->handle || t->key.session!=c->token || !t->expiry_reply || t->closing || t->notified) continue;
        /* Core 11.10.7.2.2 clears the session context before rollback. Finish
         * the response's local UDP operation, not its peer ACK: a commissioner
         * can evict PASE immediately after reading ArmFailSafeResponse. */
        if(t->sent && d->sending!=c) return false;
        if(!c->removal_reply) {
            c->removal_reply=t->handle;
            c->removal_deadline=d->now>UINT64_MAX-30000?UINT64_MAX:d->now+30000;
        }
        return c->removal_reply==t->handle && d->now<c->removal_deadline;
    }
    return false;
}
Matter_Result_T matter_dispatch_retire(Matter_Dispatch_T d,bool all) {
    if(!d) return MATTER_OK;
    bool pending=false;
    if(!all) for(unsigned i=0;i<CONNECTIONS;++i) {
        Connection* c=&d->connections[i];
        if(c->token && !c->operational) (void)keep_expiry_reply(d,c);
    }
    for(unsigned i=0;i<TRANSACTIONS;++i) {
        Transaction* t=&d->transactions[i];
        Connection* c=connection(d,t->key.session);
        if(t->handle && (all || t->pase || (c && !t->operational))) {
            if(!all && c && c->removal_reply==t->handle && keep_expiry_reply(d,c)) continue;
            t->closing=true;
            pending=true;
        }
    }
    for(unsigned i=0;i<CONNECTIONS;++i) {
        Connection* c=&d->connections[i]; if(!c->token || (!all && c->operational)) continue;
        if(!all && keep_expiry_reply(d,c)) { pending=true; continue; }
        c->retiring=true;
        if(matter_secure_channel_retire(c->channel,d->rx,d->tx)!=MATTER_OK) { pending=true; continue; }
        bool borrowed=false; for(unsigned j=0;j<TRANSACTIONS;++j) borrowed|=d->transactions[j].handle && d->transactions[j].key.session==c->token;
        if(borrowed || d->sending==c) { pending=true; continue; }
        if(matter_secure_channel_delete(c->channel)!=MATTER_OK) { pending=true; continue; }
        (void)matter_secure_delete(c->secure); clear_connection(c);
    }
    return pending?MATTER_PENDING:MATTER_OK;
}
Matter_Result_T matter_dispatch_retire_fabric(Matter_Dispatch_T d,uint8_t index) {
    if(!d || !index) return MATTER_OK;
    bool pending=false;
    for(unsigned i=0;i<CONNECTIONS;++i) {
        Connection* c=&d->connections[i];
        if(c->token && c->operational && c->fabric_index==index) {
            if(!keep_expiry_reply(d,c)) c->retiring=true;
            pending=true;
        }
    }
    for(unsigned i=0;i<TRANSACTIONS;++i) {
        Transaction* t=&d->transactions[i]; Connection* c=connection(d,t->key.session);
        if(t->handle && ((c && c->fabric_index==index) || matter_case_fabric_index(t->case_attempt)==index)) {
            if(c && c->removal_reply==t->handle && keep_expiry_reply(d,c)) continue;
            t->closing=true;
            pending=true;
        }
    }
    return pending?MATTER_PENDING:MATTER_OK;
}
void matter_dispatch_changed(Matter_Dispatch_T d) {
    if(d) for(unsigned i=0;i<TRANSACTIONS;++i) if(d->transactions[i].sub) {
        (void)matter_im_subscribe_changed(d->transactions[i].sub); (void)matter_im_subscribe_events_changed(d->transactions[i].sub);
    }
}
bool matter_dispatch_removal_pending(Matter_Dispatch_T d) {
    if(d) for(unsigned i=0;i<CONNECTIONS;++i)
        if(d->connections[i].token && d->connections[i].removal_reply && !d->connections[i].retiring) return true;
    return false;
}
Matter_Result_T matter_dispatch_process(Matter_Dispatch_T d,uint64_t now) {
    if(!d || now<d->now) return MATTER_INVALID_ARGUMENT;
    d->now=now; Matter_Result_T result=take_completion(d); if(result!=MATTER_OK) return result;
    reconcile(d);
    resolve_process(d);
    outgoing_process(d);
    if(d->queued) {
        Matter_Message_Header_T header; size_t consumed;
        if(matter_message_header_read(d->inbox,d->inbox_size,&header,&consumed)==MATTER_MESSAGE_OK) {
            Matter_Udp_Datagram_T packet={d->received_path,d->inbox,d->inbox_size};
            if(!header.session_id) (void)matter_unsecured_rx_receive(d->ingress,&packet,now);
            else for(unsigned i=0;i<CONNECTIONS;++i) {
                Connection* c=&d->connections[i]; Matter_Secure_Info_T info;
                if(c->secure && !c->retiring && matter_secure_info(c->secure,&info)==MATTER_OK && info.local_session_id==header.session_id) {
                    (void)matter_secure_channel_receive(c->channel,d->rx,&packet,now,now);
                    bool closed=false; (void)matter_secure_channel_is_closed(c->channel,&closed); c->retiring|=closed; break;
                }
            }
        }
        d->queued=false;
    }
    d->ack_waiting=false; (void)matter_rx_process(d->rx,now);
    if(d->delivered) { if(!d->stopping) dispatch(d); d->delivered=false; }
    for(unsigned i=0;i<TRANSACTIONS;++i) if(d->transactions[i].handle) process_transaction(&d->transactions[i]);
    (void)matter_retransmission_sender_process(d->tx,now);
    for(unsigned i=0;i<CONNECTIONS;++i) { Connection* c=&d->connections[i]; if(c->retiring) {
        for(unsigned j=0;j<TRANSACTIONS;++j) if(d->transactions[j].handle && d->transactions[j].key.session==c->token) d->transactions[j].closing=true;
        bool borrowed=false; for(unsigned j=0;j<TRANSACTIONS;++j) borrowed|=d->transactions[j].handle && d->transactions[j].key.session==c->token;
        if(matter_secure_channel_retire(c->channel,d->rx,d->tx)==MATTER_OK && !borrowed && d->sending!=c &&
            matter_secure_channel_delete(c->channel)==MATTER_OK) {
            (void)matter_secure_delete(c->secure); clear_connection(c);
        }
    } }
    for(unsigned i=0;i<ROUTES;++i) { Route* r=&d->routes[i]; Matter_Unsecured_Info_T info;
        if(r->token && (d->stopping || now-r->touched>=60000) && matter_unsecured_get(d->unsecured,r->token,&info)==MATTER_OK && !info.pins) {
            (void)matter_unsecured_remove(d->unsecured,r->token); memset(r,0,sizeof(*r));
        }
    }
    if(d->stopping) (void)matter_dispatch_retire(d,true);
    return d->stopped?MATTER_OK:MATTER_PENDING;
}
Matter_Result_T matter_dispatch_stop(Matter_Dispatch_T d) {
    if(!d) return MATTER_OK;
    d->stopping=true;
    for(unsigned i=0;i<TRANSACTIONS;++i) if(d->transactions[i].handle) d->transactions[i].closing=true;
    (void)matter_unsecured_rx_close(d->ingress);
    /* Retirement needs live RX tables. Finish it before service-wide RX stop. */
    if(!d->stopped && matter_dispatch_retire(d,true)!=MATTER_OK) return MATTER_PENDING;
    if(d->started) (void)matter_rx_stop(d->rx); else d->stopped=true;
    if(!d->stopped) return MATTER_PENDING;
    for(unsigned i=0;i<TRANSACTIONS;++i) if(d->transactions[i].handle) return MATTER_PENDING;
    for(unsigned i=0;i<CONNECTIONS;++i) if(d->connections[i].token) return MATTER_PENDING;
    return MATTER_OK;
}
Matter_Result_T matter_dispatch_delete(Matter_Dispatch_T d) {
    if(!d) return MATTER_OK;
    if(!d->stopped || d->request || d->outgoing.resolve) return MATTER_BUSY;
    for(unsigned i=0;i<TRANSACTIONS;++i) if(d->transactions[i].handle) return MATTER_BUSY;
    if(matter_dispatch_retire(d,true)!=MATTER_OK) return MATTER_BUSY;
    (void)matter_retransmission_sender_stop(d->tx);
    (void)matter_retransmission_sender_delete(d->tx);
    (void)matter_unsecured_rx_stop(d->ingress); (void)matter_unsecured_rx_delete(d->ingress);
    (void)matter_unsecured_tx_close(d->transport); (void)matter_unsecured_tx_delete(d->transport);
    (void)matter_rx_delete(d->rx);
    matter_im_client_delete(d->outgoing.client);
    matter_bdx_delete(d->outgoing.bdx);
    for(unsigned i=0;i<ROUTES;++i) if(d->routes[i].token) (void)matter_unsecured_remove(d->unsecured,d->routes[i].token);
    (void)matter_unsecured_delete(d->unsecured); memset(d,0,sizeof(*d)); free(d); return MATTER_OK;
}
Matter_Dispatch_T matter_dispatch_new(Matter_T owner,Matter_Udp_T udp,const Matter_Dispatch_Config_T* config) {
    if(!owner || !udp || !config || !config->root || !config->crypto.random ||
        (config->resumption_profile!=MATTER_CASE_RESUMPTION_SPEC && config->resumption_profile!=MATTER_CASE_RESUMPTION_CHIP)) return NULL;
    if(config->resolver.start && (!config->resolver.take || !config->resolver.cancel || !config->compressed_fabric)) return NULL;
    Matter_Dispatch_T d=calloc(1,sizeof(*d)); if(!d) return NULL;
    d->config=*config; d->udp=udp; d->next_id=1; d->next_token=UINT64_C(0x100000000);
    d->unsecured=matter_unsecured_new(1,UINT32_MAX);
    Matter_Retransmission_Port_T tp={d,tx_retain,tx_release,ready,parameters,random16,rediscover,send_message,cancel_send,finished,detach};
    d->tx=matter_retransmission_sender_new(5,&tp);
    Matter_Rx_Port_T rp={d,{d,send_ack,detach},retain,release,process_ack,drained,delivered,dependencies};
    uint16_t seed;
    if(random16(d,&seed)!=MATTER_OK) goto fail;
    d->rx=matter_rx_new(owner,seed,&rp);
    Matter_Unsecured_Rx_Port_T ip={d,admit,accepted,detach}; d->ingress=matter_unsecured_rx_new(d->rx,d->unsecured,&ip);
    Matter_Unsecured_Tx_Port_T up={d,tx_route,detach}; d->transport=matter_unsecured_tx_new(udp,d->unsecured,&up);
    if(!d->unsecured || !d->tx || !d->rx || !d->ingress || !d->transport ||
        matter_counter_init(&d->counter,MATTER_COUNTER_UNSECURED,random32,d)!=MATTER_OK ||
        matter_rx_register(d->rx,0,0)!=MATTER_OK || matter_rx_register(d->rx,0,1)!=MATTER_OK || matter_rx_register(d->rx,0,2)!=MATTER_OK || matter_rx_start(d->rx)!=MATTER_OK) goto fail;
    d->started=true; return d;
fail:
    d->stopped=true; (void)matter_dispatch_delete(d); return NULL;
}
static Matter_Result_T random64(void* u,uint64_t* value) {
    Matter_Dispatch_T d=u; return d->config.crypto.random(d->config.crypto.user,(uint8_t*)value,sizeof(*value));
}
static bool outgoing_transactions(Matter_Dispatch_T d) {
    for(unsigned i=0;i<TRANSACTIONS;++i) if(d->transactions[i].handle && d->transactions[i].outbound) return true;
    return false;
}
static Matter_Result_T outgoing_start(Matter_Dispatch_T d,uint8_t fabric,uint64_t node,
    Matter_Im_Client_T client,Matter_Bdx_T bdx,uint64_t* id) {
    if(!d || !id || !fabric || fabric==255 || !node || node>UINT64_C(0xffffffefffffffff)) return MATTER_INVALID_ARGUMENT;
    if(d->stopping || !d->config.fabric_live || !d->config.fabric_live(d->config.user,fabric) ||
        !d->config.credential_revision) return MATTER_INVALID_STATE;
    if(d->outgoing.id) return MATTER_BUSY;
    if(d->outgoing.serial==UINT64_MAX) return MATTER_LIMIT_REACHED;
    matter_im_client_delete(d->outgoing.client); matter_bdx_delete(d->outgoing.bdx);
    uint64_t serial=d->outgoing.serial+1; memset(&d->outgoing,0,sizeof(d->outgoing));
    d->outgoing.client=client; d->outgoing.bdx=bdx; d->outgoing.serial=d->outgoing.id=serial;
    d->outgoing.fabric=fabric; d->outgoing.node=node; d->outgoing.path=d->config.outbound;
    d->outgoing.deadline=d->now>UINT64_MAX-60000?UINT64_MAX:d->now+60000;
    Matter_Exchange_Session_T ignored;
    d->outgoing.revision=d->config.credential_revision(d->config.user,fabric,&ignored);
    for(unsigned i=0;i<CONNECTIONS;++i) {
        Connection* c=&d->connections[i];
        if(c->token && c->operational && !c->reserved && !c->retiring && !c->rotating && !c->removal_reply &&
            c->fabric_index==fabric && c->peer_node==node) { d->outgoing.session=c->token; break; }
    }
    if(!d->outgoing.session) {
        Matter_Resolver_Query_T q={.node_id=node,.interface_id=d->config.outbound.interface_id};
        if(!q.interface_id || !d->config.outbound.local.port || !d->config.resolver.start ||
            d->config.compressed_fabric(d->config.user,fabric,q.compressed_fabric)!=MATTER_OK ||
            d->config.resolver.start(d->config.resolver.user,&q,&d->outgoing.resolve)!=MATTER_PENDING) d->outgoing.failed=true;
    }
    *id=serial; return MATTER_PENDING;
}
Matter_Result_T matter_dispatch_invoke(Matter_Dispatch_T d,uint8_t fabric,uint64_t node,
    const Matter_Im_Command_Path_T* path,uint32_t response,const uint8_t* fields,size_t size,uint64_t* id) {
    Matter_Im_Client_T client=matter_im_client_new(path,response,fields,size); if(!client) return MATTER_LIMIT_REACHED;
    Matter_Result_T r=outgoing_start(d,fabric,node,client,NULL,id);
    if(r!=MATTER_PENDING) matter_im_client_delete(client);
    return r;
}
Matter_Result_T matter_dispatch_bdx(Matter_Dispatch_T d,uint8_t fabric,uint64_t node,
    const uint8_t* fd,size_t size,const Matter_Bdx_Sink_T* sink,uint64_t limit,uint64_t* id) {
    if(!d) return MATTER_INVALID_ARGUMENT;
    Matter_Bdx_T b=matter_bdx_new(fd,size,1024,limit,sink,d->now); if(!b) return MATTER_LIMIT_REACHED;
    Matter_Result_T r=outgoing_start(d,fabric,node,NULL,b,id);
    if(r!=MATTER_PENDING) matter_bdx_delete(b);
    return r;
}
Matter_Result_T matter_dispatch_bdx_take(Matter_Dispatch_T d,uint64_t id,uint64_t* bytes) {
    if(!d || !id || id!=d->outgoing.id || !bytes || !d->outgoing.bdx) return MATTER_INVALID_ARGUMENT;
    if(d->outgoing.resolve || outgoing_transactions(d)) return MATTER_PENDING;
    /* Fabric may have changed in the last dispatched command after the job's
     * process pass. Recheck before allowing publication of staged bytes. */
    Matter_Exchange_Session_T ignored;
    if(d->stopping || !d->config.fabric_live(d->config.user,d->outgoing.fabric) ||
        d->config.credential_revision(d->config.user,d->outgoing.fabric,&ignored)!=d->outgoing.revision) d->outgoing.failed=true;
    if(d->outgoing.failed || d->outgoing.cancelled) matter_bdx_cancel(d->outgoing.bdx);
    Matter_Result_T r=matter_bdx_result(d->outgoing.bdx,bytes);
    if(r!=MATTER_PENDING) d->outgoing.id=0;
    return r;
}
void matter_dispatch_invoke_cancel(Matter_Dispatch_T d,uint64_t id) {
    if(d && id && id==d->outgoing.id) d->outgoing.cancelled=true;
}
Matter_Result_T matter_dispatch_invoke_take(Matter_Dispatch_T d,uint64_t id,uint8_t* status,const uint8_t** fields,size_t* size) {
    if(!d || !id || id!=d->outgoing.id || !status || !fields || !size) return MATTER_INVALID_ARGUMENT;
    if(d->outgoing.resolve || outgoing_transactions(d)) return MATTER_PENDING;
    Matter_Exchange_Session_T ignored;
    if(d->stopping || !d->config.fabric_live(d->config.user,d->outgoing.fabric) ||
        d->config.credential_revision(d->config.user,d->outgoing.fabric,&ignored)!=d->outgoing.revision) d->outgoing.failed=true;
    Matter_Result_T r=(d->outgoing.failed || d->outgoing.cancelled)?MATTER_PORT_ERROR:
        matter_im_client_result(d->outgoing.client,status,fields,size);
    if(r!=MATTER_PENDING) d->outgoing.id=0;
    return r;
}
static void outgoing_process(Matter_Dispatch_T d) {
    if(!d->outgoing.id) return;
    Matter_Exchange_Session_T ignored;
    if(d->stopping || ((!d->outgoing.bdx || !d->outgoing.invoked) && d->now>=d->outgoing.deadline) || !d->config.fabric_live(d->config.user,d->outgoing.fabric) ||
        d->config.credential_revision(d->config.user,d->outgoing.fabric,&ignored)!=d->outgoing.revision) d->outgoing.failed=true;
    bool stop=d->outgoing.failed || d->outgoing.cancelled;
    if(d->outgoing.resolve) {
        if(stop && !d->outgoing.resolve_cancelled) {
            d->config.resolver.cancel(d->config.resolver.user,d->outgoing.resolve); d->outgoing.resolve_cancelled=true;
        }
        Matter_Operation_Result_T outcome; Matter_Resolver_Answer_T answer;
        Matter_Result_T r=d->config.resolver.take(d->config.resolver.user,d->outgoing.resolve,&outcome,&answer);
        if(r==MATTER_PENDING) return;
        d->outgoing.resolve=0;
        if(r!=MATTER_OK || outcome!=MATTER_OPERATION_SUCCEEDED) d->outgoing.failed=stop=true;
        else d->outgoing.path.peer=answer.peer;
    }
    if(stop) {
        for(unsigned i=0;i<TRANSACTIONS;++i) if(d->transactions[i].outbound) d->transactions[i].closing=true;
        return;
    }
    if(d->outgoing.invoked) return;
    if(!d->outgoing.session && outgoing_transactions(d)) return;
    Transaction* t=NULL;
    for(unsigned i=0;i<TRANSACTIONS;++i) if(!d->transactions[i].handle) { t=&d->transactions[i]; break; }
    if(!t) return;
    if(d->outgoing.session) {
        Connection* c=connection(d,d->outgoing.session);
        if(!c || c->retiring || c->rotating || c->removal_reply) { d->outgoing.failed=true; return; }
        Matter_Exchange_Handle_T handle;
        if(matter_rx_initiate(d->rx,c->token,&handle)!=MATTER_OK) return;
        *t=(Transaction){.owner=d,.handle=handle,.admission=CLIENT,.fabric_index=c->fabric_index,.operational=true,.outbound=true};
        (void)matter_rx_get(d->rx,handle,&t->key); d->outgoing.invoked=true; return;
    }
    if(!admit_work(d,HANDSHAKE,0) || !d->next_id) return;
    Connection* c=available_for(d,d->outgoing.fabric);
    /* Never evict a protected or active connection to start an optional query. */
    if(!c || c->token || c->reserved) return;
    Route* route_slot=NULL; for(unsigned i=0;i<ROUTES;++i) if(!d->routes[i].token) { route_slot=&d->routes[i]; break; }
    if(!route_slot) return;
    Matter_Exchange_Session_T token;
    if(matter_unsecured_initiate(d->unsecured,random64,d,&token)!=MATTER_OK) { d->outgoing.failed=true; return; }
    *route_slot=(Route){token,d->outgoing.path,d->now};
    Matter_Exchange_Handle_T handle;
    if(matter_rx_initiate(d->rx,token,&handle)!=MATTER_OK) {
        (void)matter_unsecured_remove(d->unsecured,token); memset(route_slot,0,sizeof(*route_slot)); return;
    }
    *t=(Transaction){.owner=d,.handle=handle,.admission=HANDSHAKE,.outbound=true,.slot=c};
    (void)matter_rx_get(d->rx,handle,&t->key); c->reserved=true; c->reserved_fabric=d->outgoing.fabric;
    Matter_Case_Config_T config={.responder=false,.local_session_id=d->next_id++,.timeout_ms=30000,
        .fabric_index=d->outgoing.fabric,.peer_node_id=d->outgoing.node,.time=d->config.time,.resumption_profile=d->config.resumption_profile};
    t->case_attempt=matter_case_new(&d->config.crypto,&d->config.credentials,&d->config.fabrics,&config,d->now);
    if(!t->case_attempt) t->closing=true;
}

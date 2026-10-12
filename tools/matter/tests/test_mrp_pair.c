#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "transport/matter_rx.h"
#include "transport/matter_retransmission_sender.h"
#include "transport/matter_unsecured.h"
#include "transport/matter_unsecured_rx.h"
#include "transport/matter_counter.h"
#include "transport/matter_unsecured_prepare.h"
#ifdef MATTER_TEST_HOST_UDP
#include <windows.h>
#include "matter_udp_windows.h"
#include "transport/matter_unsecured_tx.h"
#endif

/* Deterministic trusted link; optional real UDP, never authentication.
 * All packet storage and module contexts live on the heap, in one owner thread.
 */
#ifdef MATTER_TEST_ALLOC
static size_t live, calls, fail_at;
#ifdef MATTER_TEST_PASE
static void* last_alloc;
static size_t last_alloc_size, pase_wiped;
static struct { void* p; size_t size; } pase_allocations[2];
#endif
void* matter_test_calloc(size_t n, size_t size) {
    ++calls;
    if (calls == fail_at) return NULL;
    void* p = calloc(n, size);
    if (p) ++live;
#ifdef MATTER_TEST_PASE
    last_alloc = p; last_alloc_size = n * size;
#endif
    return p;
}
void matter_test_free(void* p) {
#ifdef MATTER_TEST_PASE
    if (p) for (unsigned i=0;i<2;++i) if (pase_allocations[i].p == p) {
        for (size_t j=0;j<pase_allocations[i].size;++j) if (((uint8_t*)p)[j]) abort();
        pase_allocations[i].p = NULL; ++pase_wiped;
    }
#endif
    if (p) { if (!live) abort(); --live; } free(p);
}
#endif
#define REQUIRE(c) do { if (!(c)) { fprintf(stderr, "fixture:%d: %s\n", __LINE__, #c); abort(); } } while (0)
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: %s\n", __func__, __LINE__, #c); goto done; } } while (0)

#ifdef MATTER_TEST_PASE
#include "session/matter_pase.h"
#include "session/matter_case.h"
#include "transport/matter_secure_channel.h"
#include "model/matter_im_read.h"
#include "model/matter_im_invoke.h"
#include "model/matter_im_write.h"
#include "model/matter_im_subscribe.h"
typedef struct { uint8_t data[1100]; size_t size; } Packet;
#else
typedef struct { uint8_t data[64]; size_t size; } Packet;
#endif
typedef struct {
#ifdef MATTER_TEST_PASE
    Matter_Pase_T pase;
    Matter_Case_T case_session;
    Matter_Secure_T secure;
    Matter_Secure_Channel_T channel;
    Matter_Im_Read_T im;
    Matter_Im_Invoke_T invoke;
    Matter_Im_Write_T write;
    Matter_Im_Subscribe_T sub;
    Packet im_received;
    uint8_t im_opcode;
    bool im_client;
    Matter_Exchange_Session_T secure_token;
    bool pase_final;
    uint64_t pase_now;
#ifdef MATTER_TEST_HOST_UDP
    uint64_t secure_request;
    Matter_Operation_Result_T secure_outcome;
#endif
#endif
    Matter_T owner;
    Matter_Rx_T rx;
    Matter_Retransmission_Sender_T tx;
    Matter_Unsecured_T sessions;
    Matter_Unsecured_Rx_T ingress, ingress_target;
    Matter_Udp_Path_T path;
    unsigned ingress_accepted, ingress_detached;
    Matter_Exchange_Handle_T handle;
    Matter_Exchange_Info_T key;
    Matter_Exchange_Session_T session, first_session, last_session, resolver_session;
    const Matter_Retransmission_Request_T* retained;
    const Matter_Ack_Message_T* retained_ack;
    uint64_t ack_request, message_id;
    Packet outbound, wire;
    Matter_Counter_T outgoing;
    unsigned rx_pins, tx_pins, ack_pins, resolver_pins, deliveries, ack_calls, notifications;
    unsigned sends, ack_sends, discoveries, dependencies, cancels;
    uint8_t last_payload, attempts;
    Matter_Retransmission_Outcome_T outcome;
    Matter_Result_T rx_result, tx_result, ack_error, pin_error;
    Matter_Retransmission_Submission_T submission;
    bool started, online, closing, stopping, stopped, ack_waiting, credentials_expired;
#ifdef MATTER_TEST_HOST_UDP
    Matter_Udp_Windows_T host;
    Matter_Udp_T udp;
    Matter_Unsecured_Tx_T transport, listener_target;
    Matter_Udp_Path_T received_path;
    Packet inbox;
    uint64_t udp_request;
    unsigned received, completed, detached;
    bool inbox_full;
#endif
} Peer;
typedef struct { Peer a, b; Packet delayed_data, delayed_ack; } Pair;
#ifdef MATTER_TEST_HOST_UDP
static bool network_take(Peer* p);
static void network_poll(Peer* p);
static Matter_Result_T network_stop(Peer* p);
static void network_delete(Peer* p);
static Matter_Retransmission_Submission_T network_submission(Matter_Result_T result) {
    if (result == MATTER_PENDING) return MATTER_RETRANSMISSION_SUBMITTED;
    return result == MATTER_WOULD_BLOCK || result == MATTER_OFFLINE || result == MATTER_BUSY ?
        MATTER_RETRANSMISSION_REJECTED_RETRYABLE : MATTER_RETRANSMISSION_REJECTED_FATAL;
}
static Matter_Retransmission_Tx_Result_T network_outcome(Matter_Operation_Result_T result) {
    /* UDP cannot promise a failed/cancelled send had no effect. Do not retry
     * ambiguous I/O here. ACK/cancel already recorded by MRP still wins. */
    return result == MATTER_OPERATION_SUCCEEDED ? MATTER_RETRANSMISSION_SENT : MATTER_RETRANSMISSION_FATAL;
}
#endif

static unsigned session_pins(Peer* p, Matter_Exchange_Session_T session) {
#ifdef MATTER_TEST_PASE
    if (p->secure && session == p->secure_token) {
        Matter_Secure_Info_T info;
        REQUIRE(matter_secure_info(p->secure,&info)==MATTER_OK); return (unsigned)info.pins;
    }
#endif
    Matter_Unsecured_Info_T info;
    REQUIRE(matter_unsecured_get(p->sessions, session, &info) == MATTER_OK);
    return info.pins;
}
static Matter_Result_T retain_session(Peer* p, Matter_Exchange_Session_T session) {
#ifdef MATTER_TEST_PASE
    if (p->secure && session == p->secure_token) return matter_secure_retain(p->secure);
#endif
    return matter_unsecured_pin(p->sessions,session);
}
static Matter_Result_T release_session(Peer* p, Matter_Exchange_Session_T session) {
#ifdef MATTER_TEST_PASE
    if (p->secure && session == p->secure_token) return matter_secure_release(p->secure);
#endif
    return matter_unsecured_unpin(p->sessions,session);
}
static bool seen(Peer* p, Matter_Exchange_Session_T session, uint32_t counter) {
    bool duplicate;
    REQUIRE(matter_unsecured_pin(p->sessions, session) == MATTER_OK);
    REQUIRE(matter_unsecured_classify(p->sessions, session, counter, &duplicate) == MATTER_OK);
    REQUIRE(matter_unsecured_unpin(p->sessions, session) == MATTER_OK);
    return duplicate;
}
static Matter_Message_Header_T outgoing_header(Peer* p, Matter_Exchange_Session_T session, uint32_t counter) {
    /* Only the legacy synthetic secure-counter test uses this manual envelope. */
    Matter_Unsecured_Info_T info;
    REQUIRE(matter_unsecured_get(p->sessions, session, &info) == MATTER_OK);
    return (Matter_Message_Header_T){.message_counter = counter,
        .message_flags = info.initiator ? MATTER_MESSAGE_SOURCE_PRESENT : MATTER_MESSAGE_DESTINATION_NODE,
        .source_node_id = info.initiator ? info.ephemeral_node_id : 0,
        .destination_id = info.initiator ? 0 : info.ephemeral_node_id};
}
static Matter_Result_T prepare_encoded(Peer* p, Matter_Exchange_Session_T session,
    const uint8_t* data, size_t size, Packet* out, Matter_Unsecured_Prepared_T* prepared) {
#ifdef MATTER_TEST_PASE
    if (p->channel && session == p->secure_token) {
        Matter_Secure_Prepared_T secure;
        Matter_Result_T r=matter_secure_channel_prepare(p->channel,data,size,p->pase_now,out->data,sizeof(out->data),&secure);
        if (r==MATTER_OK) *prepared=(Matter_Unsecured_Prepared_T){secure.size,secure.counter};
        return r;
    }
#endif
    if (p->outgoing.mode == MATTER_COUNTER_UNSECURED)
        return matter_unsecured_prepare_encoded(p->sessions, session, &p->outgoing,
            data, size, out->data, sizeof(out->data), prepared);
    /* Preserve the old counter-exhaustion/retention test, not a secure transport. */
    Matter_Counter_Value_T value;
    Matter_Result_T result = matter_counter_take(&p->outgoing, &value);
    if (result != MATTER_OK) return result;
    p->credentials_expired |= value.expires_session;
    Matter_Message_Header_T header = outgoing_header(p, session, value.counter);
    REQUIRE(size <= sizeof(out->data) - 16);
    memmove(out->data + 16, data, size);
    size_t n;
    REQUIRE(matter_message_header_write(&header, out->data, 16, &n) == MATTER_MESSAGE_OK && n == 16);
    *prepared = (Matter_Unsecured_Prepared_T){n + size, value.counter};
    return MATTER_OK;
}
static void retire_sessions(Peer* p) {
    if (!p->sessions) return;
    for (Matter_Exchange_Session_T id = p->first_session; id <= p->last_session; ++id) {
        Matter_Unsecured_Info_T info;
        if (matter_unsecured_get(p->sessions, id, &info) == MATTER_OK) {
            REQUIRE(!info.pins);
            REQUIRE(matter_unsecured_remove(p->sessions, id) == MATTER_OK);
        }
    }
}
static void complete_resolver(Peer* p) {
    if (!p->resolver_pins) return;
    REQUIRE(p->resolver_pins == 1);
    REQUIRE(release_session(p, p->resolver_session) == MATTER_OK);
    p->resolver_session = 0; p->resolver_pins = 0;
}
static Matter_Result_T pin_rx(void* u, Matter_Exchange_Session_T session) {
    Peer* p = u;
    REQUIRE(p->online);
    if (p->pin_error != MATTER_OK) return p->pin_error;
    if (retain_session(p, session) != MATTER_OK) return MATTER_PORT_ERROR;
    ++p->rx_pins; return MATTER_OK;
}
static void unpin_rx(void* u, Matter_Exchange_Session_T session) {
    Peer* p = u;
    REQUIRE(p->rx_pins);
    REQUIRE(release_session(p, session) == MATTER_OK);
    --p->rx_pins;
    REQUIRE(p->rx_pins || (!p->retained_ack && !p->tx_pins));
}
static Matter_Result_T ack_received(void* u, const Matter_Exchange_Info_T* key, uint32_t counter) {
    Peer* p = u; ++p->ack_calls;
    return matter_retransmission_sender_ack(p->tx, key, counter);
}
static Matter_Result_T drained(void* u, const Matter_Exchange_Info_T* key) {
    return matter_retransmission_sender_drained(((Peer*)u)->tx, key);
}
static void delivered(void* u, const Matter_Rx_Decision_T* d) {
    Peer* p = u;
#ifdef MATTER_TEST_PASE
    if(p->case_session) {
        p->session=d->session; p->handle=d->exchange;
        p->key=(Matter_Exchange_Info_T){d->session,d->header.exchange_id,!(d->header.exchange_flags & MATTER_PROTOCOL_INITIATOR)};
        REQUIRE(matter_case_receive(p->case_session,d->header.opcode,d->payload,d->payload_size)==MATTER_OK);
        ++p->deliveries; return;
    }
    if (p->pase) {
        p->session = d->session; p->handle = d->exchange;
        p->key = (Matter_Exchange_Info_T){d->session, d->header.exchange_id,
            !(d->header.exchange_flags & MATTER_PROTOCOL_INITIATOR)};
        REQUIRE(matter_pase_receive(p->pase, d->header.opcode, d->payload, d->payload_size) == MATTER_OK);
        ++p->deliveries; return;
    }
#endif
#ifdef MATTER_TEST_PASE
    if (p->im || p->invoke || p->write || p->sub || p->im_client) {
        REQUIRE(!d->header.vendor_id && d->header.protocol_id==1);
        p->session=d->session; p->handle=d->exchange;
        p->key=(Matter_Exchange_Info_T){d->session,d->header.exchange_id,!(d->header.exchange_flags & MATTER_PROTOCOL_INITIATOR)};
        if (p->im) REQUIRE(matter_im_read_receive(p->im,d)==MATTER_OK);
        else if (p->invoke) REQUIRE(matter_im_invoke_receive_at(p->invoke,d,p->pase_now)==MATTER_OK);
        else if (p->write) REQUIRE(matter_im_write_receive_at(p->write,d,p->pase_now)==MATTER_OK);
        else if (p->sub) REQUIRE(matter_im_subscribe_receive(p->sub,d)==MATTER_OK);
        else { REQUIRE(d->payload_size<=sizeof(p->im_received.data));
            memcpy(p->im_received.data,d->payload,d->payload_size); p->im_received.size=d->payload_size; p->im_opcode=d->header.opcode; }
        ++p->deliveries; return;
    }
#endif
    REQUIRE(!p->closing && !p->stopping && d->payload_size == 1 && d->header.protocol_id == 4);
    p->session = d->session; /* Selected application reply context, never RX routing. */
    p->handle = d->exchange;
    p->key = (Matter_Exchange_Info_T){d->session, d->header.exchange_id,
        !(d->header.exchange_flags & MATTER_PROTOCOL_INITIATOR)};
    p->last_payload = d->payload[0]; ++p->deliveries;
}
static Matter_Result_T stop_dependencies(void* u) {
    Peer* p = u; ++p->dependencies;
    REQUIRE(!p->rx_pins && !p->tx_pins && !p->ack_pins && !p->retained && !p->retained_ack);
    REQUIRE(matter_retransmission_sender_stop(p->tx) == MATTER_OK);
    if (p->resolver_pins) return MATTER_PENDING;
    REQUIRE(matter_unsecured_rx_stop(p->ingress) == MATTER_OK);
#ifdef MATTER_TEST_HOST_UDP
    if (network_stop(p) != MATTER_OK) return MATTER_PENDING;
#endif
    retire_sessions(p);
    p->online = false; p->stopped = true; return MATTER_OK;
}
static Matter_Result_T pin_tx(void* u, const Matter_Exchange_Info_T* k, const uint8_t* data, size_t size) {
    Peer* p = u;
    REQUIRE(k->session == p->session && k->exchange_id == p->key.exchange_id && k->initiator == p->key.initiator);
    REQUIRE(data == p->outbound.data && size == p->outbound.size && p->rx_pins);
    if (p->closing || p->stopping) return MATTER_PORT_ERROR;
    if (retain_session(p, k->session) != MATTER_OK) return MATTER_PORT_ERROR;
    ++p->tx_pins; return MATTER_OK;
}
static void unpin_tx(void* u, const Matter_Exchange_Info_T* k, const uint8_t* data, size_t size) {
    Peer* p = u;
    REQUIRE(p->tx_pins && !p->retained);
    REQUIRE(data == p->outbound.data && size == p->outbound.size);
    REQUIRE(release_session(p, k->session) == MATTER_OK);
    --p->tx_pins;
}
static Matter_Result_T ready(void* u) {
    Peer* p = u;
    if (!p->online) return MATTER_OFFLINE;
    return p->retained || p->retained_ack || p->ack_waiting ? MATTER_WOULD_BLOCK : MATTER_OK;
}
static Matter_Result_T parameters(void* u, const Matter_Retransmission_Message_T* m,
    uint8_t attempt, Matter_Retransmission_Parameters_T* out) {
    Peer* p = u; REQUIRE(session_pins(p, m->exchange.session) && attempt >= 1 && attempt <= 3);
    *out = (Matter_Retransmission_Parameters_T){500, 300, true};
#ifdef MATTER_TEST_PASE
    if (p->secure && m->exchange.session == p->secure_token) {
        return matter_secure_channel_parameters(p->channel,p->pase_now,out);
    }
    if (p->case_session && matter_case_state(p->case_session) != MATTER_CASE_FAILED) {
        Matter_Pase_Intervals_T intervals;
        REQUIRE(matter_case_peer_intervals(p->case_session,&intervals)==MATTER_OK);
        out->idle_interval_ms=intervals.idle_ms; out->active_interval_ms=intervals.active_ms;
    }
    if (p->pase && matter_pase_state(p->pase) != MATTER_PASE_FAILED) {
        Matter_Pase_Intervals_T intervals;
        REQUIRE(matter_pase_peer_intervals(p->pase, &intervals) == MATTER_OK);
        out->idle_interval_ms = intervals.idle_ms; out->active_interval_ms = intervals.active_ms;
    }
#endif
    return MATTER_OK;
}
static Matter_Result_T random_sample(void* u, uint16_t* out) { (void)u; *out = 0; return MATTER_OK; }
static Matter_Result_T rediscover(void* u, const Matter_Retransmission_Message_T* m) {
    Peer* p = u; REQUIRE(!p->resolver_pins);
    if (retain_session(p, m->exchange.session) != MATTER_OK) return MATTER_PORT_ERROR;
    p->resolver_session = m->exchange.session;
    ++p->discoveries; ++p->resolver_pins; return MATTER_OK;
}
static Matter_Retransmission_Submission_T send_message(void* u, const Matter_Retransmission_Request_T* r) {
    Peer* p = u;
    REQUIRE(p->online && p->tx_pins && !p->retained && !p->retained_ack);
    REQUIRE(r->message.size == p->outbound.size && !memcmp(r->message.data, p->outbound.data, p->outbound.size));
    ++p->sends;
    if (p->submission != MATTER_RETRANSMISSION_SUBMITTED) return p->submission;
#ifdef MATTER_TEST_HOST_UDP
#ifdef MATTER_TEST_PASE
    if (p->channel) {
        Matter_Result_T result=matter_secure_channel_send(p->channel,p->udp,r->message.data,r->message.size,&p->udp_request);
        if (result!=MATTER_PENDING) return network_submission(result);
    } else
#endif
    if (p->transport) {
        Matter_Result_T result = matter_unsecured_tx_send(p->transport, r->message.exchange.session,
            r->message.data, r->message.size, &p->udp_request);
        if (result != MATTER_PENDING) return network_submission(result);
    }
#endif
#ifdef MATTER_TEST_PASE
    /* First accepted submission, not MRP add, retry or completion. */
    if (p->invoke && matter_im_invoke_state(p->invoke)==MATTER_IM_INVOKE_OUTPUT)
        REQUIRE(matter_im_invoke_sent_at(p->invoke,p->pase_now)==MATTER_OK);
    if (p->write && matter_im_write_state(p->write)==MATTER_IM_WRITE_OUTPUT)
        REQUIRE(matter_im_write_sent_at(p->write,p->pase_now)==MATTER_OK);
    if (p->sub && matter_im_subscribe_state(p->sub)==MATTER_IM_SUB_OUTPUT)
        REQUIRE(matter_im_subscribe_sent_at(p->sub,p->pase_now)==MATTER_OK);
#endif
    p->wire = p->outbound; p->retained = r; return MATTER_RETRANSMISSION_SUBMITTED;
}
static Matter_Result_T send_ack(void* u, uint64_t request, const Matter_Ack_Message_T* m) {
    Peer* p = u;
    p->ack_waiting = true;
    if (p->retained || p->retained_ack) return MATTER_WOULD_BLOCK;
    if (p->ack_error != MATTER_OK) return p->ack_error;
    REQUIRE(p->online && p->rx_pins && session_pins(p, m->exchange.session));
#if defined(MATTER_TEST_PASE) && defined(MATTER_TEST_HOST_UDP)
    if (p->channel && m->exchange.session==p->secure_token) {
        Matter_Result_T result=matter_secure_channel_send_ack(p->channel,p->udp,m,p->pase_now,&p->udp_request);
        if (result!=MATTER_PENDING) return result==MATTER_BUSY ? MATTER_WOULD_BLOCK : MATTER_PORT_ERROR;
        REQUIRE(retain_session(p,m->exchange.session)==MATTER_OK);
        ++p->ack_pins; p->retained_ack=m; p->ack_request=request; ++p->ack_sends;
        return MATTER_OK;
    }
#endif
    Matter_Unsecured_Prepared_T prepared;
    if (prepare_encoded(p, m->exchange.session, m->data, m->size, &p->wire, &prepared) != MATTER_OK)
        return MATTER_PORT_ERROR;
    p->wire.size = prepared.size;
    REQUIRE(retain_session(p, m->exchange.session) == MATTER_OK);
#ifdef MATTER_TEST_HOST_UDP
    if (p->transport) {
        Matter_Result_T result = matter_unsecured_tx_send(p->transport, m->exchange.session,
            p->wire.data, p->wire.size, &p->udp_request);
        if (result != MATTER_PENDING) {
            REQUIRE(matter_unsecured_unpin(p->sessions, m->exchange.session) == MATTER_OK);
            return result == MATTER_BUSY ? MATTER_WOULD_BLOCK : result;
        }
    }
#endif
    ++p->ack_pins;
    p->retained_ack = m; p->ack_request = request; ++p->ack_sends;
    return MATTER_OK;
}
static void cancel(void* u, uint64_t request) {
    Peer* p = u; REQUIRE(p->retained && p->retained->id == request); ++p->cancels;
    /* Host WSASendMsg already ended synchronously. Keep its deferred outcome;
     * cancelling this MRP message must not stop the shared UDP/ACK transport. */
}
static void finished(void* u, const Matter_Retransmission_Result_T* result) {
    Peer* p = u;
    REQUIRE(!p->retained && p->tx_pins && p->rx_pins && result->message.id == p->message_id);
    p->outcome = result->outcome; p->attempts = result->attempts; ++p->notifications;
#ifdef MATTER_TEST_PASE
    if (p->im) {
        if (result->outcome==MATTER_RETRANSMISSION_ACKNOWLEDGED && matter_im_read_state(p->im)!=MATTER_IM_READ_FAILED)
            REQUIRE(matter_im_read_confirm(p->im,p->pase_now)==MATTER_OK);
        else REQUIRE(matter_im_read_cancel(p->im)==MATTER_OK);
    }
    if (p->invoke) {
        if (result->outcome==MATTER_RETRANSMISSION_ACKNOWLEDGED && matter_im_invoke_state(p->invoke)!=MATTER_IM_INVOKE_FAILED)
            REQUIRE(matter_im_invoke_confirm(p->invoke,p->pase_now)==MATTER_OK);
        else REQUIRE(matter_im_invoke_cancel(p->invoke)==MATTER_OK);
    }
    if (p->write) {
        if (result->outcome==MATTER_RETRANSMISSION_ACKNOWLEDGED && matter_im_write_state(p->write)!=MATTER_IM_WRITE_FAILED)
            REQUIRE(matter_im_write_confirm(p->write,p->pase_now)==MATTER_OK);
        else REQUIRE(matter_im_write_cancel(p->write)==MATTER_OK);
    }
    if (p->sub) {
        if (result->outcome==MATTER_RETRANSMISSION_ACKNOWLEDGED && matter_im_subscribe_state(p->sub)!=MATTER_IM_SUB_FAILED) {
            Matter_Result_T r=matter_im_subscribe_confirm(p->sub,p->pase_now);
            REQUIRE(r==MATTER_OK || (r==MATTER_PORT_ERROR && matter_im_subscribe_state(p->sub)==MATTER_IM_SUB_FAILED));
        } else REQUIRE(matter_im_subscribe_cancel(p->sub)==MATTER_OK);
    }
    if(p->case_session) {
        if(result->outcome!=MATTER_RETRANSMISSION_ACKNOWLEDGED) {
            if(matter_case_state(p->case_session)!=MATTER_CASE_COMPLETE) REQUIRE(matter_case_cancel(p->case_session)==MATTER_OK);
        }
        else if(p->pase_final) REQUIRE(matter_case_confirm_delivery(p->case_session,p->pase_now)==MATTER_OK);
    }
    if (p->pase) {
        if (result->outcome != MATTER_RETRANSMISSION_ACKNOWLEDGED) REQUIRE(matter_pase_cancel(p->pase) == MATTER_OK);
        else if (p->pase_final) REQUIRE(matter_pase_confirm_delivery(p->pase, p->pase_now) == MATTER_OK);
    }
#endif
}
static void detach_tx(void* u) { Peer* p = u; REQUIRE(!p->retained && !p->tx_pins); }
static void detach_ack(void* u) { Peer* p = u; REQUIRE(!p->retained_ack && !p->rx_pins && !p->ack_pins); }

static bool complete_tx(Peer* p, Matter_Retransmission_Tx_Result_T result) {
#ifdef MATTER_TEST_HOST_UDP
    REQUIRE(!p->udp_request); /* No producer completion before adapter take. */
#endif
    if (!p->retained) return false;
    REQUIRE(p->retained->message.data == p->outbound.data && p->retained->message.size == p->wire.size);
    REQUIRE(!memcmp(p->retained->message.data, p->wire.data, p->wire.size));
    uint64_t id = p->retained->id; p->retained = NULL;
    return matter_retransmission_sender_complete(p->tx, id, result) == MATTER_OK;
}
static bool complete_ack(Peer* p, Matter_Operation_Result_T result) {
#ifdef MATTER_TEST_HOST_UDP
    REQUIRE(!p->udp_request);
#endif
    if (!p->retained_ack) return false;
#ifdef MATTER_TEST_PASE
    if (!p->channel)
#endif
    {
    REQUIRE(p->wire.size == 16 + p->retained_ack->size && p->ack_pins == 1);
    REQUIRE(!memcmp(p->wire.data + 16, p->retained_ack->data, p->retained_ack->size));
    }
    REQUIRE(release_session(p, p->retained_ack->exchange.session) == MATTER_OK);
    --p->ack_pins;
    p->retained_ack = NULL;
    return matter_rx_complete(p->rx, p->ack_request, result) == MATTER_OK;
}
static Matter_Result_T admit_ingress(void* u, const Matter_Unsecured_Rx_Message_T* m, bool* create) {
    Peer* p = u;
    const Matter_Protocol_Header_T* protocol = &m->protocol;
    bool data = !protocol->vendor_id && protocol->protocol_id == 4 && protocol->opcode == 1 && m->payload_size == 1;
    bool ack = !protocol->vendor_id && !protocol->protocol_id && protocol->opcode == 0x10 &&
        (protocol->exchange_flags & MATTER_PROTOCOL_ACK) && !(protocol->exchange_flags & MATTER_PROTOCOL_RELIABLE) &&
        !m->payload_size;
#ifdef MATTER_TEST_PASE
    if (p->pase || p->case_session) {
        data = !protocol->vendor_id && !protocol->protocol_id &&
            ((p->case_session?(protocol->opcode>=0x30 && protocol->opcode<=0x33):(protocol->opcode>=0x20 && protocol->opcode<=0x24)) || protocol->opcode==0x40) &&
            (protocol->exchange_flags & MATTER_PROTOCOL_RELIABLE) && m->payload_size <= (p->case_session?MATTER_CASE_MAX_PAYLOAD:MATTER_PASE_MAX_PAYLOAD);
        if (!data && !ack) return MATTER_INVALID_ARGUMENT;
        if (p->handle) {
            if (m->session != p->session || protocol->exchange_id != p->key.exchange_id ||
                !!(protocol->exchange_flags & MATTER_PROTOCOL_INITIATOR) == p->key.initiator) return MATTER_INVALID_ARGUMENT;
        } else if (!data || protocol->opcode != (p->case_session?0x30:0x20) || !(protocol->exchange_flags & MATTER_PROTOCOL_INITIATOR))
            return MATTER_INVALID_ARGUMENT;
        *create = !p->handle && !p->closing && !p->stopping;
        return MATTER_OK;
    }
#endif
    if (!data && !ack) return MATTER_INVALID_ARGUMENT; /* NOT a commissioning allowlist. */
    *create = data && !p->closing && !p->stopping;
    return MATTER_OK;
}
static void accepted_ingress(void* u, const Matter_Unsecured_Rx_Message_T* m, bool duplicate) {
    Peer* p = u; (void)duplicate;
    REQUIRE(session_pins(p, m->session) >= 2); /* Ingress and copied RX. */
    if (!p->session) p->session = m->session;
    p->path = m->datagram->path;
    ++p->ingress_accepted;
}
static void detach_ingress(void* u) {
    Peer* p = u; p->ingress_target = NULL; ++p->ingress_detached;
#ifdef MATTER_TEST_HOST_UDP
    p->inbox_full = false;
#endif
}
static Matter_Result_T receive_datagram(Peer* p, const Matter_Udp_Datagram_T* datagram, uint64_t now) {
    if (!p->online || !p->ingress_target) return MATTER_OFFLINE;
#ifdef MATTER_TEST_PASE
    if (p->channel) return matter_secure_channel_receive(p->channel,p->rx,datagram,now,now);
#endif
    return matter_unsecured_rx_receive(p->ingress_target, datagram, now);
}
static Matter_Result_T receive_packet(Peer* p, const Packet* packet, uint64_t now) {
    Matter_Udp_Datagram_T datagram = {.path = p->path, .data = packet->data, .size = packet->size};
    return receive_datagram(p, &datagram, now);
}
static bool tick(Peer* p, uint64_t now) {
#ifdef MATTER_TEST_PASE
    p->pase_now = now;
#endif
    p->ack_waiting = false; /* RX/ACK gets the first chance at this turn's TX. */
    p->rx_result = matter_rx_process(p->rx, now);
    p->tx_result = matter_retransmission_sender_process(p->tx, now);
    return (p->rx_result == MATTER_OK || p->rx_result == MATTER_PENDING || p->rx_result == MATTER_OFFLINE ||
        p->rx_result == MATTER_PORT_ERROR) && (p->tx_result == MATTER_OK || p->tx_result == MATTER_PENDING ||
        p->tx_result == MATTER_WOULD_BLOCK || p->tx_result == MATTER_PORT_ERROR || p->tx_result == MATTER_OFFLINE);
}
static bool queue_data(Peer* p, uint8_t payload) {
    REQUIRE(!p->tx_pins && !p->closing && !p->stopping);
    if (!p->handle) {
        if (matter_rx_initiate(p->rx, p->session, &p->handle) != MATTER_OK ||
            matter_rx_get(p->rx, p->handle, &p->key) != MATTER_OK) return false;
    }
    Matter_Protocol_Header_T protocol = {.exchange_id = p->key.exchange_id, .protocol_id = 4,
        .exchange_flags = MATTER_PROTOCOL_RELIABLE | (p->key.initiator ? MATTER_PROTOCOL_INITIATOR : 0), .opcode = 1};
    Matter_Unsecured_Prepared_T prepared;
    bool unsecured=p->outgoing.mode == MATTER_COUNTER_UNSECURED;
#ifdef MATTER_TEST_PASE
    if (p->channel) unsecured=false;
#endif
    if (unsecured) {
        if (matter_unsecured_prepare(p->sessions, p->key.session, &p->outgoing, &protocol, &payload, 1,
            p->outbound.data, sizeof(p->outbound.data), &prepared) != MATTER_OK) return false;
    } else {
        uint8_t plaintext[7]; /* Legacy test only; leave outbound intact if take fails. */
        size_t h;
        REQUIRE(matter_protocol_header_write(&protocol, plaintext,
            sizeof(plaintext), &h) == MATTER_MESSAGE_OK && h == 6);
        plaintext[h] = payload;
        if (prepare_encoded(p, p->key.session, plaintext, h + 1,
            &p->outbound, &prepared) != MATTER_OK) return false;
    }
    p->outbound.size = prepared.size;
    return matter_retransmission_sender_add(p->tx, &p->key, prepared.counter, p->outbound.data, p->outbound.size,
        &p->message_id) == MATTER_OK;
}
static bool stop_peer(Peer* p) {
    p->stopping = p->closing = true;
    REQUIRE(matter_unsecured_rx_close(p->ingress) == MATTER_OK);
    Matter_Result_T tx = matter_retransmission_sender_stop(p->tx);
    Matter_Result_T rx = matter_rx_stop(p->rx);
    return (tx == MATTER_OK || tx == MATTER_PENDING) && (rx == MATTER_OK || rx == MATTER_PENDING);
}
static void cleanup_peer(Peer* p) {
    if (p->ingress) REQUIRE(matter_unsecured_rx_close(p->ingress) == MATTER_OK);
    complete_resolver(p); p->ack_error = p->pin_error = MATTER_OK;
    p->submission = MATTER_RETRANSMISSION_REJECTED_FATAL;
    if (p->tx && p->message_id) matter_retransmission_sender_cancel(p->tx, p->message_id);
#ifdef MATTER_TEST_HOST_UDP
    if (p->host) { p->inbox_full = false; network_poll(p); REQUIRE(network_take(p)); }
#endif
    if (p->retained) REQUIRE(complete_tx(p, MATTER_RETRANSMISSION_FATAL));
    if (p->retained_ack) REQUIRE(complete_ack(p, MATTER_OPERATION_SUCCEEDED));
    if (p->tx) matter_retransmission_sender_stop(p->tx);
    if (p->rx) matter_rx_stop(p->rx);
    if (p->started) {
        for (unsigned i = 0; i < 16 && !p->stopped; ++i) {
            REQUIRE(tick(p, UINT64_MAX));
#ifdef MATTER_TEST_HOST_UDP
            if (p->host) { p->inbox_full = false; network_poll(p); REQUIRE(network_take(p)); }
#endif
            if (p->retained_ack) REQUIRE(complete_ack(p, MATTER_OPERATION_SUCCEEDED));
        }
        REQUIRE(p->stopped);
    }
    if (p->tx) {
        REQUIRE(matter_retransmission_sender_process(p->tx, UINT64_MAX) == MATTER_OK);
        REQUIRE(matter_retransmission_sender_delete(p->tx) == MATTER_OK);
    }
    if (p->ingress) {
        REQUIRE(matter_unsecured_rx_stop(p->ingress) == MATTER_OK);
        REQUIRE(matter_unsecured_rx_delete(p->ingress) == MATTER_OK);
        p->ingress = NULL;
        REQUIRE(!p->ingress_target && p->ingress_detached == 1);
    }
    REQUIRE(matter_rx_delete(p->rx) == MATTER_OK);
#ifdef MATTER_TEST_HOST_UDP
    network_delete(p);
#endif
#ifdef MATTER_TEST_PASE
    REQUIRE(matter_im_read_delete(p->im)==MATTER_OK); p->im=NULL;
    REQUIRE(matter_im_invoke_delete(p->invoke)==MATTER_OK); p->invoke=NULL;
    REQUIRE(matter_im_write_delete(p->write)==MATTER_OK); p->write=NULL;
    REQUIRE(matter_im_subscribe_delete(p->sub)==MATTER_OK); p->sub=NULL;
    if (p->channel) {
        REQUIRE(matter_secure_channel_close(p->channel)==MATTER_OK);
        REQUIRE(matter_secure_channel_delete(p->channel)==MATTER_OK); p->channel=NULL;
    }
    if (p->secure) {
        REQUIRE(matter_secure_close(p->secure)==MATTER_OK && matter_secure_delete(p->secure)==MATTER_OK); p->secure=NULL;
    }
#endif
    retire_sessions(p); /* Also covers partial construction, with no consumers. */
    REQUIRE(matter_unsecured_delete(p->sessions) == MATTER_OK);
    if (p->owner) REQUIRE(matter_stop(p->owner) == MATTER_OK);
    REQUIRE(matter_delete(p->owner) == MATTER_OK);
    REQUIRE(!p->rx_pins && !p->tx_pins && !p->ack_pins && !p->resolver_pins);
}
static void cleanup(Pair* f) { if (f) { cleanup_peer(&f->a); cleanup_peer(&f->b); free(f); } }
static Matter_Result_T initial_random(void* user, uint32_t* random28) {
    *random28 = *(const uint32_t*)user - 1; return MATTER_OK; /* Deterministic test DRBG input. */
}
static Matter_Result_T node_random(void* user, uint64_t* sample) {
    *sample = *(const uint64_t*)user; return MATTER_OK;
}
static bool construct(Peer* p, Matter_Exchange_Session_T first, uint32_t counter, Matter_Counter_Mode_T mode) {
    p->first_session = first; p->last_session = first + 31; p->online = true;
    p->sessions = matter_unsecured_new(p->first_session, p->last_session);
    REQUIRE(matter_counter_init(&p->outgoing, mode, initial_random, &counter) == MATTER_OK);
    p->owner = matter_new(NULL);
    Matter_Retransmission_Port_T tx = {p, pin_tx, unpin_tx, ready, parameters, random_sample, rediscover,
        send_message, cancel, finished, detach_tx};
    p->tx = matter_retransmission_sender_new(3, &tx);
    Matter_Rx_Port_T rx = {p, {p, send_ack, detach_ack}, pin_rx, unpin_rx, ack_received, drained,
        delivered, stop_dependencies};
    p->rx = matter_rx_new(p->owner, 0x1234, &rx);
    Matter_Unsecured_Rx_Port_T ingress = {p, admit_ingress, accepted_ingress, detach_ingress};
    p->ingress = matter_unsecured_rx_new(p->rx, p->sessions, &ingress);
    p->ingress_target = p->ingress;
    /* Explicit fake IPv6 receive metadata; real host replaces it with socket path. */
    p->path.local.address[15] = p->path.peer.address[15] = 1;
    p->path.local.port = (uint16_t)(5540 + first); p->path.peer.port = 5540;
    p->path.interface_id = 1;
    return p->sessions && p->owner && p->tx && p->rx && p->ingress;
}
static Pair* create_mode(Matter_Counter_Mode_T mode) {
    Pair* f = calloc(1, sizeof(*f));
    if (!f) return NULL;
    if (!construct(&f->a, 11, 1, mode) || !construct(&f->b, 22, 100, MATTER_COUNTER_UNSECURED)) { cleanup(f); return NULL; }
    uint64_t node = UINT64_C(0x0102030405060708);
    REQUIRE(matter_unsecured_initiate(f->a.sessions, node_random, &node, &f->a.session) == MATTER_OK);
    Peer* peers[] = {&f->a, &f->b};
    for (unsigned i = 0; i < 2; ++i) {
        REQUIRE(matter_start(peers[i]->owner) == MATTER_OK);
        REQUIRE(matter_rx_register(peers[i]->rx, 0, 4) == MATTER_OK);
        REQUIRE(matter_rx_start(peers[i]->rx) == MATTER_OK); peers[i]->started = true;
    }
    return f;
}
static Pair* create(void) { return create_mode(MATTER_COUNTER_UNSECURED); }

#ifdef MATTER_TEST_HOST_UDP
static void network_received(void* u, const Matter_Udp_Datagram_T* d) {
    Peer* p = u;
    if (!p->ingress_target) return; /* Detached routing cannot enqueue stale ingress work. */
    REQUIRE(!p->inbox_full && d->size <= sizeof(p->inbox.data));
    memcpy(p->inbox.data, d->data, d->size); p->inbox.size = d->size;
    p->received_path = d->path; p->inbox_full = true; ++p->received;
    /* No parser/MRP/ACK or send from a UDP listener. */
}
static void network_sent(void* u, uint64_t id, Matter_Operation_Result_T result) {
    Peer* p = u;
#ifdef MATTER_TEST_PASE
    if (p->channel && id == p->udp_request) {
        REQUIRE(matter_secure_channel_complete(p->channel,id,result)==MATTER_OK); ++p->completed; return;
    }
    if (p->secure_request) {
        REQUIRE(id == p->secure_request && !p->udp_request && !p->retained && !p->retained_ack);
        p->secure_request = 0; p->secure_outcome = result; return;
    }
#endif
    REQUIRE(p->listener_target && id == p->udp_request && (p->retained || p->retained_ack));
    REQUIRE(matter_unsecured_tx_complete(p->listener_target, id, result) == MATTER_OK);
    ++p->completed;
}
static Matter_Result_T network_route(void* u, Matter_Exchange_Session_T session, Matter_Udp_Path_T* path) {
    Peer* p = u; REQUIRE(session == p->session && session_pins(p, session));
    *path = p->path; return MATTER_OK;
}
static void network_detach(void* u) {
    Peer* p = u; REQUIRE(!p->udp_request && !p->retained && !p->retained_ack);
    p->listener_target = NULL; ++p->detached;
}
static bool network_attach(Peer* p) {
    p->path = (Matter_Udp_Path_T){0}; /* No synthetic interface/cache in the real backend. */
    Matter_Udp_Address_T address = {{0}, 0}; address.address[15] = 1;
    Matter_Udp_Listener_T listener = {p, network_received, network_sent};
    p->host = matter_udp_windows_new(p->owner, &address, 0, &listener);
    if (!p->host) return false;
    p->udp = matter_udp_windows_module(p->host);
    Matter_Unsecured_Tx_Port_T port = {p, network_route, network_detach};
    p->transport = matter_unsecured_tx_new(p->udp, p->sessions, &port);
    if (!p->transport) return false;
    p->listener_target = p->transport;
    return matter_udp_start(p->udp) == MATTER_OK &&
        matter_udp_windows_local(p->host, &p->path.local) == MATTER_OK;
}
static Pair* create_network(void) {
    Pair* f = create();
    if (!f) return NULL;
    if (!network_attach(&f->a) || !network_attach(&f->b)) { cleanup(f); return NULL; }
    f->a.path.peer = f->b.path.local; /* Initiator's test discovery cache. */
    return f;
}
static void network_poll(Peer* p) {
    REQUIRE(!p->inbox_full);
    Matter_Result_T result = matter_udp_windows_poll(p->host);
    REQUIRE(result == MATTER_OK || result == MATTER_WOULD_BLOCK);
}
static bool network_receive(Peer* p) {
    ULONGLONG end = GetTickCount64() + 2000;
    while (!p->inbox_full && GetTickCount64() < end) {
        network_poll(p);
        if (!p->inbox_full) Sleep(1); /* Test wait only, logical MRP time is explicit. */
    }
    return p->inbox_full;
}
static bool network_admit(Peer* p, uint64_t now) {
    if (!p->inbox_full) return false;
    p->inbox_full = false;
    Matter_Udp_Datagram_T datagram = {.path = p->received_path, .data = p->inbox.data, .size = p->inbox.size};
    return receive_datagram(p, &datagram, now) == MATTER_OK;
}
static bool network_take(Peer* p) {
#ifdef MATTER_TEST_PASE
    if (p->channel && p->udp_request) {
        Matter_Secure_Channel_Result_T result;
        Matter_Result_T status=matter_secure_channel_take(p->channel,&result);
        if (status==MATTER_PENDING) return true;
        if (status!=MATTER_OK) return false;
        REQUIRE(result.request==p->udp_request); p->udp_request=0;
        if (p->retained) return complete_tx(p,network_outcome(result.outcome));
        if (p->retained_ack) return complete_ack(p,result.outcome);
        return result.outcome==MATTER_OPERATION_SUCCEEDED; /* Direct CloseSession producer. */
    }
#endif
    if (!p->transport) return true;
    Matter_Unsecured_Tx_Result_T result;
    Matter_Result_T status = matter_unsecured_tx_take(p->transport, &result);
    if (status == MATTER_INVALID_STATE) return !p->udp_request;
    if (status == MATTER_PENDING) return true;
    if (status != MATTER_OK) return false;
    REQUIRE(result.request == p->udp_request && result.session == p->session);
    p->udp_request = 0; /* Drop transport binding BEFORE invoking producer completion. */
    if (p->retained) {
        REQUIRE(!p->retained_ack && result.data == p->retained->message.data && result.size == p->retained->message.size);
        return complete_tx(p, network_outcome(result.outcome));
    }
    REQUIRE(p->retained_ack && result.data == p->wire.data && result.size == p->wire.size);
    return complete_ack(p, result.outcome);
}
static Matter_Result_T network_stop(Peer* p) {
    if (!p->host) return MATTER_OK;
    if (p->transport && matter_unsecured_tx_close(p->transport) != MATTER_OK) return MATTER_PENDING;
    Matter_Result_T result = matter_udp_stop(p->udp);
    REQUIRE(result == MATTER_OK || result == MATTER_PENDING);
    result = matter_udp_process(p->udp);
    REQUIRE(result == MATTER_OK || result == MATTER_PENDING);
    return matter_udp_is_active(p->udp) ? MATTER_PENDING : MATTER_OK;
}
static void network_delete(Peer* p) {
    for (unsigned i = 0; i < 5 && network_stop(p) != MATTER_OK; ++i) {
        p->inbox_full = false; network_poll(p); REQUIRE(network_take(p));
    }
    REQUIRE(network_stop(p) == MATTER_OK);
    REQUIRE(matter_unsecured_tx_delete(p->transport) == MATTER_OK);
    REQUIRE(!p->listener_target);
    REQUIRE(matter_udp_windows_delete(p->host) == MATTER_OK);
    p->transport = NULL; p->host = NULL; p->udp = NULL;
}
static bool network_exchange(void) {
    bool ok = false;
    Pair* f = create_network();
    static const uint8_t data[] = {4,0,0,0,1,0,0,0,8,7,6,5,4,3,2,1,5,1,0x34,0x12,4,0,0xa1};
    static const uint8_t ack[] = {1,0,0,0,100,0,0,0,8,7,6,5,4,3,2,1,2,0x10,0x34,0x12,0,0,1,0,0,0};
    CHECK(f);
#ifdef MATTER_TEST_ALLOC
    size_t before = calls;
#endif
    CHECK(queue_data(&f->a, 0xa1) && tick(&f->a, 0) && f->a.retained && !f->a.completed);
    CHECK(session_pins(&f->a, f->a.session) == 3); /* Exchange, MRP, transport. */
    network_poll(&f->a); /* Complete recorded; keep adapter borrow until after ACK. */
    CHECK(f->a.completed == 1 && session_pins(&f->a, f->a.session) == 3);
    CHECK(network_receive(&f->b) && f->b.inbox.size == sizeof(data) && !memcmp(f->b.inbox.data, data, sizeof(data)));
    CHECK(!f->b.deliveries && network_admit(&f->b, 0) && tick(&f->b, 0) && f->b.deliveries == 1);
    CHECK(f->b.ingress_accepted == 1 && f->b.path.peer.port == f->a.path.local.port &&
        f->b.path.interface_id == f->b.received_path.interface_id);
    CHECK(tick(&f->b, 199) && !f->b.retained_ack);
    CHECK(tick(&f->b, 200) && f->b.retained_ack && session_pins(&f->b, f->b.session) == 3);
    CHECK(network_receive(&f->a) && f->a.inbox.size == sizeof(ack) && !memcmp(f->a.inbox.data, ack, sizeof(ack)));
    CHECK(network_admit(&f->a, 200) && tick(&f->a, 200) && f->a.ack_calls == 1 && !f->a.notifications);
    CHECK(f->a.retained && f->a.tx_pins == 1 && !memcmp(f->a.outbound.data, data, sizeof(data)));
    CHECK(network_take(&f->a) && !f->a.retained && session_pins(&f->a, f->a.session) == 2);
    CHECK(tick(&f->a, 200) && f->a.notifications == 1 && f->a.outcome == MATTER_RETRANSMISSION_ACKNOWLEDGED);
    CHECK(f->a.attempts == 1 && !f->a.tx_pins);
    network_poll(&f->b);
    CHECK(f->b.completed == 1 && network_take(&f->b) && !f->b.ack_pins);
    CHECK(f->a.outgoing.next == 2 && f->b.outgoing.next == 101);
#ifdef MATTER_TEST_ALLOC
    CHECK(calls == before);
#endif
    ok = true;
done: cleanup(f); return ok;
}
static bool network_retry_and_stop(void) {
    bool ok = false;
    Pair* f = create_network();
    CHECK(f && queue_data(&f->a, 0xa1) && tick(&f->a, 0));
    network_poll(&f->a); CHECK(network_take(&f->a));
    CHECK(network_receive(&f->b));
    f->delayed_data = f->b.inbox; f->b.inbox_full = false; /* Loss injected AFTER real socket RX. */
    CHECK(!f->b.session && tick(&f->a, 329) && f->a.sends == 1);
    CHECK(tick(&f->a, 330) && f->a.sends == 2 && f->a.resolver_pins == 1);
    CHECK(network_receive(&f->b) && f->b.inbox.size == f->delayed_data.size &&
        !memcmp(f->b.inbox.data, f->delayed_data.data, f->delayed_data.size));
    CHECK(network_admit(&f->b, 330) && tick(&f->b, 330) && f->b.deliveries == 1);
    CHECK(tick(&f->b, 530) && f->b.retained_ack);
    CHECK(stop_peer(&f->a) && stop_peer(&f->b));
    CHECK(tick(&f->a, 530) && tick(&f->b, 530) && !f->a.stopped && !f->b.stopped);
    CHECK(network_receive(&f->a) && network_admit(&f->a, 530) && tick(&f->a, 530));
    CHECK(f->a.completed == 2 && !f->a.notifications && f->a.retained);
    CHECK(network_take(&f->a) && tick(&f->a, 530));
    CHECK(f->a.notifications == 1 && f->a.attempts == 2 && f->a.outcome == MATTER_RETRANSMISSION_ACKNOWLEDGED);
    CHECK(!f->a.stopped && matter_udp_is_active(f->a.udp)); /* Resolver still owns session. */
    complete_resolver(&f->a);
    network_poll(&f->b); CHECK(network_take(&f->b));
    for (unsigned i = 0; i < 5; ++i) CHECK(tick(&f->a, 531 + i) && tick(&f->b, 531 + i));
    CHECK(f->a.stopped && f->b.stopped && !matter_udp_is_active(f->a.udp) && !matter_udp_is_active(f->b.udp));
    CHECK(f->a.outgoing.next == 2 && f->b.outgoing.next == 101 && !f->a.cancels);
    ok = true;
done: cleanup(f); return ok;
}
static bool network_shared_tx_and_cancel(void) {
    bool ok = false;
    Pair* f = create_network();
    CHECK(f && queue_data(&f->a, 0xa1) && tick(&f->a, 0));
    CHECK(network_receive(&f->b) && network_admit(&f->b, 0) && tick(&f->b, 0));
    CHECK(queue_data(&f->b, 0xb2) && tick(&f->b, 0));
    CHECK(network_receive(&f->a) && network_admit(&f->a, 0) && tick(&f->a, 0));
    CHECK(f->a.completed == 1 && f->a.retained && f->b.retained);
    CHECK(tick(&f->a, 200) && tick(&f->b, 200) && f->a.ack_waiting && f->b.ack_waiting);
    CHECK(!f->a.ack_sends && !f->b.ack_sends); /* Shared slot still owned by data. */
    CHECK(matter_retransmission_sender_cancel(f->a.tx, f->a.message_id) == MATTER_PENDING && f->a.cancels == 1);
    CHECK(!f->a.notifications && matter_udp_is_active(f->a.udp));
    CHECK(network_take(&f->a) && tick(&f->a, 200) && f->a.retained_ack);
    CHECK(f->a.notifications == 1 && f->a.outcome == MATTER_RETRANSMISSION_CANCELLED);
    CHECK(network_receive(&f->b) && network_admit(&f->b, 200) && tick(&f->b, 200));
    CHECK(!f->b.notifications && f->b.retained && f->b.completed == 1);
    CHECK(network_take(&f->b) && tick(&f->b, 200) && f->b.retained_ack);
    CHECK(f->b.notifications == 1 && f->b.outcome == MATTER_RETRANSMISSION_ACKNOWLEDGED);
    /* ACK reservations advance even on backpressure: A rejected once, B twice.
     * B's UDP request 2 must complete ACK request 3, never MRP request 1. */
    CHECK(f->a.udp_request == 2 && f->b.udp_request == 2 && f->a.ack_request == 2 && f->b.ack_request == 3);
    CHECK(network_receive(&f->a) && network_admit(&f->a, 201) && tick(&f->a, 201));
    CHECK(network_take(&f->a) && f->a.notifications == 1);
    network_poll(&f->b); CHECK(network_take(&f->b));
    CHECK(f->a.deliveries == 1 && f->b.deliveries == 1 && f->a.outgoing.next == 3 && f->b.outgoing.next == 102);
    CHECK(network_outcome(MATTER_OPERATION_FAILED) == MATTER_RETRANSMISSION_FATAL &&
        network_outcome(MATTER_OPERATION_CANCELLED) == MATTER_RETRANSMISSION_FATAL);
    CHECK(network_submission(MATTER_WOULD_BLOCK) == MATTER_RETRANSMISSION_REJECTED_RETRYABLE &&
        network_submission(MATTER_OFFLINE) == MATTER_RETRANSMISSION_REJECTED_RETRYABLE &&
        network_submission(MATTER_BUSY) == MATTER_RETRANSMISSION_REJECTED_RETRYABLE &&
        network_submission(MATTER_PORT_ERROR) == MATTER_RETRANSMISSION_REJECTED_FATAL);
    ok = true;
done: cleanup(f); return ok;
}
static bool network_rejected_routes(void) {
    bool ok = false;
    Pair* f = create_network();
    CHECK(f);
    uint16_t port = f->a.path.local.port;
    f->a.path.local.port = port == 1 ? 2 : 1; /* Valid envelope, wrong backend binding. */
    CHECK(queue_data(&f->a, 0xa1) && tick(&f->a, 0));
    CHECK(f->a.tx_result == MATTER_PORT_ERROR && f->a.notifications == 1 &&
        f->a.outcome == MATTER_RETRANSMISSION_FAILED && !f->a.retained && !f->a.udp_request);
    CHECK(!f->a.tx_pins && session_pins(&f->a, f->a.session) == 1);
    f->a.path.local.port = port;
    CHECK(queue_data(&f->a, 0xa2) && tick(&f->a, 1));
    CHECK(network_receive(&f->b) && network_admit(&f->b, 1) && tick(&f->b, 1));
    CHECK(f->b.deliveries == 1 && f->b.last_payload == 0xa2);
    port = f->b.path.local.port;
    f->b.path.local.port = port == 1 ? 2 : 1;
    CHECK(tick(&f->b, 201) && f->b.rx_result == MATTER_PORT_ERROR && !f->b.retained_ack && !f->b.udp_request);
    CHECK(!f->b.ack_pins && session_pins(&f->b, f->b.session) == 1);
    CHECK(f->b.outgoing.next == 101); /* Failed new ACK preparation never returns its counter. */
    f->b.path.local.port = port;
    CHECK(tick(&f->b, 202) && f->b.retained_ack && f->b.outgoing.next == 102);
    CHECK(network_receive(&f->a) && f->a.inbox.data[4] == 101 && f->a.inbox.data[22] == 2);
    CHECK(network_admit(&f->a, 202) && tick(&f->a, 202) && f->a.notifications == 1);
    CHECK(network_take(&f->a) && tick(&f->a, 202) && f->a.notifications == 2 &&
        f->a.outcome == MATTER_RETRANSMISSION_ACKNOWLEDGED && f->a.attempts == 1);
    network_poll(&f->b); CHECK(network_take(&f->b));
    CHECK(f->a.completed == 1 && f->b.completed == 1); /* Rejections produced no result event. */
    ok = true;
done: cleanup(f); return ok;
}
#ifdef MATTER_TEST_ALLOC
static bool network_allocation_failures(void) {
    bool ok = false;
    Pair* f = create_network();
    CHECK(f);
    size_t allocations = live;
    CHECK(allocations == 26); /* Existing 20 + host/UDP/TX adapter per peer. */
    cleanup(f); f = NULL;
    for (size_t i = 1; i <= allocations; ++i) {
        fail_at = calls + i; f = create_network();
        CHECK(!f && !live);
        fail_at = 0;
    }
    ok = true;
done: fail_at = 0; cleanup(f); return ok && !live;
}
#endif
#endif

static bool loss_duplicates_and_reordering(void) {
    bool ok = false;
    Pair* f = create();
    static const uint8_t expected[] = {4,0,0,0,1,0,0,0, 8,7,6,5,4,3,2,1, 5,1,0x34,0x12,4,0,0xa1};
    CHECK(f && queue_data(&f->a, 0xa1) && tick(&f->a, 0));
    CHECK(f->a.wire.size == sizeof(expected) && !memcmp(f->a.wire.data, expected, sizeof(expected)));
    f->delayed_data = f->a.wire; /* Initially lost; later delivered out of order. */
    CHECK(complete_tx(&f->a, MATTER_RETRANSMISSION_SENT));
    CHECK(tick(&f->a, 329) && f->a.sends == 1 && !f->b.deliveries);
    CHECK(tick(&f->a, 330) && f->a.sends == 2 && f->a.discoveries == 1);
    CHECK(!memcmp(f->a.wire.data, expected, sizeof(expected)));
    CHECK(receive_packet(&f->b, &f->a.wire, 330) == MATTER_OK && tick(&f->b, 330));
    CHECK(f->b.deliveries == 1 && f->b.last_payload == 0xa1 && !f->b.retained_ack);
    CHECK(complete_tx(&f->a, MATTER_RETRANSMISSION_SENT));
    CHECK(tick(&f->b, 529) && !f->b.retained_ack);
    CHECK(tick(&f->b, 530) && f->b.retained_ack);
    CHECK(f->b.wire.data[0] == 1 && f->b.wire.data[4] == 100 && f->b.wire.data[22] == 1);
    f->delayed_ack = f->b.wire; /* Lost ACK, local send still succeeds. */
    CHECK(complete_ack(&f->b, MATTER_OPERATION_SUCCEEDED));
    CHECK(tick(&f->a, 659) && f->a.sends == 2);
    CHECK(tick(&f->a, 660) && f->a.sends == 3 && f->a.discoveries == 1);
    CHECK(!memcmp(f->a.wire.data, expected, sizeof(expected)));
    CHECK(receive_packet(&f->b, &f->a.wire, 660) == MATTER_OK && tick(&f->b, 660));
    CHECK(f->b.deliveries == 1 && f->b.retained_ack); /* duplicate -> immediate ACK */
    CHECK(f->a.outgoing.next == 2 && f->b.wire.data[4] == 101 && f->b.wire.data[22] == 1);
    CHECK(receive_packet(&f->a, &f->b.wire, 660) == MATTER_OK && tick(&f->a, 660));
    CHECK(f->a.ack_calls == 1 && !f->a.notifications && f->a.tx_pins == 1);
    CHECK(complete_ack(&f->b, MATTER_OPERATION_SUCCEEDED) && complete_tx(&f->a, MATTER_RETRANSMISSION_SENT));
    CHECK(tick(&f->a, 660) && f->a.notifications == 1 && !f->a.tx_pins);
    CHECK(f->a.outcome == MATTER_RETRANSMISSION_ACKNOWLEDGED && f->a.attempts == 3);
    CHECK(receive_packet(&f->a, &f->delayed_ack, 661) == MATTER_OK && tick(&f->a, 661));
    CHECK(receive_packet(&f->a, &f->delayed_ack, 661) == MATTER_OK && tick(&f->a, 661));
    CHECK(f->a.ack_calls == 3 && f->a.notifications == 1 && !f->a.deliveries);
    CHECK(receive_packet(&f->b, &f->delayed_data, 661) == MATTER_OK && tick(&f->b, 661));
    CHECK(f->b.deliveries == 1 && f->b.retained_ack && f->b.ack_sends == 3);
    CHECK(complete_ack(&f->b, MATTER_OPERATION_SUCCEEDED));
    ok = true;
done: cleanup(f); return ok;
}

static bool bidirectional_stop(void) {
    bool ok = false;
    Pair* f = create();
    CHECK(f && queue_data(&f->a, 0xa1) && tick(&f->a, 0));
    CHECK(receive_packet(&f->b, &f->a.wire, 0) == MATTER_OK && tick(&f->b, 0));
    CHECK(queue_data(&f->b, 0xb2) && tick(&f->b, 0));
    CHECK(receive_packet(&f->a, &f->b.wire, 0) == MATTER_OK && tick(&f->a, 0));
    CHECK(f->a.deliveries == 1 && f->b.deliveries == 1 && f->a.last_payload == 0xb2);
    CHECK(stop_peer(&f->a) && stop_peer(&f->b) && tick(&f->a, 1) && tick(&f->b, 1));
    CHECK(f->a.ack_waiting && f->b.ack_waiting && !f->a.dependencies && !f->b.dependencies);
    CHECK(matter_rx_delete(f->a.rx) == MATTER_INVALID_STATE && matter_rx_delete(f->b.rx) == MATTER_INVALID_STATE);
    CHECK(complete_tx(&f->a, MATTER_RETRANSMISSION_SENT) && tick(&f->a, 1) && f->a.retained_ack);
    CHECK(receive_packet(&f->b, &f->a.wire, 1) == MATTER_OK && tick(&f->b, 1));
    CHECK(f->b.ack_calls == 1 && !f->b.notifications && f->b.tx_pins == 1);
    CHECK(complete_ack(&f->a, MATTER_OPERATION_SUCCEEDED));
    CHECK(complete_tx(&f->b, MATTER_RETRANSMISSION_FATAL) && tick(&f->b, 1)); /* ACK already won. */
    CHECK(f->b.notifications == 1 && f->b.outcome == MATTER_RETRANSMISSION_ACKNOWLEDGED && f->b.retained_ack);
    CHECK(receive_packet(&f->a, &f->b.wire, 1) == MATTER_OK && tick(&f->a, 1));
    CHECK(f->a.notifications == 1 && f->a.outcome == MATTER_RETRANSMISSION_ACKNOWLEDGED);
    CHECK(tick(&f->a, 2) && f->a.stopped && !f->a.rx_pins && !f->a.tx_pins);
    CHECK(tick(&f->b, 2) && !f->b.stopped && !f->b.dependencies && f->b.rx_pins == 1);
    CHECK(matter_get_state(f->a.owner) == MATTER_STATE_RUNNING && matter_get_state(f->b.owner) == MATTER_STATE_RUNNING);
    CHECK(complete_ack(&f->b, MATTER_OPERATION_SUCCEEDED) && tick(&f->b, 2) && f->b.stopped);
    CHECK(!f->b.rx_pins && !f->b.tx_pins && !f->a.cancels && !f->b.cancels);
    CHECK(f->a.deliveries == 1 && f->b.deliveries == 1);
    ok = true;
done: cleanup(f); return ok;
}

static bool reception_backpressure(void) {
    bool ok = false;
    Pair* f = create();
    Matter_Unsecured_Info_T info;
    CHECK(f && queue_data(&f->a, 0xa1) && tick(&f->a, 0));
    f->b.pin_error = MATTER_OFFLINE;
    CHECK(receive_packet(&f->b, &f->a.wire, 0) == MATTER_OFFLINE && !f->b.session && !f->b.rx_pins);
    CHECK(matter_unsecured_get(f->b.sessions, f->b.first_session, &info) == MATTER_INVALID_STATE);
    CHECK(!f->b.ingress_accepted); /* New context rolled back, no cache/selection update. */
    f->b.pin_error = MATTER_OK;
    CHECK(receive_packet(&f->b, &f->a.wire, 0) == MATTER_OK && seen(&f->b, f->b.session, 1));
    CHECK(f->b.session == f->b.first_session + 1); /* Rejected token never reused. */
    CHECK(session_pins(&f->b, f->b.session) == 1);
    CHECK(matter_unsecured_remove(f->b.sessions, f->b.session) == MATTER_BUSY); /* Queued RX owns pin. */
    f->b.pin_error = MATTER_WOULD_BLOCK; /* Defer responder insertion, after RX copied input. */
    CHECK(tick(&f->b, 0) && f->b.rx_result == MATTER_PENDING && !f->b.deliveries);
    f->delayed_data = f->a.wire;
    f->delayed_data.data[4] = 2; /* Literal next counter, same test exchange. */
    CHECK(receive_packet(&f->b, &f->delayed_data, 1) == MATTER_WOULD_BLOCK);
    CHECK(seen(&f->b, f->b.session, 1) && !seen(&f->b, f->b.session, 2));
    CHECK(session_pins(&f->b, f->b.session) == 1);
    f->b.pin_error = MATTER_OK;
    CHECK(tick(&f->b, 1) && f->b.deliveries == 1); /* Original new flag survived internal retry. */
    CHECK(receive_packet(&f->b, &f->delayed_data, 1) == MATTER_OK && tick(&f->b, 1));
    CHECK(seen(&f->b, f->b.session, 2) && f->b.deliveries == 1 && f->b.retained_ack);
    /* ACK for counter 1 must drain before queued counter 2 can be delivered. */
    CHECK(complete_ack(&f->b, MATTER_OPERATION_SUCCEEDED));
    CHECK(tick(&f->b, 2) && f->b.deliveries == 2);
    CHECK(receive_packet(&f->b, &f->delayed_data, 3) == MATTER_OK && tick(&f->b, 3));
    CHECK(f->b.deliveries == 2 && f->b.retained_ack); /* External duplicate still acknowledged. */
    CHECK(complete_ack(&f->b, MATTER_OPERATION_SUCCEEDED));
    CHECK(complete_tx(&f->a, MATTER_RETRANSMISSION_SENT));
    ok = true;
done: cleanup(f); return ok;
}

static bool ingress_routing_and_rejection(void) {
    bool ok = false;
    Pair* f = create();
    Matter_Unsecured_Info_T info;
    CHECK(f && queue_data(&f->a, 0xa1) && tick(&f->a, 0));
    f->delayed_data = f->a.wire;
    Matter_Udp_Datagram_T d = {.path = f->b.path, .data = f->delayed_data.data, .size = f->delayed_data.size};
    d.path.peer.port = 6000;
    uint16_t local = d.path.local.port;
    d.path.local.port = 0;
    CHECK(receive_datagram(&f->b, &d, 0) == MATTER_INVALID_ARGUMENT);
    d.path.local.port = local; f->delayed_data.data[20] = 5;
    CHECK(receive_datagram(&f->b, &d, 0) == MATTER_INVALID_ARGUMENT);
    CHECK(!f->b.session && !f->b.ingress_accepted && f->b.path.peer.port == 5540);
    CHECK(matter_unsecured_get(f->b.sessions, f->b.first_session, &info) == MATTER_INVALID_STATE);
    f->delayed_data.data[20] = 4;
    CHECK(receive_datagram(&f->b, &d, 0) == MATTER_OK && f->b.path.peer.port == 6000);
    CHECK(f->b.session == f->b.first_session && f->b.ingress_accepted == 1 && !f->b.deliveries);
    d.path.peer.port = 6001; f->delayed_data.data[4] = 2;
    CHECK(receive_datagram(&f->b, &d, 1) == MATTER_WOULD_BLOCK && !seen(&f->b, f->b.session, 2));
    CHECK(f->b.path.peer.port == 6000 && f->b.ingress_accepted == 1);
    f->delayed_data.data[8] = 9; /* Another context also rejected by full RX slot. */
    CHECK(receive_datagram(&f->b, &d, 1) == MATTER_WOULD_BLOCK);
    CHECK(matter_unsecured_get(f->b.sessions, f->b.first_session + 1, &info) == MATTER_INVALID_STATE);
    CHECK(f->b.session == f->b.first_session && session_pins(&f->b, f->b.session) == 1);
    CHECK(f->b.path.peer.port == 6000 && f->b.ingress_accepted == 1);
    f->delayed_data.data[8] = 8;
    CHECK(tick(&f->b, 1) && f->b.deliveries == 1);
    f->b.pin_error = MATTER_OFFLINE;
    CHECK(receive_datagram(&f->b, &d, 1) == MATTER_OFFLINE && !seen(&f->b, f->b.session, 2));
    CHECK(f->b.path.peer.port == 6000 && session_pins(&f->b, f->b.session) == 1);
    f->b.pin_error = MATTER_OK;
    CHECK(receive_datagram(&f->b, &d, 1) == MATTER_OK && f->b.path.peer.port == 6001);
    CHECK(tick(&f->b, 1) && f->b.retained_ack && complete_ack(&f->b, MATTER_OPERATION_SUCCEEDED));
    CHECK(tick(&f->b, 1) && f->b.deliveries == 2);
    CHECK(matter_unsecured_rx_close(f->b.ingress) == MATTER_OK);
    f->delayed_data.data[8] = 9;
    CHECK(receive_datagram(&f->b, &d, 1) == MATTER_INVALID_STATE); /* Adapter gates new sessions itself. */
    f->delayed_data.data[8] = 8; d.path.peer.port = 6002;
    CHECK(receive_datagram(&f->b, &d, 1) == MATTER_OK && f->b.path.peer.port == 6002);
    CHECK(tick(&f->b, 1) && f->b.deliveries == 2 && f->b.retained_ack);
    CHECK(complete_ack(&f->b, MATTER_OPERATION_SUCCEEDED));
    CHECK(stop_peer(&f->b) && tick(&f->b, 2) && f->b.stopped);
    CHECK(receive_datagram(&f->b, &d, 2) == MATTER_OFFLINE);
    CHECK(matter_unsecured_rx_receive(f->b.ingress, &d, 2) == MATTER_INVALID_STATE);
    CHECK(complete_tx(&f->a, MATTER_RETRANSMISSION_SENT));
    ok = true;
done: cleanup(f); return ok;
}

static bool exhausted_counter_retains_final_tx(void) {
    bool ok = false;
    /* Only the counter policy is secure here; link/session/crypto remain fake. */
    Pair* f = create_mode(MATTER_COUNTER_SECURE_UNICAST);
    Matter_Counter_Value_T rejected = {99, false};
    CHECK(f);
    f->a.outgoing.next = UINT32_MAX; /* Test-only fast-forward of prior consumption. */
    CHECK(queue_data(&f->a, 0xa1) && f->a.credentials_expired && f->a.outgoing.exhausted);
    CHECK(tick(&f->a, 0) && f->a.retained->message.counter == UINT32_MAX && f->a.tx_pins == 1);
    CHECK(matter_counter_take(&f->a.outgoing, &rejected) == MATTER_LIMIT_REACHED && rejected.counter == 99);
    CHECK(complete_tx(&f->a, MATTER_RETRANSMISSION_SENT)); /* Lost packet. */
    CHECK(tick(&f->a, 330) && f->a.retained->message.counter == UINT32_MAX && f->a.sends == 2);
    CHECK(receive_packet(&f->b, &f->a.wire, 330) == MATTER_OK && tick(&f->b, 330));
    CHECK(tick(&f->b, 530) && f->b.retained_ack);
    CHECK(receive_packet(&f->a, &f->b.wire, 530) == MATTER_OK && tick(&f->a, 530));
    CHECK(!f->a.notifications && f->a.tx_pins == 1 && f->a.rx_pins == 1);
    CHECK(complete_ack(&f->b, MATTER_OPERATION_SUCCEEDED));
    CHECK(complete_tx(&f->a, MATTER_RETRANSMISSION_SENT) && tick(&f->a, 530));
    CHECK(f->a.notifications == 1 && f->a.outcome == MATTER_RETRANSMISSION_ACKNOWLEDGED && !f->a.tx_pins);
    CHECK(f->a.outgoing.exhausted && !queue_data(&f->a, 0xb2));
    CHECK(f->a.sends == 2 && f->b.deliveries == 1);
    ok = true;
done: cleanup(f); return ok;
}

static bool timeout_and_cancel(void) {
    bool ok = false;
    Pair* f = NULL;
    Matter_Exchange_Info_T info;
    for (unsigned cancelled = 0; cancelled < 2; ++cancelled) {
        f = create();
        CHECK(f && queue_data(&f->a, 0xa1) && tick(&f->a, 0));
        f->delayed_data = f->a.wire;
        f->a.closing = true;
        CHECK(matter_unsecured_rx_close(f->a.ingress) == MATTER_OK);
        CHECK(matter_rx_close(f->a.rx, f->a.handle) == MATTER_PENDING);
        if (cancelled) {
            CHECK(matter_retransmission_sender_cancel(f->a.tx, f->a.message_id) == MATTER_PENDING);
            CHECK(f->a.cancels == 1 && f->a.tx_pins == 1 && !f->a.notifications);
            CHECK(complete_tx(&f->a, MATTER_RETRANSMISSION_FATAL) && tick(&f->a, 0));
            CHECK(f->a.outcome == MATTER_RETRANSMISSION_CANCELLED && f->a.attempts == 1);
        } else {
            CHECK(complete_tx(&f->a, MATTER_RETRANSMISSION_SENT));
            CHECK(tick(&f->a, 330) && complete_tx(&f->a, MATTER_RETRANSMISSION_SENT));
            CHECK(tick(&f->a, 660) && complete_tx(&f->a, MATTER_RETRANSMISSION_SENT));
            CHECK(tick(&f->a, 1187) && !f->a.notifications && f->a.tx_pins == 1);
            CHECK(tick(&f->a, 1188) && f->a.outcome == MATTER_RETRANSMISSION_TIMEOUT && f->a.attempts == 3);
        }
        CHECK(f->a.notifications == 1 && !f->a.tx_pins && tick(&f->a, 1189));
        CHECK(!f->a.rx_pins && matter_rx_get(f->a.rx, f->a.handle, &info) == MATTER_INVALID_STATE);
        /* A delayed datagram/ACK after local abort/timeout must not resurrect
         * the sender's exchange or emit a second terminal notification. */
        CHECK(receive_packet(&f->b, &f->delayed_data, 1190) == MATTER_OK && tick(&f->b, 1190));
        CHECK(tick(&f->b, 1390) && f->b.retained_ack);
        CHECK(receive_packet(&f->a, &f->b.wire, 1390) == MATTER_OK && tick(&f->a, 1390));
        CHECK(f->a.ack_calls == 1 && f->a.notifications == 1 && !f->a.rx_pins);
        CHECK(complete_ack(&f->b, MATTER_OPERATION_SUCCEEDED));
        cleanup(f); f = NULL;
    }
    ok = true;
done: cleanup(f); return ok;
}

static bool errors_close_and_resolver(void) {
    bool ok = false;
    Pair* f = create();
    Matter_Exchange_Info_T info;
    uint64_t id = 999;
    CHECK(f && queue_data(&f->a, 0xa1));
    f->a.submission = MATTER_RETRANSMISSION_REJECTED_RETRYABLE;
    CHECK(tick(&f->a, 0) && f->a.tx_result == MATTER_WOULD_BLOCK && !f->a.retained);
    f->a.submission = MATTER_RETRANSMISSION_SUBMITTED;
    CHECK(tick(&f->a, 330) && f->a.retained && f->a.resolver_pins == 1);
    CHECK(receive_packet(&f->b, &f->a.wire, 330) == MATTER_OK && tick(&f->b, 330));
    f->b.ack_error = MATTER_OFFLINE;
    CHECK(tick(&f->b, 530) && f->b.rx_result == MATTER_OFFLINE && !f->b.retained_ack);
    f->b.ack_error = MATTER_OK;
    CHECK(tick(&f->b, 531) && f->b.retained_ack);
    CHECK(complete_ack(&f->b, MATTER_OPERATION_FAILED));
    CHECK(tick(&f->b, 531) && f->b.retained_ack && f->b.ack_sends == 2);
    f->a.closing = true;
    CHECK(matter_unsecured_rx_close(f->a.ingress) == MATTER_OK);
    CHECK(matter_rx_close(f->a.rx, f->a.handle) == MATTER_PENDING);
    CHECK(matter_retransmission_sender_add(f->a.tx, &f->a.key, 1, f->a.outbound.data, f->a.outbound.size, &id)
        == MATTER_PORT_ERROR && id == 999 && f->a.tx_pins == 1);
    CHECK(receive_packet(&f->a, &f->b.wire, 531) == MATTER_OK && tick(&f->a, 531));
    CHECK(!f->a.notifications && matter_rx_get(f->a.rx, f->a.handle, &info) == MATTER_OK);
    CHECK(complete_tx(&f->a, MATTER_RETRANSMISSION_FATAL) && tick(&f->a, 531));
    CHECK(f->a.notifications == 1 && f->a.outcome == MATTER_RETRANSMISSION_ACKNOWLEDGED);
    CHECK(stop_peer(&f->a) && tick(&f->a, 532));
    CHECK(!f->a.rx_pins && !f->a.tx_pins && f->a.dependencies == 1 && !f->a.stopped && f->a.online);
    CHECK(matter_retransmission_sender_stop(f->a.tx) == MATTER_OK && f->a.rx_result == MATTER_PENDING);
    CHECK(session_pins(&f->a, f->a.session) == 1);
    CHECK(matter_unsecured_remove(f->a.sessions, f->a.session) == MATTER_BUSY);
    complete_resolver(&f->a); /* Independent completion, no sender pointer. */
    CHECK(tick(&f->a, 533) && f->a.stopped && !f->a.online);
    CHECK(complete_ack(&f->b, MATTER_OPERATION_SUCCEEDED) && stop_peer(&f->b) && tick(&f->b, 533));
    CHECK(f->b.stopped && f->b.deliveries == 1 && !f->a.deliveries);
    ok = true;
done: cleanup(f); return ok;
}

static bool two_contexts_and_independent_roles(void) {
    bool ok = false;
    Pair* f = create();
    Matter_Exchange_Session_T a_second, b_first, b_second;
    Matter_Exchange_Handle_T b_first_exchange;
    uint64_t node = UINT64_C(0x0102030405060709);
    CHECK(f && queue_data(&f->a, 0xa1) && tick(&f->a, 0));
    CHECK(receive_packet(&f->b, &f->a.wire, 0) == MATTER_OK && tick(&f->b, 0));
    b_first = f->b.session; b_first_exchange = f->b.handle;
    CHECK(matter_unsecured_initiate(f->a.sessions, node_random, &node, &a_second) == MATTER_OK);
    /* Same wire exchange ID and counter from a second simulated context.
     * Clone is intentional input injection, not a second call to the sender. */
    f->delayed_data = f->a.wire; f->delayed_data.data[8] = 9;
    CHECK(receive_packet(&f->b, &f->delayed_data, 1) == MATTER_OK && tick(&f->b, 1));
    b_second = f->b.session;
    CHECK(b_second != b_first && f->b.handle != b_first_exchange && f->b.deliveries == 2);
    CHECK(seen(&f->b, b_first, 1) && seen(&f->b, b_second, 1));
    CHECK(session_pins(&f->b, b_first) == 1 && session_pins(&f->b, b_second) == 1);
    CHECK(tick(&f->b, 200) && f->b.retained_ack && f->b.retained_ack->exchange.session == b_first);
    CHECK(f->b.wire.data[0] == 1 && f->b.wire.data[8] == 8 && f->b.wire.data[4] == 100);
    CHECK(session_pins(&f->b, b_first) == 2 && session_pins(&f->b, b_second) == 1);
    CHECK(matter_unsecured_remove(f->b.sessions, b_first) == MATTER_BUSY);
    CHECK(receive_packet(&f->a, &f->b.wire, 200) == MATTER_OK && tick(&f->a, 200));
    CHECK(seen(&f->a, f->a.session, 100) && !seen(&f->a, a_second, 100));
    CHECK(!f->a.notifications && complete_ack(&f->b, MATTER_OPERATION_SUCCEEDED));
    CHECK(tick(&f->b, 201) && f->b.retained_ack && f->b.retained_ack->exchange.session == b_second);
    CHECK(f->b.wire.data[8] == 9 && f->b.wire.data[4] == 101);
    CHECK(receive_packet(&f->a, &f->b.wire, 201) == MATTER_OK && tick(&f->a, 201));
    CHECK(seen(&f->a, a_second, 101) && !seen(&f->a, f->a.session, 101));
    CHECK(f->a.ack_calls == 2 && !f->a.notifications && !f->a.deliveries);
    CHECK(complete_ack(&f->b, MATTER_OPERATION_SUCCEEDED));
    CHECK(complete_tx(&f->a, MATTER_RETRANSMISSION_SENT) && tick(&f->a, 201) && f->a.notifications == 1);

    /* Session responder B now INITIATES an exchange: destination still carries
     * the session initiator's ID. A's responding ACK still carries source. */
    f->b.session = b_first;
    CHECK(matter_rx_initiate(f->b.rx, b_first, &f->b.handle) == MATTER_OK);
    CHECK(matter_rx_get(f->b.rx, f->b.handle, &f->b.key) == MATTER_OK && f->b.key.initiator);
    CHECK(queue_data(&f->b, 0xb2) && tick(&f->b, 202));
    CHECK(f->b.wire.data[0] == 1 && f->b.wire.data[16] == 5 && f->b.wire.data[4] == 102);
    CHECK(receive_packet(&f->a, &f->b.wire, 202) == MATTER_OK && tick(&f->a, 202));
    CHECK(f->a.deliveries == 1 && !f->a.key.initiator);
    CHECK(tick(&f->a, 402) && f->a.retained_ack && f->a.wire.data[0] == 4 && f->a.wire.data[16] == 2);
    CHECK(receive_packet(&f->b, &f->a.wire, 402) == MATTER_OK && tick(&f->b, 402));
    CHECK(complete_ack(&f->a, MATTER_OPERATION_SUCCEEDED));
    CHECK(complete_tx(&f->b, MATTER_RETRANSMISSION_SENT) && tick(&f->b, 402));
    CHECK(f->b.notifications == 1 && f->b.outcome == MATTER_RETRANSMISSION_ACKNOWLEDGED);
    CHECK(f->a.outgoing.next == 3 && f->b.outgoing.next == 103);
    ok = true;
done: cleanup(f); return ok;
}

static bool session_admission_and_retirement(void) {
    bool ok = false;
    Pair* f = create();
    Matter_Unsecured_Info_T info;
    Matter_Exchange_Session_T old, replacement;
    Matter_Message_Header_T header;
    size_t n;
    CHECK(f && queue_data(&f->a, 0xa1) && tick(&f->a, 0));
    f->delayed_data = f->a.wire;
    f->delayed_data.data[0] = 1; /* Unknown destination must never create a context. */
    CHECK(receive_packet(&f->b, &f->delayed_data, 0) == MATTER_INVALID_STATE && !f->b.rx_pins);
    f->delayed_data = f->a.wire; f->delayed_data.data[20] = 5; /* Unsupported test protocol. */
    CHECK(receive_packet(&f->b, &f->delayed_data, 0) == MATTER_INVALID_ARGUMENT);
    f->b.closing = true;
    CHECK(receive_packet(&f->b, &f->a.wire, 0) == MATTER_INVALID_STATE);
    CHECK(matter_unsecured_get(f->b.sessions, f->b.first_session, &info) == MATTER_INVALID_STATE);
    f->b.closing = false;
    CHECK(receive_packet(&f->b, &f->a.wire, 0) == MATTER_OK && tick(&f->b, 0));
    old = f->b.session;
    CHECK(old == f->b.first_session); /* Rejections consumed neither context nor token. */
    CHECK(tick(&f->b, 200) && f->b.retained_ack);
    CHECK(matter_rx_close(f->b.rx, f->b.handle) == MATTER_PENDING);
    CHECK(matter_unsecured_remove(f->b.sessions, old) == MATTER_BUSY && session_pins(&f->b, old) == 2);
    CHECK(receive_packet(&f->a, &f->b.wire, 200) == MATTER_OK && tick(&f->a, 200));
    CHECK(complete_ack(&f->b, MATTER_OPERATION_SUCCEEDED) && tick(&f->b, 200));
    CHECK(session_pins(&f->b, old) == 0 && matter_unsecured_remove(f->b.sessions, old) == MATTER_OK);
    CHECK(pin_rx(&f->b, old) == MATTER_PORT_ERROR && !f->b.rx_pins);
    CHECK(complete_tx(&f->a, MATTER_RETRANSMISSION_SENT) && tick(&f->a, 200));
    CHECK(matter_message_header_read(f->a.wire.data, f->a.wire.size, &header, &n) == MATTER_MESSAGE_OK);
    CHECK(matter_unsecured_resolve(f->b.sessions, &header, true, &replacement) == MATTER_OK && replacement != old);
    CHECK(!seen(&f->b, replacement, 1));
    CHECK(receive_packet(&f->b, &f->a.wire, 201) == MATTER_OK && tick(&f->b, 201));
    CHECK(f->b.session == replacement && f->b.deliveries == 2 && seen(&f->b, replacement, 1));
    CHECK(matter_unsecured_get(f->b.sessions, old, &info) == MATTER_INVALID_STATE);
    CHECK(stop_peer(&f->b) && tick(&f->b, 201) && f->b.retained_ack);
    f->delayed_data = f->a.wire; f->delayed_data.data[8] = 9;
    CHECK(receive_packet(&f->b, &f->delayed_data, 201) == MATTER_INVALID_STATE);
    CHECK(matter_unsecured_get(f->b.sessions, replacement + 1, &info) == MATTER_INVALID_STATE);
    CHECK(complete_ack(&f->b, MATTER_OPERATION_SUCCEEDED) && tick(&f->b, 202) && f->b.stopped);
    CHECK(matter_unsecured_get(f->b.sessions, replacement, &info) == MATTER_INVALID_STATE);
    CHECK(receive_packet(&f->b, &f->a.wire, 202) == MATTER_OFFLINE);
    ok = true;
done: cleanup(f); return ok;
}

#ifdef MATTER_TEST_ALLOC
static bool allocation_failures(void) {
    bool ok = false;
    Pair* f = NULL;
    /* Each peer owns sessions + owner + sender/ledger + RX's five + ingress. */
    for (unsigned i = 1; i <= 20; ++i) {
        fail_at = calls + i;
        f = create();
        CHECK(!f && !live);
        fail_at = 0;
    }
    f = create();
    CHECK(f && live == 20);
    size_t before = calls;
    CHECK(queue_data(&f->a, 0xa1) && tick(&f->a, 0));
    CHECK(receive_packet(&f->b, &f->a.wire, 0) == MATTER_OK && tick(&f->b, 0));
    CHECK(tick(&f->b, 200) && receive_packet(&f->a, &f->b.wire, 200) == MATTER_OK && tick(&f->a, 200));
    CHECK(complete_tx(&f->a, MATTER_RETRANSMISSION_SENT) && complete_ack(&f->b, MATTER_OPERATION_SUCCEEDED));
    CHECK(tick(&f->a, 200) && f->a.notifications == 1 && calls == before);
    ok = true;
done: fail_at = 0; cleanup(f); return ok && !live;
}
#endif
int main(void) {
    unsigned passed = 0;
#define RUN(t) do { if (!(t)()) return 1; ++passed; } while (0)
    RUN(loss_duplicates_and_reordering); RUN(bidirectional_stop); RUN(errors_close_and_resolver); RUN(timeout_and_cancel);
    RUN(reception_backpressure); RUN(ingress_routing_and_rejection);
    RUN(exhausted_counter_retains_final_tx);
    RUN(two_contexts_and_independent_roles); RUN(session_admission_and_retirement);
#ifdef MATTER_TEST_HOST_UDP
    RUN(network_exchange); RUN(network_retry_and_stop); RUN(network_shared_tx_and_cancel);
    RUN(network_rejected_routes);
#ifdef MATTER_TEST_ALLOC
    RUN(network_allocation_failures);
#endif
#endif
#ifdef MATTER_TEST_ALLOC
    RUN(allocation_failures);
    REQUIRE(!live);
#endif
#ifdef MATTER_TEST_HOST_UDP
    printf("PASS MRP pair Windows: %u groups (including real IPv6 R/ACK, retry, shared TX and drain)\n", passed);
#else
    printf("PASS MRP pair: %u groups\n", passed);
#endif
    return 0;
}

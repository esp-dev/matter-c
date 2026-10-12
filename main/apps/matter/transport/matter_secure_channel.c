#include "matter_secure_channel.h"
#include <stdlib.h>
#include <string.h>

struct Matter_Secure_Channel {
	Matter_Secure_T session;
	Matter_Exchange_Session_T token;
	Matter_Udp_Datagram_T datagram;
	Matter_Secure_Channel_Result_T result;
	Matter_Rx_T rx;
	uint64_t received_ms;
	uint16_t peer_session_id;
	bool busy, closed, pending, done, terminal, drained;
	uint8_t ack[38]; /* Largest control packet: CloseSession (8 + 14 + 16). */
};
static Matter_Result_T check(Matter_Secure_Channel_T c) {
	return !c ? MATTER_INVALID_ARGUMENT : c->busy ? MATTER_BUSY : MATTER_OK;
}
static bool unicast(const Matter_Udp_Address_T* a) {
	if (!a->port || a->address[0] == 0xff) return false;
	for (size_t i=0;i<sizeof(a->address);++i) if (a->address[i]) return true;
	return false;
}
static bool same_address(const Matter_Udp_Address_T* a, const Matter_Udp_Address_T* b) {
	return a->port == b->port && !memcmp(a->address,b->address,sizeof(a->address));
}
Matter_Secure_Channel_T matter_secure_channel_new(Matter_Secure_T session,
	Matter_Exchange_Session_T token, const Matter_Udp_Path_T* path) {
	Matter_Secure_Info_T info;
	if (!token || !path || !unicast(&path->local) || !unicast(&path->peer) ||
		matter_secure_info(session,&info) != MATTER_OK || info.closing) return NULL;
	Matter_Secure_Channel_T c = calloc(1,sizeof(*c));
	if (!c) return NULL;
	if (matter_secure_retain(session) != MATTER_OK) { free(c); return NULL; }
	c->session=session; c->token=token; c->datagram.path=*path; c->peer_session_id=info.peer_session_id;
	return c;
}
Matter_Result_T matter_secure_channel_parameters(Matter_Secure_Channel_T c, uint64_t now,
	Matter_Retransmission_Parameters_T* out) {
	Matter_Result_T r=check(c); if (r != MATTER_OK) return r;
	if (!out) return MATTER_INVALID_ARGUMENT;
	if (c->closed) return MATTER_INVALID_STATE;
	Matter_Secure_Info_T info;
	r=matter_secure_info(c->session,&info); if (r != MATTER_OK) return r;
	if (info.closing) return MATTER_INVALID_STATE;
	if (now < info.last_received_ms) return MATTER_INVALID_ARGUMENT;
	*out=(Matter_Retransmission_Parameters_T){info.peer_intervals.idle_ms,info.peer_intervals.active_ms,
		now-info.last_received_ms < info.peer_intervals.active_threshold_ms};
	return MATTER_OK;
}
Matter_Result_T matter_secure_channel_path(Matter_Secure_Channel_T c,Matter_Udp_Path_T* path) {
    Matter_Result_T r=check(c); if(r!=MATTER_OK) return r;
    if(!path) return MATTER_INVALID_ARGUMENT;
    *path=c->datagram.path; return MATTER_OK;
}
Matter_Result_T matter_secure_channel_route(Matter_Secure_Channel_T c,const Matter_Udp_Address_T* peer) {
    Matter_Result_T r=check(c); if(r!=MATTER_OK) return r;
    if(!peer || !unicast(peer)) return MATTER_INVALID_ARGUMENT;
    if(c->closed) return MATTER_INVALID_STATE;
    if(c->pending) return MATTER_BUSY;
    Matter_Secure_Identity_T identity;
    if(matter_secure_identity(c->session,&identity)!=MATTER_OK) return MATTER_INVALID_STATE;
    c->datagram.path.peer=*peer; return MATTER_OK;
}
Matter_Result_T matter_secure_channel_prepare(Matter_Secure_Channel_T c,
	const uint8_t* plain, size_t size, uint64_t now, uint8_t* packet, size_t capacity, Matter_Secure_Prepared_T* out) {
	Matter_Result_T r=check(c); if (r != MATTER_OK) return r;
	if (!out) return MATTER_INVALID_ARGUMENT;
	if (c->closed) return MATTER_INVALID_STATE;
	c->busy=true;
	size_t n;
	r=matter_secure_seal(c->session,plain,size,now,packet,capacity,&n);
	if (r == MATTER_OK) {
		Matter_Message_Header_T h; size_t offset;
		(void)matter_message_header_read(packet,n,&h,&offset);
		*out=(Matter_Secure_Prepared_T){n,h.message_counter};
	}
	c->busy=false; return r;
}
static Matter_Result_T admit(void* user, const Matter_Secure_Received_T* m) {
	Matter_Secure_Channel_T c=user;
	if (!m->protocol.vendor_id && !m->protocol.protocol_id && m->protocol.opcode == 0x40 && !m->duplicate) {
		if (m->size < 8) return MATTER_INVALID_ARGUMENT;
		/* Appendix D: GeneralCode SUCCESS, ProtocolId SECURE_CHANNEL, code 3.
		 * Only recognize the body protocol too; another protocol's code 3 is not close. */
		if (!m->payload[2] && !m->payload[3] && !m->payload[4] && !m->payload[5] &&
			m->payload[6] == 3 && !m->payload[7]) {
			if (m->size != 8 || m->payload[0] || m->payload[1] ||
				(m->protocol.exchange_flags & (MATTER_PROTOCOL_INITIATOR | MATTER_PROTOCOL_ACK | MATTER_PROTOCOL_RELIABLE)) !=
				MATTER_PROTOCOL_INITIATOR) return MATTER_INVALID_ARGUMENT;
			c->terminal=true; /* No RX queue/ACK obligation for CloseSession. */
			return MATTER_OK;
		}
	}
	/* A malformed duplicate standalone ACK must not become valid merely because
	 * secure_receive hides its application payload from the duplicate path. */
	if (!m->protocol.vendor_id && !m->protocol.protocol_id && m->protocol.opcode == 0x10 &&
		(!(m->protocol.exchange_flags & MATTER_PROTOCOL_ACK) || m->payload_size_on_wire)) return MATTER_INVALID_ARGUMENT;
	Matter_Rx_Input_T in={c->token,m->message.message_counter,m->duplicate,m->encoded,m->encoded_size};
	return matter_rx_receive(c->rx,&in,c->received_ms);
}
Matter_Result_T matter_secure_channel_receive(Matter_Secure_Channel_T c, Matter_Rx_T rx,
	const Matter_Udp_Datagram_T* d, uint64_t received, uint64_t now) {
	Matter_Result_T r=check(c); if (r != MATTER_OK) return r;
	if (!rx || !d || now < received) return MATTER_INVALID_ARGUMENT;
	if (c->closed) return MATTER_INVALID_STATE;
	if (!same_address(&d->path.local,&c->datagram.path.local) ||
		!same_address(&d->path.peer,&c->datagram.path.peer) || d->path.interface_id != c->datagram.path.interface_id)
		return MATTER_INVALID_ARGUMENT;
	c->busy=true; c->rx=rx; c->received_ms=received;
	r=matter_secure_receive(c->session,d->data,d->size,now,admit,c);
	if (r == MATTER_OK && c->terminal) {
		c->closed=true;
		(void)matter_secure_close(c->session); /* After authenticate/admit/commit unlocks. */
	}
	c->rx=NULL; c->busy=false; return r;
}
static Matter_Result_T submit(Matter_Secure_Channel_T c, Matter_Udp_T udp,
	const uint8_t* packet, size_t size, uint64_t* request) {
	c->datagram.data=packet; c->datagram.size=size;
	uint64_t id;
	Matter_Result_T r=matter_udp_send(udp,&c->datagram,&id);
	if (r == MATTER_PENDING) {
		c->result=(Matter_Secure_Channel_Result_T){id,MATTER_OPERATION_SUCCEEDED};
		c->pending=true; c->done=false; *request=id;
	} else { c->datagram.data=NULL; c->datagram.size=0; }
	return r;
}
Matter_Result_T matter_secure_channel_send(Matter_Secure_Channel_T c, Matter_Udp_T udp,
	const uint8_t* packet, size_t size, uint64_t* request) {
	Matter_Result_T r=check(c); if (r != MATTER_OK) return r;
	if (!udp || !packet || !request) return MATTER_INVALID_ARGUMENT;
	if (c->closed) return MATTER_INVALID_STATE;
	if (c->pending) return MATTER_BUSY;
	if (size > MATTER_SECURE_MAX_PACKET) return MATTER_LIMIT_REACHED;
	Matter_Message_Header_T h; size_t offset;
	if (matter_message_header_read(packet,size,&h,&offset) != MATTER_MESSAGE_OK ||
		h.session_id != c->peer_session_id || h.message_flags || h.security_flags || size-offset < 22)
		return MATTER_INVALID_ARGUMENT;
	c->busy=true; r=submit(c,udp,packet,size,request); c->busy=false; return r;
}
Matter_Result_T matter_secure_channel_send_ack(Matter_Secure_Channel_T c, Matter_Udp_T udp,
	const Matter_Ack_Message_T* m, uint64_t now, uint64_t* request) {
	Matter_Result_T r=check(c); if (r != MATTER_OK) return r;
	if (!udp || !m || !request || m->exchange.session != c->token) return MATTER_INVALID_ARGUMENT;
	if (c->closed) return MATTER_INVALID_STATE;
	if (c->pending) return MATTER_BUSY;
	Matter_Protocol_Header_T h; size_t n;
	if (m->size != 10 || matter_protocol_header_read(m->data,m->size,&h,&n) != MATTER_MESSAGE_OK ||
		n != m->size || h.exchange_flags != (MATTER_PROTOCOL_ACK | (m->exchange.initiator ? MATTER_PROTOCOL_INITIATOR : 0)) ||
		h.exchange_id != m->exchange.exchange_id || h.protocol_id || h.vendor_id || h.opcode != 0x10) return MATTER_INVALID_ARGUMENT;
	c->busy=true;
	r=matter_secure_seal(c->session,m->data,m->size,now,c->ack,sizeof(c->ack),&n);
	if (r == MATTER_OK) r=submit(c,udp,c->ack,n,request);
	if (r != MATTER_PENDING) memset(c->ack,0,sizeof(c->ack)); /* Ciphertext, no secrets. */
	c->busy=false; return r;
}
Matter_Result_T matter_secure_channel_complete(Matter_Secure_Channel_T c, uint64_t request, Matter_Operation_Result_T outcome) {
	Matter_Result_T r=check(c); if (r != MATTER_OK) return r;
	if (!request || (outcome != MATTER_OPERATION_SUCCEEDED && outcome != MATTER_OPERATION_FAILED && outcome != MATTER_OPERATION_CANCELLED)) return MATTER_INVALID_ARGUMENT;
	if (!c->pending || c->done || request != c->result.request) return MATTER_INVALID_STATE;
	c->result.outcome=outcome; c->done=true; return MATTER_OK;
}
Matter_Result_T matter_secure_channel_take(Matter_Secure_Channel_T c, Matter_Secure_Channel_Result_T* out) {
	Matter_Result_T r=check(c); if (r != MATTER_OK) return r;
	if (!out) return MATTER_INVALID_ARGUMENT;
	if (!c->pending) return MATTER_INVALID_STATE;
	if (!c->done) return MATTER_PENDING;
	*out=c->result; c->result=(Matter_Secure_Channel_Result_T){0};
	c->datagram.data=NULL; c->datagram.size=0; c->pending=c->done=false;
	memset(c->ack,0,sizeof(c->ack)); return MATTER_OK;
}
Matter_Result_T matter_secure_channel_close(Matter_Secure_Channel_T c) {
	Matter_Result_T r=check(c); if (r != MATTER_OK) return r;
	c->closed=true; return c->pending ? MATTER_PENDING : MATTER_OK;
}
Matter_Result_T matter_secure_channel_is_closed(Matter_Secure_Channel_T c, bool* closed) {
	Matter_Result_T r=check(c); if (r != MATTER_OK) return r;
	if (!closed) return MATTER_INVALID_ARGUMENT;
	*closed=c->closed; return MATTER_OK;
}
Matter_Result_T matter_secure_channel_send_close(Matter_Secure_Channel_T c, Matter_Rx_T rx,
	Matter_Udp_T udp, uint64_t now, uint64_t* request) {
	Matter_Result_T r=check(c); if (r != MATTER_OK) return r;
	if (!rx || !udp || !request) return MATTER_INVALID_ARGUMENT;
	if (c->closed) return MATTER_INVALID_STATE;
	if (c->pending) return MATTER_BUSY;
	c->busy=true;
	Matter_Exchange_Handle_T handle;
	r=matter_rx_initiate(rx,c->token,&handle);
	if (r == MATTER_OK) {
		Matter_Exchange_Info_T key;
		r=matter_rx_get(rx,handle,&key);
		if (r == MATTER_OK) {
			/* 14 bytes, bounded control message only; ciphertext lives on heap. */
			uint8_t plain[14]={0}; size_t n;
			Matter_Protocol_Header_T h={.exchange_id=key.exchange_id,
				.exchange_flags=MATTER_PROTOCOL_INITIATOR,.opcode=0x40};
			(void)matter_protocol_header_write(&h,plain,sizeof(plain),&n);
			plain[n+6]=3;
			r=matter_secure_seal(c->session,plain,sizeof(plain),now,c->ack,sizeof(c->ack),&n);
			if (r == MATTER_OK) r=submit(c,udp,c->ack,n,request);
		}
		/* No R, ACK, RX or MRP record belongs to this newly allocated exchange. */
		(void)matter_rx_close(rx,handle);
	}
	if (r == MATTER_PENDING) {
		c->closed=c->terminal=true;
		(void)matter_secure_close(c->session);
	} else memset(c->ack,0,sizeof(c->ack));
	c->busy=false; return r;
}
Matter_Result_T matter_secure_channel_retire(Matter_Secure_Channel_T c, Matter_Rx_T rx,
	Matter_Retransmission_Sender_T tx) {
	Matter_Result_T r=check(c); if (r != MATTER_OK) return r;
	if (!rx || !tx) return MATTER_INVALID_ARGUMENT;
	c->busy=true; c->closed=c->terminal=true;
	r=matter_secure_close(c->session);
	if (r == MATTER_OK) {
		Matter_Result_T mrp=matter_retransmission_sender_cancel_session(tx,c->token);
		Matter_Result_T received=matter_rx_retire_session(rx,c->token);
		if (mrp != MATTER_OK && mrp != MATTER_PENDING) r=mrp;
		else if (received != MATTER_OK && received != MATTER_PENDING) r=received;
		else {
			Matter_Secure_Info_T info;
			r=matter_secure_info(c->session,&info);
			if (r == MATTER_OK && (mrp == MATTER_PENDING || received == MATTER_PENDING ||
				c->pending || info.pins != 1)) r=MATTER_PENDING;
		}
	}
	c->drained=r == MATTER_OK; c->busy=false; return r;
}
Matter_Result_T matter_secure_channel_delete(Matter_Secure_Channel_T c) {
	if (!c) return MATTER_OK;
	Matter_Result_T r=check(c); if (r != MATTER_OK) return r;
	if (!c->closed || c->pending || (c->terminal && !c->drained)) return MATTER_INVALID_STATE;
	c->busy=true; r=matter_secure_release(c->session);
	if (r != MATTER_OK) { c->busy=false; return r; }
	free(c); return MATTER_OK;
}

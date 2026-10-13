#include "matter_rx.h"
#include <stdlib.h>
#include <string.h>

typedef struct {
	Matter_Exchange_Handle_T handle;
	Matter_Exchange_Info_T info;
	bool closing;
} Exchange;

enum State { NEW, RUNNING, DRAINING, DEPENDENCIES, STOPPED };
struct Matter_Rx {
	Matter_T owner;
	Matter_Rx_Port_T port;
	Matter_Exchange_Table_T table;
	Matter_Rx_Policy_T policy;
	Matter_Ack_Table_T ack;
	Matter_Ack_Sender_T sender;
	Exchange exchanges[MATTER_EXCHANGE_CAPACITY];
	Matter_Exchange_Info_T ephemeral, queued_key;
	Matter_Rx_Input_T input;
	Matter_Rx_Decision_T decision;
	uint64_t received, now;
	uint32_t im_received;
	enum State state;
	bool queued, ack_processed, busy;
	uint8_t bytes[MATTER_RX_MAX_PLAINTEXT];
};

static bool same(const Matter_Exchange_Info_T* a, const Matter_Exchange_Info_T* b) {
	return a->session == b->session && a->exchange_id == b->exchange_id && a->initiator == b->initiator;
}

static Matter_Result_T check(Matter_Rx_T rx) {
	return !rx ? MATTER_INVALID_ARGUMENT : rx->busy ? MATTER_BUSY : MATTER_OK;
}

static Matter_Result_T ready(Matter_Rx_T rx) {
	Matter_Result_T result = check(rx);
	if (result != MATTER_OK) return result;
	if (rx->state != RUNNING && rx->state != DRAINING) return MATTER_INVALID_STATE;
	return matter_exchange_check(rx->table);
}

static Matter_Result_T submission(Matter_Result_T result) {
	return result == MATTER_OK || result == MATTER_WOULD_BLOCK || result == MATTER_OFFLINE ?
		result : MATTER_PORT_ERROR;
}

/* Error > pending > OK. WOULD_BLOCK is internal deferred work here. */
static Matter_Result_T combine(Matter_Result_T a, Matter_Result_T b) {
	if (a == MATTER_WOULD_BLOCK) a = MATTER_PENDING;
	if (b == MATTER_WOULD_BLOCK) b = MATTER_PENDING;
	if (a != MATTER_OK && a != MATTER_PENDING) return a;
	if (b != MATTER_OK && b != MATTER_PENDING) return b;
	return a == MATTER_PENDING || b == MATTER_PENDING ? MATTER_PENDING : MATTER_OK;
}

static void decided(void* user, const Matter_Rx_Decision_T* decision) {
	Matter_Rx_T rx = user;
	rx->decision = *decision; /* Replaced before use; process points into owned bytes. */
}

static Matter_Result_T prepare(void* user, Matter_Exchange_Handle_T handle, const Matter_Exchange_Info_T* info) {
	Matter_Rx_T rx = user;
	(void)handle;
	Matter_Result_T ack = matter_ack_close(rx->ack, info);
	Matter_Result_T tx = rx->port.exchange_drained(rx->port.user, info);
	if (tx != MATTER_OK && tx != MATTER_PENDING) tx = MATTER_PORT_ERROR;
	if (rx->queued && same(info, &rx->queued_key)) ack = combine(ack, MATTER_PENDING);
	return combine(ack, tx);
}

Matter_Rx_T matter_rx_new(Matter_T owner, uint16_t initial_id, const Matter_Rx_Port_T* port) {
	if (!owner || !port || !port->ack.send || !port->ack.detach || !port->retain || !port->release ||
		!port->process_ack || !port->exchange_drained || !port->deliver || !port->stop_dependencies) return NULL;
	Matter_Rx_T rx = calloc(1, sizeof(*rx));
	if (!rx) return NULL;
	rx->owner = owner;
	rx->port = *port;
	rx->table = matter_exchange_new(owner, initial_id);
	rx->ack = matter_ack_new();
	Matter_Rx_Listener_T listener = {rx, decided};
	rx->policy = matter_rx_policy_new(rx->table, &listener);
	/* Sender last: no detach callback on any construction failure. */
	if (rx->table && rx->ack && rx->policy) rx->sender = matter_ack_sender_new(rx->ack, &port->ack);
	if (!rx->sender) {
		matter_rx_policy_delete(rx->policy);
		matter_exchange_delete(rx->table);
		matter_ack_delete(rx->ack);
		free(rx);
		return NULL;
	}
	Matter_Exchange_Close_Port_T close_port = {rx, prepare};
	matter_exchange_set_close_port(rx->table, &close_port);
	return rx;
}

Matter_Result_T matter_rx_delete(Matter_Rx_T rx) {
	if (!rx) return MATTER_OK;
	Matter_Result_T result = check(rx);
	if (result != MATTER_OK) return result;
	if (rx->state != NEW && rx->state != STOPPED) return MATTER_INVALID_STATE;
	rx->busy = true;
	matter_ack_sender_stop(rx->sender); /* Empty, also on a never-started instance. */
	matter_ack_sender_delete(rx->sender);
	matter_rx_policy_delete(rx->policy);
	matter_exchange_delete(rx->table);
	matter_ack_delete(rx->ack);
	free(rx);
	return MATTER_OK;
}

Matter_Result_T matter_rx_start(Matter_Rx_T rx) {
	Matter_Result_T result = check(rx);
	if (result != MATTER_OK) return result;
	if (rx->state == RUNNING) return matter_exchange_check(rx->table);
	if (rx->state != NEW) return MATTER_INVALID_STATE;
	result = matter_exchange_start(rx->table);
	if (result == MATTER_OK) rx->state = RUNNING;
	return result;
}

Matter_Result_T matter_rx_stop(Matter_Rx_T rx) {
	Matter_Result_T result = check(rx);
	if (result != MATTER_OK) return result;
	if (rx->state == NEW) rx->state = STOPPED;
	if (rx->state == STOPPED) return MATTER_OK;
	if (rx->state == RUNNING) rx->state = DRAINING;
	return MATTER_PENDING;
}

Matter_Result_T matter_rx_register(Matter_Rx_T rx, uint16_t vendor, uint16_t protocol) {
	Matter_Result_T result = check(rx);
	return result == MATTER_OK ? matter_rx_policy_register(rx->policy, vendor, protocol) : result;
}

Matter_Result_T matter_rx_unregister(Matter_Rx_T rx, uint16_t vendor, uint16_t protocol) {
	Matter_Result_T result = check(rx);
	return result == MATTER_OK ? matter_rx_policy_unregister(rx->policy, vendor, protocol) : result;
}

static Exchange* find(Matter_Rx_T rx, Matter_Exchange_Handle_T handle) {
	for (size_t i = 0; i < MATTER_EXCHANGE_CAPACITY; ++i)
		if (rx->exchanges[i].handle == handle) return &rx->exchanges[i];
	return NULL;
}

static Matter_Result_T insert(Matter_Rx_T rx, Matter_Exchange_Session_T session,
	uint16_t wire, bool initiator, Matter_Exchange_Handle_T* handle) {
	Exchange* entry = find(rx, 0);
	if (!entry) return MATTER_LIMIT_REACHED;
	/* A private ephemeral must finish before this key can become normal.
	 * Initiate's next random wire ID is private to the table: conservatively wait. */
	Matter_Exchange_Info_T key = {session, wire, false};
	if (rx->ephemeral.session && (initiator || same(&key, &rx->ephemeral))) return MATTER_WOULD_BLOCK;
	Matter_Result_T result = submission(rx->port.retain(rx->port.user, session));
	if (result != MATTER_OK) return result;
	result = initiator ? matter_exchange_initiate(rx->table, session, handle) :
		matter_exchange_accept(rx->table, session, wire, handle);
	if (result != MATTER_OK) rx->port.release(rx->port.user, session);
	else {
		entry->handle = *handle;
		matter_exchange_get(rx->table, *handle, &entry->info);
	}
	return result;
}

Matter_Result_T matter_rx_initiate(Matter_Rx_T rx, Matter_Exchange_Session_T session,
	Matter_Exchange_Handle_T* handle) {
	Matter_Result_T result = ready(rx);
	if (result != MATTER_OK) return result;
	if (!session || !handle) return MATTER_INVALID_ARGUMENT;
	if (rx->state != RUNNING) return MATTER_INVALID_STATE;
	rx->busy = true;
	result = insert(rx, session, 0, true, handle);
	rx->busy = false;
	return result;
}

Matter_Result_T matter_rx_get(Matter_Rx_T rx, Matter_Exchange_Handle_T handle, Matter_Exchange_Info_T* info) {
	Matter_Result_T result = ready(rx);
	return result == MATTER_OK ? matter_exchange_get(rx->table, handle, info) : result;
}

static Matter_Result_T close_entry(Matter_Rx_T rx, Exchange* entry) {
	entry->closing = true;
	Matter_Result_T result = matter_exchange_release(rx->table, entry->handle);
	if (result == MATTER_OK) {
		rx->port.release(rx->port.user, entry->info.session);
		*entry = (Exchange){0};
	}
	return result;
}

Matter_Result_T matter_rx_close(Matter_Rx_T rx, Matter_Exchange_Handle_T handle) {
	Matter_Result_T result = ready(rx);
	if (result != MATTER_OK) return result;
	if (!handle) return MATTER_INVALID_ARGUMENT;
	Exchange* entry = find(rx, handle);
	if (!entry) return MATTER_INVALID_STATE;
	rx->busy = true;
	result = close_entry(rx, entry);
	rx->busy = false;
	return result;
}

Matter_Result_T matter_rx_receive(Matter_Rx_T rx, const Matter_Rx_Input_T* input, uint64_t received_ms) {
	Matter_Result_T result = ready(rx);
	if (result != MATTER_OK) return result;
	if (!input || !input->data || !input->session) return MATTER_INVALID_ARGUMENT;
	if (input->size > sizeof(rx->bytes)) return MATTER_LIMIT_REACHED;
	if (rx->queued) return MATTER_WOULD_BLOCK;
	rx->busy = true;
	result = matter_rx_policy_receive(rx->policy, input);
	if (result == MATTER_OK) result = submission(rx->port.retain(rx->port.user, input->session));
	if (result == MATTER_OK) {
		memcpy(rx->bytes, input->data, input->size);
		rx->input = *input;
		rx->input.data = rx->bytes;
		rx->queued_key = (Matter_Exchange_Info_T){input->session, rx->decision.header.exchange_id,
			!(rx->decision.header.exchange_flags & MATTER_PROTOCOL_INITIATOR)};
		rx->received = received_ms;
		rx->queued = true;
		rx->ack_processed = false;
		/* Count admitted IM messages once, even if later rejected by an
		 * exchange/handler. Authentication and replay classification precede RX. */
		if (!input->duplicate && !rx->decision.header.vendor_id && rx->decision.header.protocol_id == 1 && rx->im_received < UINT32_MAX)
			++rx->im_received;
	}
	rx->decision = (Matter_Rx_Decision_T){0}; /* Never retain the caller's bytes. */
	rx->busy = false;
	return result;
}

uint32_t matter_rx_im_received(Matter_Rx_T rx) { return rx ? rx->im_received : 0; }

Matter_Result_T matter_rx_retire_session(Matter_Rx_T rx, Matter_Exchange_Session_T session) {
	Matter_Result_T result = ready(rx);
	if (result != MATTER_OK) return result;
	if (!session) return MATTER_INVALID_ARGUMENT;
	rx->busy = true;
	if (rx->queued && rx->input.session == session) {
		rx->port.release(rx->port.user, session);
		rx->queued = rx->ack_processed = false;
		rx->input = (Matter_Rx_Input_T){0};
		rx->decision = (Matter_Rx_Decision_T){0};
		memset(rx->bytes, 0, sizeof(rx->bytes));
	}
	result = matter_ack_discard_session(rx->ack, session);
	if (rx->ephemeral.session == session && matter_ack_close(rx->ack, &rx->ephemeral) == MATTER_OK) {
		rx->port.release(rx->port.user, session);
		rx->ephemeral = (Matter_Exchange_Info_T){0};
	}
	for (size_t i = 0; i < MATTER_EXCHANGE_CAPACITY; ++i) {
		Exchange* entry = &rx->exchanges[i];
		if (entry->handle && entry->info.session == session) result = combine(result, close_entry(rx, entry));
	}
	rx->busy = false;
	return result;
}

static Matter_Result_T receive_queued(Matter_Rx_T rx) {
	if (!rx->queued) return MATTER_OK;
	Matter_Result_T result = matter_rx_policy_receive(rx->policy, &rx->input);
	if (result != MATTER_OK) return result;
	Matter_Rx_Decision_T* d = &rx->decision;
	if (d->process_ack && !rx->ack_processed) {
		result = submission(rx->port.process_ack(rx->port.user, &rx->queued_key,
			d->header.acknowledged_message_counter));
		if (result != MATTER_OK) return result;
		rx->ack_processed = true;
	}
	if (rx->state == DRAINING) {
		d->action = MATTER_RX_DROP;
		if (d->ack != MATTER_RX_ACK_NONE) d->ack = MATTER_RX_ACK_IMMEDIATE;
	}
	if (d->action == MATTER_RX_NEW_RESPONDER) {
		result = insert(rx, d->session, d->header.exchange_id, false, &d->exchange);
		if (result != MATTER_OK) return result;
	}
	bool transfer = false;
	if (d->ack == MATTER_RX_ACK_PENDING)
		result = matter_ack_record(rx->ack, &rx->queued_key, d->message_counter, rx->received);
	else if (d->ack == MATTER_RX_ACK_IMMEDIATE) {
		if (!d->exchange && rx->ephemeral.session) return MATTER_WOULD_BLOCK;
		result = matter_ack_immediate(rx->ack, &rx->queued_key, d->message_counter);
		if (result == MATTER_OK && !d->exchange) {
			rx->ephemeral = rx->queued_key;
			transfer = true;
		}
	}
	if (result != MATTER_OK) return result;
	if (d->action != MATTER_RX_DROP) rx->port.deliver(rx->port.user, d);
	if (!transfer) rx->port.release(rx->port.user, rx->input.session);
	rx->queued = false;
	rx->input = (Matter_Rx_Input_T){0};
	rx->decision = (Matter_Rx_Decision_T){0};
	return MATTER_OK;
}

Matter_Result_T matter_rx_complete(Matter_Rx_T rx, uint64_t request, Matter_Operation_Result_T result) {
	Matter_Result_T checked = check(rx);
	return checked == MATTER_OK ? matter_ack_sender_complete(rx->sender, request, result) : checked;
}

Matter_Result_T matter_rx_process(Matter_Rx_T rx, uint64_t now_ms) {
	Matter_Result_T result = check(rx);
	if (result != MATTER_OK) return result;
	if (rx->state == NEW) return MATTER_INVALID_STATE;
	if (rx->state == STOPPED) return MATTER_OK;
	if (matter_get_state(rx->owner) != MATTER_STATE_RUNNING) return MATTER_INVALID_STATE;
	if (now_ms < rx->now || (rx->queued && now_ms < rx->received)) return MATTER_INVALID_ARGUMENT;
	rx->now = now_ms;
	rx->busy = true;
	if (rx->state != DEPENDENCIES) {
		result = receive_queued(rx);
		if (rx->ephemeral.session && matter_ack_close(rx->ack, &rx->ephemeral) == MATTER_OK) {
			rx->port.release(rx->port.user, rx->ephemeral.session);
			rx->ephemeral = (Matter_Exchange_Info_T){0};
		}
		bool entries = false;
		for (size_t i = 0; i < MATTER_EXCHANGE_CAPACITY; ++i) {
			Exchange* entry = &rx->exchanges[i];
			if (entry->handle && (entry->closing || rx->state == DRAINING))
				result = combine(result, close_entry(rx, entry));
			entries |= entry->handle != 0;
		}
		Matter_Result_T sent = matter_ack_sender_process(rx->sender, now_ms);
		result = combine(result, sent == MATTER_WOULD_BLOCK ? MATTER_OK : sent);
		if (rx->state == DRAINING && !entries && !rx->queued && !rx->ephemeral.session &&
			matter_ack_sender_stop(rx->sender) == MATTER_OK) {
			Matter_Result_T stopped = matter_exchange_stop(rx->table);
			if (stopped == MATTER_PENDING) stopped = matter_exchange_process(rx->table);
			result = combine(result, stopped);
			if (stopped == MATTER_OK) rx->state = DEPENDENCIES;
		}
	}
	if (rx->state == DEPENDENCIES) {
		result = rx->port.stop_dependencies(rx->port.user);
		if (result == MATTER_OK) rx->state = STOPPED;
		else if (result != MATTER_PENDING) result = MATTER_PORT_ERROR;
	} else if (rx->state == DRAINING || rx->queued || rx->ephemeral.session)
		result = combine(result, MATTER_PENDING);
	rx->busy = false;
	return result;
}

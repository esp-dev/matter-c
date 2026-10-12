#include "matter_rx_policy.h"
#include <stdlib.h>

typedef struct {
	uint16_t vendor, protocol;
	bool used;
} Protocol;

struct Matter_Rx_Policy {
	Matter_Exchange_Table_T table;
	Matter_Rx_Listener_T listener;
	Protocol protocols[MATTER_RX_PROTOCOL_CAPACITY];
	bool busy;
};

static Protocol* find_protocol(Matter_Rx_Policy_T policy, uint16_t vendor, uint16_t protocol) {
	for (size_t i = 0; i < MATTER_RX_PROTOCOL_CAPACITY; ++i) {
		Protocol* p = &policy->protocols[i];
		if (p->used && p->vendor == vendor && p->protocol == protocol) return p;
	}
	return NULL;
}

Matter_Rx_Policy_T matter_rx_policy_new(Matter_Exchange_Table_T table, const Matter_Rx_Listener_T* listener) {
	if (!table || !listener || !listener->decided) return NULL;
	Matter_Rx_Policy_T policy = calloc(1, sizeof(*policy));
	if (!policy) return NULL;
	policy->table = table;
	policy->listener = *listener;
	return policy;
}

Matter_Result_T matter_rx_policy_delete(Matter_Rx_Policy_T policy) {
	if (!policy) return MATTER_OK;
	if (policy->busy) return MATTER_BUSY;
	free(policy);
	return MATTER_OK;
}

Matter_Result_T matter_rx_policy_register(Matter_Rx_Policy_T policy, uint16_t vendor, uint16_t protocol) {
	if (!policy) return MATTER_INVALID_ARGUMENT;
	if (policy->busy) return MATTER_BUSY;
	if (!vendor && protocol > 4) return MATTER_INVALID_ARGUMENT;
	if (find_protocol(policy, vendor, protocol)) return MATTER_BUSY;
	for (size_t i = 0; i < MATTER_RX_PROTOCOL_CAPACITY; ++i) {
		if (!policy->protocols[i].used) {
			policy->protocols[i] = (Protocol){vendor, protocol, true};
			return MATTER_OK;
		}
	}
	return MATTER_LIMIT_REACHED;
}

Matter_Result_T matter_rx_policy_unregister(Matter_Rx_Policy_T policy, uint16_t vendor, uint16_t protocol) {
	if (!policy) return MATTER_INVALID_ARGUMENT;
	if (policy->busy) return MATTER_BUSY;
	Protocol* p = find_protocol(policy, vendor, protocol);
	if (!p) return MATTER_INVALID_STATE;
	*p = (Protocol){0};
	return MATTER_OK;
}

Matter_Result_T matter_rx_policy_receive(Matter_Rx_Policy_T policy, const Matter_Rx_Input_T* input) {
	if (!policy) return MATTER_INVALID_ARGUMENT;
	if (policy->busy) return MATTER_BUSY;
	if (!input || !input->session || !input->data) return MATTER_INVALID_ARGUMENT;
	Matter_Result_T result = matter_exchange_check(policy->table);
	if (result != MATTER_OK) return result;
	Matter_Rx_Decision_T decision = {0}; /* Small descriptor only; no packet buffer. */
	size_t consumed = 0;
	if (matter_protocol_header_read(input->data, input->size, &decision.header, &consumed) != MATTER_MESSAGE_OK)
		return MATTER_INVALID_ARGUMENT;
	const Matter_Protocol_Header_T* header = &decision.header;
	bool initiator = (header->exchange_flags & MATTER_PROTOCOL_INITIATOR) != 0;
	result = matter_exchange_match(policy->table, input->session, header->exchange_id,
		initiator, &decision.exchange);
	/* check + match have no callback/yield between them; INVALID_STATE now means
	 * missing key, never a stopped table. All calls run on the same owner thread. */
	if (result != MATTER_OK && result != MATTER_INVALID_STATE) return result;
	bool closing = false;
	if (decision.exchange) {
		result = matter_exchange_is_closing(policy->table, decision.exchange, &closing);
		if (result != MATTER_OK) return result;
	}
	bool registered = find_protocol(policy, header->vendor_id, header->protocol_id) != NULL;
	decision.standalone_ack = !header->vendor_id && !header->protocol_id && header->opcode == 0x10;
	if (decision.standalone_ack && (!(header->exchange_flags & MATTER_PROTOCOL_ACK) || consumed != input->size))
		return MATTER_INVALID_ARGUMENT;
	if (registered && !input->duplicate && !decision.standalone_ack && !closing) {
		if (decision.exchange) decision.action = MATTER_RX_EXISTING;
		else if (initiator) decision.action = MATTER_RX_NEW_RESPONDER;
	}
	decision.process_ack = (header->exchange_flags & MATTER_PROTOCOL_ACK) != 0;
	if (header->exchange_flags & MATTER_PROTOCOL_RELIABLE) {
		decision.ack = input->duplicate || closing || (!decision.exchange && decision.action == MATTER_RX_DROP) ?
			MATTER_RX_ACK_IMMEDIATE : MATTER_RX_ACK_PENDING;
	}
	decision.session = input->session;
	decision.message_counter = input->message_counter;
	decision.payload = input->data + consumed;
	decision.payload_size = input->size - consumed;
	policy->busy = true;
	policy->listener.decided(policy->listener.user, &decision);
	policy->busy = false;
	return MATTER_OK;
}

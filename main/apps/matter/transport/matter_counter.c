#include "matter_counter.h"

static bool valid_mode(Matter_Counter_Mode_T mode) {
	return mode == MATTER_COUNTER_UNSECURED || mode == MATTER_COUNTER_SECURE_UNICAST;
}

Matter_Result_T matter_counter_init(Matter_Counter_T* state, Matter_Counter_Mode_T mode,
	Matter_Counter_Random_T random, void* user) {
	if (!state) return MATTER_INVALID_ARGUMENT;
	if (state->busy) return MATTER_BUSY;
	if (!valid_mode(mode) || !random) return MATTER_INVALID_ARGUMENT;
	if (state->initialized || state->mode || state->next || state->exhausted) return MATTER_INVALID_STATE;
	uint32_t sample = UINT32_MAX; /* Reject OK without an actual sample. */
	state->busy = true;
	Matter_Result_T result = random(user, &sample);
	state->busy = false;
	if (result != MATTER_OK)
		return result == MATTER_WOULD_BLOCK || result == MATTER_OFFLINE ? result : MATTER_PORT_ERROR;
	if (sample > UINT32_C(0x0fffffff)) return MATTER_PORT_ERROR;
	*state = (Matter_Counter_T){.next = sample + 1u, .mode = mode, .initialized = true};
	return MATTER_OK;
}

Matter_Result_T matter_counter_take(Matter_Counter_T* state, Matter_Counter_Value_T* value) {
	if (!state || !value) return MATTER_INVALID_ARGUMENT;
	if (state->busy) return MATTER_BUSY;
	if (!state->initialized || !valid_mode(state->mode)) return MATTER_INVALID_STATE;
	if (state->exhausted) return MATTER_LIMIT_REACHED;
	bool last = state->mode == MATTER_COUNTER_SECURE_UNICAST && state->next == UINT32_MAX;
	*value = (Matter_Counter_Value_T){state->next, last};
	if (last) state->exhausted = true;
	else ++state->next; /* uint32 modulo wrap is allowed only for unsecured. */
	return MATTER_OK;
}

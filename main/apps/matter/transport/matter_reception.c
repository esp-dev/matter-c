#include "matter_reception.h"

static bool valid_mode(Matter_Reception_Mode_T mode) {
	return mode == MATTER_RECEPTION_UNSECURED || mode == MATTER_RECEPTION_SECURE_UNICAST || mode == MATTER_RECEPTION_SECURE_GROUP;
}

Matter_Result_T matter_reception_reset(Matter_Reception_T* state, Matter_Reception_Mode_T mode) {
	if (!state || !valid_mode(mode)) return MATTER_INVALID_ARGUMENT;
	*state = (Matter_Reception_T){.mode = mode};
	return MATTER_OK;
}

Matter_Result_T matter_reception_seed(Matter_Reception_T* state, Matter_Reception_Mode_T mode, uint32_t counter) {
	if (!state || !valid_mode(mode)) return MATTER_INVALID_ARGUMENT;
	*state = (Matter_Reception_T){counter, UINT32_MAX, mode, true};
	return MATTER_OK;
}

Matter_Result_T matter_reception_classify(const Matter_Reception_T* state, uint32_t counter, bool* duplicate) {
	if (!state || !duplicate) return MATTER_INVALID_ARGUMENT;
	if (!valid_mode(state->mode)) return MATTER_INVALID_STATE;
	bool seen = false;
	if (state->initialized) {
		uint32_t back = state->max_counter - counter;
		if (!back) seen = true;
		else if (state->mode == MATTER_RECEPTION_SECURE_UNICAST && counter > state->max_counter) seen = false;
		else if (state->mode == MATTER_RECEPTION_SECURE_GROUP && counter-state->max_counter < UINT32_C(0x80000000)) seen = false;
		else if (back <= MATTER_RECEPTION_WINDOW_SIZE)
			seen = (state->bitmap & (UINT32_C(1) << (back - 1u))) != 0;
		else seen = state->mode != MATTER_RECEPTION_UNSECURED;
	}
	*duplicate = seen;
	return MATTER_OK;
}

Matter_Result_T matter_reception_commit(Matter_Reception_T* state, uint32_t counter, bool* duplicate) {
	if (!duplicate) return MATTER_INVALID_ARGUMENT;
	bool seen;
	Matter_Result_T result = matter_reception_classify(state, counter, &seen);
	if (result != MATTER_OK) return result;
	if (!seen) {
		if (!state->initialized) matter_reception_seed(state, state->mode, counter);
		else {
			uint32_t back = state->max_counter - counter;
			if (back <= MATTER_RECEPTION_WINDOW_SIZE &&
				(state->mode == MATTER_RECEPTION_UNSECURED ||
                    (state->mode == MATTER_RECEPTION_SECURE_UNICAST ? counter < state->max_counter : counter-state->max_counter >= UINT32_C(0x80000000)))) {
				state->bitmap |= UINT32_C(1) << (back - 1u);
			} else {
				uint32_t forward = counter - state->max_counter;
				/* A rollback beyond the unsecured window also has forward > 32:
				 * old history no longer overlaps, so start with an empty bitmap.
				 * Never shift by 32 (or more); previous max enters at forward-1.
				 */
				state->bitmap = forward < MATTER_RECEPTION_WINDOW_SIZE ? state->bitmap << forward : 0;
				if (forward <= MATTER_RECEPTION_WINDOW_SIZE) state->bitmap |= UINT32_C(1) << (forward - 1u);
				state->max_counter = counter;
			}
		}
	}
	*duplicate = seen;
	return MATTER_OK;
}

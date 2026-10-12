#include "matter_tlv_validate.h"

static bool same_tag(const Matter_Tlv_Tag_T* a, const Matter_Tlv_Tag_T* b) {
	return a->control == b->control && a->number == b->number &&
		a->vendor == b->vendor && a->profile == b->profile;
}

Matter_Tlv_Result_T matter_tlv_validate(const uint8_t* data, size_t size,
	const Matter_Tlv_Validation_Options_T* options, Matter_Tlv_Validation_Workspace_T* workspace,
	Matter_Tlv_Tag_T* tags, size_t tag_capacity, Matter_Tlv_Validation_Report_T* report) {
	if ((!data && size) || !options || !workspace || !report || (!tags && tag_capacity) ||
		tag_capacity > SIZE_MAX / sizeof(*tags) || !options->max_depth ||
		options->max_depth > MATTER_TLV_MAX_DEPTH) return MATTER_TLV_INVALID_ARGUMENT;
	*report = (Matter_Tlv_Validation_Report_T){0};
	if (size > options->max_bytes) return MATTER_TLV_LIMIT_REACHED;
	Matter_Tlv_Reader_T* reader = &workspace->reader;
	Matter_Tlv_Result_T result = matter_tlv_init(reader, data, size, options->max_depth);
	if (result != MATTER_TLV_OK) return result;
	size_t used = 0;
	for (;;) {
		report->offset = reader->offset;
		/* EOF/DONE checks do not consume a token budget. */
		if (reader->offset < size && report->tokens == options->max_tokens) return MATTER_TLV_LIMIT_REACHED;
		uint8_t depth = reader->depth;
		Matter_Tlv_Element_T element;
		result = matter_tlv_next(reader, &element);
		if (result == MATTER_TLV_DONE) return MATTER_TLV_OK;
		if (result != MATTER_TLV_OK) return result;
		++report->tokens;
		if (element.type == MATTER_TLV_END) {
			used = workspace->bases[depth - 1];
			continue;
		}
		Matter_Tlv_Tag_T key = element.tag;
		if (key.control == 4 || key.control == 5) {
			if (!options->has_implicit_profile) return MATTER_TLV_PROFILE_REQUIRED;
			key.vendor = options->implicit_vendor;
			key.profile = options->implicit_profile;
		}
		/* Reader initializes common/context vendor/profile to zero. */
		if (key.control >= 2) key.control = 6;
		if (depth && workspace->structures[depth - 1]) {
			for (size_t i = workspace->bases[depth - 1]; i < used; ++i) {
				if (report->comparisons == options->max_comparisons) return MATTER_TLV_LIMIT_REACHED;
				++report->comparisons;
				if (same_tag(&tags[i], &key)) return MATTER_TLV_DUPLICATE_TAG;
			}
			if (used == tag_capacity) return MATTER_TLV_LIMIT_REACHED;
			tags[used++] = key;
			if (used > report->peak_tags) report->peak_tags = used;
		}
		if (reader->depth > depth) {
			/* Save after recording this container's tag in its parent. Its own
			 * members are discarded on END; the parent key stays live. */
			workspace->bases[depth] = used;
			workspace->structures[depth] = element.type == MATTER_TLV_STRUCTURE;
		}
	}
}

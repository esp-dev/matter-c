#ifndef MATTER_TLV_VALIDATE_H_INCLUDED
#define MATTER_TLV_VALIDATE_H_INCLUDED 1

#include "matter_tlv.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	size_t max_bytes, max_tokens, max_comparisons;
	uint8_t max_depth; /* 1..16; all other budgets may be zero. */
	bool has_implicit_profile;
	uint16_t implicit_vendor, implicit_profile;
} Matter_Tlv_Validation_Options_T;

typedef struct {
	/* Start of rejected/current token, size on success, zero for byte limit.
	 * tokens includes successfully decoded opens/ENDs, even if semantic rejection
	 * follows. comparisons counts actual key comparisons, never exceeds budget.
	 */
	size_t offset, tokens, comparisons, peak_tags;
} Matter_Tlv_Validation_Report_T;

/* Caller-owned scratch, private fields. No initialization/cleanup required.
 * Keep this and the tag slots off small embedded task stacks: allocate in the
 * owning request/instance after checking its memory budget. No heap used here.
 */
typedef struct {
	Matter_Tlv_Reader_T reader;
	size_t bases[MATTER_TLV_MAX_DEPTH];
	bool structures[MATTER_TLV_MAX_DEPTH];
} Matter_Tlv_Validation_Workspace_T;

/* Synchronous, bounded validation of one complete immutable span. OK only after
 * reader DONE AND unique direct-member tags in every structure. Lists permit
 * duplicates. Common tags normalize to vendor/profile 0/0; qualified tags use
 * their tuple. Context tags remain a separate namespace. Implicit forms use the
 * supplied profile throughout the document, not the containing element's tag;
 * absent context -> PROFILE_REQUIRED, including at root/in a list.
 * Does not check schemas, canonical ordering, assigned/reserved identifiers or
 * application ranges. Callers needing different implicit profiles within one
 * document need a future explicit context policy; no inference is performed.
 *
 * tags is scratch for active structure-member keys (including ancestors); slots
 * are reused on container close. NULL only when tag_capacity==0. Exhaustion of
 * bytes/tokens/comparisons/slots -> LIMIT_REACHED; depth uses DEPTH_LIMIT.
 * Budgets checked before the work they govern. Total work O(bytes + tokens +
 * comparisons), not a wall-clock deadline or incremental scheduling guarantee.
 * A token with UTF-8 may scan up to max_bytes; choose budgets for the task.
 * Limits may stop traversal before a later malformed token/duplicate is found.
 *
 * Invalid arguments leave all outputs/scratch untouched. Otherwise report is
 * filled on EVERY return, scratch may change and cannot be resumed. Reuse it by
 * calling again; concurrent calls require separate scratch/report. Input,
 * options, workspace, slots and report must be valid and must not overlap.
 * No pointers are retained outside caller-owned scratch, no allocation/callbacks.
 */
Matter_Tlv_Result_T matter_tlv_validate(const uint8_t* data, size_t size,
	const Matter_Tlv_Validation_Options_T* options, Matter_Tlv_Validation_Workspace_T* workspace,
	Matter_Tlv_Tag_T* tags, size_t tag_capacity, Matter_Tlv_Validation_Report_T* report);

#ifdef __cplusplus
}
#endif
#endif

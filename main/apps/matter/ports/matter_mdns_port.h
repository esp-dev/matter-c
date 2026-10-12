#ifndef MATTER_MDNS_PORT_H_INCLUDED
#define MATTER_MDNS_PORT_H_INCLUDED 1

#include <stdbool.h>
#include <stdint.h>

typedef struct {
	const char* key;
	const char* value;
} Matter_Mdns_Txt_T;

/* Prepared, immutable service description; not a Matter record generator.
 * Strings are NUL terminated; TXT values are text in this initial port.
 * hostname NULL selects the application's local host. Arrays/counts must match.
 * All pointed-to data stays borrowed and immutable until mdns_delete succeeds.
 * The backend validates DNS names, TXT sizes and its capacity before accepting.
 * No claim that arbitrary descriptions satisfy Matter discovery requirements.
 */
typedef struct {
	const char* instance;
	const char* service;
	const char* protocol;
	const char* hostname;
	uint16_t port;
	const Matter_Mdns_Txt_T* txt;
	uint16_t txt_count;
	const char* const* subtypes;
	uint16_t subtype_count;
} Matter_Mdns_Record_T;

/* One binding and at most one advertisement per module, identified by user.
 * Do not share a binding between modules. Publish/remove must affect only it.
 * All callbacks run on the owner thread, return normally and do not block.
 * No inline completion/events or mutations of the module/owner from callbacks.
 * Backend work/results from another task must be marshalled by the adapter.
 *
 * publish/remove: true accepts work and promises one later complete, or a
 * drained backend-generation event which terminates all old requests instead;
 * false means no effect, no retained request/record reference and no completion.
 * SUCCEEDED means installed/removed in the backend, not observed on the wire.
 * FAILED/CANCELLED means no effect (rollback); remove failure keeps the record.
 * Before complete, drop request references. A successful publish may keep the
 * record until successful remove or an acknowledged backend loss.
 *
 * cancel: request once; deliver the terminal result or drained backend loss.
 * A success racing cancellation is legal; the module will remove that record.
 *
 * detach: synchronous routing barrier, only called on inactive module deletion.
 * Remove all routes to this module and invalidate queued events BEFORE return.
 * Backend must use a fresh binding identity when reusing user for a new module;
 * request IDs alone cannot distinguish old/new allocations at the same address.
 * detach must not shut down the application's shared mDNS service.
 */
typedef struct {
	void* user;
	bool (*publish)(void* user, uint64_t request, const Matter_Mdns_Record_T* record);
	bool (*remove)(void* user, uint64_t request);
	void (*cancel)(void* user, uint64_t request);
	void (*detach)(void* user);
} Matter_Mdns_Port_T;

#endif

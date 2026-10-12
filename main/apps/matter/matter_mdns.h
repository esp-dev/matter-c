#ifndef MATTER_MDNS_H_INCLUDED
#define MATTER_MDNS_H_INCLUDED 1

#include "matter.h"
#include "ports/matter_mdns_port.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Matter_Mdns* Matter_Mdns_T;

/* Copies the port and record structs, borrows their pointed-to data and owner.
 * Delete this module BEFORE deleting owner, including when inactive. Returns
 * NULL for missing required callbacks/fields or allocation failure; no callbacks.
 * No network work until start + process. Initially backend availability unknown.
 */
Matter_Mdns_T matter_mdns_new(Matter_T owner, const Matter_Mdns_Port_T* port,
	const Matter_Mdns_Record_T* record);

/* NULL -> OK; active -> INVALID_STATE. Detach routing synchronously, then free.
 * Mutations during this module's callbacks -> BUSY; never use freed handles.
 */
Matter_Result_T matter_mdns_delete(Matter_Mdns_T mdns);

/* Owner must be RUNNING. Reserves M04a's slot for the whole service lifetime,
 * including published/temporarily offline states, not just a publish request.
 * Repeated start -> OK, start during stop -> INVALID_STATE. No allocation.
 */
Matter_Result_T matter_mdns_start(Matter_Mdns_T mdns);

/* Request module shutdown, without stopping other services. Idempotent; returns
 * PENDING while active. matter_stop(owner) also requests this shutdown.
 */
Matter_Result_T matter_mdns_stop(Matter_Mdns_T mdns);

/* Application-driven, bounded step: at most one backend call or lease release.
 * Continue driving it while owner is STOPPING. PENDING = awaiting backend/work;
 * OK = inactive or published. PORT_ERROR latches failure; retry explicitly to
 * avoid spinning. A failed remove retains the lease and prevents owner deletion.
 * No forced free/timeout. Initial offline state waits without calling backend.
 */
Matter_Result_T matter_mdns_process(Matter_Mdns_T mdns);
Matter_Result_T matter_mdns_retry(Matter_Mdns_T mdns);

/* Adapter event, owner thread only. generation is nonzero, strictly increasing
 * for each availability/incarnation change on this binding (no wrap). Before
 * delivering a new generation, backend MUST invalidate old requests and remove
 * old advertisements/references. ready means usable, not publication success.
 * Both loss and restoration clear old publication/pending state. Repeated/old
 * generations -> INVALID_STATE. Stop never republishes when ready returns.
 */
Matter_Result_T matter_mdns_backend(Matter_Mdns_T mdns, uint64_t generation, bool ready);

/* One terminal result of publish/remove, deferred until callback returned.
 * Old/duplicate request -> INVALID_STATE, invalid input -> INVALID_ARGUMENT.
 * A late event after delete must be discarded by binding routing, not this API.
 * BUSY rejects inline completion; adapter must deliver it later.
 */
Matter_Result_T matter_mdns_complete(Matter_Mdns_T mdns, uint64_t request,
	Matter_Operation_Result_T result);
bool matter_mdns_is_active(Matter_Mdns_T mdns);
bool matter_mdns_is_published(Matter_Mdns_T mdns);

#ifdef __cplusplus
}
#endif
#endif

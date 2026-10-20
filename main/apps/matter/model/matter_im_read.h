#ifndef MATTER_IM_READ_H_INCLUDED
#define MATTER_IM_READ_H_INCLUDED 1
#include "../transport/matter_rx_policy.h"
#include "../session/matter_secure.h"
#include "../codec/matter_tlv.h"
#include "matter_events.h"
#ifdef __cplusplus
extern "C" {
#endif

enum { MATTER_IM_REVISION = 13,
	/* Core 4.4.4: secure UDP ceiling minus message header/MIC and the minimum
	 * standard-vendor protocol header. RX framing enforces actual header sizes.
	 * TX reserves room for a piggybacked 32-bit MRP acknowledgment as well. */
	MATTER_IM_HEADER_BYTES = 6,
	MATTER_IM_READ_MAX_PAYLOAD = MATTER_SECURE_MAX_PACKET - MATTER_SECURE_OVERHEAD - MATTER_IM_HEADER_BYTES,
	MATTER_IM_READ_MAX_OUTPUT = MATTER_IM_READ_MAX_PAYLOAD - sizeof(uint32_t),
	MATTER_IM_READ_MAX_PATHS = 9,
	/* Application resource ceiling, NOT a Matter maximum. Result tables grow
	 * per interaction; no allocation for unused entries up to this ceiling. */
	MATTER_IM_READ_MAX_RESULTS = 512,
	/* Even an empty AttributeReportIB needs at least eight TLV structural bytes.
	 * This conservative lower bound sizes the chunk plan from output capacity. */
	MATTER_IM_READ_MIN_REPORT_BYTES = 8,
	/* Core 10.6.3: a minimal DataVersionFilterIB occupies 14 bytes (anonymous
	 * structure, concrete ClusterPath LIST, version and both ENDs). Budget for
	 * every filter that can fit in one request, including duplicate paths. */
	MATTER_IM_READ_MIN_FILTER_BYTES = 14,
	MATTER_IM_READ_MAX_FILTERS = MATTER_IM_READ_MAX_PAYLOAD / MATTER_IM_READ_MIN_FILTER_BYTES,
	MATTER_IM_READ_WORK_BATCH = 8,
	MATTER_IM_READ_MAX_VALUE = 4096, MATTER_IM_READ_SNAPSHOT_BYTES = 16384 };
typedef enum {
	MATTER_IM_SUCCESS=0, MATTER_IM_FAILURE=1, MATTER_IM_UNSUPPORTED_ACCESS=0x7e,
	MATTER_IM_UNSUPPORTED_ENDPOINT=0x7f, MATTER_IM_INVALID_ACTION=0x80,
	MATTER_IM_UNSUPPORTED_ATTRIBUTE=0x86, MATTER_IM_RESOURCE_EXHAUSTED=0x89,
	MATTER_IM_UNSUPPORTED_READ=0x8f, MATTER_IM_ACCESS_RESTRICTED=0x9d,
	MATTER_IM_UNSUPPORTED_CLUSTER=0xc3, MATTER_IM_UNSUPPORTED_EVENT=0xc7, MATTER_IM_PATHS_EXHAUSTED=0xc8
} Matter_Im_Status_T;
typedef enum { MATTER_IM_VIEW=1, MATTER_IM_OPERATE=3, MATTER_IM_MANAGE=4, MATTER_IM_ADMINISTER=5 } Matter_Im_Privilege_T;
typedef struct { uint16_t endpoint; uint32_t cluster, attribute; } Matter_Im_Path_T;
enum { MATTER_IM_ENDPOINT = 1, MATTER_IM_CLUSTER = 2, MATTER_IM_ATTRIBUTE = 4, MATTER_IM_CONCRETE = 7 };
typedef struct { Matter_Im_Path_T path; uint8_t present; } Matter_Im_Selector_T;
enum { MATTER_IM_EVENT=4 };
typedef struct { Matter_Event_Path_T path; uint8_t present; } Matter_Im_Event_Selector_T;
/* Same stateless, ordered and bounded enumeration contract as the attribute
 * port below. Existent metadata, not log contents; user is Events port.user.
 * Valid masks are 0,1,2,3,6,7: a specific event requires a specific cluster. */
typedef Matter_Result_T (*Matter_Im_Event_Enumerate_T)(void*,const Matter_Im_Event_Selector_T*,
    const Matter_Event_Path_T* after,Matter_Event_Path_T* next,bool* found);
typedef struct { Matter_Im_Privilege_T privilege; bool fabric_scoped; } Matter_Im_Attribute_T;
typedef struct {
	Matter_Tlv_Type_T type; /* SIGNED/UNSIGNED/BOOL/NULL, UTF8/BYTES, STRUCTURE/ARRAY. */
	uint64_t unsigned_value;
	int64_t signed_value;
	uint32_t data_version; /* Cluster instance version of this value snapshot. */
	/* UTF8/BYTES: raw span, no terminator. STRUCTURE/ARRAY: one complete anonymous
	 * TLV document, including open/end. Use the existing TLV writer to build it.
	 * Provider-owned storage must remain valid/unchanged until the next provider
	 * callback or process return, whichever comes first. Never return stack data.
	 * Copied immediately; no pointers retained into provider storage. NULL only
	 * for empty strings. Maximum encoded snapshot 4096 bytes, depth 4, 1024 tokens;
	 * total copied snapshots <=16384 bytes per transaction. */
	const uint8_t* data;
	size_t size;
    /* Opt-in report policy for versioned or continuously changing attributes.
     * Read always returns the current value. Subscribe updates suppress this
     * attribute until its provider marks a reportable change via DataVersion.
     * Default false preserves existing providers. Authorization still runs. */
    bool report_on_version_change;
} Matter_Im_Value_T;
typedef struct {
	void* user;
	/* Required, synchronous and nonblocking. Session is an authenticated opaque
	 * incarnation, never a wire-supplied credential. Check commissioning window,
	 * PASE direction/grant/revocation here on EVERY call. SUCCESS/UNSUPPORTED_ACCESS/
	 * ACCESS_RESTRICTED only. No built-in allow-all or claims of a complete ACL. */
	Matter_Im_Status_T (*authorize)(void*, Matter_Exchange_Session_T, const Matter_Im_Path_T*, Matter_Im_Privilege_T);
	/* Describe existence/readability and required privilege. Concrete paths first
	 * check View permission; expanded wildcard paths describe then check actual
	 * privilege (Core 8.4.3.2). Wildcard unreadable/denied paths are omitted.
	 * Do not read the value here. Return SUCCESS or a corresponding path error. */
	Matter_Im_Status_T (*describe)(void*, const Matter_Im_Path_T*, Matter_Im_Attribute_T*);
	/* After the required authorization. Write one coherent value/version snapshot;
	 * return SUCCESS, FAILURE, UNSUPPORTED_ACCESS or ACCESS_RESTRICTED. Providers
	 * enforce fabric-sensitive data policy. Output ignored on error. No retained pointers. */
	Matter_Im_Status_T (*read)(void*, const Matter_Im_Path_T*, bool fabric_filtered, Matter_Im_Value_T*);
	/* Optional for concrete-only reads. Enumerate the next existent concrete path
	 * matching selector (missing fields are wildcards), strictly lexicographically
	 * after the previous path, or first when after=NULL. OK with found=false means
	 * end; any error aborts the interaction. No resource handle to retain/release.
	 * Caller owns a stable model topology for this transaction, including between
	 * process calls; values/permissions may change. Callback must be nonblocking,
	 * bounded, not filter by access, and never retain any argument pointers. */
	Matter_Result_T (*enumerate)(void*, const Matter_Im_Selector_T*, const Matter_Im_Path_T* after,
		Matter_Im_Path_T* next, bool* found);
	/* Optional fast path for matching DataVersionFilters, after access checks. Current
	 * cluster version, no value read. On mismatch read supplies its own coherent
	 * value/version, checked again. Without this callback filtering uses read's
	 * snapshot. Errors become FAILURE, never a cached/zero version. */
	Matter_Result_T (*version)(void*, const Matter_Im_Path_T*, uint32_t*);
} Matter_Im_Read_Port_T;
typedef struct {
	Matter_Exchange_Info_T exchange; /* Already admitted responder exchange. */
	uint32_t timeout_ms; /* Application budget, absolute, not extended by retry. */
	size_t output_capacity; /* Read/Subscribe: 8..MAX_OUTPUT bytes; 8 fits StatusResponse. */
	bool pase_commissionee; /* Trusted application binding; true for PASE; false with matter_im_read_new_case. */
} Matter_Im_Read_Config_T;
typedef struct Matter_Im_Read* Matter_Im_Read_T;
typedef enum { MATTER_IM_READ_WAITING, MATTER_IM_READ_OUTPUT, MATTER_IM_READ_IN_FLIGHT,
	MATTER_IM_READ_COMPLETE, MATTER_IM_READ_FAILED, MATTER_IM_READ_WAIT_STATUS,
	MATTER_IM_READ_EXPANDING, MATTER_IM_READ_COLLECTING } Matter_Im_Read_State_T;
typedef struct { const uint8_t* data; size_t size; uint8_t opcode; } Matter_Im_Read_Message_T;

/* One transaction, heap context plus separately allocated RX/TX buffers and a
 * demand-sized immutable snapshots for complex
 * values and an exactly sized validated filter table;
 * copied config/port, borrowed port.user. Empty/absent filters allocate nothing.
 * RX allocates the received length before replacing the old copy; OOM returns
 * LIMIT_REACHED with queue/state unchanged, so the owner may retry. TX allocates
 * output_capacity during construction; failure unwinds the context allocation.
 * Parser/tag scratch is reserved with RX and released after process; yielded
 * work reacquires it on demand. Selectors allocate the validated count and are
 * released after expansion/copying. Results/snapshots and ACK/drain stay separate.
 * Owner thread, no tasks, hardware, session ownership or transport queue.
 * Subset: 0..9 local attribute selectors, concrete cluster version filters up to
 * the request payload budget, up to MATTER_IM_READ_MAX_RESULTS expanded results and chunking.
 * Enumeration and collection are bounded
 * to 8 candidates each per process call (concrete-only reads keep their original
 * single-call budget of 9); compact private scalar/span results and one stable allocation per encoded complex value,
 * within the same 4096-byte value / 16384-byte total payload budget. No snapshot
 * allocation per chunk. Consumed values release after MRP plus continuation IM
 * success; partial lists stay stable. Final Read values release at confirmation.
 * Cancellation/failure retains remaining copies until drain/delete. The total
 * encoded admission budget stays cumulative even after consumed values release.
 * Scalars keep the old API and allocate no snapshot bytes.
 * Lists fitting one report use one ARRAY. Larger lists start with an ARRAY
 * prefix, followed by complete item IBs with ListIndex=null (Core 10.6.4.3.1).
 * Strings, structures and individual list items are never split; an item that
 * cannot fit yields RESOURCE_EXHAUSTED. No borrowed provider data across chunks.
 * Optional Events extension below; no request Node/ListIndex,
 * compression or nonzero provisional wildcard flags.
 * Unsupported shapes produce INVALID_ACTION; >9 paths PATHS_EXHAUSTED.
 * Each unfiltered permitted value/version is read once after the WHOLE request
 * has been validated and expansion completed. Wildcard access/readability errors
 * are omitted; concrete errors are reported. Limits never silently truncate.
 * Expansion limits count candidates before access/version filtering, including
 * repeated/overlapping request selectors. Snapshots are per attribute, not atomic
 * across attributes/clusters. The provider must change data_version when cluster
 * data changes. Unsent snapshots
 * are reauthorized between chunks; newly granted access does not trigger reads.
 * This host subset does not provide full IM/ACL or per-fabric resource guarantees.
 */
Matter_Im_Read_T matter_im_read_new(const Matter_Im_Read_Port_T*, const Matter_Im_Read_Config_T*, uint64_t now_ms);
/* Optional authenticated session-to-fabric resolver for PASE before/after AddNOC.
 * Uses port.user, returns 0 for no fabric, 1..254 otherwise; not a wire field.
 * Index 0 permits list reads: the provider applies filtering/sensitive policy.
 * Rechecked on every authorization, fabric changes abort old snapshots. Old
 * constructor still denies all fabric-scoped attributes. No CASE support implied. */
typedef struct { Matter_Result_T (*index)(void*,Matter_Exchange_Session_T,uint8_t*); } Matter_Im_Read_Fabric_Port_T;
Matter_Im_Read_T matter_im_read_new_fabric(const Matter_Im_Read_Port_T*, const Matter_Im_Read_Fabric_Port_T*,
    const Matter_Im_Read_Config_T*, uint64_t now_ms);
/* CASE constructor requires pase_commissionee=false and a nonzero authenticated
 * fabric from the resolver; authorization still checks peer node/CAT/ACL. */
Matter_Im_Read_T matter_im_read_new_case(const Matter_Im_Read_Port_T*,const Matter_Im_Read_Fabric_Port_T*,
    const Matter_Im_Read_Config_T*,uint64_t now_ms);
/* Optional bounded Events extension, bind once BEFORE receive. Separate API
 * preserves existing attribute ports/constructors. Allocates a private snapshot
 * workspace; borrowed log/user live through handler deletion. Up to 9 requested
 * attribute/event paths combined, plus one optional local EventMin (inclusive).
 * Concrete EventPaths form a deduplicated union in ascending EventNumber order;
 * per-path errors coexist with valid data. Event records follow attribute chunks,
 * one per chunk, sharing a single bounded log snapshot across all paths.
 * With bind_event_enumerator, missing endpoint/cluster/event fields expand
 * from model metadata (six valid masks). Up to 120 event candidates, counting
 * overlaps before ACL/dedup, with at most 8 enumeration/collection candidates
 * each per process. Concrete-only keeps its single-call budget. Chunk ACL
 * revalidation visits at most 120 selected paths. No Node selectors.
 * Wildcard denied/nonexistent paths are omitted; an overlapping explicit path
 * retains its status semantics. Topology must be stable through the interaction.
 * Sensitive records always match the
 * authenticated fabric, independently of FabricFiltered. Subscribe has its own port.
 * Existing authorizer is reused with path.attribute = event ID; it must apply
 * endpoint/cluster ACL, not infer attribute metadata from that number.
 * describe must validate endpoint/cluster/event even when no records exist.
 * Capture once after validating the entire request; reauthorize unsent copies
 * before every event chunk. MRPs resend immutable output, never reread log. */
typedef struct {
    void* user; Matter_Events_T log;
    Matter_Im_Status_T (*describe)(void*,const Matter_Event_Path_T*,Matter_Im_Attribute_T*);
} Matter_Im_Read_Events_Port_T;
Matter_Result_T matter_im_read_bind_events(Matter_Im_Read_T,const Matter_Im_Read_Events_Port_T*);
/* Optional wildcard support; bind once after bind_events, before receive.
 * Existing concrete-only port/initializers remain unchanged. */
Matter_Result_T matter_im_read_bind_event_enumerator(Matter_Im_Read_T,Matter_Im_Event_Enumerate_T);
/* Copy one accepted fresh RX payload, bound to session/exchange, protocol 1,
 * peer I=1: ReadRequest opcode 2 initially, StatusResponse opcode 1 after an
 * intermediate report is sent (also before its MRP completion). Only one queued
 * input; a valid error StatusResponse ends the interaction without a reply.
 * No callbacks/parsing here. Never call for duplicates/standalone ACK.
 * Oversize -> LIMIT_REACHED, no ownership; caller reports resource error/closes.
 */
Matter_Result_T matter_im_read_receive(Matter_Im_Read_T, const Matter_Rx_Decision_T*);
/* Parse/callback/encode outside RX/poll. Monotonic clock; timeout -> FAILED and
 * PORT_ERROR, discards output. Existing transport work must still be cancelled
 * and drained by the application. No speculative reads for malformed requests.
 */
Matter_Result_T matter_im_read_process(Matter_Im_Read_T, uint64_t now_ms);
/* Borrow immutable output until sent/cancel/delete/process timeout. COPY into
 * existing secure/MRP packet storage before sent; retries never re-read provider.
 * ReportData opcode 5: intermediate MoreChunkedMessages=true, SuppressResponse
 * omitted/false; final SuppressResponse=true. Error StatusResponse opcode 1.
 * Both use SAME exchange, protocol 1, local I=0 and reliable UDP delivery.
 */
Matter_Result_T matter_im_read_output(Matter_Im_Read_T, Matter_Im_Read_Message_T*);
/* Final response sent; only delivery/cleanup remains (never a report chunk).
 * Does not release bytes or replace confirm/cancel/delete obligations. */
bool matter_im_read_awaiting_delivery(Matter_Im_Read_T);
Matter_Result_T matter_im_read_sent(Matter_Im_Read_T);
/* Call once after MRP ACK AND transport drain, not merely UDP completion.
 * Intermediate report -> WAIT_STATUS; next process builds output only when both
 * this completion and a successful IM StatusResponse have arrived, in either
 * order. No provider callbacks here. Failed transport -> cancel. A late confirm
 * after failure/cancel is INVALID_STATE; it never revives the transaction. */
Matter_Result_T matter_im_read_confirm(Matter_Im_Read_T, uint64_t now_ms);
/* Last decoded peer status, including unknown uint8 error codes. INVALID_STATE
 * if none received (e.g. malformed TLV). Does not clear it. */
Matter_Result_T matter_im_read_peer_status(Matter_Im_Read_T, uint8_t* status);
Matter_Result_T matter_im_read_cancel(Matter_Im_Read_T);
Matter_Im_Read_State_T matter_im_read_state(Matter_Im_Read_T);
/* Invalidate application routing first; MRP must never retain a pointer here. */
Matter_Result_T matter_im_read_delete(Matter_Im_Read_T);
#ifdef __cplusplus
}
#endif
#endif

#ifndef MATTER_EVENTS_H_INCLUDED
#define MATTER_EVENTS_H_INCLUDED 1
#include "../codec/matter_tlv_writer.h"
#include "../matter.h"
#ifndef MATTER_EVENTS_CAPACITY
#define MATTER_EVENTS_CAPACITY 16
#endif
#if MATTER_EVENTS_CAPACITY < 16 || MATTER_EVENTS_CAPACITY > 1024
#error "MATTER_EVENTS_CAPACITY must be in 16..1024"
#endif
enum { MATTER_EVENT_DATA_MAX=192, MATTER_EVENT_PATH_CAPACITY=120 };
typedef struct { uint16_t endpoint; uint32_t cluster,event; } Matter_Event_Path_T;
typedef struct {
    Matter_Event_Path_T path; uint64_t number,timestamp_ms;
    uint8_t priority,fabric; bool epoch; size_t size; uint8_t data[MATTER_EVENT_DATA_MAX];
} Matter_Event_Record_T;
typedef struct {
    void* user;
    /* Durable exclusive reservation high-water mark; absent storage -> 0.
     * Atomic store: failure leaves the previous value intact. Owner serializes
     * ONE allocator per node. These bounded callbacks must not retain pointers
     * or reenter. A host backend may use a synchronous local transaction. */
    Matter_Result_T (*load)(void*,uint64_t*);
    Matter_Result_T (*store)(void*,uint64_t);
} Matter_Events_Port_T;
typedef struct Matter_Events* Matter_Events_T;
/* Node-owned heap log, MATTER_EVENTS_CAPACITY records of <=192-byte STRUCTURE TLV.
 * Configure capacity consistently for the library and all consumers; CMake
 * exports the setting. Retention is bounded by traffic, not wall-clock time.
 * fabric=0 is public; 1..254 associates a sensitive event with a fabric.
 * Producer includes matching global FabricIndex in its payload. Reserve at least 32
 * numbers (or the complete batch, if larger)
 * before use; monotonically consecutive within a boot, skips on restart.
 * Priority DEBUG=0/INFO=1/CRITICAL=2. Evict oldest lowest-priority record;
 * if all records have higher priority, return LIMIT_REACHED without consuming
 * a number. Caller handles backpressure. No allocation after construction.
 * Single owner, log/user outlive all producers and Read handlers. */
Matter_Events_T matter_events_new(const Matter_Events_Port_T*);
Matter_Result_T matter_events_append(Matter_Events_T,const Matter_Event_Path_T*,uint8_t priority,
    uint64_t timestamp_ms,bool epoch,const uint8_t*,size_t);
/* Atomic batch for model mutations: prepare validates/copies up to CAPACITY
 * records and reserves durable numbers BEFORE changing the model. number is
 * assigned by the log. On success log is locked until finish(commit); failed
 * model store calls finish(false). No records/numbers become visible on abort.
 * Single owner; no retained input pointers. Finish cannot fail after prepare. */
Matter_Result_T matter_events_prepare(Matter_Events_T,const Matter_Event_Record_T*,size_t);
void matter_events_finish(Matter_Events_T,bool commit);
/* Owner calls after successful fabric removal/rollback, before index reuse. */
Matter_Result_T matter_events_forget_fabric(Matter_Events_T,uint8_t);
/* Trusted model boundary; IM performs ACL before calling. Copy at most 16
 * retained matching records in increasing number order, number >= minimum.
 * out must have MATTER_EVENTS_CAPACITY entries (allocate on heap). */
Matter_Result_T matter_events_copy(Matter_Events_T,const Matter_Event_Path_T*,uint64_t minimum,
    Matter_Event_Record_T* out,size_t* count);
/* IM boundary: scoped events always require matching nonzero fabric, regardless
 * of FabricFiltered. Unscoped events never expose records associated with a fabric. */
Matter_Result_T matter_events_copy_fabric(Matter_Events_T,const Matter_Event_Path_T*,uint64_t minimum,
    uint8_t fabric,bool scoped,Matter_Event_Record_T* out,size_t* count);
typedef struct { Matter_Event_Path_T path; bool scoped; } Matter_Event_Filter_T;
/* Union of up to EVENT_PATH_CAPACITY authorized concrete paths, one copy per event in
 * increasing number order. Same fabric rules as copy_fabric. Caller checks ACL
 * before constructing filters. out=NULL counts matches without copying payload
 * (e.g. urgent subscription wakeup); otherwise out has CAPACITY heap entries,
 * or the exact count obtained immediately beforehand on the same owner turn,
 * with no intervening log mutation or application callback.
 * No allocation, retained pointers or duplicate records for overlapping filters. */
Matter_Result_T matter_events_copy_selected(Matter_Events_T,const Matter_Event_Filter_T*,size_t paths,
    uint64_t minimum,uint8_t fabric,Matter_Event_Record_T* out,size_t* count);
/* Next unassigned node event number (exclusive snapshot watermark). Read with
 * copy on the same owner turn; no append may interleave. RAM empty after restart
 * still retains the durable high-water mark. Does not reserve/consume numbers. */
Matter_Result_T matter_events_position(Matter_Events_T,uint64_t*);
Matter_Result_T matter_events_delete(Matter_Events_T);
#endif

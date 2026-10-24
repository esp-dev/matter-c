#ifndef MATTER_EVENTS_INTERNAL_H_INCLUDED
#define MATTER_EVENTS_INTERNAL_H_INCLUDED 1
#include "matter_events.h"

/* Private immutable node references, never a borrowed traversal of the live
 * log. The owner serializes acquisition/release; no process-global registry.
 * Record pointers stay valid after eviction or fabric removal until released.
 * Public copy APIs and their caller-owned DTO layout are unchanged. */
typedef struct {
    const Matter_Event_Record_T** records;
    size_t count,released;
} Matter_Events_Snapshot;
Matter_Result_T matter_events_snapshot_acquire(Matter_Events_T,const Matter_Event_Filter_T*,size_t,
    uint64_t minimum,uint8_t fabric,Matter_Events_Snapshot*);
/* Release only a confirmed consumed prefix. No allocation or callback. */
void matter_events_snapshot_release_before(Matter_Events_Snapshot*,size_t end);
void matter_events_snapshot_clear(Matter_Events_Snapshot*);
#endif

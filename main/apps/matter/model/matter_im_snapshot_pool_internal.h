#ifndef MATTER_IM_SNAPSHOT_POOL_INTERNAL_H_INCLUDED
#define MATTER_IM_SNAPSHOT_POOL_INTERNAL_H_INCLUDED 1
#include "matter_im_subscribe.h"

/* One serialized runtime owns this index. Only validated immutable bytes are
 * shared, never provider reads, authorization, versions or report byte budgets.
 * Standalone engines keep their existing private storage unless bound before RX.
 * Every engine must drain/delete before its borrowed pool goes out of scope. */
enum { MATTER_IM_SNAPSHOT_BUCKETS=32, MATTER_IM_SNAPSHOT_SHARE_MIN=32,
    MATTER_IM_SNAPSHOT_INDEX_LIMIT=128, MATTER_IM_SNAPSHOT_SMALL_LIMIT=112,
    MATTER_IM_SNAPSHOT_LARGE=256 };
typedef struct Matter_Im_Shared_Snapshot {
    struct Matter_Im_Shared_Snapshot* next;
    size_t size, references;
    uint32_t hash;
    uint8_t data[];
} Matter_Im_Shared_Snapshot;
typedef struct {
    Matter_Im_Shared_Snapshot* buckets[MATTER_IM_SNAPSHOT_BUCKETS];
    size_t entries,small_entries;
} Matter_Im_Snapshot_Pool;
Matter_Result_T matter_im_read_bind_snapshot_pool(Matter_Im_Read_T,Matter_Im_Snapshot_Pool*);
Matter_Result_T matter_im_subscribe_bind_snapshot_pool(Matter_Im_Subscribe_T,Matter_Im_Snapshot_Pool*);
#endif

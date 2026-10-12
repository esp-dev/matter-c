#ifndef MATTER_TIME_HOST_H_INCLUDED
#define MATTER_TIME_HOST_H_INCLUDED 1
#include "clusters/matter_time_sync.h"
#include "ports/matter_credentials_port.h"
typedef struct Matter_Time_Host* Matter_Time_Host_T;
/* Independent simulated clock, seeded from OS UTC, thereafter monotonic.
 * SetUTCTime never changes OS time. Owns state_path + .clock through delete.
 * Stores LKG only: restart never mistakes an old anchor for synchronized UTC.
 * Build floor is supplied in Matter seconds; owner also supplies operational certificate floors. */
Matter_Time_Host_T matter_time_host_new(const char* state_path,uint64_t build_epoch_s,uint64_t now_ms);
Matter_Result_T matter_time_host_delete(Matter_Time_Host_T);
Matter_Time_Sync_Port_T matter_time_host_port(Matter_Time_Host_T);
/* Credentials/timestamps use this SAME instance clock, with LKG fallback. */
Matter_Result_T matter_time_host_cert(void*,Matter_Cert_Time_T*);
Matter_Result_T matter_time_host_timestamp(void*,uint32_t*);
/* Raise-only floor; not-before input is Matter epoch seconds. Commit before
 * accepting the new floor. Does not move synchronized live UTC. */
Matter_Result_T matter_time_host_floor(Matter_Time_Host_T,uint64_t epoch_s);
uint64_t matter_time_host_last_good(Matter_Time_Host_T);
#endif

#ifndef MATTER_OTA_FILE_H
#define MATTER_OTA_FILE_H 1
#include "transport/matter_bdx.h"
#include "clusters/matter_ota_update.h"
typedef struct Matter_Ota_File* Matter_Ota_File_T;
/* Explicit application path, never derived from remote file designator.
 * Exclusive .part, max64MiB file/1024B header; SHA-256 payload only.
 * No install, image signature validation or crash-resume/durability guarantee. */
Matter_Ota_File_T matter_ota_file_new(const char* path,uint16_t vendor,uint16_t product,uint32_t current);
Matter_Result_T matter_ota_file_prepare(Matter_Ota_File_T,uint32_t expected_version);
Matter_Bdx_Sink_T matter_ota_file_sink(Matter_Ota_File_T);
/* No I/O. Unknown until the header is validated; 0..100 of whole-file bytes
 * while receiving/staged. Unknown again after commit or cancellation. */
int matter_ota_file_progress(Matter_Ota_File_T);
Matter_Result_T matter_ota_file_commit(Matter_Ota_File_T);
/* Volatile artifact identity, issued only by commit. Whole-file digest binds
 * header and payload; check rereads current path, but does not authenticate
 * firmware or reserve that path for a future installer. Zero after restart.
 * Owner must not prepare a new transfer while this artifact is in use. */
uint64_t matter_ota_file_artifact(Matter_Ota_File_T);
Matter_Result_T matter_ota_file_check(Matter_Ota_File_T,uint64_t artifact);
/* Consume one opened stream into an authenticated-metadata candidate, binding
 * header+payload to the committed digest. Caller verifies signature with its
 * trust anchor, then consumes ONLY this returned metadata for simulation.
 * No later file open/use is authorized. Output unchanged on failure. */
Matter_Result_T matter_ota_file_signed(Matter_Ota_File_T,uint64_t artifact,Matter_Ota_Signed_T*);
/* Revoke logical candidacy; keep published file for host inspection. */
void matter_ota_file_invalidate(Matter_Ota_File_T);
/* Remove only this instance's live committed candidate. Stale/zero IDs and
 * restarted instances cannot delete a file. Even an I/O failure revokes the
 * candidate; unrelated paths and partial transfers are never removed here. */
Matter_Result_T matter_ota_file_discard(Matter_Ota_File_T,uint64_t artifact);
void matter_ota_file_cancel(Matter_Ota_File_T);
void matter_ota_file_delete(Matter_Ota_File_T);
#define MATTER_OTA_FILE_LIMIT UINT64_C(67108864)
#endif

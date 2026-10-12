#ifndef MATTER_STORE_FILE_H
#define MATTER_STORE_FILE_H 1
#include "storage/matter_store_blob.h"
typedef struct Matter_Store_File* Matter_Store_File_T;
/* UTF-8 path in an existing, application-controlled directory. Owns exclusive
 * path.lock until delete; path.tmp is staging only, never boot recovery input.
 * Windows: flushed staging + MoveFileEx(REPLACE_EXISTING|WRITE_THROUGH).
 * Publication retries access/sharing/lock errors up to five times, with 250 ms
 * total requested sleep (OS scheduling/I/O may take longer). Permanent errors
 * still fail, preserve the old blob, and do not alter ACLs/file attributes.
 * POSIX: mode0600, flock, fsync staging, rename, directory fsync. An error
 * AFTER rename cannot satisfy replace's old-blob guarantee: the Linux test
 * host aborts rather than returning/reusing stale RAM. Reopen after restart.
 * File contains secrets: directory ACL/encryption belongs to the application. */
Matter_Store_File_T matter_store_file_new(const char* path);
Matter_Result_T matter_store_file_delete(Matter_Store_File_T);
Matter_Store_Blob_Port_T matter_store_file_port(Matter_Store_File_T);
/* Host fault injection: 0=none, 1=before write, 2=partial write, 3=flush, 4=rename.
 * POSIX only: 5=directory sync after rename (intentional process abort). */
void matter_store_file_fault(Matter_Store_File_T,unsigned);
#endif

#ifndef MATTER_IDF_STORE_H
#define MATTER_IDF_STORE_H 1
#include "storage/matter_store_blob.h"
typedef struct Matter_Idf_Store* Matter_Idf_Store_T;
/* Application initializes/deinitializes dedicated NVS partition. One writer per
 * namespace. Two unchanged TLV blobs plus a one-byte active selector. A staged
 * candidate never replaces the selected blob. Corrupt/missing selected data
 * fails closed; do not erase/fall back to older commissioning state.
 * IDF6.1 NVS commits synchronously in set_item; commit on a live handle is a
 * no-op. Review that implementation before upgrading this adapter.
 * Ordinary rejected writes preserve the selected blob. Physical flash errors
 * latch the writer offline; power loss selects an entire old or new checkpoint.
 * Calls are synchronous flash I/O scheduled by the application owner. */
Matter_Idf_Store_T matter_idf_store_new(const char* partition,const char* space);
Matter_Store_Blob_Port_T matter_idf_store_port(Matter_Idf_Store_T);
void matter_idf_store_delete(Matter_Idf_Store_T);
/* Lab fault BEFORE stage or BEFORE selector, once; 0 disables. No flash-fault
 * simulation claim. stage2 leaves a durable but unselected candidate. */
void matter_idf_store_fail(Matter_Idf_Store_T,unsigned stage);
#endif

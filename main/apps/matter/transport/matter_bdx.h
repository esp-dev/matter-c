#ifndef MATTER_BDX_H_INCLUDED
#define MATTER_BDX_H_INCLUDED 1
#include "../matter.h"
#include <stddef.h>
typedef struct Matter_Bdx* Matter_Bdx_T;
/* Receiver-driven BDX v0, one complete file, offset zero. Owner supplies a
 * reliable authenticated CASE exchange, deduplication and monotonic time.
 * Callbacks are synchronous, bounded, non-reentrant; write borrows one block.
 * open failure owns nothing; after open, cancel releases partial output exactly
 * once on failure/delete. finish validates/stages, never installs. Publish the
 * staged file only after exchange/MRP drain confirms success. */
typedef struct {
    void* user;
    Matter_Result_T (*open)(void*);
    Matter_Result_T (*write)(void*,const uint8_t*,size_t);
    Matter_Result_T (*finish)(void*,uint64_t bytes);
    void (*cancel)(void*);
} Matter_Bdx_Sink_T;
typedef struct { const uint8_t* data; size_t size; uint16_t protocol; uint8_t opcode; } Matter_Bdx_Message_T;
/* FD copied, 1..233 bytes; block=16..128 or 256/512/1024. Heap workspace.
 * max_size is a hard local limit even when ReceiveAccept omits length.
 * 300s idle timeout; transport MRP exhaustion may terminate earlier. */
Matter_Bdx_T matter_bdx_new(const uint8_t* fd,size_t size,uint16_t block,uint64_t max_size,const Matter_Bdx_Sink_T*,uint64_t now);
Matter_Result_T matter_bdx_output(Matter_Bdx_T,Matter_Bdx_Message_T*);
Matter_Result_T matter_bdx_sent(Matter_Bdx_T,uint64_t now);
Matter_Result_T matter_bdx_receive(Matter_Bdx_T,uint16_t protocol,uint8_t opcode,const uint8_t*,size_t,uint64_t now);
Matter_Result_T matter_bdx_process(Matter_Bdx_T,uint64_t now);
Matter_Result_T matter_bdx_result(Matter_Bdx_T,uint64_t* bytes);
void matter_bdx_cancel(Matter_Bdx_T);
void matter_bdx_delete(Matter_Bdx_T);
#endif

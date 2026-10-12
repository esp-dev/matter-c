#ifndef MATTER_ACK_SENDER_H_INCLUDED
#define MATTER_ACK_SENDER_H_INCLUDED 1

#include "matter_ack.h"
#include "../ports/matter_ack_port.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Matter_Ack_Sender* Matter_Ack_Sender_T;

/* One sender per borrowed ACK table, one allocation with a fixed 10-byte TX
 * buffer. All calls on the application owner thread. No owner lease, session
 * pinning, exchange release, clock, sockets or restart. No callbacks on new or
 * construction failure. Both port callbacks required; NULL on bad args/OOM.
 * Keep table alive until AFTER sender_delete; no other next/complete executor
 * may manipulate the sender's reservations. Outside port callbacks, caller may
 * record/immediate/close and use piggyback with its OWN reservations. Such a
 * piggyback must drain too before stop can finish. No borrowed RX is retained.
 * Caller handles admission/backpressure, retaining original RX time on retry.
 * Caller keeps session/exchange/routing alive until ACK close/stop returns OK;
 * stop sender BEFORE UDP/exchanges/owner. Existing cancel-all is not ordered.
 */
Matter_Ack_Sender_T matter_ack_sender_new(Matter_Ack_Table_T table, const Matter_Ack_Port_T* port);
/* NULL OK. Requires successful stop/drain, else INVALID_STATE. Calls detach
 * before free, never deletes the borrowed table. Callback reentry -> BUSY.
 */
Matter_Result_T matter_ack_sender_delete(Matter_Ack_Sender_T sender);

/* At most one send callback per call. Gets due ACK from table, encodes with
 * existing protocol writer: A=1, I=local role, R/V/SX=0, protocol=0, opcode=0x10,
 * ACK counter, empty payload. Port acceptance -> PENDING; rejection returns
 * WOULD_BLOCK/OFFLINE/PORT_ERROR and rolls reservation back without losing ACK.
 * Already in flight -> PENDING without touching its bytes. No ready work ->
 * WOULD_BLOCK (also when another piggyback reservation blocks the table).
 * Stopping and fully drained -> OK. Other table/codec errors are propagated
 * (codec errors as PORT_ERROR). now_ms follows table's next clock contract;
 * when no new reservation is attempted, time is ignored. Application schedules
 * prompt calls/retries; no implicit loop, sleep, backoff or deadline guarantee.
 */
Matter_Result_T matter_ack_sender_process(Matter_Ack_Sender_T sender, uint64_t now_ms);
/* Backend terminal event AFTER port.send returns and references are dropped.
 * Does not send again or notify callbacks. Actual result commits/rolls back ACK;
 * FAILED/CANCELLED remain for next explicit process, including during stop.
 * Invalid result/zero ID -> INVALID_ARGUMENT; stale ID -> INVALID_STATE.
 * BUSY on inline reentry means event NOT accepted, retry after outer callback.
 */
Matter_Result_T matter_ack_sender_complete(Matter_Ack_Sender_T sender, uint64_t request,
	Matter_Operation_Result_T result);
/* Irreversibly stop ACK table admission, flush pending ACKs via process and
 * await accepted sends. OK only when drained; otherwise PENDING. No cancellation,
 * forced timeout or dropping errors. Repeat to query, then delete. Does not
 * stop shared transport/owner or automatically release exchange metadata.
 */
Matter_Result_T matter_ack_sender_stop(Matter_Ack_Sender_T sender);

#ifdef __cplusplus
}
#endif
#endif

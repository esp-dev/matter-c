#ifndef MATTER_SECURE_CHANNEL_H_INCLUDED
#define MATTER_SECURE_CHANNEL_H_INCLUDED 1
#include "../session/matter_secure.h"
#include "../matter_udp.h"
#include "matter_rx.h"
#include "matter_retransmission.h"
#include "matter_retransmission_sender.h"

#ifdef __cplusplus
extern "C" {
#endif
typedef struct Matter_Secure_Channel* Matter_Secure_Channel_T;
typedef struct { size_t size; uint32_t counter; } Matter_Secure_Prepared_T;
typedef struct { uint64_t request; Matter_Operation_Result_T outcome; } Matter_Secure_Channel_Result_T;
/* One application-owned PASE/CASE binding: unique opaque exchange token (not wire
 * session ID), unicast path, borrowed session pinned until delete. Only CASE
 * permits an explicit owner-resolved peer update after outstanding I/O drains.
 * No registry, tasks, clocks or UDP ownership. Route to it by local session ID;
 * RX also checks exact source/destination/interface before authentication.
 * Same owner thread as RX/MRP/UDP. NULL on invalid args, closed session or OOM.
 */
Matter_Secure_Channel_T matter_secure_channel_new(Matter_Secure_T session,
	Matter_Exchange_Session_T token, const Matter_Udp_Path_T* path);
/* Read-only route snapshot. CASE-only peer update from owner-resolved operational
 * identity; local address/interface unchanged. DNS does not authenticate packets:
 * receive still enforces bound path and AEAD/replay. BUSY while UDP borrows the
 * old route, including until take. No key/counter/encoded packet mutation. */
Matter_Result_T matter_secure_channel_path(Matter_Secure_Channel_T,Matter_Udp_Path_T*);
Matter_Result_T matter_secure_channel_route(Matter_Secure_Channel_T,const Matter_Udp_Address_T* peer);
/* Read-only MRP scheduling inputs from negotiated PASE/CASE parameters and last
 * authenticated RX time (initially session creation). No clock/timer mutation. */
Matter_Result_T matter_secure_channel_parameters(Matter_Secure_Channel_T channel, uint64_t now_ms,
	Matter_Retransmission_Parameters_T* parameters);
/* Encoded protocol plaintext -> full immutable packet/counter for sender_add.
 * Caller owns buffer and pins it/session/exchange until sender release. Rejected
 * sender_add does NOT undo this counter. Retry uses send, never prepare again.
 * Output metadata preserved on error; packet follows secure_seal contract. */
Matter_Result_T matter_secure_channel_prepare(Matter_Secure_Channel_T channel,
	const uint8_t* plain, size_t size, uint64_t now_ms, uint8_t* packet, size_t capacity,
	Matter_Secure_Prepared_T* prepared);
/* Outside UDP callback: authenticates, submits to existing RX, commits only on
 * accepted copy/pin. RX's retain/release port must map token to this session.
 * received_ms preserves original RX time on retry; now_ms is current monotonic
 * processing time (>=received_ms). Authenticated CloseSession closes admission
 * without queueing application data/ACK. After receive, check is_closed and call
 * retire BEFORE processing executors. Duplicate StatusReport cannot close again.
 */
Matter_Result_T matter_secure_channel_receive(Matter_Secure_Channel_T channel, Matter_Rx_T rx,
	const Matter_Udp_Datagram_T* datagram, uint64_t received_ms, uint64_t now_ms);
/* One shared pending TX slot (MRP and ACK), raw UDP borrowed until take. Returns
 * PENDING on acceptance; caller maps result to producer's deferred completion.
 * send borrows caller's immutable packet, including after session exhaustion;
 * only packets produced by prepare/seal for this binding are permitted.
 * send_ack encrypts the existing ACK sender's 10-byte plaintext into private
 * heap storage. Never edit it while pending. BUSY means no new work; callers
 * map BUSY to their port's WOULD_BLOCK/retryable rejection. Rejected UDP send
 * may consume a fresh ACK counter, but retains no packet or event obligation.
 */
Matter_Result_T matter_secure_channel_send(Matter_Secure_Channel_T channel, Matter_Udp_T udp,
	const uint8_t* packet, size_t size, uint64_t* request);
Matter_Result_T matter_secure_channel_send_ack(Matter_Secure_Channel_T channel, Matter_Udp_T udp,
	const Matter_Ack_Message_T* message, uint64_t now_ms, uint64_t* request);
Matter_Result_T matter_secure_channel_complete(Matter_Secure_Channel_T channel, uint64_t request,
	Matter_Operation_Result_T outcome);
Matter_Result_T matter_secure_channel_take(Matter_Secure_Channel_T channel, Matter_Secure_Channel_Result_T* result);
/* Stop RX/MRP first, allowing ACK/control drain. Then close channel, complete/
 * take outstanding I/O, invalidate external routing, delete, close/delete secure
 * session when all other pins drain. Never stops shared UDP or cancels another
 * producer. Cancellation still owes the actual deferred UDP completion.
 */
Matter_Result_T matter_secure_channel_close(Matter_Secure_Channel_T channel);
/* Read-only gate state (including local/remote protocol close). */
Matter_Result_T matter_secure_channel_is_closed(Matter_Secure_Channel_T channel, bool* closed);
/* Core 4.11.1.4: encrypted SUCCESS/SECURE_CHANNEL/CLOSE_SESSION, fresh exchange,
 * I=1, R=0, no MRP retry. Uses private heap control storage and the shared TX slot.
 * PENDING accepts UDP, gates RX/TX and closes secure admission immediately. Keep
 * forwarding real complete/take, then retire; even failed accepted TX terminates
 * the session. Rejected submission leaves channel open and closes the temporary
 * exchange (may consume a counter); RX process finishes deferred close barriers.
 * BUSY while another TX owns the slot; caller may instead retire without sending.
 * No new core allocation; CCM backend may fail. Request unchanged on error.
 */
Matter_Result_T matter_secure_channel_send_close(Matter_Secure_Channel_T channel, Matter_Rx_T rx,
	Matter_Udp_T udp, uint64_t now_ms, uint64_t* request);
/* Terminal removal for local/remote close, exhausted counter or explicit fatal
 * error. Idempotent, no allocation. Gates channel/session, cancels matching MRP,
 * discards queued RX/unsent ACK, closes exchanges. PENDING until real I/O take,
 * executor process and all external pins (e.g. resolver) drain. Does not drive
 * process/poll, stop shared UDP/RX/MRP, or reset counters/keys. Call with the SAME
 * RX and sender which own this token, before their service-wide stop. Route and
 * retain hooks must reject this closed incarnation; never reuse its token.
 * After OK invalidate external routing, delete channel (releases final base pin
 * and clears keys), then delete secure. Protocol-close delete requires retire OK.
 */
Matter_Result_T matter_secure_channel_retire(Matter_Secure_Channel_T channel, Matter_Rx_T rx,
	Matter_Retransmission_Sender_T tx);
Matter_Result_T matter_secure_channel_delete(Matter_Secure_Channel_T channel);
#ifdef __cplusplus
}
#endif
#endif

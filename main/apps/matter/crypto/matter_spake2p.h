#ifndef MATTER_SPAKE2P_H_INCLUDED
#define MATTER_SPAKE2P_H_INCLUDED 1
#include "../ports/matter_crypto_port.h"

#ifdef __cplusplus
extern "C" {
#endif
typedef struct Matter_Spake2p* Matter_Spake2p_T;
enum { MATTER_SPAKE2P_MAX_CONTEXT = 64, MATTER_SPAKE2P_MAX_PARAMS = 1024 };

/* Core 3.10: SHA256("CHIP PAKE V1 Commissioning" || request || response).
 * Supply exact PBKDFParamRequest/Response payloads, not decoded/re-encoded TLV
 * or packet headers. Each <= MAX_PARAMS; NULL only if size=0. Output 32 B.
 * Bounded heap temporary; synchronous, no span retention. */
Matter_Result_T matter_spake2p_context(const Matter_Crypto_Port_T* port,
	const uint8_t* request, size_t request_size, const uint8_t* response, size_t response_size,
	uint8_t* context);

/* Own heap context; copied port descriptor, borrowed backend user (must outlive
 * session). Serialized owner-thread, no task, network or internal timeout.
 * Application schedules crypto outside RX/poll, cancels by delete.
 * Inputs copied: canonical w0[32], credential = w1[32] (initiator) or L[65]
 * (responder), context <=64 B. Matter MUST use context()'s 32-byte result;
 * other lengths permit independent standard vectors, not a different PASE profile.
 * NULL: invalid args/OOM. Scalar/point validity checked during start/derive.
 * Application must clear its own input copies. Never supply predictable entropy
 * or override p256_scalar outside tests. All API output spans disjoint from inputs.
 */
Matter_Spake2p_T matter_spake2p_new(const Matter_Crypto_Port_T* port, bool responder,
	const uint8_t* w0, const uint8_t* credential, size_t credential_size,
	const uint8_t* context, size_t context_size);
/* NEW -> STARTED, fresh random x/y, output own 65-byte share. One attempt only. */
Matter_Result_T matter_spake2p_start(Matter_Spake2p_T session, uint8_t* share);
/* STARTED -> WAITING: validate peer share, compute Z/V/TT, Ka/Ke and cA/cB.
 * Erases x/y, w0, credential and work buffers after derivation. */
Matter_Result_T matter_spake2p_derive(Matter_Spake2p_T session, const uint8_t* peer, size_t size);
/* Responder may export cB after derive; initiator may export cA ONLY after
 * successful verify(cB). Output 32 B. Repeat allowed for retransmission.
 * Export does not prove network delivery; transport still owns send/status. */
Matter_Result_T matter_spake2p_confirmation(Matter_Spake2p_T session, uint8_t* confirmation);
/* Verify once, constant-time. Responder must export cB before accepting cA.
 * Wrong confirmation -> PORT_ERROR, terminal failure, secrets erased. */
Matter_Result_T matter_spake2p_verify(Matter_Spake2p_T session, const uint8_t* confirmation, size_t size);
/* Output 16-byte Ke only when local confirmation exported AND peer verified.
 * Caller owns/clears exported copies. This is not yet a secure Matter session. */
Matter_Result_T matter_spake2p_key(Matter_Spake2p_T session, uint8_t* key);
/* NULL OK, reentry BUSY. Zeroizes entire heap context. No reset/reuse. */
Matter_Result_T matter_spake2p_delete(Matter_Spake2p_T session);
/* Invalid arguments/state/BUSY preserve output and state. Once crypto work
 * begins, any backend failure is terminal; start also zeroizes its output.
 * A failed session must be deleted and replaced; no reuse of ephemeral secrets.
 */
#ifdef __cplusplus
}
#endif
#endif

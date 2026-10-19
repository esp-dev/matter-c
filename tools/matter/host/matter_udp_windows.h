#ifndef MATTER_UDP_WINDOWS_H_INCLUDED
#define MATTER_UDP_WINDOWS_H_INCLUDED 1

#include "matter_udp.h"

/* Opaque IPv6 unicast host API. Legacy _windows names are retained for source
 * compatibility; select exactly one Windows/Linux implementation at link time.
 * Windows RX wire-MTU gap remains; Linux enforces IPv6 <=1280 with socket BPF
 * and rejects atomic/reassembled fragments via IPV6_RECVFRAGSIZE. No OS types.
 * Owner thread only. Owns a module, socket, heap RX buffer (Windows: WSA ref).
 */
typedef struct Matter_Udp_Windows* Matter_Udp_Windows_T;

/* Copies bind address/listener. Port zero chooses an ephemeral port on EACH
 * start. :: binds all local IPv6 addresses. interface_id is the OS IPv6 interface index,
 * required for link-local bind. No multicast membership or IPv4-mapped support.
 * NULL on invalid configuration, OOM or Winsock startup failure.
 */
Matter_Udp_Windows_T matter_udp_windows_new(Matter_T owner,
    const Matter_Udp_Address_T* bind_address, uint32_t interface_id,
    const Matter_Udp_Listener_T* listener);

/* Borrowed module: use normal start/send/stop/process, never delete directly.
 * Delete host BEFORE owner, after module drain. NULL delete is harmless.
 */
Matter_Udp_T matter_udp_windows_module(Matter_Udp_Windows_T host);
Matter_Result_T matter_udp_windows_delete(Matter_Udp_Windows_T host);
/* Active socket address/actual port; output unchanged on error. */
Matter_Result_T matter_udp_windows_local(Matter_Udp_Windows_T host,
    Matter_Udp_Address_T* address);
/* At most one deferred completion AND one received packet, never waits/retries.
 * Call even while stopping to drain TX; separately call matter_udp_process.
 * Completion precedes RX. Empty RX preserves completion success; a completion
 * error defers RX. WOULD_BLOCK = no event. Malformed/oversize RX consumed, error returned, no
 * listener callback. Linux kernel drops may instead give WOULD_BLOCK.
 * Reentry/mutation of host from its listeners returns BUSY.
 */
Matter_Result_T matter_udp_windows_poll(Matter_Udp_Windows_T host);

#endif

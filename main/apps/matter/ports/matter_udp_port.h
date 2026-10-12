#ifndef MATTER_UDP_PORT_H_INCLUDED
#define MATTER_UDP_PORT_H_INCLUDED 1

#include "../matter.h"
#include <stddef.h>

/* Core 1.6.1 4.4.4: UDP IPv6 packet <=1280 B. Ceiling assumes a 40-byte
 * IPv6 header and 8-byte UDP header. Backend MUST also enforce the full packet
 * limit, reducing usable payload if extension headers are present. No fragments
 * or truncated receive buffers may be passed as complete datagrams.
 */
enum { MATTER_UDP_MAX_PAYLOAD = 1232 };

typedef struct {
	uint8_t address[16]; /* IPv6 network byte order; no OS-specific address type. */
	uint16_t port;       /* Host byte order, nonzero. */
} Matter_Udp_Address_T;

typedef struct {
	Matter_Udp_Address_T local, peer;
	uint32_t interface_id;
} Matter_Udp_Path_T;

/* TX: local/peer are source/destination; local :: lets backend select source.
 * RX: local is actual destination (including multicast), peer is source.
 * interface_id is adapter's interface/scope key (host byte order), not an OS
 * handle. TX zero = default route when unambiguous; scoped addresses require
 * a usable nonzero key. Backend validates addresses/routes/scopes and binds.
 * RX must include destination/interface metadata for correct scoped replies.
 */
typedef struct {
	Matter_Udp_Path_T path;
	const uint8_t* data;
	size_t size;
} Matter_Udp_Datagram_T;

/* One binding per module. Application owns sockets/event loop/configuration.
 * Callbacks run on the owner thread, return normally, and never block or mutate
 * module/owner inline. Marshal external events onto that thread. No hidden task.
 *
 * activate(epoch): synchronously enable routing for this epoch. OK = enabled;
 * WOULD_BLOCK/OFFLINE/PORT_ERROR = no retained references/events or side effects.
 * deactivate(epoch): synchronous nonblocking RX barrier; disable this epoch,
 * invalidate queued receives BEFORE return. Does NOT finish a pending send.
 * Socket closure can be deferred/owned by application; no shared network stop.
 *
 * send(request, datagram): OK accepts exactly one whole datagram and promises
 * one later complete, even for immediate OS send success. Other allowed results
 * WOULD_BLOCK/OFFLINE/PORT_ERROR reject without sending, retaining references
 * or scheduling completion. No partial success. Descriptor and bytes borrowed
 * immutable until backend drops ALL send references before delivering complete.
 * SUCCEEDED means local transport accepted it, NOT delivery/ACK by the peer.
 *
 * cancel requests cancellation once; later complete with actual outcome, even
 * if success races cancel. Offline/errors do not remove this drain obligation.
 * detach is a synchronous routing barrier on inactive deletion: invalidate all
 * events/references before return, without closing others' sockets. New module
 * allocations require fresh binding identity; epoch/request alone are not safe
 * across deletion/address reuse. Never call into a freed module.
 */
typedef struct {
	void* user;
	Matter_Result_T (*activate)(void* user, Matter_Operation_Id_T epoch);
	void (*deactivate)(void* user, Matter_Operation_Id_T epoch);
	Matter_Result_T (*send)(void* user, uint64_t request, const Matter_Udp_Datagram_T* datagram);
	void (*cancel)(void* user, uint64_t request);
	void (*detach)(void* user);
} Matter_Udp_Port_T;

#endif

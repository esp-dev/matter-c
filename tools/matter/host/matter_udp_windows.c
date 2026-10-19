#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <stdlib.h>
#include <string.h>
#include "matter_udp_windows.h"

typedef union {
    WSACMSGHDR alignment;
    char bytes[WSA_CMSG_SPACE(sizeof(IN6_PKTINFO))];
} Control;

struct Matter_Udp_Windows {
    Matter_Udp_T udp;
    SOCKET socket;
    LPFN_WSARECVMSG receive;
    Matter_Udp_Address_T configured, local;
    uint32_t interface_id;
    Matter_Operation_Id_T epoch;
    uint64_t pending;
    Matter_Operation_Result_T terminal;
    bool busy;
    WSADATA startup; /* Also heap: WSADATA is over 400 bytes on this host. */
    Control rx_control;
    uint8_t rx[MATTER_UDP_MAX_PAYLOAD];
};

static bool unspecified(const uint8_t* address) {
    static const uint8_t zero[16] = {0};
    return memcmp(address, zero, 16) == 0;
}

static bool link_local(const uint8_t* address) {
    return address[0] == 0xfe && (address[1] & 0xc0) == 0x80;
}

static bool unicast(const uint8_t* address) {
    static const uint8_t mapped[12] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff};
    return address[0] != 0xff && memcmp(address, mapped, 12) != 0;
}

static void socket_address(SOCKADDR_IN6* out, const Matter_Udp_Address_T* in,
    uint32_t interface_id) {
    memset(out, 0, sizeof(*out));
    out->sin6_family = AF_INET6;
    out->sin6_port = htons(in->port);
    memcpy(&out->sin6_addr, in->address, 16);
    if (link_local(in->address)) out->sin6_scope_id = interface_id;
}

static Matter_Result_T socket_error(int error) {
    if (error == WSAEWOULDBLOCK) return MATTER_WOULD_BLOCK;
    if (error == WSAENETDOWN || error == WSAENETUNREACH || error == WSAEHOSTUNREACH)
        return MATTER_OFFLINE;
    return MATTER_PORT_ERROR;
}

static void close_socket(Matter_Udp_Windows_T host) {
    if (host->socket != INVALID_SOCKET) closesocket(host->socket);
    host->socket = INVALID_SOCKET;
    host->epoch = 0;
    host->receive = NULL;
}

static Matter_Result_T activate(void* user, Matter_Operation_Id_T epoch) {
    Matter_Udp_Windows_T host = user;
    SOCKET s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return socket_error(WSAGetLastError());
    DWORD yes = 1, mtu = 1280, bytes = 0;
    u_long nonblocking = 1;
    GUID extension = WSAID_WSARECVMSG;
    LPFN_WSARECVMSG receive = NULL;
    SOCKADDR_IN6 address;
    int length = sizeof(address);
    socket_address(&address, &host->configured, host->interface_id);
    if (setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char*)&yes, sizeof(yes)) ||
        setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&yes, sizeof(yes)) ||
        setsockopt(s, IPPROTO_IPV6, IPV6_PKTINFO, (const char*)&yes, sizeof(yes)) ||
        setsockopt(s, IPPROTO_IPV6, IPV6_USER_MTU, (const char*)&mtu, sizeof(mtu)) ||
        setsockopt(s, IPPROTO_IPV6, IPV6_DONTFRAG, (const char*)&yes, sizeof(yes)) ||
        ioctlsocket(s, FIONBIO, &nonblocking) ||
        WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &extension, sizeof(extension),
            &receive, sizeof(receive), &bytes, NULL, NULL) ||
        bind(s, (const SOCKADDR*)&address, sizeof(address)) ||
        getsockname(s, (SOCKADDR*)&address, &length)) {
        Matter_Result_T result = socket_error(WSAGetLastError());
        closesocket(s);
        return result;
    }
    host->socket = s;
    host->receive = receive;
    host->epoch = epoch;
    host->local = host->configured;
    host->local.port = ntohs(address.sin6_port);
    return MATTER_OK;
}

static void deactivate(void* user, Matter_Operation_Id_T epoch) {
    Matter_Udp_Windows_T host = user;
    if (host->epoch == epoch) close_socket(host); /* Discard kernel RX queue. */
}

static Matter_Result_T send_packet(void* user, uint64_t request,
    const Matter_Udp_Datagram_T* datagram) {
    Matter_Udp_Windows_T host = user;
    const Matter_Udp_Path_T* path = &datagram->path;
    if (host->socket == INVALID_SOCKET) return MATTER_OFFLINE;
    if ((host->interface_id && path->interface_id != host->interface_id) ||
        path->local.port != host->local.port || unspecified(path->peer.address) ||
        !unicast(path->peer.address) || !unicast(path->local.address) ||
        ((link_local(path->peer.address) || link_local(path->local.address)) && !path->interface_id) ||
        (!unspecified(host->local.address) && !unspecified(path->local.address) &&
            memcmp(host->local.address, path->local.address, 16))) return MATTER_PORT_ERROR;
    SOCKADDR_IN6 peer;
    socket_address(&peer, &path->peer, path->interface_id);
    WSABUF buffer = {(ULONG)datagram->size, (char*)datagram->data};
    Control control = {0}; /* 40 bytes, aligned for WSACMSGHDR. */
    WSAMSG message = {0};
    message.name = (SOCKADDR*)&peer;
    message.namelen = sizeof(peer);
    message.lpBuffers = &buffer;
    message.dwBufferCount = 1;
    message.Control.buf = control.bytes;
    message.Control.len = sizeof(control.bytes);
    WSACMSGHDR* header = WSA_CMSG_FIRSTHDR(&message);
    header->cmsg_level = IPPROTO_IPV6;
    header->cmsg_type = IPV6_PKTINFO;
    header->cmsg_len = WSA_CMSG_LEN(sizeof(IN6_PKTINFO));
    IN6_PKTINFO info = {0};
    memcpy(&info.ipi6_addr, path->local.address, 16);
    info.ipi6_ifindex = path->interface_id;
    memcpy(WSA_CMSG_DATA(header), &info, sizeof(info));
    DWORD sent = 0;
    if (WSASendMsg(host->socket, &message, 0, &sent, NULL, NULL) == SOCKET_ERROR)
        return socket_error(WSAGetLastError());
    /* Datagram writes are atomic. Still drain an unexpected short success as a
     * FAILED accepted send, never report rejection after a possible side effect. */
    host->terminal = sent == datagram->size ? MATTER_OPERATION_SUCCEEDED : MATTER_OPERATION_FAILED;
    host->pending = request;
    return MATTER_OK;
}

static void cancel(void* user, uint64_t request) {
    /* Synchronous OS send already ended; its deferred result wins the race. */
    (void)user;
    (void)request;
}

static void detach(void* user) {
    Matter_Udp_Windows_T host = user;
    close_socket(host);
    host->pending = 0;
    host->udp = NULL;
}

Matter_Udp_Windows_T matter_udp_windows_new(Matter_T owner,
    const Matter_Udp_Address_T* bind_address, uint32_t interface_id,
    const Matter_Udp_Listener_T* listener) {
    if (!owner || !bind_address || !unicast(bind_address->address) ||
        (link_local(bind_address->address) && !interface_id)) return NULL;
    Matter_Udp_Windows_T host = calloc(1, sizeof(*host));
    if (!host) return NULL;
    host->socket = INVALID_SOCKET;
    host->configured = *bind_address;
    host->interface_id = interface_id;
    if (WSAStartup(MAKEWORD(2,2), &host->startup)) { free(host); return NULL; }
    Matter_Udp_Port_T port = {host, activate, deactivate, send_packet, cancel, detach};
    host->udp = matter_udp_new(owner, &port, listener);
    if (!host->udp) { WSACleanup(); free(host); return NULL; }
    return host;
}

Matter_Udp_T matter_udp_windows_module(Matter_Udp_Windows_T host) {
    return host ? host->udp : NULL;
}

Matter_Result_T matter_udp_windows_delete(Matter_Udp_Windows_T host) {
    if (!host) return MATTER_OK;
    if (host->busy) return MATTER_BUSY;
    Matter_Result_T result = matter_udp_delete(host->udp);
    if (result != MATTER_OK) return result;
    WSACleanup();
    free(host);
    return MATTER_OK;
}

Matter_Result_T matter_udp_windows_local(Matter_Udp_Windows_T host,
    Matter_Udp_Address_T* address) {
    if (!host || !address) return MATTER_INVALID_ARGUMENT;
    if (host->socket == INVALID_SOCKET) return MATTER_INVALID_STATE;
    *address = host->local;
    return MATTER_OK;
}

static Matter_Result_T receive_packet(Matter_Udp_Windows_T host) {
    SOCKADDR_IN6 peer = {0};
    WSABUF buffer = {sizeof(host->rx), (char*)host->rx};
    WSAMSG message = {0};
    message.name = (SOCKADDR*)&peer;
    message.namelen = sizeof(peer);
    message.lpBuffers = &buffer;
    message.dwBufferCount = 1;
    message.Control.buf = host->rx_control.bytes;
    message.Control.len = sizeof(host->rx_control.bytes);
    DWORD received = 0;
    if (host->receive(host->socket, &message, &received, NULL, NULL) == SOCKET_ERROR) {
        int error = WSAGetLastError();
        /* An ICMP Port Unreachable from one departed peer must not shut down
         * the shared unconnected UDP socket and all other Matter sessions. */
        if(error == WSAECONNRESET) return MATTER_WOULD_BLOCK;
        return error == WSAEMSGSIZE ? MATTER_LIMIT_REACHED : socket_error(error);
    }
    if (message.dwFlags & (MSG_TRUNC | MSG_CTRUNC | MSG_PARTIAL)) return MATTER_LIMIT_REACHED;
    if (message.namelen != sizeof(peer) || peer.sin6_family != AF_INET6 || !received)
        return MATTER_INVALID_ARGUMENT;
    Matter_Udp_Datagram_T datagram = {0};
    datagram.path.local.port = host->local.port;
    datagram.path.peer.port = ntohs(peer.sin6_port);
    memcpy(datagram.path.peer.address, &peer.sin6_addr, 16);
    bool found = false;
    for (WSACMSGHDR* h = WSA_CMSG_FIRSTHDR(&message); h; h = WSA_CMSG_NXTHDR(&message, h)) {
        if (h->cmsg_level == IPPROTO_IPV6 && h->cmsg_type == IPV6_PKTINFO &&
            h->cmsg_len == WSA_CMSG_LEN(sizeof(IN6_PKTINFO))) {
            IN6_PKTINFO info;
            memcpy(&info, WSA_CMSG_DATA(h), sizeof(info));
            memcpy(datagram.path.local.address, &info.ipi6_addr, 16);
            datagram.path.interface_id = info.ipi6_ifindex;
            found = true;
        }
    }
    if (!found || !datagram.path.interface_id) return MATTER_PORT_ERROR;
    if (host->interface_id && datagram.path.interface_id != host->interface_id) return MATTER_WOULD_BLOCK;
    datagram.data = host->rx;
    datagram.size = received;
    return matter_udp_receive(host->udp, host->epoch, &datagram, false);
}

Matter_Result_T matter_udp_windows_poll(Matter_Udp_Windows_T host) {
    if (!host) return MATTER_INVALID_ARGUMENT;
    if (host->busy) return MATTER_BUSY;
    host->busy = true;
    Matter_Result_T result = MATTER_WOULD_BLOCK;
    if (host->pending) {
        uint64_t request = host->pending;
        host->pending = 0;
        result = matter_udp_complete(host->udp, request, host->terminal);
        if (result == MATTER_BUSY) host->pending = request;
    }
    /* A continuous TX backlog must not starve peer ACKs. Do at most one RX
     * as well as one completion; preserve completion success if RX is empty. */
    if (host->socket != INVALID_SOCKET && (result == MATTER_OK || result == MATTER_WOULD_BLOCK)) {
        Matter_Result_T received = receive_packet(host);
        if (received != MATTER_WOULD_BLOCK) result = received;
    }
    host->busy = false;
    return result;
}

/* Linux backend of the existing opaque host API (legacy _windows names). */
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <linux/filter.h>
#include <stdlib.h>
#include <string.h>
#include "matter_udp_windows.h"

typedef union {
    struct cmsghdr alignment;
    char bytes[CMSG_SPACE(sizeof(struct in6_pktinfo)) + CMSG_SPACE(sizeof(int))];
} Control;

struct Matter_Udp_Windows {
    Matter_Udp_T udp;
    int socket;
    Matter_Udp_Address_T configured, local;
    uint32_t interface_id;
    Matter_Operation_Id_T epoch;
    uint64_t pending;
    Matter_Operation_Result_T terminal;
    bool busy;
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

static void socket_address(struct sockaddr_in6* out, const Matter_Udp_Address_T* in,
    uint32_t interface_id) {
    memset(out, 0, sizeof(*out));
    out->sin6_family = AF_INET6;
    out->sin6_port = htons(in->port);
    memcpy(&out->sin6_addr, in->address, 16);
    if (link_local(in->address)) out->sin6_scope_id = interface_id;
}

static Matter_Result_T socket_error(int error) {
    if (error == EAGAIN || error == EWOULDBLOCK || error == EINTR) return MATTER_WOULD_BLOCK;
    if (error == ENETDOWN || error == ENETUNREACH || error == EHOSTUNREACH) return MATTER_OFFLINE;
    return MATTER_PORT_ERROR;
}

/* Kernel-validated IPv6 header, including ALL extension headers. Socket-local
 * classic BPF needs no privilege. Zero payload_len (jumbogram) is forbidden.
 * Reassembled and atomic fragments are rejected separately via RECVFRAGSIZE.
 * Failing to install either gate fails activation; no permissive fallback. */
static bool mtu_filter(int s) {
    static const struct sock_filter code[] = {
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, SKF_NET_OFF),
        BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xf0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x60, 0, 4),
        BPF_STMT(BPF_LD | BPF_H | BPF_ABS, SKF_NET_OFF + 4),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JGT | BPF_K, 1280 - 40, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, UINT32_MAX),
        BPF_STMT(BPF_RET | BPF_K, 0)
    };
    struct sock_fprog filter = {sizeof(code)/sizeof(code[0]), (struct sock_filter*)code};
    return setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter)) == 0;
}

static void close_socket(Matter_Udp_Windows_T host) {
    if (host->socket != -1) close(host->socket);
    host->socket = -1;
    host->epoch = 0;
}

static Matter_Result_T activate(void* user, Matter_Operation_Id_T epoch) {
    Matter_Udp_Windows_T host = user;
    int s = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_UDP);
    if (s == -1) return socket_error(errno);
    int yes = 1, mtu = 1280;
    struct sockaddr_in6 address;
    socklen_t length = sizeof(address);
    socket_address(&address, &host->configured, host->interface_id);
    /* No REUSEADDR/REUSEPORT: one owner for this unicast binding. */
    if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &yes, sizeof(yes)) ||
        setsockopt(s, IPPROTO_IPV6, IPV6_RECVPKTINFO, &yes, sizeof(yes)) ||
        setsockopt(s, IPPROTO_IPV6, IPV6_RECVFRAGSIZE, &yes, sizeof(yes)) ||
        setsockopt(s, IPPROTO_IPV6, IPV6_MTU, &mtu, sizeof(mtu)) ||
        setsockopt(s, IPPROTO_IPV6, IPV6_DONTFRAG, &yes, sizeof(yes)) ||
        !mtu_filter(s) || bind(s, (const struct sockaddr*)&address, sizeof(address)) ||
        getsockname(s, (struct sockaddr*)&address, &length)) {
        Matter_Result_T result = socket_error(errno);
        close(s);
        return result;
    }
    host->socket = s;
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
    if (host->socket == -1) return MATTER_OFFLINE;
    if ((host->interface_id && path->interface_id != host->interface_id) ||
        path->local.port != host->local.port || unspecified(path->peer.address) ||
        !unicast(path->peer.address) || !unicast(path->local.address) ||
        ((link_local(path->peer.address) || link_local(path->local.address)) && !path->interface_id) ||
        (!unspecified(host->local.address) && !unspecified(path->local.address) &&
            memcmp(host->local.address, path->local.address, 16))) return MATTER_PORT_ERROR;
    struct sockaddr_in6 peer;
    socket_address(&peer, &path->peer, path->interface_id);
    struct iovec buffer = {(void*)datagram->data, datagram->size};
    Control control = {0}; /* 64 bytes, not the packet workspace. */
    struct msghdr message = {.msg_name=&peer, .msg_namelen=sizeof(peer),
        .msg_iov=&buffer, .msg_iovlen=1, .msg_control=control.bytes,
        .msg_controllen=CMSG_SPACE(sizeof(struct in6_pktinfo))};
    struct cmsghdr* header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = IPPROTO_IPV6;
    header->cmsg_type = IPV6_PKTINFO;
    header->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
    struct in6_pktinfo info = {0};
    memcpy(&info.ipi6_addr, path->local.address, 16);
    info.ipi6_ifindex = path->interface_id;
    memcpy(CMSG_DATA(header), &info, sizeof(info));
    ssize_t sent = sendmsg(host->socket, &message, MSG_DONTWAIT);
    if (sent < 0) return socket_error(errno);
    /* Datagram writes are atomic. Still drain an unexpected short success as a
     * FAILED accepted send, never report rejection after a possible side effect. */
    host->terminal = (size_t)sent == datagram->size ? MATTER_OPERATION_SUCCEEDED : MATTER_OPERATION_FAILED;
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
    host->socket = -1;
    host->configured = *bind_address;
    host->interface_id = interface_id;
    Matter_Udp_Port_T port = {host, activate, deactivate, send_packet, cancel, detach};
    host->udp = matter_udp_new(owner, &port, listener);
    if (!host->udp) { free(host); return NULL; }
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
    free(host);
    return MATTER_OK;
}

Matter_Result_T matter_udp_windows_local(Matter_Udp_Windows_T host,
    Matter_Udp_Address_T* address) {
    if (!host || !address) return MATTER_INVALID_ARGUMENT;
    if (host->socket == -1) return MATTER_INVALID_STATE;
    *address = host->local;
    return MATTER_OK;
}

static Matter_Result_T receive_packet(Matter_Udp_Windows_T host) {
    struct sockaddr_in6 peer = {0};
    struct iovec buffer = {host->rx, sizeof(host->rx)};
    struct msghdr message = {.msg_name=&peer, .msg_namelen=sizeof(peer),
        .msg_iov=&buffer, .msg_iovlen=1, .msg_control=host->rx_control.bytes,
        .msg_controllen=sizeof(host->rx_control.bytes)};
    ssize_t received = recvmsg(host->socket, &message, MSG_DONTWAIT);
    if (received < 0) {
        if (errno == ECONNREFUSED) return MATTER_WOULD_BLOCK;
        return socket_error(errno);
    }
    if (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) return MATTER_LIMIT_REACHED;
    if (message.msg_namelen != sizeof(peer) || peer.sin6_family != AF_INET6 || !received)
        return MATTER_INVALID_ARGUMENT;
    Matter_Udp_Datagram_T datagram = {0};
    datagram.path.local.port = host->local.port;
    datagram.path.peer.port = ntohs(peer.sin6_port);
    memcpy(datagram.path.peer.address, &peer.sin6_addr, 16);
    bool found = false;
    for (struct cmsghdr* h = CMSG_FIRSTHDR(&message); h; h = CMSG_NXTHDR(&message, h)) {
        /* Linux exposes this for both atomic and reassembled fragments.
         * Fragmentation support is optional in Core 4.4.4. Drop before core. */
        if (h->cmsg_level == IPPROTO_IPV6 && h->cmsg_type == IPV6_RECVFRAGSIZE)
            return MATTER_LIMIT_REACHED;
        if (h->cmsg_level == IPPROTO_IPV6 && h->cmsg_type == IPV6_PKTINFO &&
            h->cmsg_len == CMSG_LEN(sizeof(struct in6_pktinfo))) {
            struct in6_pktinfo info;
            memcpy(&info, CMSG_DATA(h), sizeof(info));
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
    if (host->socket != -1 && (result == MATTER_OK || result == MATTER_WOULD_BLOCK)) {
        Matter_Result_T received = receive_packet(host);
        if (received != MATTER_WOULD_BLOCK) result = received;
    }
    host->busy = false;
    return result;
}

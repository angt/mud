#include "mud.h"

#ifdef __APPLE__
#define __APPLE_USE_RFC_3542
#endif

#ifdef DEBUG
#include <stdio.h>
#define MUD_DEBUG(...) fprintf(stderr, __VA_ARGS__);
#else
#define MUD_DEBUG(...)
#endif

#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <net/if.h>
#include <netinet/in.h>
#include <ifaddrs.h>

#include <sodium.h>

#define MUD_ASSERT(X) (void)sizeof(char[(X)?1:-1])
#define MUD_COUNT(X)  (sizeof(X)/sizeof(X[0]))

#define MUD_PACKET_MASK    (0x3FFU)
#define MUD_PACKET_COUNT   (MUD_PACKET_MASK+1)
#define MUD_PACKET_NEXT(X) (((X)+1)&MUD_PACKET_MASK)

#define MUD_TIME_SIZE (6U)

#define MUD_AD_SIZE   (16U)
#define MUD_KEY_SIZE  (32U)
#define MUD_NPUB_SIZE (MUD_TIME_SIZE)

#define MUD_PACKET_MIN_SIZE (MUD_NPUB_SIZE+MUD_AD_SIZE)

#define MUD_PONG_DATA_SIZE (3*MUD_TIME_SIZE)
#define MUD_PONG_SIZE      (MUD_PONG_DATA_SIZE+MUD_PACKET_MIN_SIZE)

#define MUD_KEYX_DATA_SIZE (MUD_TIME_SIZE+2*crypto_scalarmult_BYTES)
#define MUD_KEYX_SIZE      (MUD_KEYX_DATA_SIZE+MUD_PACKET_MIN_SIZE)

#define MUD_ONE_MSEC (UINT64_C(1000))
#define MUD_ONE_SEC  (1000*MUD_ONE_MSEC)
#define MUD_ONE_MIN  (60*MUD_ONE_SEC)

#ifndef MUD_SEND_TIMEOUT
#define MUD_SEND_TIMEOUT (10*MUD_ONE_SEC)
#endif

#ifndef MUD_PING_TIMEOUT
#define MUD_PING_TIMEOUT (100*MUD_ONE_MSEC)
#endif

#ifndef MUD_PONG_TIMEOUT
#define MUD_PONG_TIMEOUT (100*MUD_ONE_MSEC)
#endif

#ifndef MUD_TIME_TOLERANCE
#define MUD_TIME_TOLERANCE (10*MUD_ONE_MIN)
#endif

#ifndef MUD_KEYX_TIMEOUT
#define MUD_KEYX_TIMEOUT (60*MUD_ONE_MIN)
#endif

#ifndef MUD_PACKET_MAX_SIZE
#define MUD_PACKET_MAX_SIZE (1500U)
#endif

struct path_info {
    uint64_t dt;
    uint64_t time;
    uint64_t send_time;
    uint64_t count;
};

struct path {
    unsigned up;
    unsigned index;
    struct sockaddr_storage addr;
    struct {
        unsigned char data[256];
        size_t size;
    } ctrl;
    uint64_t dt;
    uint64_t rdt;
    uint64_t rtt;
    int64_t  sdt;
    uint64_t limit;
    uint64_t ping_time;
    uint64_t pong_time;
    uint64_t last_time;
    unsigned last_count;
    struct path_info recv;
    struct path_info send;
    struct path *next;
};

struct sock {
    unsigned index;
    char name[IF_NAMESIZE];
    struct sock *next;
};

struct packet {
    size_t size;
    unsigned char data[MUD_PACKET_MAX_SIZE];
};

struct queue {
    struct packet *packet;
    unsigned start;
    unsigned end;
};

struct crypto {
    uint64_t time;
    uint8_t secret[crypto_scalarmult_SCALARBYTES];
    uint8_t shared[crypto_scalarmult_BYTES];
    uint8_t key[MUD_KEY_SIZE];
    uint8_t old_key[MUD_KEY_SIZE];
    struct {
        uint8_t public[crypto_scalarmult_BYTES];
        uint8_t key[MUD_KEY_SIZE];
    } send, recv;
};

struct mud {
    int fd;
    uint64_t send_timeout;
    uint64_t time_tolerance;
    struct queue tx;
    struct queue rx;
    struct sock *sock;
    struct path *path;
    uint64_t keyx_time;
    struct crypto crypto;
};

static
void mud_write48 (unsigned char *dst, uint64_t src)
{
    dst[0] = (unsigned char)(UINT64_C(255)&(src));
    dst[1] = (unsigned char)(UINT64_C(255)&(src>>8));
    dst[2] = (unsigned char)(UINT64_C(255)&(src>>16));
    dst[3] = (unsigned char)(UINT64_C(255)&(src>>24));
    dst[4] = (unsigned char)(UINT64_C(255)&(src>>32));
    dst[5] = (unsigned char)(UINT64_C(255)&(src>>40));
}

static
uint64_t mud_read48 (const unsigned char *src)
{
    return ((uint64_t)src[0])
         | ((uint64_t)src[1]<<8)
         | ((uint64_t)src[2]<<16)
         | ((uint64_t)src[3]<<24)
         | ((uint64_t)src[4]<<32)
         | ((uint64_t)src[5]<<40);
}

static
uint64_t mud_now (struct mud *mud)
{
    struct timeval now;
    gettimeofday(&now, NULL);
    return (now.tv_sec*MUD_ONE_SEC+now.tv_usec)&((UINT64_C(1)<<48)-1);
}

static
uint64_t mud_dt (uint64_t a, uint64_t b)
{
    return (a >= b)?a-b:b-a;
}

static
void mud_unmapv4 (struct sockaddr *addr)
{
    if (addr->sa_family != AF_INET6)
        return;

    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;

    if (!IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr))
        return;

    struct sockaddr_in sin = {
        .sin_family = AF_INET,
        .sin_port = sin6->sin6_port,
    };

    memcpy(&sin.sin_addr.s_addr,
           &sin6->sin6_addr.s6_addr[12],
           sizeof(sin.sin_addr.s_addr));

    memcpy(addr, &sin, sizeof(sin));
}

static
ssize_t mud_send_path (struct mud *mud, struct path *path, uint64_t now,
                       void *data, size_t size)
{
    if (!size)
        return 0;

    struct iovec iov = {
        .iov_base = data,
        .iov_len = size,
    };

    struct msghdr msg = {
        .msg_name = &path->addr,
        .msg_namelen = sizeof(path->addr),
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = path->ctrl.data,
        .msg_controllen = path->ctrl.size,
    };

    ssize_t ret = sendmsg(mud->fd, &msg, 0);

    if (ret == (ssize_t)size) {
        if (path->recv.time > path->send.time) {
            path->last_time = now;
            path->last_count = 0;
        }

        path->send.time = now;
    }

    return ret;
}

static
int mud_set_nonblock (int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);

    if (flags == -1)
        flags = 0;

    return fcntl(fd, F_SETFL, flags|O_NONBLOCK);
}

static
int mud_sso_int (int fd, int level, int optname, int opt)
{
    return setsockopt(fd, level, optname, &opt, sizeof(opt));
}

static
struct addrinfo *mud_addrinfo (const char *host, const char *port, int flags)
{
    struct addrinfo *ai = NULL, hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_DGRAM,
        .ai_protocol = IPPROTO_UDP,
        .ai_flags = flags,
    };

    switch (getaddrinfo(host, port, &hints, &ai)) {
    case 0:
        return ai;
    case EAI_SYSTEM:
        break;
    case EAI_FAIL:
    case EAI_AGAIN:
        errno = EAGAIN;
        break;
    case EAI_MEMORY:
        errno = ENOMEM;
        break;
    default:
        errno = EINVAL;
        break;
    }

    return NULL;
}

static
int mud_cmp_addr (struct sockaddr *a, struct sockaddr *b)
{
    if (a == b)
        return 0;

    if (a->sa_family != b->sa_family)
        return 1;

    if (a->sa_family == AF_INET) {
        struct sockaddr_in *_a = (struct sockaddr_in *)a;
        struct sockaddr_in *_b = (struct sockaddr_in *)b;

        return ((_a->sin_port != _b->sin_port) ||
                (memcmp(&_a->sin_addr.s_addr, &_b->sin_addr.s_addr,
                        sizeof(_a->sin_addr.s_addr))));
    }

    if (a->sa_family == AF_INET6) {
        struct sockaddr_in6 *_a = (struct sockaddr_in6 *)a;
        struct sockaddr_in6 *_b = (struct sockaddr_in6 *)b;

        return ((_a->sin6_port != _b->sin6_port) ||
                (memcmp(&_a->sin6_addr.s6_addr, &_b->sin6_addr.s6_addr,
                        sizeof(_a->sin6_addr.s6_addr))));
    }

    return 1;
}

static
struct sock *mud_get_sock (struct mud *mud, unsigned index)
{
    struct sock *sock;

    for (sock = mud->sock; sock; sock = sock->next) {
        if (sock->index == index)
            break;
    }

    return sock;
}

static
struct path *mud_get_path (struct mud *mud, int index, struct sockaddr *addr)
{
    struct path *path;

    for (path = mud->path; path; path = path->next) {
        if ((path->index == index) &&
            (!mud_cmp_addr(addr, (struct sockaddr *)&path->addr)))
            break;
    }

    return path;
}

static
void mud_set_path (struct path *path, unsigned index,
                   struct sockaddr *addr, struct sockaddr *ifa_addr)
{
    struct msghdr msg = {
        .msg_control = path->ctrl.data,
        .msg_controllen = sizeof(path->ctrl.data),
    };

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);

    if (addr->sa_family == AF_INET) {
        MUD_ASSERT(sizeof(index)==sizeof(((struct in_pktinfo *)0)->ipi_ifindex));

        path->index = index;
        memcpy(&path->addr, addr, sizeof(struct sockaddr_in));

        cmsg->cmsg_level = IPPROTO_IP;
        cmsg->cmsg_type = IP_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));

        memcpy(&((struct in_pktinfo *)CMSG_DATA(cmsg))->ipi_ifindex,
               &index, sizeof(index));

        memcpy(&((struct in_pktinfo *)CMSG_DATA(cmsg))->ipi_spec_dst,
               &((struct sockaddr_in *)ifa_addr)->sin_addr.s_addr,
               sizeof(struct in_addr));

        path->ctrl.size = CMSG_SPACE(sizeof(struct in_pktinfo));
    }

    if (addr->sa_family == AF_INET6) {
        MUD_ASSERT(sizeof(index)==sizeof(((struct in6_pktinfo *)0)->ipi6_ifindex));

        path->index = index;
        memcpy(&path->addr, addr, sizeof(struct sockaddr_in6));

        cmsg->cmsg_level = IPPROTO_IPV6;
        cmsg->cmsg_type = IPV6_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));

        memcpy(&((struct in6_pktinfo *)CMSG_DATA(cmsg))->ipi6_ifindex,
               &index, sizeof(index));

        memcpy(&((struct in6_pktinfo *)CMSG_DATA(cmsg))->ipi6_addr,
               &((struct sockaddr_in6 *)ifa_addr)->sin6_addr.s6_addr,
               sizeof(struct in6_addr));

        path->ctrl.size = CMSG_SPACE(sizeof(struct in6_pktinfo));
    }
}

static
struct path *mud_new_path (struct mud *mud, unsigned index, struct sockaddr *addr)
{
    struct path *path = mud_get_path(mud, index, addr);

    if (path)
        return path;

    struct sock *sock = mud_get_sock(mud, index);

    if (!sock)
        return NULL;

    path = calloc(1, sizeof(struct path));

    if (!path)
        return NULL;

    struct ifaddrs *ifaddrs;

    if (getifaddrs(&ifaddrs) == -1) {
        free(path);
        return NULL;
    }

    for (struct ifaddrs *ifa = ifaddrs; ifa; ifa = ifa->ifa_next) {
        struct sockaddr *ifa_addr = ifa->ifa_addr;

        if (!ifa_addr)
            continue;

        if (ifa_addr->sa_family != addr->sa_family)
            continue;

        if (strncmp(sock->name, ifa->ifa_name, sizeof(sock->name)))
            continue;

        mud_set_path(path, index, addr, ifa_addr);
        break;
    }

    freeifaddrs(ifaddrs);

    if (!path->index) {
        free(path);
        return NULL;
    }

    path->next = mud->path;
    mud->path = path;

    return path;
}

int mud_peer (struct mud *mud, const char *host, const char *port)
{
    if (!host || !port)
        return -1;

    struct addrinfo *p, *ai = mud_addrinfo(host, port, AI_NUMERICSERV);

    if (!ai)
        return -1;

    for (p = ai; p; p = p->ai_next) {
        struct sock *sock;

        if (!p->ai_addr)
            continue;

        for (sock = mud->sock; sock; sock = sock->next)
            mud_new_path(mud, sock->index, p->ai_addr);
    }

    freeaddrinfo(ai);

    return 0;
}

int mud_bind (struct mud *mud, const char *name)
{
    if (!name)
        return -1;

    const size_t len = strlen(name);

    if (len >= IF_NAMESIZE)
        return -1;

    unsigned index = if_nametoindex(name);

    if (!index)
        return -1;

    struct sock *sock = mud_get_sock(mud, index);

    if (sock)
        return 0;

    sock = calloc(1, sizeof(struct sock));

    if (!sock)
        return -1;

    memcpy(sock->name, name, len+1);
    sock->index = index;
    sock->next = mud->sock;
    mud->sock = sock;

    struct path *path;

    for (path = mud->path; path; path = path->next)
        mud_new_path(mud, index, (struct sockaddr *)&path->addr);

    return 0;
}

int mud_set_key (struct mud *mud, unsigned char *key, size_t size)
{
    if (size != MUD_KEY_SIZE) {
        errno = EINVAL;
        return -1;
    }

    memcpy(mud->crypto.key, key, MUD_KEY_SIZE);
    memcpy(mud->crypto.old_key, key, MUD_KEY_SIZE);

    memcpy(mud->crypto.send.key, key, MUD_KEY_SIZE);
    memcpy(mud->crypto.recv.key, key, MUD_KEY_SIZE);

    return 0;
}

void mud_set_send_timeout_msec (struct mud *mud, unsigned msec)
{
    mud->send_timeout = msec*MUD_ONE_MSEC;
}

void mud_set_time_tolerance_sec (struct mud *mud, unsigned sec)
{
    mud->time_tolerance = sec*MUD_ONE_SEC;
}

static
int mud_setup_socket (int fd)
{
    if (mud_sso_int(fd, SOL_SOCKET, SO_REUSEADDR, 1) ||
        mud_sso_int(fd, IPPROTO_IP, IP_PKTINFO, 1) ||
        mud_sso_int(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, 1) ||
        mud_sso_int(fd, IPPROTO_IPV6, IPV6_V6ONLY, 0) ||
        mud_set_nonblock(fd))
        return -1;

    mud_sso_int(fd, SOL_SOCKET, SO_RCVBUF, 1<<24);
    mud_sso_int(fd, SOL_SOCKET, SO_SNDBUF, 1<<24);

    return 0;
}

static
int mud_create_socket (const char *port)
{
    struct addrinfo *p, *ai = mud_addrinfo(NULL, port, AI_PASSIVE|AI_NUMERICSERV);

    if (!ai)
        return -1;

    int fd = -1;

    for (p = ai; p; p = p->ai_next) {
        if (p->ai_family != AF_INET6)
            continue;

        if (!p->ai_addr)
            continue;

        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);

        if (fd == -1)
            continue;

        if (mud_setup_socket(fd) ||
            bind(fd, p->ai_addr, p->ai_addrlen)) {
            close(fd);
            fd = -1;
            continue;
        }

        break;
    }

    freeaddrinfo(ai);

    return fd;
}

static
int mud_create_queue (struct queue *queue)
{
    queue->packet = calloc(MUD_PACKET_COUNT, sizeof(struct packet));

    if (!queue->packet)
        return -1;

    return 0;
}

struct mud *mud_create (const char *port)
{
    if (sodium_init() == -1)
        return NULL;

    struct mud *mud = calloc(1, sizeof(struct mud));

    if (!mud)
        return NULL;

    mud->fd = mud_create_socket(port);

    if (mud->fd == -1) {
        mud_delete(mud);
        return NULL;
    }

    if (mud_create_queue(&mud->tx) ||
        mud_create_queue(&mud->rx)) {
        mud_delete(mud);
        return NULL;
    }

    mud->send_timeout = MUD_SEND_TIMEOUT;
    mud->time_tolerance = MUD_TIME_TOLERANCE;

    return mud;
}

int mud_get_fd (struct mud *mud)
{
    return mud->fd;
}

void mud_delete (struct mud *mud)
{
    if (!mud)
        return;

    free(mud->tx.packet);
    free(mud->rx.packet);

    while (mud->sock) {
        struct sock *sock = mud->sock;
        mud->sock = sock->next;
        free(sock);
    }

    while (mud->path) {
        struct path *path = mud->path;
        mud->path = path->next;
        free(path);
    }

    if (mud->fd != -1) {
        int err = errno;
        close(mud->fd);
        errno = err;
    }

    free(mud);
}

static
int mud_encrypt (struct mud *mud, uint64_t nonce,
                 unsigned char *dst, size_t dst_size,
                 const unsigned char *src, size_t src_size,
                 size_t ad_size)
{
    if (ad_size > src_size)
        ad_size = src_size;

    size_t size = src_size+MUD_PACKET_MIN_SIZE;

    if (size > dst_size)
        return 0;

    unsigned char npub[crypto_aead_chacha20poly1305_NPUBBYTES] = {0};

    mud_write48(npub, nonce);
    memcpy(dst, npub, MUD_NPUB_SIZE);

    if (src)
        memcpy(dst+MUD_NPUB_SIZE, src, ad_size);

    crypto_aead_chacha20poly1305_encrypt(
            dst+ad_size+MUD_NPUB_SIZE, NULL,
            src+ad_size, src_size-ad_size,
            dst, ad_size+MUD_NPUB_SIZE,
            NULL,
            npub,
            mud->crypto.send.key);

    return size;
}

static
int mud_decrypt (struct mud *mud, uint64_t *nonce,
                 unsigned char *dst, size_t dst_size,
                 const unsigned char *src, size_t src_size,
                 size_t ad_size)
{
    size_t size = src_size-MUD_PACKET_MIN_SIZE;

    if (ad_size > size)
        ad_size = size;

    if (size > dst_size)
        return 0;

    unsigned char npub[crypto_aead_chacha20poly1305_NPUBBYTES] = {0};

    memcpy(npub, src, MUD_NPUB_SIZE);
    memcpy(dst, src+MUD_NPUB_SIZE, ad_size);

    uint8_t *keys[] = {
        mud->crypto.key,
        mud->crypto.old_key,
        mud->crypto.recv.key,
    };

    int i = MUD_COUNT(keys);

    while ((i-- > 0) &&
           crypto_aead_chacha20poly1305_decrypt(
               dst+ad_size, NULL,
               NULL,
               src+ad_size+MUD_NPUB_SIZE, src_size-ad_size-MUD_NPUB_SIZE,
               src, ad_size+MUD_NPUB_SIZE,
               npub,
               keys[i]));

    if (i == -1)
        return -1;

    if (nonce)
        *nonce = mud_read48(src);

    return size;
}

int mud_can_pull (struct mud *mud)
{
    return (mud->rx.start != MUD_PACKET_NEXT(mud->rx.end));
}

int mud_can_push (struct mud *mud)
{
    return (mud->tx.start != mud->tx.end);
}

int mud_is_up (struct mud *mud)
{
    struct path *path;

    int ret = 0;

    for (path = mud->path; path; path = path->next)
        ret += path->up;

    return ret;
}

static
struct cmsghdr *mud_get_pktinfo (struct msghdr *msg, int family)
{
    int cmsg_level = IPPROTO_IP;
    int cmsg_type = IP_PKTINFO;

    if (family == AF_INET6) {
        cmsg_level = IPPROTO_IPV6;
        cmsg_type = IPV6_PKTINFO;
    }

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg);

    for (; cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
        if ((cmsg->cmsg_level == cmsg_level) &&
            (cmsg->cmsg_type == cmsg_type))
            return cmsg;
    }

    return NULL;
}

static
void mud_ping_path (struct mud *mud, struct path *path, uint64_t now)
{
    if (now-path->ping_time < MUD_PING_TIMEOUT)
        return;

    unsigned char ping[MUD_PACKET_MIN_SIZE];

    int ret = mud_encrypt(mud, now, ping, sizeof(ping), NULL, 0, 0);

    if (ret <= 0)
        return;

    mud_send_path(mud, path, now, ping, (size_t)ret);
    path->ping_time = now;
}

static
void mud_pong_path (struct mud *mud, struct path *path, uint64_t now)
{
    if (now-path->pong_time < MUD_PONG_TIMEOUT)
        return;

    unsigned char pong[MUD_PONG_SIZE];
    unsigned char data[MUD_PONG_DATA_SIZE];

    mud_write48(data, now);
    mud_write48(&data[MUD_TIME_SIZE], path->recv.send_time);
    mud_write48(&data[MUD_TIME_SIZE*2], path->rdt);

    int ret = mud_encrypt(mud, 0, pong, sizeof(pong),
                          data, sizeof(data), sizeof(data));

    if (ret <= 0)
        return;

    mud_send_path(mud, path, now, pong, (size_t)ret);
    path->pong_time = now;
}

static
void mud_keyx_path (struct mud *mud, struct path *path, uint64_t now)
{
    unsigned char keyx[MUD_KEYX_SIZE];
    unsigned char data[MUD_KEYX_DATA_SIZE];

    mud_write48(data, now);

    memcpy(&data[MUD_TIME_SIZE],
           mud->crypto.send.public,
           sizeof(mud->crypto.send.public));

    memcpy(&data[MUD_TIME_SIZE+sizeof(mud->crypto.send.public)],
           mud->crypto.recv.public,
           sizeof(mud->crypto.recv.public));

    int ret = mud_encrypt(mud, 0, keyx, sizeof(keyx),
                          data, sizeof(data), sizeof(data));

    if (ret <= 0)
        return;

    mud_send_path(mud, path, now, keyx, (size_t)ret);
    mud->crypto.time = now;
}

static
void mud_recv_keyx (struct mud *mud, struct path *path, uint64_t now, uint8_t *data, size_t size)
{
    if ((memcmp(mud->crypto.send.public, &data[crypto_scalarmult_BYTES], crypto_scalarmult_BYTES)) ||
        (memcmp(mud->crypto.recv.public, data, crypto_scalarmult_BYTES))) {
        memcpy(mud->crypto.recv.public, data, crypto_scalarmult_BYTES);
        mud_keyx_path(mud, path, now);
        return;
    }

    if (crypto_scalarmult(mud->crypto.shared, mud->crypto.secret, mud->crypto.recv.public))
        return;

    crypto_generichash_state state;

    crypto_generichash_init(&state, mud->crypto.key, MUD_KEY_SIZE, MUD_KEY_SIZE);
    crypto_generichash_update(&state, mud->crypto.shared,
                              sizeof(mud->crypto.shared));
    crypto_generichash_update(&state, mud->crypto.send.public,
                              sizeof(mud->crypto.send.public));
    crypto_generichash_update(&state, mud->crypto.recv.public,
                              sizeof(mud->crypto.recv.public));
    crypto_generichash_final(&state, mud->crypto.send.key, MUD_KEY_SIZE);

    memcpy(mud->crypto.old_key, mud->crypto.recv.key, MUD_KEY_SIZE);

    crypto_generichash_init(&state, mud->crypto.key, MUD_KEY_SIZE, MUD_KEY_SIZE);
    crypto_generichash_update(&state, mud->crypto.shared,
                              sizeof(mud->crypto.shared));
    crypto_generichash_update(&state, mud->crypto.recv.public,
                              sizeof(mud->crypto.recv.public));
    crypto_generichash_update(&state, mud->crypto.send.public,
                              sizeof(mud->crypto.send.public));
    crypto_generichash_final(&state, mud->crypto.recv.key, MUD_KEY_SIZE);

    sodium_memzero(mud->crypto.secret, sizeof(mud->crypto.secret));
    sodium_memzero(mud->crypto.shared, sizeof(mud->crypto.shared));

    memset(mud->crypto.send.public, 0, sizeof(mud->crypto.send.public));
    memset(mud->crypto.recv.public, 0, sizeof(mud->crypto.recv.public));
}

int mud_pull (struct mud *mud)
{
    unsigned char ctrl[256];

    for (int i = 0; i < 16; i++) {
        unsigned next = MUD_PACKET_NEXT(mud->rx.end);

        if (mud->rx.start == next) {
            errno = ENOBUFS;
            return -1;
        }

        struct packet *packet = &mud->rx.packet[mud->rx.end];

        struct sockaddr_storage addr;

        struct iovec iov = {
            .iov_base = &packet->data,
            .iov_len = sizeof(packet->data),
        };

        struct msghdr msg = {
            .msg_name = &addr,
            .msg_namelen = sizeof(addr),
            .msg_iov = &iov,
            .msg_iovlen = 1,
            .msg_control = ctrl,
            .msg_controllen = sizeof(ctrl),
        };

        ssize_t ret = recvmsg(mud->fd, &msg, 0);

        if (ret <= (ssize_t)0)
            return (int)ret;

        if (ret < (ssize_t)MUD_PACKET_MIN_SIZE)
            continue;

        uint64_t now = mud_now(mud);
        uint64_t send_time = mud_read48(packet->data);

        int mud_packet = !send_time;

        if (mud_packet) {
            if (ret < (ssize_t)(MUD_TIME_SIZE+MUD_PACKET_MIN_SIZE))
                continue;

            send_time = mud_read48(&packet->data[MUD_TIME_SIZE]);
        }

        if (mud_dt(now, send_time) >= mud->time_tolerance)
            continue;

        if (mud_packet || (ret == (ssize_t)MUD_PACKET_MIN_SIZE)) {
            unsigned char tmp[sizeof(packet->data)];

            if (mud_decrypt(mud, NULL, tmp, sizeof(tmp),
                            packet->data, (size_t)ret, (size_t)ret) == -1)
                continue;
        }

        mud_unmapv4((struct sockaddr *)&addr);

        struct cmsghdr *cmsg = mud_get_pktinfo(&msg, addr.ss_family);

        if (!cmsg)
            continue;

        unsigned index = 0;

        if (cmsg->cmsg_level == IPPROTO_IP) {
            memcpy(&index,
                   &((struct in_pktinfo *)CMSG_DATA(cmsg))->ipi_ifindex,
                   sizeof(index));
        } else {
            memcpy(&index,
                   &((struct in6_pktinfo *)CMSG_DATA(cmsg))->ipi6_ifindex,
                   sizeof(index));
        }

        struct path *path = mud_get_path(mud, index, (struct sockaddr *)&addr);

        if (path) {
            struct msghdr send_msg = {
                .msg_control = path->ctrl.data,
                .msg_controllen = path->ctrl.size,
            };

            struct cmsghdr *send_cmsg = CMSG_FIRSTHDR(&send_msg);

            if (cmsg->cmsg_level == IPPROTO_IP) {
                memcpy(&((struct in_pktinfo *)CMSG_DATA(send_cmsg))->ipi_spec_dst,
                       &((struct in_pktinfo *)CMSG_DATA(cmsg))->ipi_addr,
                       sizeof(struct in_addr));
            } else {
                memcpy(&((struct in6_pktinfo *)CMSG_DATA(send_cmsg))->ipi6_addr,
                       &((struct in6_pktinfo *)CMSG_DATA(cmsg))->ipi6_addr,
                       sizeof(struct in6_addr));
            }
        } else {
            if (mud_packet && (ret == (ssize_t)MUD_PONG_SIZE))
                continue;

            unsigned char tmp[sizeof(packet->data)];

            if (mud_decrypt(mud, NULL, tmp, sizeof(tmp),
                            packet->data, (size_t)ret, 4) == -1)
                continue;

            path = mud_new_path(mud, index, (struct sockaddr *)&addr);

            if (!path)
                return -1;
        }

        path->up = 1;

        int64_t dt = (now-path->recv.time)-(send_time-path->recv.send_time);

        if (path->recv.time && path->recv.send_time && (dt > 0))
            path->rdt = (path->rdt*UINT64_C(7)+dt)/UINT64_C(8);

        path->recv.send_time = send_time;
        path->recv.time = now;

        if (mud_packet && (ret == (ssize_t)MUD_PONG_SIZE)) {
            uint64_t old_send_time = mud_read48(&packet->data[MUD_TIME_SIZE*2]);
            uint64_t dt = mud_read48(&packet->data[MUD_TIME_SIZE*3]);

            path->dt = dt;
            path->sdt = send_time-old_send_time;
            path->rtt = now-old_send_time;
            continue;
        }

        mud_pong_path(mud, path, now);

        if (mud_packet) {
            if (ret == (ssize_t)MUD_KEYX_SIZE)
                mud_recv_keyx(mud, path, now, &packet->data[2*MUD_TIME_SIZE], ret-2*MUD_TIME_SIZE);

            continue;
        }

        if (ret == (ssize_t)MUD_PACKET_MIN_SIZE)
            continue;

        packet->size = ret;
        mud->rx.end = next;
    }

    return 0;
}

int mud_recv (struct mud *mud, void *data, size_t size)
{
    if (mud->rx.start == mud->rx.end) {
        errno = EAGAIN;
        return -1;
    }

    struct packet *packet = &mud->rx.packet[mud->rx.start];

    int ret = mud_decrypt(mud, NULL, data, size,
                          packet->data, packet->size, 4);

    mud->rx.start = MUD_PACKET_NEXT(mud->rx.start);

    if (ret == -1) {
        errno = EINVAL;
        return -1;
    }

    return ret;
}

int mud_push (struct mud *mud)
{
    struct path *path;

    for (path = mud->path; path; path = path->next) {
        uint64_t now = mud_now(mud);

        if ((path->last_time) &&
            (path->send.time > path->last_time) &&
            (path->send.time-path->last_time
                             > MUD_PONG_TIMEOUT+path->rtt+(path->rtt>>1))) {
            if (path->last_count == 4) {
                path->last_time = 0;
                path->last_count = 0;
                path->up = 0;
            } else {
                path->last_time = path->send.time;
                path->last_count++;
            }
        }

        if (path->up && (now-mud->crypto.time >= MUD_KEYX_TIMEOUT)) {
            randombytes_buf(mud->crypto.secret, sizeof(mud->crypto.secret));
            crypto_scalarmult_base(mud->crypto.send.public, mud->crypto.secret);
            memset(mud->crypto.recv.public, 0, sizeof(mud->crypto.recv.public));
            mud_keyx_path(mud, path, now);
            continue;
        }

        if ((path->send.time) &&
            (!path->last_count) &&
            (now > path->send.time) &&
            (now-path->send.time) < mud->send_timeout)
            continue;

        mud_ping_path(mud, path, now);
    }

    while (mud->tx.start != mud->tx.end) {
        uint64_t now = mud_now(mud);

        struct packet *packet = &mud->tx.packet[mud->tx.start];

        struct path *path_min = NULL;
        int64_t limit_min = INT64_MAX;

        for (path = mud->path; path; path = path->next) {
            if (!path->up)
                continue;

            int64_t limit = path->limit;
            uint64_t elapsed = now-path->send.time;

            if (limit > elapsed) {
                limit += path->rtt/2-elapsed;
            } else {
                limit = path->rtt/2;
            }

            if (limit_min > limit) {
                limit_min = limit;
                path_min = path;
            }
        }

        if (!path_min)
            break;

        ssize_t ret = mud_send_path(mud, path_min, now, packet->data, packet->size);

        mud->tx.start = MUD_PACKET_NEXT(mud->tx.start);

        if (ret != packet->size)
            break;

        path_min->limit = limit_min;
    }

    return 0;
}

int mud_send (struct mud *mud, const void *data, size_t size)
{
    if (!size)
        return 0;

    unsigned next = MUD_PACKET_NEXT(mud->tx.end);

    if (mud->tx.start == next) {
        errno = ENOBUFS;
        return -1;
    }

    struct packet *packet = &mud->tx.packet[mud->tx.end];

    int ret = mud_encrypt(mud, mud_now(mud),
                          packet->data, sizeof(packet->data),
                          data, size, 4);

    if (!ret) {
        errno = EMSGSIZE;
        return -1;
    }

    packet->size = ret;
    mud->tx.end = next;

    return size;
}

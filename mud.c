#include "mud.h"

#ifdef __APPLE__
#define __APPLE_USE_RFC_3542
#endif

#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <ifaddrs.h>

#include <sodium.h>

#if defined IP_PKTINFO
#define MUD_PKTINFO IP_PKTINFO
#define MUD_PKTINFO_SRC(X) &((struct in_pktinfo *)(X))->ipi_addr
#define MUD_PKTINFO_DST(X) &((struct in_pktinfo *)(X))->ipi_spec_dst
#define MUD_PKTINFO_SIZE sizeof(struct in_pktinfo)
#elif defined IP_RECVDSTADDR
#define MUD_PKTINFO IP_RECVDSTADDR
#define MUD_PKTINFO_SRC(X) (X)
#define MUD_PKTINFO_DST(X) (X)
#define MUD_PKTINFO_SIZE sizeof(struct in_addr)
#endif

#define MUD_COUNT(X)  (sizeof(X)/sizeof(X[0]))

#define MUD_ONE_MSEC (UINT64_C(1000))
#define MUD_ONE_SEC  (1000*MUD_ONE_MSEC)
#define MUD_ONE_MIN  (60*MUD_ONE_SEC)

#define MUD_TIME_SIZE (6U)
#define MUD_KEY_SIZE  (32U)
#define MUD_MAC_SIZE  (16U)

#define MUD_PACKET_MIN_SIZE  (MUD_TIME_SIZE+MUD_MAC_SIZE)
#define MUD_PACKET_MAX_SIZE  (1500U)
#define MUD_PACKET_MASK      (0x3FFU)
#define MUD_PACKET_COUNT     ((MUD_PACKET_MASK)+1)
#define MUD_PACKET_NEXT(X)   (((X)+1)&(MUD_PACKET_MASK))
#define MUD_PACKET_SIZEOF(X) ((X)+MUD_PACKET_MIN_SIZE)

#define MUD_PONG_SIZE      MUD_PACKET_SIZEOF(MUD_TIME_SIZE*3)
#define MUD_PKEY_SIZE      (crypto_scalarmult_BYTES+1)
#define MUD_KEYX_SIZE      MUD_PACKET_SIZEOF(MUD_TIME_SIZE+2*MUD_PKEY_SIZE)

#define MUD_PONG_TIMEOUT   (100*MUD_ONE_MSEC)
#define MUD_KEYX_TIMEOUT   (60*MUD_ONE_MIN)
#define MUD_SEND_TIMEOUT   (10*MUD_ONE_SEC)
#define MUD_TIME_TOLERANCE (10*MUD_ONE_MIN)

enum mud_msg {
    mud_ping,
    mud_pong,
    mud_keyx,
};

struct ipaddr {
    int family;
    union {
        struct in_addr v4;
        struct in6_addr v6;
    } ip;
};

struct path {
    struct {
        unsigned up : 1;
        unsigned on : 1;
        unsigned active : 1;
    } state;
    struct ipaddr local_addr;
    struct sockaddr_storage addr;
    struct {
        unsigned char data[256];
        size_t size;
    } ctrl;
    unsigned char *tc;
    uint64_t dt;
    uint64_t rdt;
    uint64_t rtt;
    int64_t  sdt;
    uint64_t limit;
    uint64_t recv_time;
    uint64_t recv_send_time;
    uint64_t send_time;
    uint64_t pong_time;
    struct path *next;
};

struct packet {
    size_t size;
    int tc;
    unsigned char data[MUD_PACKET_MAX_SIZE];
};

struct queue {
    struct packet *packet;
    unsigned start;
    unsigned end;
};

struct public {
    unsigned char send[MUD_PKEY_SIZE];
    unsigned char recv[MUD_PKEY_SIZE];
};

struct crypto_opt {
    unsigned char *dst;
    struct {
        const unsigned char *data;
        size_t size;
    } src, ad;
    unsigned char npub[16];
};

struct crypto_key {
    struct {
        unsigned char key[MUD_KEY_SIZE];
        crypto_aead_aes256gcm_state state;
    } encrypt, decrypt;
    int aes;
};

struct crypto {
    uint64_t time;
    unsigned char secret[crypto_scalarmult_SCALARBYTES];
    struct public public;
    struct crypto_key private, last, next, current;
    int use_next;
    int aes;
    int bad_key;
};

struct mud {
    int fd;
    uint64_t send_timeout;
    uint64_t time_tolerance;
    struct queue tx;
    struct queue rx;
    struct path *path;
    struct crypto crypto;
};

static
int mud_encrypt_opt (const struct crypto_key *k, const struct crypto_opt *c)
{
    if (k->aes) {
        return crypto_aead_aes256gcm_encrypt_afternm(
                    c->dst, NULL, c->src.data, c->src.size,
                    c->ad.data, c->ad.size, NULL, c->npub,
                    (const crypto_aead_aes256gcm_state *)&k->encrypt.state);
    } else {
        return crypto_aead_chacha20poly1305_encrypt(
                    c->dst, NULL, c->src.data, c->src.size,
                    c->ad.data, c->ad.size, NULL, c->npub, k->encrypt.key);
    }
}

static
int mud_decrypt_opt (const struct crypto_key *k, const struct crypto_opt *c)
{
    if (k->aes) {
        return crypto_aead_aes256gcm_decrypt_afternm(
                    c->dst, NULL, NULL, c->src.data, c->src.size,
                    c->ad.data, c->ad.size, c->npub,
                    (const crypto_aead_aes256gcm_state *)&k->decrypt.state);
    } else {
        return crypto_aead_chacha20poly1305_decrypt(
                    c->dst, NULL, NULL, c->src.data, c->src.size,
                    c->ad.data, c->ad.size, c->npub, k->decrypt.key);
    }
}

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
    uint64_t now;
#if defined CLOCK_REALTIME
    struct timespec tv;
    clock_gettime(CLOCK_REALTIME, &tv);
    now = tv.tv_sec*MUD_ONE_SEC+tv.tv_nsec/MUD_ONE_MSEC;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    now = tv.tv_sec*MUD_ONE_SEC+tv.tv_usec;
#endif
    return now&((UINT64_C(1)<<48)-1);
}

static
uint64_t mud_dt (uint64_t a, uint64_t b)
{
    return (a >= b) ? a-b : b-a;
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
size_t mud_addrlen (struct sockaddr_storage *addr)
{
    return (addr->ss_family == AF_INET) ? sizeof(struct sockaddr_in)
                                        : sizeof(struct sockaddr_in6);
}

static
int mud_addrinfo (struct sockaddr_storage *addr, const char *host, int port)
{
    struct sockaddr_in sin = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
    };

    if (inet_pton(AF_INET, host, &sin.sin_addr) == 1) {
        memcpy(addr, &sin, sizeof(sin));
        return 0;
    }

    struct sockaddr_in6 sin6 = {
        .sin6_family = AF_INET6,
        .sin6_port = htons(port),
    };

    if (inet_pton(AF_INET6, host, &sin6.sin6_addr) == 1) {
        memcpy(addr, &sin6, sizeof(sin6));
        return 0;
    }

    errno = EINVAL;

    return -1;
}

static
ssize_t mud_send_path (struct mud *mud, struct path *path, uint64_t now,
                       void *data, size_t size, int tc)
{
    if (!size)
        return 0;

    struct iovec iov = {
        .iov_base = data,
        .iov_len = size,
    };

    struct msghdr msg = {
        .msg_name = &path->addr,
        .msg_namelen = mud_addrlen(&path->addr),
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = path->ctrl.data,
        .msg_controllen = path->ctrl.size,
    };

    if (path->tc)
        memcpy(path->tc, &tc, sizeof(tc));

    ssize_t ret = sendmsg(mud->fd, &msg, 0);
    path->send_time = now;

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
int mud_cmp_ipaddr (struct ipaddr *a, struct ipaddr *b)
{
    if (a == b)
        return 0;

    if (a->family != b->family)
        return 1;

    if (a->family == AF_INET)
        return memcmp(&a->ip.v4, &b->ip.v4, sizeof(a->ip.v4));

    if (a->family == AF_INET6)
        return memcmp(&a->ip.v6, &b->ip.v6, sizeof(a->ip.v6));

    return 1;
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
                (memcmp(&_a->sin_addr, &_b->sin_addr,
                        sizeof(_a->sin_addr))));
    }

    if (a->sa_family == AF_INET6) {
        struct sockaddr_in6 *_a = (struct sockaddr_in6 *)a;
        struct sockaddr_in6 *_b = (struct sockaddr_in6 *)b;

        return ((_a->sin6_port != _b->sin6_port) ||
                (memcmp(&_a->sin6_addr, &_b->sin6_addr,
                        sizeof(_a->sin6_addr))));
    }

    return 1;
}

static
void mud_set_path (struct path *path, struct ipaddr *local_addr,
                   struct sockaddr *addr)
{
    struct msghdr msg = {
        .msg_control = path->ctrl.data,
        .msg_controllen = sizeof(path->ctrl.data),
    };

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);

    memset(path->ctrl.data, 0, sizeof(path->ctrl.data));
    memmove(&path->local_addr, local_addr, sizeof(struct ipaddr));

    if (addr->sa_family == AF_INET) {
        memmove(&path->addr, addr, sizeof(struct sockaddr_in));

        cmsg->cmsg_level = IPPROTO_IP;
        cmsg->cmsg_type = MUD_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(MUD_PKTINFO_SIZE);

        memcpy(MUD_PKTINFO_DST(CMSG_DATA(cmsg)),
               &local_addr->ip.v4,
               sizeof(struct in_addr));

        cmsg = CMSG_NXTHDR(&msg, cmsg);

        cmsg->cmsg_level = IPPROTO_IP;
        cmsg->cmsg_type = IP_TOS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));

        path->tc = CMSG_DATA(cmsg);
        path->ctrl.size = CMSG_SPACE(MUD_PKTINFO_SIZE)
                        + CMSG_SPACE(sizeof(int));
    }

    if (addr->sa_family == AF_INET6) {
        memmove(&path->addr, addr, sizeof(struct sockaddr_in6));

        cmsg->cmsg_level = IPPROTO_IPV6;
        cmsg->cmsg_type = IPV6_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));

        memcpy(&((struct in6_pktinfo *)CMSG_DATA(cmsg))->ipi6_addr,
               &local_addr->ip.v6,
               sizeof(struct in6_addr));

        cmsg = CMSG_NXTHDR(&msg, cmsg);

        cmsg->cmsg_level = IPPROTO_IPV6;
        cmsg->cmsg_type = IPV6_TCLASS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));

        path->tc = CMSG_DATA(cmsg);
        path->ctrl.size = CMSG_SPACE(sizeof(struct in6_pktinfo))
                        + CMSG_SPACE(sizeof(int));
    }
}

static
struct path *mud_path (struct mud *mud, struct ipaddr *local_addr,
                       struct sockaddr *addr, int create)
{
    if (local_addr->family != addr->sa_family) {
        errno = EINVAL;
        return NULL;
    }

    struct path *path;

    for (path = mud->path; path; path = path->next) {
        if (mud_cmp_ipaddr(local_addr, &path->local_addr))
            continue;

        if (mud_cmp_addr(addr, (struct sockaddr *)&path->addr))
            continue;

        break;
    }

    if (path || !create)
        return path;

    path = calloc(1, sizeof(struct path));

    if (!path)
        return NULL;

    mud_set_path(path, local_addr, addr);

    path->state.on = 1;

    path->next = mud->path;
    mud->path = path;

    return path;
}

static
int mud_ipaddrinfo (struct ipaddr *ipaddr, const char *name)
{
    if (!name) {
        errno = EINVAL;
        return -1;
    }

    if (inet_pton(AF_INET, name, &ipaddr->ip.v4) == 1) {
        ipaddr->family = AF_INET;
        return 0;
    }

    if (inet_pton(AF_INET6, name, &ipaddr->ip.v6) == 1) {
        ipaddr->family = AF_INET6;
        return 0;
    }

    return -1;
}

int mud_set_on (struct mud *mud, const char *name, int on)
{
    if (!name) {
        errno = EINVAL;
        return -1;
    }

    struct ipaddr local_addr;

    if (mud_ipaddrinfo(&local_addr, name))
        return -1;

    struct path *path = NULL;

    for (path = mud->path; path; path = path->next) {
        if (!path->state.active)
            continue;

        if (mud_cmp_ipaddr(&local_addr, &path->local_addr))
            continue;

        path->state.on = on;
    }

    return 0;
}

int mud_peer (struct mud *mud, const char *name, const char *host, int port)
{
    if (!name || !host || !port) {
        errno = EINVAL;
        return -1;
    }

    struct ipaddr local_addr;

    if (mud_ipaddrinfo(&local_addr, name))
        return -1;

    struct sockaddr_storage addr;

    if (mud_addrinfo(&addr, host, port))
        return -1;

    mud_unmapv4((struct sockaddr *)&addr);

    struct path *path = mud_path(mud, &local_addr,
            (struct sockaddr *)&addr, 1);

    if (!path)
        return -1;

    path->state.active = 1;

    return 0;
}

int mud_get_key (struct mud *mud, unsigned char *key, size_t *size)
{
    if (!key || !size || (*size < MUD_KEY_SIZE)) {
        errno = EINVAL;
        return -1;
    }

    memcpy(key, mud->crypto.private.encrypt.key, MUD_KEY_SIZE);
    *size = MUD_KEY_SIZE;

    return 0;
}

int mud_set_key (struct mud *mud, unsigned char *key, size_t size)
{
    if (!key || (size < MUD_KEY_SIZE)) {
        errno = EINVAL;
        return -1;
    }

    memcpy(mud->crypto.private.encrypt.key, key, MUD_KEY_SIZE);
    memcpy(mud->crypto.private.decrypt.key, key, MUD_KEY_SIZE);

    mud->crypto.current = mud->crypto.private;
    mud->crypto.next = mud->crypto.private;
    mud->crypto.last = mud->crypto.private;

    return 0;
}

int mud_set_send_timeout_msec (struct mud *mud, unsigned msec)
{
    if (!msec) {
        errno = EINVAL;
        return -1;
    }

    mud->send_timeout = msec*MUD_ONE_MSEC;

    return 0;
}

int mud_set_time_tolerance_sec (struct mud *mud, unsigned sec)
{
    if (!sec) {
        errno = EINVAL;
        return -1;
    }

    mud->time_tolerance = sec*MUD_ONE_SEC;

    return 0;
}

static
int mud_setup_socket (int fd, int v4, int v6)
{
    if ((mud_sso_int(fd, SOL_SOCKET, SO_REUSEADDR, 1)) ||
        (v4 && mud_sso_int(fd, IPPROTO_IP, MUD_PKTINFO, 1)) ||
        (v6 && mud_sso_int(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, 1)) ||
        (v6 && mud_sso_int(fd, IPPROTO_IPV6, IPV6_V6ONLY, !v4)) ||
        (mud_set_nonblock(fd)))
        return -1;

//  mud_sso_int(fd, SOL_SOCKET, SO_RCVBUF, 1<<24);
//  mud_sso_int(fd, SOL_SOCKET, SO_SNDBUF, 1<<24);

    return 0;
}

static
int mud_create_socket (int port, int v4, int v6)
{
    struct sockaddr_storage addr;

    if (mud_addrinfo(&addr, v6 ? "::" : "0.0.0.0", port))
        return -1;

    int fd = socket(addr.ss_family, SOCK_DGRAM, IPPROTO_UDP);

    if (fd == -1)
        return -1;

    if (mud_setup_socket(fd, v4, v6) ||
        bind(fd, (struct sockaddr *)&addr, mud_addrlen(&addr))) {
        int err = errno;
        close(fd);
        errno = err;
        return -1;
    }

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

static
void mud_keyx_init (struct mud *mud)
{
    randombytes_buf(mud->crypto.secret, sizeof(mud->crypto.secret));
    crypto_scalarmult_base(mud->crypto.public.send, mud->crypto.secret);
    memset(mud->crypto.public.recv, 0, sizeof(mud->crypto.public.recv));
    mud->crypto.public.send[MUD_PKEY_SIZE-1] = mud->crypto.aes;
}

struct mud *mud_create (int port, int v4, int v6, int aes)
{
    if (sodium_init() == -1)
        return NULL;

    struct mud *mud = calloc(1, sizeof(struct mud));

    if (!mud)
        return NULL;

    mud->fd = mud_create_socket(port, v4, v6);

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

    unsigned char key[MUD_KEY_SIZE];

    randombytes_buf(key, sizeof(key));
    mud_set_key(mud, key, sizeof(key));

    mud->crypto.aes = aes && crypto_aead_aes256gcm_is_available();
    mud_keyx_init(mud);

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
                 const unsigned char *src, size_t src_size)
{
    if (!nonce)
        return 0;

    size_t size = src_size+MUD_PACKET_MIN_SIZE;

    if (size > dst_size)
        return 0;

    struct crypto_opt opt = {
        .dst = dst+MUD_TIME_SIZE,
        .src = { .data = src,
                 .size = src_size },
        .ad  = { .data = dst,
                 .size = MUD_TIME_SIZE },
    };

    mud_write48(opt.npub, nonce);
    memcpy(dst, opt.npub, MUD_TIME_SIZE);

    if (mud->crypto.use_next) {
        mud_encrypt_opt(&mud->crypto.next, &opt);
    } else {
        mud_encrypt_opt(&mud->crypto.current, &opt);
    }

    return size;
}

static
int mud_decrypt (struct mud *mud,
                 unsigned char *dst, size_t dst_size,
                 const unsigned char *src, size_t src_size)
{
    size_t size = src_size-MUD_PACKET_MIN_SIZE;

    if (size > dst_size)
        return 0;

    struct crypto_opt opt = {
        .dst = dst,
        .src = { .data = src+MUD_TIME_SIZE,
                 .size = src_size-MUD_TIME_SIZE },
        .ad  = { .data = src,
                 .size = MUD_TIME_SIZE },
    };

    memcpy(opt.npub, src, MUD_TIME_SIZE);

    if (mud_decrypt_opt(&mud->crypto.current, &opt)) {
        if (!mud_decrypt_opt(&mud->crypto.next, &opt)) {
            mud_keyx_init(mud);
            mud->crypto.last = mud->crypto.current;
            mud->crypto.current = mud->crypto.next;
            mud->crypto.use_next = 0;
        } else {
            if (mud_decrypt_opt(&mud->crypto.last, &opt) &&
                mud_decrypt_opt(&mud->crypto.private, &opt))
                return -1;
        }
    }

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

int mud_peer_is_up (struct mud *mud, const char *name, const char *host, int port)
{
    if (!name || !host || !port)
        return 0;

    struct ipaddr local_addr;

    if (mud_ipaddrinfo(&local_addr, name))
        return 0;

    struct sockaddr_storage addr;

    if (mud_addrinfo(&addr, host, port))
        return 0;

    mud_unmapv4((struct sockaddr *)&addr);

    struct path *path = mud_path(mud, &local_addr,
            (struct sockaddr *)&addr, 0);

    return path->state.on && path->state.up;
}

int mud_is_up (struct mud *mud)
{
    struct path *path;

    int up = 0;

    for (path = mud->path; path; path = path->next) {
        if (path->state.on)
            up += path->state.up;
    }

    return up;
}

static
int mud_localaddr (struct ipaddr *local_addr, struct msghdr *msg, int family)
{
    int cmsg_level = IPPROTO_IP;
    int cmsg_type = MUD_PKTINFO;

    if (family == AF_INET6) {
        cmsg_level = IPPROTO_IPV6;
        cmsg_type = IPV6_PKTINFO;
    }

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg);

    for (; cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
        if ((cmsg->cmsg_level == cmsg_level) &&
            (cmsg->cmsg_type == cmsg_type))
            break;
    }

    if (!cmsg)
        return 1;

    local_addr->family = family;

    if (family == AF_INET) {
        memcpy(&local_addr->ip.v4,
               MUD_PKTINFO_SRC(CMSG_DATA(cmsg)),
               sizeof(struct in_addr));
    } else {
        memcpy(&local_addr->ip.v6,
               &((struct in6_pktinfo *)CMSG_DATA(cmsg))->ipi6_addr,
               sizeof(struct in6_addr));
    }

    return 0;
}

static
void mud_ctrl_path (struct mud *mud, enum mud_msg msg, struct path *path,
                    uint64_t now)
{
    struct {
        unsigned char zero[MUD_TIME_SIZE];
        unsigned char time[MUD_TIME_SIZE];
        unsigned char data[128+MUD_MAC_SIZE];
    } ctrl;

    size_t size = 0;

    memset(ctrl.zero, 0, MUD_TIME_SIZE);
    mud_write48(ctrl.time, now);

    if (msg == mud_pong) {
        mud_write48(&ctrl.data[0], path->recv_send_time);
        mud_write48(&ctrl.data[MUD_TIME_SIZE], path->rdt);
        size = MUD_TIME_SIZE*2;
    }

    if (msg == mud_keyx) {
        memcpy(ctrl.data, &mud->crypto.public, sizeof(mud->crypto.public));
        size = sizeof(mud->crypto.public);
    }

    struct crypto_opt opt = {
        .dst = ctrl.data+size,
        .ad  = { .data = ctrl.zero,
                 .size = size+2*MUD_TIME_SIZE },
    };

    mud_encrypt_opt(&mud->crypto.private, &opt);
    mud_send_path(mud, path, now, &ctrl, size+2*MUD_TIME_SIZE+MUD_MAC_SIZE, 0);
}

static
void mud_recv_keyx (struct mud *mud, struct path *path, uint64_t now,
                    unsigned char *data)
{
    struct crypto_key *key = &mud->crypto.next;

    struct {
        unsigned char secret[crypto_scalarmult_BYTES];
        struct public public;
    } shared_send, shared_recv;

    memcpy(&shared_recv.public, data, sizeof(shared_recv.public));

    int sync_send = memcmp(shared_recv.public.recv, mud->crypto.public.send,
                           sizeof(shared_recv.public.recv));

    int sync_recv = memcmp(mud->crypto.public.recv, shared_recv.public.send,
                           sizeof(mud->crypto.public.recv));

    memcpy(shared_recv.public.recv, mud->crypto.public.send,
           sizeof(shared_recv.public.recv));

    memcpy(mud->crypto.public.recv, shared_recv.public.send,
           sizeof(mud->crypto.public.recv));

    mud->crypto.use_next = !sync_send;

    if (sync_send)
        mud_ctrl_path(mud, mud_keyx, path, now);

    if (crypto_scalarmult(shared_recv.secret, mud->crypto.secret,
                          shared_recv.public.send))
        return;

    memcpy(shared_send.secret, shared_recv.secret,
           sizeof(shared_send.secret));

    memcpy(shared_send.public.send, shared_recv.public.recv,
           sizeof(shared_send.public.send));

    memcpy(shared_send.public.recv, shared_recv.public.send,
           sizeof(shared_send.public.recv));

    crypto_generichash(key->encrypt.key, MUD_KEY_SIZE,
                       (unsigned char *)&shared_send, sizeof(shared_send),
                       mud->crypto.private.encrypt.key, MUD_KEY_SIZE);

    crypto_generichash(key->decrypt.key, MUD_KEY_SIZE,
                       (unsigned char *)&shared_recv, sizeof(shared_recv),
                       mud->crypto.private.encrypt.key, MUD_KEY_SIZE);

    crypto_aead_aes256gcm_beforenm(&key->encrypt.state, key->encrypt.key);
    crypto_aead_aes256gcm_beforenm(&key->decrypt.state, key->decrypt.key);

    key->aes = (shared_recv.public.send[MUD_PKEY_SIZE-1] == 1) &&
               (shared_recv.public.recv[MUD_PKEY_SIZE-1] == 1);

    mud->crypto.time = now;
}

int mud_pull (struct mud *mud)
{
    unsigned char ctrl[256];

    while (1) {
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

        if (ret <= (ssize_t)MUD_PACKET_MIN_SIZE) {
            if (ret <= (ssize_t)0)
                return (int)ret;
            continue;
        }

        uint64_t now = mud_now(mud);
        uint64_t send_time = mud_read48(packet->data);

        int mud_packet = !send_time;

        if (mud_packet) {
            if (ret < (ssize_t)MUD_PACKET_SIZEOF(MUD_TIME_SIZE))
                continue;

            send_time = mud_read48(&packet->data[MUD_TIME_SIZE]);
        }

        if (mud_dt(now, send_time) >= mud->time_tolerance)
            continue;

        if (mud_packet) {
            unsigned char tmp[sizeof(packet->data)];

            struct crypto_opt opt = {
                .dst = tmp,
                .src = { .data = packet->data+ret-MUD_MAC_SIZE,
                         .size = MUD_MAC_SIZE },
                .ad  = { .data = packet->data,
                         .size = ret-MUD_MAC_SIZE },
            };

            if (mud_decrypt_opt(&mud->crypto.private, &opt))
                continue;
        }

        mud_unmapv4((struct sockaddr *)&addr);

        struct ipaddr local_addr;

        if (mud_localaddr(&local_addr, &msg, addr.ss_family))
            continue;

        struct path *path = mud_path(mud, &local_addr,
                (struct sockaddr *)&addr, mud_packet);

        if (!path)
            return -1;

        if (mud_packet)
            path->state.up = 1;

        int64_t dt = (now-path->recv_time)-(send_time-path->recv_send_time);

        if (path->recv_time && path->recv_send_time && (dt > 0))
            path->rdt = (path->rdt*UINT64_C(7)+dt)/UINT64_C(8);

        path->recv_send_time = send_time;
        path->recv_time = now;

        if (mud_packet && (ret == (ssize_t)MUD_PONG_SIZE)) {
            uint64_t st = mud_read48(&packet->data[MUD_TIME_SIZE*2]);
            uint64_t dt = mud_read48(&packet->data[MUD_TIME_SIZE*3]);

            path->dt = dt;
            path->sdt = send_time-st;
            path->rtt = now-st;
            continue;
        }

        if ((!path->pong_time) ||
            (now-path->pong_time >= MUD_PONG_TIMEOUT)) {
            mud_ctrl_path(mud, mud_pong, path, now);
            path->pong_time = now;
        }

        if (mud_packet) {
            if (ret == (ssize_t)MUD_KEYX_SIZE)
                mud_recv_keyx(mud, path, now, &packet->data[MUD_TIME_SIZE*2]);
            continue;
        }

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

    int ret = mud_decrypt(mud, data, size, packet->data, packet->size);

    mud->rx.start = MUD_PACKET_NEXT(mud->rx.start);

    if (ret == -1) {
        mud->crypto.bad_key = 1;
        return 0;
    }

    return ret;
}

int mud_push (struct mud *mud)
{
    struct path *path;

    for (path = mud->path; path; path = path->next) {
        if (!path->state.on)
            continue;

        uint64_t now = mud_now(mud);

        if (path->state.up) {
            if ((!path->recv_time) ||
                (now-path->recv_time >= mud->send_timeout))
                path->state.up = 0;
        }

        if ((path->send_time) &&
            (now-path->send_time < (mud->send_timeout>>1)))
            continue;

        if (!path->state.active) {
            if (mud->crypto.bad_key) {
                mud_ctrl_path(mud, mud_keyx, path, now);
                mud->crypto.bad_key = 0;
            }
            continue;
        }

        if ((!mud->crypto.time) ||
            (now-mud->crypto.time >= MUD_KEYX_TIMEOUT)) {
            mud_ctrl_path(mud, mud_keyx, path, now);
            continue;
        }

        mud_ctrl_path(mud, mud_ping, path, now);
    }

    while (mud->tx.start != mud->tx.end) {
        uint64_t now = mud_now(mud);

        struct packet *packet = &mud->tx.packet[mud->tx.start];

        struct path *path_min = NULL;
        int64_t limit_min = INT64_MAX;

        for (path = mud->path; path; path = path->next) {
            if (!path->state.up || !path->state.on)
                continue;

            int64_t limit = path->limit;
            uint64_t elapsed = now-path->send_time;

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

        ssize_t ret = mud_send_path(mud, path_min, now,
                                    packet->data, packet->size, packet->tc);

        if (ret != packet->size)
            break;

        mud->tx.start = MUD_PACKET_NEXT(mud->tx.start);
        path_min->limit = limit_min;
    }

    return 0;
}

int mud_send (struct mud *mud, const void *data, size_t size, int tc)
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
                          data, size);

    if (!ret) {
        errno = EMSGSIZE;
        return -1;
    }

    packet->size = ret;
    packet->tc = tc;

    mud->tx.end = next;

    return size;
}

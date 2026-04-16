#if defined __APPLE__
#define __APPLE_USE_RFC_3542
#endif

#if defined __linux__ && !defined _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "mud.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/time.h>

#include <arpa/inet.h>
#include <net/if.h>

#include "charm/src/charm.h"
#include "aegis256/aegis256.h"

#if !defined MSG_CONFIRM
#define MSG_CONFIRM 0
#endif

#if defined __linux__
#define MUD_V4V6 1
#else
#define MUD_V4V6 0
#endif

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

#if defined IP_MTU_DISCOVER
#define MUD_DFRAG IP_MTU_DISCOVER
#define MUD_DFRAG_OPT IP_PMTUDISC_PROBE
#elif defined IP_DONTFRAG
#define MUD_DFRAG IP_DONTFRAG
#define MUD_DFRAG_OPT 1
#endif

#define MUD_ONE_MSEC (UINT64_C(1000))
#define MUD_ONE_SEC  (1000 * MUD_ONE_MSEC)
#define MUD_ONE_MIN  (60 * MUD_ONE_SEC)

#define MUD_MSG_SENT_MAX (5)
#define MUD_KEEPALIVE    (5 * MUD_ONE_SEC)

#define MUD_CTRL_SIZE (CMSG_SPACE(MUD_PKTINFO_SIZE) + \
                       CMSG_SPACE(sizeof(struct in6_pktinfo)))

struct mud_crypto_key {
    struct mud_key aegis;
    struct mud_key charm;
};

struct mud_addr {
    union {
        unsigned char v6[16];
        struct {
            unsigned char zero[10];
            unsigned char ff[2];
            unsigned char v4[4];
        };
    };
    unsigned char port[2];
};

struct mud_u16 {
    unsigned char b[2];
};

struct mud_u32 {
    unsigned char b[4];
};

struct mud_pkt_id {
    struct mud_id id;
    struct mud_u32 count;
};

struct mud_u64 {
    unsigned char b[8];
};

union mud_nonce {
    struct {
        struct mud_u32 time;
        struct mud_pkt_id id;
    };
    unsigned char b[32];
};

struct mud_mac {
    unsigned char b[10];
};

struct mud_msg {
    struct {
        struct mud_u64 echo;
        struct mud_u64 peer;
    } now;
    unsigned char aes;
    struct {
        struct mud_u64 bytes;
        struct mud_u64 total;
    } tx, rx, fw;
    struct mud_u64 max_rate;
    struct mud_u64 beat;
    struct mud_u16 mtu;
    unsigned char pref;
    unsigned char loss;
    unsigned char loss_limit;
    struct mud_addr addr;
};

struct mud_hdr {
    struct mud_pkt_id id;
    struct mud_mac mac;
};

struct mud {
    int fd;
    int aes;
    struct mud_path *paths;
    unsigned pref;
    unsigned capacity;
    struct mud_crypto_key key;
    uint64_t last_recv_time;
    uint64_t mtu;
    struct mud_errors err;
    uint64_t rate;
    uint64_t time;
    uint32_t count;
    uint32_t random;
    struct mud_id id;
};

static inline uint64_t
mud_le64(uint64_t x)
{
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    return __builtin_bswap64(x);
#else
    return x;
#endif
}

static inline struct mud_u16
mud_to_u16(uint64_t v)
{
    struct mud_u16 u;
    v = mud_le64(v);
    memcpy(u.b, &v, sizeof(u));
    return u;
}

static inline uint64_t
mud_from_u16(struct mud_u16 u)
{
    uint64_t v = 0;
    memcpy(&v, u.b, sizeof(u));
    return mud_le64(v);
}

static inline struct mud_u32
mud_to_u32(uint64_t v)
{
    struct mud_u32 u;
    v = mud_le64(v);
    memcpy(u.b, &v, sizeof(u));
    return u;
}

static inline uint64_t
mud_from_u32(struct mud_u32 u)
{
    uint64_t v = 0;
    memcpy(&v, u.b, sizeof(u));
    return mud_le64(v);
}

static inline struct mud_u64
mud_to_u64(uint64_t v)
{
    struct mud_u64 u;
    v = mud_le64(v);
    memcpy(u.b, &v, sizeof(u));
    return u;
}

static inline uint64_t
mud_from_u64(struct mud_u64 u)
{
    uint64_t v;
    memcpy(&v, u.b, sizeof(u));
    return mud_le64(v);
}

static inline uint64_t
mud_time(void)
{
#if defined CLOCK_REALTIME
    struct timespec tv;
    clock_gettime(CLOCK_REALTIME, &tv);
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
#endif
    return (uint64_t)tv.tv_sec;
}

static inline uint64_t
mud_now(void)
{
#if defined CLOCK_MONOTONIC
    struct timespec tv;
    clock_gettime(CLOCK_MONOTONIC, &tv);
    return (uint64_t)tv.tv_sec * MUD_ONE_SEC
         + (uint64_t)tv.tv_nsec / MUD_ONE_MSEC;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * MUD_ONE_SEC
         + (uint64_t)tv.tv_usec;
#endif
}

enum mud_pkt_flag {
    MUD_PKT_MSG  = 0,
    MUD_PKT_DATA = 1,
};

static inline union mud_nonce
mud_nonce_encrypt(struct mud *mud, enum mud_pkt_flag flag)
{
    if (flag == MUD_PKT_MSG) {
        mud->time = mud_time();
    }
    uint64_t time = mud->time >> 3;
    struct mud_id id = mud->id;

    id.b[0] &= ~7;
    id.b[0] |= ((time & 3) << 1) | flag;

    return (union mud_nonce){
        .time = mud_to_u32(time),
        .id = {
            .id = id,
            .count = mud_to_u32(mud->count),
        },
    };
}

static inline int
mud_nonce_decrypt(struct mud *mud, struct mud_pkt_id id, union mud_nonce *nonce)
{
    if ((id.id.b[0] & 1) == MUD_PKT_MSG) {
        mud->time = mud_time();
    }
    uint64_t time = mud->time >> 3;
    int diff = (((id.id.b[0] >> 1) - time + 1) & 3) - 1;

    if (diff == 2)
        return -1;

    *nonce = (union mud_nonce){
        .time = mud_to_u32(time + diff),
        .id = id,
    };
    return 0;
}

static inline void
mud_derive_key(struct mud_crypto_key *dst, const struct mud_key *src)
{
    uint32_t st[12];
    unsigned char aegis[] = "MUD-AEGIS";
    unsigned char charm[] = "MUD-CHARM";

    uc_state_init(st, src->b, NULL);
    uc_hash(st, dst->aegis.b, aegis, sizeof(aegis));
    uc_memzero(st, sizeof(st));

    uc_state_init(st, src->b, NULL);
    uc_hash(st, dst->charm.b, charm, sizeof(charm));
    uc_memzero(st, sizeof(st));
}

static void
mud_encrypt(struct mud *mud, union mud_nonce nonce,
            struct mud_mac *mac, void *data, size_t size)
{
    _Alignas(16) union {
        unsigned char raw[16];
        struct {
            struct mud_mac mac;
            uint32_t random;
        };
    } tag;

    if (mud->aes && (nonce.id.id.b[0] & 1) == MUD_PKT_DATA) {
        aegis256_encrypt(data, data, size, NULL, 0,
                         nonce.b, mud->key.aegis.b, tag.raw);
    } else {
        uint32_t st[12];
        uc_state_init(st, mud->key.charm.b, nonce.b);
        uc_encrypt(st, data, size, tag.raw);
        uc_memzero(st, sizeof(st));
    }
    mud->random ^= tag.random;
    *mac = tag.mac;
}

static int
mud_decrypt(struct mud *mud, union mud_nonce nonce,
            struct mud_mac *mac, void *data, size_t size)
{
    int ret;

    if (mud->aes && (nonce.id.id.b[0] & 1) == MUD_PKT_DATA) {
        ret = aegis256_decrypt(data, data, size, NULL, 0,
                               nonce.b, mud->key.aegis.b, mac->b, sizeof(*mac));
    } else {
        uint32_t st[12];
        uc_state_init(st, mud->key.charm.b, nonce.b);
        ret = uc_decrypt(st, data, size, mac->b, sizeof(*mac));
        uc_memzero(st, sizeof(st));
    }
    return ret;
}

static inline uint64_t
mud_abs_diff(uint64_t a, uint64_t b)
{
    return (a >= b) ? a - b : b - a;
}

static inline int
mud_timeout(uint64_t now, uint64_t last, uint64_t timeout)
{
    return (!last) || ((now - last) >= timeout);
}

static inline void
mud_unmapv4(union mud_sockaddr *addr)
{
    if (addr->sa.sa_family != AF_INET6)
        return;

    if (!IN6_IS_ADDR_V4MAPPED(&addr->sin6.sin6_addr))
        return;

    struct sockaddr_in sin = {
        .sin_family = AF_INET,
        .sin_port = addr->sin6.sin6_port,
    };
    memcpy(&sin.sin_addr.s_addr,
           &addr->sin6.sin6_addr.s6_addr[12],
           sizeof(sin.sin_addr.s_addr));

    addr->sin = sin;
}

static struct mud_path *
mud_select_path(struct mud *mud)
{
    uint64_t k = (mud->random * mud->rate) >> 32;

    for (unsigned i = 0; i < mud->capacity; i++) {
        struct mud_path *path = &mud->paths[i];

        if (path->status != MUD_RUNNING)
            continue;

        if (k < path->tx.rate)
            return path;

        k -= path->tx.rate;
    }
    return NULL;
}

static ssize_t
mud_send_path(struct mud *mud, struct mud_path *path, uint64_t now,
              struct mud_hdr hdr, void *data, size_t size, int flags)
{
    if (!size || !path)
        return 0;

    struct msghdr msg = {
        .msg_iov = (struct iovec[]){
            { .iov_base = &hdr, .iov_len = sizeof(hdr) },
            { .iov_base = data, .iov_len = size        },
        },
        .msg_iovlen = 2,
        .msg_control = (unsigned char[MUD_CTRL_SIZE]){0},
    };
    if (path->conf.remote.sa.sa_family == AF_INET) {
        msg.msg_name = &path->conf.remote.sin;
        msg.msg_namelen = sizeof(struct sockaddr_in);
        msg.msg_controllen = CMSG_SPACE(MUD_PKTINFO_SIZE);

        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = IPPROTO_IP;
        cmsg->cmsg_type = MUD_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(MUD_PKTINFO_SIZE);
        memcpy(MUD_PKTINFO_DST(CMSG_DATA(cmsg)),
               &path->conf.local.sin.sin_addr,
               sizeof(struct in_addr));
    } else if (path->conf.remote.sa.sa_family == AF_INET6) {
        msg.msg_name = &path->conf.remote.sin6;
        msg.msg_namelen = sizeof(struct sockaddr_in6);
        msg.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));

        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = IPPROTO_IPV6;
        cmsg->cmsg_type = IPV6_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
        memcpy(&((struct in6_pktinfo *)CMSG_DATA(cmsg))->ipi6_addr,
               &path->conf.local.sin6.sin6_addr,
               sizeof(struct in6_addr));
    } else {
        errno = EAFNOSUPPORT;
        return -1;
    }
    ssize_t ret = sendmsg(mud->fd, &msg, flags);

    if (ret == (ssize_t)-1)
        return -1;

    const size_t bytes = sizeof(hdr) + size;

    path->tx.total++;
    path->tx.bytes += bytes;
    path->tx.time = now;
    mud->count++;

    return (ssize_t)size;
}

static int
mud_sso_int(int fd, int level, int optname, int opt)
{
    return setsockopt(fd, level, optname, &opt, sizeof(opt));
}

static inline int
mud_cmp_addr(union mud_sockaddr *a, union mud_sockaddr *b)
{
    if (a->sa.sa_family != b->sa.sa_family)
        return 1;

    if (a->sa.sa_family == AF_INET)
        return memcmp(&a->sin.sin_addr, &b->sin.sin_addr,
                      sizeof(a->sin.sin_addr));

    if (a->sa.sa_family == AF_INET6)
        return memcmp(&a->sin6.sin6_addr, &b->sin6.sin6_addr,
                      sizeof(a->sin6.sin6_addr));
    return 1;
}

static inline int
mud_cmp_port(union mud_sockaddr *a, union mud_sockaddr *b)
{
    if (a->sa.sa_family != b->sa.sa_family)
        return 1;

    if (a->sa.sa_family == AF_INET)
        return memcmp(&a->sin.sin_port, &b->sin.sin_port,
                      sizeof(a->sin.sin_port));

    if (a->sa.sa_family == AF_INET6)
        return memcmp(&a->sin6.sin6_port, &b->sin6.sin6_port,
                      sizeof(a->sin6.sin6_port));
    return 1;
}

int
mud_get_paths(struct mud *mud, struct mud_paths *paths,
              union mud_sockaddr *local, union mud_sockaddr *remote)
{
    if (!paths) {
        errno = EINVAL;
        return -1;
    }
    unsigned count = 0;

    for (unsigned i = 0; i < mud->capacity; i++) {
        struct mud_path *path = &mud->paths[i];

        if (local && local->sa.sa_family &&
            mud_cmp_addr(local, &path->conf.local))
            continue;

        if (remote && remote->sa.sa_family &&
            (mud_cmp_addr(remote, &path->conf.remote) ||
             mud_cmp_port(remote, &path->conf.remote)))
            continue;

        if (path->conf.state != MUD_EMPTY)
            paths->path[count++] = *path;
    }
    paths->count = count;
    return 0;
}

static struct mud_path *
mud_get_path(struct mud *mud,
             union mud_sockaddr *local,
             union mud_sockaddr *remote,
             enum mud_state state)
{
    if (local->sa.sa_family != remote->sa.sa_family) {
        errno = EINVAL;
        return NULL;
    }
    for (unsigned i = 0; i < mud->capacity; i++) {
        struct mud_path *path = &mud->paths[i];

        if (path->conf.state == MUD_EMPTY)
            continue;

        if (mud_cmp_addr(local, &path->conf.local)   ||
            mud_cmp_addr(remote, &path->conf.remote) ||
            mud_cmp_port(remote, &path->conf.remote))
            continue;

        return path;
    }
    if (state <= MUD_DOWN) {
        errno = 0;
        return NULL;
    }
    struct mud_path *path = NULL;

    for (unsigned i = 0; i < mud->capacity; i++) {
        if (mud->paths[i].conf.state == MUD_EMPTY) {
            path = &mud->paths[i];
            break;
        }
    }
    if (!path) {
        if (mud->capacity == MUD_PATH_MAX) {
            errno = ENOMEM;
            return NULL;
        }
        struct mud_path *paths = realloc(mud->paths,
                (mud->capacity + 1) * sizeof(struct mud_path));

        if (!paths)
            return NULL;

        path = &paths[mud->capacity];

        mud->capacity++;
        mud->paths = paths;
    }
    memset(path, 0, sizeof(struct mud_path));

    path->conf.local      = *local;
    path->conf.remote     = *remote;
    path->conf.state      = state;
    path->conf.beat       = 100 * MUD_ONE_MSEC;
    path->conf.loss_limit = 255;
    path->status          = MUD_PROBING;
    path->idle            = mud_now();

    return path;
}

int
mud_get_errors(struct mud *mud, struct mud_errors *err)
{
    if (!err) {
        errno = EINVAL;
        return -1;
    }
    memcpy(err, &mud->err, sizeof(struct mud_errors));
    return 0;
}

uint64_t
mud_get_mtu(struct mud *mud)
{
    if (!mud->mtu)
        return 0;

    return mud->mtu - sizeof(struct mud_hdr);
}

static int
mud_setup_socket(int fd, int v4, int v6)
{
    if ((mud_sso_int(fd, SOL_SOCKET, SO_REUSEADDR, 1)) ||
        (v4 && mud_sso_int(fd, IPPROTO_IP, MUD_PKTINFO, 1)) ||
        (v6 && mud_sso_int(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, 1)) ||
        (v6 && mud_sso_int(fd, IPPROTO_IPV6, IPV6_V6ONLY, !v4)))
        return -1;

#if defined MUD_DFRAG
    if (v4)
        mud_sso_int(fd, IPPROTO_IP, MUD_DFRAG, MUD_DFRAG_OPT);
#endif
    return 0;
}

struct mud *
mud_create(union mud_sockaddr addr, struct mud_key *key)
{
    if (!key)
        return NULL;

    int v4, v6;
    socklen_t addrlen = 0;

    switch (addr.sa.sa_family) {
    case AF_INET:
        addrlen = sizeof(struct sockaddr_in);
        v4 = 1;
        v6 = 0;
        break;
    case AF_INET6:
        addrlen = sizeof(struct sockaddr_in6);
        v4 = MUD_V4V6;
        v6 = 1;
        break;
    default:
        return NULL;
    }
    struct mud *mud = calloc(1, sizeof(struct mud));

    if (!mud)
        return NULL;

    mud->fd = socket(addr.sa.sa_family, SOCK_DGRAM, IPPROTO_UDP);

    if ((mud->fd == -1) ||
        (mud_setup_socket(mud->fd, v4, v6)) ||
        (bind(mud->fd, &addr.sa, addrlen)) ||
        (getsockname(mud->fd, &addr.sa, &addrlen))) {
        mud_delete(mud);
        return NULL;
    }
    mud_derive_key(&mud->key, key);
    uc_memzero(key, sizeof(*key));

    uc_randombytes_buf(mud->id.b, sizeof(mud->id));
    mud->id.b[0] |= 1;

    return mud;
}

int
mud_get_fd(struct mud *mud)
{
    if (!mud)
        return -1;

    return mud->fd;
}

void
mud_delete(struct mud *mud)
{
    if (!mud)
        return;

    if (mud->paths)
        free(mud->paths);

    if (mud->fd >= 0)
        close(mud->fd);

    free(mud);
}

static int
mud_localaddr(union mud_sockaddr *addr, struct msghdr *msg)
{
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg);

    for (; cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
        if ((cmsg->cmsg_level == IPPROTO_IP) &&
            (cmsg->cmsg_type == MUD_PKTINFO)) {
            addr->sa.sa_family = AF_INET;
            memcpy(&addr->sin.sin_addr,
                   MUD_PKTINFO_SRC(CMSG_DATA(cmsg)),
                   sizeof(struct in_addr));
            return 0;
        }
        if ((cmsg->cmsg_level == IPPROTO_IPV6) &&
            (cmsg->cmsg_type == IPV6_PKTINFO)) {
            addr->sa.sa_family = AF_INET6;
            memcpy(&addr->sin6.sin6_addr,
                   &((struct in6_pktinfo *)CMSG_DATA(cmsg))->ipi6_addr,
                   sizeof(struct in6_addr));
            mud_unmapv4(addr);
            return 0;
        }
    }
    return 1;
}

static int
mud_addr_is_v6(struct mud_addr *addr)
{
    static const unsigned char v4mapped[] = {
        [10] = 255,
        [11] = 255,
    };
    return memcmp(addr->v6, v4mapped, sizeof(v4mapped));
}

static int
mud_addr_from_sock(struct mud_addr *addr, union mud_sockaddr *sock)
{
    if (sock->sa.sa_family == AF_INET) {
        memset(addr->zero, 0, sizeof(addr->zero));
        memset(addr->ff, 0xFF, sizeof(addr->ff));
        memcpy(addr->v4, &sock->sin.sin_addr, 4);
        memcpy(addr->port, &sock->sin.sin_port, 2);
    } else if (sock->sa.sa_family == AF_INET6) {
        memcpy(addr->v6, &sock->sin6.sin6_addr, 16);
        memcpy(addr->port, &sock->sin6.sin6_port, 2);
    } else {
        errno = EAFNOSUPPORT;
        return -1;
    }
    return 0;
}

static void
mud_sock_from_addr(union mud_sockaddr *sock, struct mud_addr *addr)
{
    if (mud_addr_is_v6(addr)) {
        sock->sin6.sin6_family = AF_INET6;
        memcpy(&sock->sin6.sin6_addr, addr->v6, 16);
        memcpy(&sock->sin6.sin6_port, addr->port, 2);
    } else {
        sock->sin.sin_family = AF_INET;
        memcpy(&sock->sin.sin_addr, addr->v4, 4);
        memcpy(&sock->sin.sin_port, addr->port, 2);
    }
}

static ssize_t
mud_send_msg(struct mud *mud, struct mud_path *path, uint64_t now,
             uint64_t echo, uint64_t fw_bytes, uint64_t fw_total,
             size_t size)
{
    union mud_nonce nonce = mud_nonce_encrypt(mud, MUD_PKT_MSG);
    union {
        unsigned char data[1500];
        struct {
            struct mud_hdr hdr;
            struct mud_msg msg;
        } pkt;
    } u = {
        .pkt = {
            .hdr = {
                .id = nonce.id,
            },
            .msg = {
                .now = {
                    .echo = mud_to_u64(echo),
                    .peer = mud_to_u64(now),
                },
                .aes = aegis256_is_available(),
                .tx = {
                    .bytes = mud_to_u64(path->tx.bytes),
                    .total = mud_to_u64(path->tx.total),
                },
                .rx = {
                    .bytes = mud_to_u64(path->rx.bytes),
                    .total = mud_to_u64(path->rx.total),
                },
                .fw = {
                    .bytes = mud_to_u64(fw_bytes),
                    .total = mud_to_u64(fw_total),
                },
                .max_rate   = mud_to_u64(path->conf.rx_max_rate),
                .beat       = mud_to_u64(path->conf.beat),
                .pref       = path->conf.pref,
                .loss       = path->tx.loss,
                .loss_limit = path->conf.loss_limit,
            },
        },
    };
    if (size < sizeof(u.pkt))
        size = sizeof(u.pkt);

    if (mud_addr_from_sock(&u.pkt.msg.addr, &path->conf.remote))
        return -1;

    if (!path->mtu.probe)
        u.pkt.msg.mtu = mud_to_u16(path->mtu.last);

    size_t msg_size = size - sizeof(u.pkt.hdr);
    mud_encrypt(mud, nonce, &u.pkt.hdr.mac, &u.pkt.msg, msg_size);

    return mud_send_path(mud, path, now, u.pkt.hdr,
                         &u.pkt.msg, msg_size,
                         echo ? MSG_CONFIRM : 0);
}

static void
mud_update_rl(struct mud *mud, struct mud_path *path, uint64_t now,
              uint64_t tx_dt, uint64_t tx_bytes, uint64_t tx_pkt,
              uint64_t rx_dt, uint64_t rx_bytes, uint64_t rx_pkt)
{
    if (rx_dt && rx_dt > tx_dt + (tx_dt >> 3)) {
        path->tx.rate = (7 * rx_bytes * MUD_ONE_SEC) / (8 * rx_dt);
    } else {
        uint64_t tx_acc = path->msg.tx.acc + tx_pkt;
        uint64_t rx_acc = path->msg.rx.acc + rx_pkt;

        if (tx_acc > 1000) {
            if (tx_acc >= rx_acc)
                path->tx.loss = (tx_acc - rx_acc) * 255U / tx_acc;
            path->msg.tx.acc = tx_acc - (tx_acc >> 4);
            path->msg.rx.acc = rx_acc - (rx_acc >> 4);
        } else {
            path->msg.tx.acc = tx_acc;
            path->msg.rx.acc = rx_acc;
        }
        path->tx.rate += path->tx.rate / 10;
    }
    if (path->tx.rate > path->conf.tx_max_rate)
        path->tx.rate = path->conf.tx_max_rate;
}

static void
mud_reset_mtu(struct mud_path *path)
{
    if (path->conf.local.sa.sa_family == AF_INET6) {
        path->mtu.min = 1280U + sizeof(struct mud_hdr);
    } else {
        path->mtu.min = 576U + sizeof(struct mud_hdr);
    }
    path->mtu.max = 1450U + sizeof(struct mud_hdr);
    path->mtu.probe = path->mtu.max;
}

static void
mud_update_mtu(struct mud_path *path, uint64_t size)
{
    if (!path->mtu.probe) {
        if (!path->mtu.last) {
            mud_reset_mtu(path);
        }
        return;
    }
    if (size) {
        if (path->mtu.min > size || path->mtu.max < size)
            return;
        path->mtu.min = size + 1;
        path->mtu.last = size;
    } else {
        path->mtu.max = path->mtu.probe - 1;
    }

    uint64_t probe = (path->mtu.min + path->mtu.max) >> 1;

    if (path->mtu.min > path->mtu.max) {
        path->mtu.probe = 0;
    } else {
        path->mtu.probe = probe;
    }
}

static void
mud_update_stat(struct mud_stat *stat, const uint64_t val)
{
    if (stat->setup) {
        const uint64_t var = mud_abs_diff(stat->val, val);
        stat->var = ((stat->var << 1) + stat->var + var) >> 2;
        stat->val = ((stat->val << 3) - stat->val + val) >> 3;
    } else {
        stat->setup = 1;
        stat->var = val >> 1;
        stat->val = val;
    }
}

static void
mud_recv_msg(struct mud *mud, struct mud_path *path,
             unsigned char *data, size_t size)
{
    struct mud_msg *msg = (struct mud_msg *)data;
    const uint64_t now = mud->last_recv_time;
    const uint64_t echo_now = mud_from_u64(msg->now.echo);
    const uint64_t peer_now = mud_from_u64(msg->now.peer);

    mud_sock_from_addr(&path->remote, &msg->addr);

    if (echo_now) {
        mud_update_stat(&path->rtt, now - echo_now);

        const uint64_t tx_bytes = mud_from_u64(msg->fw.bytes);
        const uint64_t tx_total = mud_from_u64(msg->fw.total);
        const uint64_t rx_bytes = mud_from_u64(msg->rx.bytes);
        const uint64_t rx_total = mud_from_u64(msg->rx.total);

        if ((peer_now > path->msg.tx.time) && (tx_bytes > path->msg.tx.bytes) &&
            (now > path->msg.rx.time) && (rx_bytes > path->msg.rx.bytes)) {
            if (path->msg.set && path->status > MUD_PROBING) {
                mud_update_rl(mud, path, now,
                        peer_now   - path->msg.tx.time,
                        tx_bytes   - path->msg.tx.bytes,
                        tx_total   - path->msg.tx.total,
                        now        - path->msg.rx.time,
                        rx_bytes   - path->msg.rx.bytes,
                        rx_total   - path->msg.rx.total);
            }
            path->msg.tx.time  = peer_now;
            path->msg.rx.time  = now;
            path->msg.tx.bytes = tx_bytes;
            path->msg.rx.bytes = rx_bytes;
            path->msg.tx.total = tx_total;
            path->msg.rx.total = rx_total;
            path->msg.set = 1;
        }
        path->rx.loss = (uint64_t)msg->loss;
        path->msg.sent = 0;

        if (path->conf.state == MUD_PASSIVE)
            return;

        mud_update_mtu(path, size);

        if (path->mtu.last && path->mtu.last == mud_from_u16(msg->mtu))
            path->mtu.ok = path->mtu.last;
    } else {
        path->conf.beat = mud_from_u64(msg->beat);

        const uint64_t max_rate = mud_from_u64(msg->max_rate);

        if (path->conf.tx_max_rate != max_rate)
            path->tx.rate = max_rate;

        path->conf.tx_max_rate = max_rate;
        path->conf.pref        = msg->pref;
        path->conf.loss_limit  = msg->loss_limit;

        path->mtu.last = mud_from_u16(msg->mtu);
        path->mtu.ok = path->mtu.last;

        path->msg.sent++;
        path->msg.time = now;
    }
    mud->aes = msg->aes && aegis256_is_available();

    mud_send_msg(mud, path, now, peer_now,
                 mud_from_u64(msg->tx.bytes),
                 mud_from_u64(msg->tx.total),
                 size);
}

ssize_t
mud_recv(struct mud *mud, void *data, size_t size)
{
    union mud_sockaddr remote;
    struct mud_hdr hdr;

    struct msghdr msg = {
        .msg_name = &remote,
        .msg_namelen = sizeof(remote),
        .msg_iov = (struct iovec[]){
            { .iov_base = &hdr, .iov_len = sizeof(hdr) },
            { .iov_base = data, .iov_len = size        },
        },
        .msg_iovlen = 2,
        .msg_control = (unsigned char[MUD_CTRL_SIZE]){0},
        .msg_controllen = MUD_CTRL_SIZE,
    };
    const ssize_t ret = recvmsg(mud->fd, &msg, 0);

    if (ret == (ssize_t)-1)
        return -1;

    if ((msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) ||
        (ret <= (ssize_t)sizeof(hdr)))
        return 0;

    const uint64_t now = mud_now();
    const size_t bytes = ret;
    size = bytes - sizeof(hdr);

    union mud_sockaddr local;

    if (mud_localaddr(&local, &msg))
        return 0;

    mud_unmapv4(&remote);

    struct mud_path *path = mud_get_path(mud, &local, &remote, MUD_PASSIVE);

    if (!path || path->conf.state <= MUD_DOWN)
        return 0;

    union mud_nonce nonce;

    if (mud_nonce_decrypt(mud, hdr.id, &nonce)) {
        mud->err.clocksync.addr = remote;
        mud->err.clocksync.time = mud_time();
        mud->err.clocksync.count++;
        return 0;
    }
    if (mud_decrypt(mud, nonce, &hdr.mac, data, size)) {
        mud->err.decrypt.addr = remote;
        mud->err.decrypt.time = mud_time();
        mud->err.decrypt.count++;
        return 0;
    }
    path->rx.total++;
    path->rx.time = now;
    path->rx.bytes += bytes;
    mud->last_recv_time = now;

    if (!(hdr.id.id.b[0] & 1)) {
        mud_recv_msg(mud, path, data, bytes);
        return 0;
    }
    path->idle = now;
    return (ssize_t)size;
}

static int
mud_path_update(struct mud *mud, struct mud_path *path, uint64_t now)
{
    switch (path->conf.state) {
    case MUD_DOWN:
        path->status = MUD_DELETING;
        if (mud_timeout(now, path->rx.time, 2 * MUD_ONE_MIN))
            memset(path, 0, sizeof(struct mud_path));
        return 0;
    case MUD_PASSIVE:
        if (mud_timeout(now, mud->last_recv_time, 2 * MUD_ONE_MIN)) {
            memset(path, 0, sizeof(struct mud_path));
            return 0;
        }
    case MUD_UP: break;
    default:     return 0;
    }
    if (path->msg.sent >= MUD_MSG_SENT_MAX) {
        if (path->mtu.probe) {
            mud_update_mtu(path, 0);
            path->msg.sent = 0;
        } else {
            path->msg.sent = MUD_MSG_SENT_MAX;
            path->status = MUD_DEGRADED;
            return 0;
        }
    }
    if (!path->mtu.ok) {
        path->status = MUD_PROBING;
        return 0;
    }
    if (path->tx.loss > path->conf.loss_limit ||
        path->rx.loss > path->conf.loss_limit) {
        path->status = MUD_LOSSY;
        return 0;
    }
    if (path->conf.state == MUD_PASSIVE &&
        mud_timeout(mud->last_recv_time, path->rx.time,
                    MUD_MSG_SENT_MAX * path->conf.beat)) {
        path->status = MUD_WAITING;
        return 0;
    }
    if (path->conf.pref > mud->pref) {
        path->status = MUD_READY;
    } else if (path->status != MUD_RUNNING) {
        path->status = MUD_RUNNING;
        path->idle = now;
    }
    return 1;
}

static uint64_t
mud_path_track(struct mud *mud, struct mud_path *path, uint64_t now)
{
    if (path->conf.state != MUD_UP)
        return now;

    uint64_t timeout = path->conf.beat;

    switch (path->status) {
        case MUD_RUNNING:
            if (mud_timeout(now, path->idle, MUD_ONE_SEC))
                timeout = MUD_KEEPALIVE;
            break;
        case MUD_DEGRADED:
        case MUD_LOSSY:
        case MUD_PROBING:
            break;
        default:
            return now;
    }
    if (mud_timeout(now, path->msg.time, timeout)) {
        path->msg.sent++;
        path->msg.time = now;
        mud_send_msg(mud, path, now, 0, 0, 0, path->mtu.probe);
        now = mud_now();
    }
    return now;
}

int
mud_update(struct mud *mud)
{
    unsigned count = 0;
    unsigned pref = 255;
    unsigned next_pref = 255;
    uint64_t rate = 0;
    uint64_t mtu = 0;
    uint64_t now = mud_now();

    for (unsigned i = 0; i < mud->capacity; i++) {
        struct mud_path *path = &mud->paths[i];

        if (mud_path_update(mud, path, now)) {
            if (next_pref > path->conf.pref && path->conf.pref > mud->pref)
                next_pref = path->conf.pref;
            if (pref > path->conf.pref)
                pref = path->conf.pref;
            if (path->status == MUD_RUNNING)
                rate += path->tx.rate;
        }
        if (path->mtu.ok) {
            if (!mtu || mtu > path->mtu.ok)
                mtu = path->mtu.ok;
        }
        now = mud_path_track(mud, path, now);
        count++;
    }
    if (rate) {
        mud->pref = pref;
    } else {
        mud->pref = next_pref;

        for (unsigned i = 0; i < mud->capacity; i++) {
            struct mud_path *path = &mud->paths[i];

            if (!mud_path_update(mud, path, now))
                continue;

            if (path->status == MUD_RUNNING)
                rate += path->tx.rate;
        }
    }
    mud->rate = rate;
    mud->mtu = mtu;

    if (!count)
        return -1;

    return 0;
}

int
mud_set_path(struct mud *mud, struct mud_path_conf *conf)
{
    if (conf->state < MUD_EMPTY || conf->state >= MUD_LAST) {
        errno = EINVAL;
        return -1;
    }
    struct mud_path *path = mud_get_path(mud, &conf->local,
                                              &conf->remote,
                                              conf->state);
    if (!path)
        return -1;

    struct mud_path_conf c = path->conf;

    if (conf->state)       c.state       = conf->state;
    if (conf->pref)        c.pref        = conf->pref >> 1;
    if (conf->beat)        c.beat        = conf->beat * MUD_ONE_MSEC;
    if (conf->loss_limit)  c.loss_limit  = conf->loss_limit;
    if (conf->tx_max_rate) c.tx_max_rate = path->tx.rate = conf->tx_max_rate;
    if (conf->rx_max_rate) c.rx_max_rate = path->rx.rate = conf->rx_max_rate;

    *conf = path->conf = c;
    return 0;
}

ssize_t
mud_send(struct mud *mud, void *data, size_t size)
{
    struct mud_path *path = mud_select_path(mud);

    if (!path) {
        errno = EAGAIN;
        return -1;
    }
    union mud_nonce nonce = mud_nonce_encrypt(mud, MUD_PKT_DATA);

    struct mud_hdr hdr = {
        .id = nonce.id
    };
    mud_encrypt(mud, nonce, &hdr.mac, data, size);

    const uint64_t now = mud_now();
    path->idle = now;

    return mud_send_path(mud, path, now, hdr, data, size, 0);
}

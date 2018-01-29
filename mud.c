#include "mud.h"

#if defined __APPLE__
#define __APPLE_USE_RFC_3542
#endif

#if defined __linux__ && !defined _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <ifaddrs.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>

#include <sodium.h>

#if !defined MSG_CONFIRM
#define MSG_CONFIRM 0
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

#if defined IP_DONTFRAG
#define MUD_DFRAG IP_DONTFRAG
#define MUD_DFRAG_OPT 1
#elif defined IP_MTU_DISCOVER
#define MUD_DFRAG IP_MTU_DISCOVER
#define MUD_DFRAG_OPT IP_PMTUDISC_DO
#endif

#define MUD_ONE_MSEC (UINT64_C(1000))
#define MUD_ONE_SEC (1000 * MUD_ONE_MSEC)
#define MUD_ONE_MIN (60 * MUD_ONE_SEC)

#define MUD_EPOCH UINT64_C(1483228800) // 1 Jan 2017

#define MUD_U48_SIZE (6U)
#define MUD_KEY_SIZE (32U)
#define MUD_MAC_SIZE (16U)
#define MUD_PUB_SIZE (crypto_scalarmult_BYTES)
#define MUD_SID_SIZE (8U)

#define MUD_PACKET_MIN_SIZE (MUD_U48_SIZE + MUD_MAC_SIZE)
#define MUD_PACKET_MAX_SIZE (1500U)

#define MUD_PACKET_TC (192) // CS6

#define MUD_PACKET_SIZE(X) \
    (sizeof(((struct mud_packet *)0)->hdr) + (X) + MUD_MAC_SIZE)

#define MUD_STAT_TIMEOUT (100 * MUD_ONE_MSEC)
#define MUD_KEYX_TIMEOUT (60 * MUD_ONE_MIN)
#define MUD_SEND_TIMEOUT (MUD_ONE_SEC)
#define MUD_TIME_TOLERANCE (10 * MUD_ONE_MIN)

struct mud_path {
    struct {
        unsigned skip : 1;
        unsigned backup : 1;
    } state;
    struct sockaddr_storage local_addr, addr;
    struct {
        unsigned char data[256];
        size_t size;
    } ctrl;
    struct {
        uint64_t send_time;
        int remote;
        struct {
            int remote;
            int local;
        } mtu;
        unsigned char kiss[MUD_SID_SIZE];
    } conf;
    unsigned char *tc;
    uint64_t rdt;
    uint64_t rtt;
    uint64_t sdt;
    uint64_t rst;
    uint64_t r_sdt;
    uint64_t r_rdt;
    uint64_t r_rst;
    int64_t r_dt;
    uint64_t limit;
    uint64_t recv_time;
    uint64_t send_time;
    uint64_t stat_time;
    struct mud_path *next;
};

struct mud_crypto_opt {
    unsigned char *dst;
    struct {
        const unsigned char *data;
        size_t size;
    } src, ad;
    unsigned char npub[16];
};

struct mud_crypto_key {
    struct {
        unsigned char key[MUD_KEY_SIZE];
        crypto_aead_aes256gcm_state state;
    } encrypt, decrypt;
    int aes;
};

enum mud_packet_code {
    mud_conf,
    mud_stat,
};

struct mud_public {
    unsigned char remote[MUD_PUB_SIZE];
    unsigned char local[MUD_PUB_SIZE];
};

struct mud_packet {
    struct {
        unsigned char zero[MUD_U48_SIZE];
        unsigned char time[MUD_U48_SIZE];
        unsigned char code;
    } hdr;
    union {
        struct {
            unsigned char kiss[MUD_SID_SIZE];
            unsigned char mtu[MUD_U48_SIZE];
            unsigned char backup;
            struct mud_public public;
            unsigned char aes;
        } conf;
        struct {
            unsigned char sdt[MUD_U48_SIZE];
            unsigned char rdt[MUD_U48_SIZE];
            unsigned char rst[MUD_U48_SIZE];
        } stat;
    } data;
    unsigned char _do_not_use_[MUD_MAC_SIZE];
};

struct mud {
    int fd;
    uint64_t send_timeout;
    uint64_t time_tolerance;
    struct mud_path *path;
    struct {
        uint64_t time;
        unsigned char secret[crypto_scalarmult_SCALARBYTES];
        struct mud_public public;
        struct mud_crypto_key private, last, next, current;
        int ready;
        int use_next;
        int aes;
    } crypto;
    int mtu;
    int tc;
    struct {
        int set;
        struct sockaddr_storage addr;
    } peer;
    unsigned char kiss[MUD_SID_SIZE];
};

static int
mud_encrypt_opt(const struct mud_crypto_key *k, const struct mud_crypto_opt *c)
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

static int
mud_decrypt_opt(const struct mud_crypto_key *k, const struct mud_crypto_opt *c)
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

static void
mud_write48(unsigned char *dst, uint64_t src)
{
    dst[0] = (unsigned char)(UINT64_C(255) & (src));
    dst[1] = (unsigned char)(UINT64_C(255) & (src >> 8));
    dst[2] = (unsigned char)(UINT64_C(255) & (src >> 16));
    dst[3] = (unsigned char)(UINT64_C(255) & (src >> 24));
    dst[4] = (unsigned char)(UINT64_C(255) & (src >> 32));
    dst[5] = (unsigned char)(UINT64_C(255) & (src >> 40));
}

static uint64_t
mud_read48(const unsigned char *src)
{
    uint64_t ret = src[0];
    ret |= ((uint64_t)src[1]) << 8;
    ret |= ((uint64_t)src[2]) << 16;
    ret |= ((uint64_t)src[3]) << 24;
    ret |= ((uint64_t)src[4]) << 32;
    ret |= ((uint64_t)src[5]) << 40;
    return ret;
}

static uint64_t
mud_now(void)
{
    uint64_t now;
#if defined CLOCK_REALTIME
    struct timespec tv;
    clock_gettime(CLOCK_REALTIME, &tv);
    now = (tv.tv_sec - MUD_EPOCH) * MUD_ONE_SEC + tv.tv_nsec / MUD_ONE_MSEC;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    now = (tv.tv_sec - MUD_EPOCH) * MUD_ONE_SEC + tv.tv_usec;
#endif
    return now;
}

static uint64_t
mud_abs_diff(uint64_t a, uint64_t b)
{
    return (a >= b) ? a - b : b - a;
}

static int
mud_timeout(uint64_t now, uint64_t last, uint64_t timeout)
{
    return ((!last) || ((now > last) && (now - last >= timeout)));
}

static void
mud_unmapv4(struct sockaddr_storage *addr)
{
    if (addr->ss_family != AF_INET6)
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

static size_t
mud_addrlen(struct sockaddr_storage *addr)
{
    return (addr->ss_family == AF_INET) ? sizeof(struct sockaddr_in)
                                        : sizeof(struct sockaddr_in6);
}

static int
mud_addrinfo(struct sockaddr_storage *addr, const char *host, int port)
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

static ssize_t
mud_send_path(struct mud *mud, struct mud_path *path, uint64_t now,
              void *data, size_t size, int tc, int flags)
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

    ssize_t ret = sendmsg(mud->fd, &msg, flags);
    path->send_time = now;

    return ret;
}

static int
mud_sso_int(int fd, int level, int optname, int opt)
{
    return setsockopt(fd, level, optname, &opt, sizeof(opt));
}

static int
mud_cmp_addr(struct sockaddr_storage *a, struct sockaddr_storage *b)
{
    if (a == b)
        return 0;

    if (a->ss_family != b->ss_family)
        return 1;

    if (a->ss_family == AF_INET) {
        struct sockaddr_in *_a = (struct sockaddr_in *)a;
        struct sockaddr_in *_b = (struct sockaddr_in *)b;

        return ((_a->sin_port != _b->sin_port) ||
                (memcmp(&_a->sin_addr, &_b->sin_addr,
                        sizeof(_a->sin_addr))));
    }

    if (a->ss_family == AF_INET6) {
        struct sockaddr_in6 *_a = (struct sockaddr_in6 *)a;
        struct sockaddr_in6 *_b = (struct sockaddr_in6 *)b;

        return ((_a->sin6_port != _b->sin6_port) ||
                (memcmp(&_a->sin6_addr, &_b->sin6_addr,
                        sizeof(_a->sin6_addr))));
    }

    return 1;
}

static int
mud_set_path(struct mud_path *path, struct sockaddr_storage *local_addr,
             struct sockaddr_storage *addr)
{
    struct msghdr msg = {
        .msg_control = path->ctrl.data,
        .msg_controllen = sizeof(path->ctrl.data),
    };

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);

    if (!cmsg)
        return -1;

    memset(&path->ctrl, 0, sizeof(path->ctrl));

    if (local_addr)
        memmove(&path->local_addr, local_addr, mud_addrlen(local_addr));

    memmove(&path->addr, addr, mud_addrlen(addr));

    if (addr->ss_family == AF_INET) {
        if (local_addr) {
            cmsg->cmsg_level = IPPROTO_IP;
            cmsg->cmsg_type = MUD_PKTINFO;
            cmsg->cmsg_len = CMSG_LEN(MUD_PKTINFO_SIZE);

            memcpy(MUD_PKTINFO_DST(CMSG_DATA(cmsg)),
                   &((struct sockaddr_in *)local_addr)->sin_addr,
                   sizeof(struct in_addr));

            cmsg = CMSG_NXTHDR(&msg, cmsg);

            if (!cmsg)
                return -1;

            path->ctrl.size += CMSG_SPACE(MUD_PKTINFO_SIZE);
        }

        cmsg->cmsg_level = IPPROTO_IP;
        cmsg->cmsg_type = IP_TOS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));

        path->tc = CMSG_DATA(cmsg);
        path->ctrl.size += CMSG_SPACE(sizeof(int));
    }

    if (addr->ss_family == AF_INET6) {
        if (local_addr) {
            cmsg->cmsg_level = IPPROTO_IPV6;
            cmsg->cmsg_type = IPV6_PKTINFO;
            cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));

            memcpy(&((struct in6_pktinfo *)CMSG_DATA(cmsg))->ipi6_addr,
                   &((struct sockaddr_in6 *)local_addr)->sin6_addr,
                   sizeof(struct in6_addr));

            cmsg = CMSG_NXTHDR(&msg, cmsg);

            if (!cmsg)
                return -1;

            path->ctrl.size += CMSG_SPACE(sizeof(struct in6_pktinfo));
        }

        cmsg->cmsg_level = IPPROTO_IPV6;
        cmsg->cmsg_type = IPV6_TCLASS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));

        path->tc = CMSG_DATA(cmsg);
        path->ctrl.size += CMSG_SPACE(sizeof(int));
    }

    return 0;
}

static struct mud_path *
mud_path(struct mud *mud, struct sockaddr_storage *local_addr,
         struct sockaddr_storage *addr, int create)
{
    struct mud_path *path;

    if (local_addr->ss_family != addr->ss_family) {
        errno = EINVAL;
        return NULL;
    }

    for (path = mud->path; path; path = path->next) {
        if (mud_cmp_addr(local_addr, &path->local_addr))
            continue;

        if (mud_cmp_addr(addr, &path->addr))
            continue;

        break;
    }

    if (path || !create)
        return path;

    path = calloc(1, sizeof(struct mud_path));

    if (!path)
        return NULL;

    if (mud_set_path(path, local_addr, addr)) {
        free(path);
        errno = EINVAL;
        return NULL;
    }

    path->conf.mtu.local = mud->mtu; // XXX
    path->next = mud->path;
    mud->path = path;

    return path;
}

int
mud_peer(struct mud *mud, const char *host, int port)
{
    if (!host || !port) {
        errno = EINVAL;
        return -1;
    }

    if (mud_addrinfo(&mud->peer.addr, host, port))
        return -1;

    mud_unmapv4(&mud->peer.addr);
    mud->peer.set = 1;

    return 0;
}

int
mud_del_path(struct mud *mud, const char *name)
{
    if (!name) {
        errno = EINVAL;
        return -1;
    }

    struct sockaddr_storage addr;

    if (mud_addrinfo(&addr, name, 0))
        return -1;

    struct mud_path *path;

    for (path = mud->path; path; path = path->next) {
        if (mud_cmp_addr(&addr, mud->peer.set ? &path->local_addr : &path->addr))
            continue;

        path->state.skip = 1;
    }

    return 0;
}

int
mud_add_path(struct mud *mud, const char *name)
{
    if (!name || !mud->peer.set) {
        errno = EINVAL;
        return -1;
    }

    struct sockaddr_storage addr;

    if (mud_addrinfo(&addr, name, 0))
        return -1;

    return -!mud_path(mud, &addr, &mud->peer.addr, 1);
}

int
mud_get_key(struct mud *mud, unsigned char *key, size_t *size)
{
    if (!key || !size || (*size < MUD_KEY_SIZE)) {
        errno = EINVAL;
        return -1;
    }

    memcpy(key, mud->crypto.private.encrypt.key, MUD_KEY_SIZE);
    *size = MUD_KEY_SIZE;

    return 0;
}

int
mud_set_key(struct mud *mud, unsigned char *key, size_t size)
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

int
mud_new_key(struct mud *mud)
{
    unsigned char key[MUD_KEY_SIZE];

    randombytes_buf(key, sizeof(key));
    return mud_set_key(mud, key, sizeof(key));
}

int
mud_set_tc(struct mud *mud, int tc)
{
    if (tc != (tc & 255)) {
        errno = EINVAL;
        return -1;
    }

    mud->tc = tc;

    return 0;
}

int
mud_set_send_timeout_msec(struct mud *mud, unsigned msec)
{
    if (!msec) {
        errno = EINVAL;
        return -1;
    }

    mud->send_timeout = msec * MUD_ONE_MSEC;

    return 0;
}

int
mud_set_time_tolerance_sec(struct mud *mud, unsigned sec)
{
    if (!sec) {
        errno = EINVAL;
        return -1;
    }

    mud->time_tolerance = sec * MUD_ONE_SEC;

    return 0;
}

int
mud_get_mtu(struct mud *mud)
{
    int mtu = mud->mtu;

    struct mud_path *path;

    for (path = mud->path; path; path = path->next) {
        if (path->conf.mtu.local && path->conf.mtu.local < mtu)
            mtu = path->conf.mtu.local;
        if (path->conf.mtu.remote && path->conf.mtu.remote < mtu)
            mtu = path->conf.mtu.remote;
    }

    return mtu;
}

int
mud_set_mtu(struct mud *mud, int mtu)
{
    if (mtu <= 0 || mtu > MUD_PACKET_MAX_SIZE)
        mtu = MUD_PACKET_MAX_SIZE;

    if (mtu < sizeof(struct mud_packet))
        mtu = sizeof(struct mud_packet);

    mtu -= MUD_PACKET_MIN_SIZE;

    struct mud_path *path;

    for (path = mud->path; path; path = path->next) {
        if (path->conf.mtu.local == mtu)
            continue;
        path->conf.mtu.local = mtu;
        path->conf.remote = 0;
    }

    if (!mud->mtu)
        mud->mtu = mtu;

    return 0;
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

static int
mud_create_socket(int port, int v4, int v6)
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

static void
mud_keyx_set(struct mud *mud, unsigned char *key, unsigned char *secret,
             unsigned char *pub0, unsigned char *pub1)
{
    crypto_generichash_state state;

    crypto_generichash_init(&state, mud->crypto.private.encrypt.key,
                            MUD_KEY_SIZE, MUD_KEY_SIZE);

    crypto_generichash_update(&state, secret, crypto_scalarmult_BYTES);
    crypto_generichash_update(&state, pub0, MUD_PUB_SIZE);
    crypto_generichash_update(&state, pub1, MUD_PUB_SIZE);

    crypto_generichash_final(&state, key, MUD_KEY_SIZE);
}

static void
mud_keyx(struct mud *mud, unsigned char *public, int aes)
{
    unsigned char secret[crypto_scalarmult_BYTES];

    if (crypto_scalarmult(secret, mud->crypto.secret, public))
        return;

    mud_keyx_set(mud, mud->crypto.next.encrypt.key,
                 secret, public, mud->crypto.public.local);

    mud_keyx_set(mud, mud->crypto.next.decrypt.key,
                 secret, mud->crypto.public.local, public);

    memcpy(mud->crypto.public.remote, public, MUD_PUB_SIZE);

    mud->crypto.next.aes = mud->crypto.aes && aes;

    if (mud->crypto.next.aes) {
        crypto_aead_aes256gcm_beforenm((crypto_aead_aes256gcm_state *)
                                           mud->crypto.next.encrypt.state,
                                       mud->crypto.next.encrypt.key);

        crypto_aead_aes256gcm_beforenm((crypto_aead_aes256gcm_state *)
                                           mud->crypto.next.decrypt.state,
                                       mud->crypto.next.decrypt.key);
    }
}

static int
mud_keyx_init(struct mud *mud, uint64_t now)
{
    if (!mud_timeout(now, mud->crypto.time, MUD_KEYX_TIMEOUT))
        return -1;

    mud->crypto.time = now;

    if (mud->crypto.ready)
        return 0;

    randombytes_buf(mud->crypto.secret, sizeof(mud->crypto.secret));
    crypto_scalarmult_base(mud->crypto.public.local, mud->crypto.secret);

    mud->crypto.ready = 1;

    return 0;
}

int
mud_set_aes(struct mud *mud)
{
    if (!crypto_aead_aes256gcm_is_available())
        return 1;

    mud->crypto.aes = 1;

    return 0;
}

struct mud *
mud_create(int port, int v4, int v6)
{
    uint64_t now = mud_now();

    if (now >> 48)
        return NULL;

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

    mud->send_timeout = MUD_SEND_TIMEOUT;
    mud->time_tolerance = MUD_TIME_TOLERANCE;
    mud->tc = MUD_PACKET_TC;

    randombytes_buf(mud->kiss, sizeof(mud->kiss));

    return mud;
}

int
mud_get_fd(struct mud *mud)
{
    return mud->fd;
}

void
mud_delete(struct mud *mud)
{
    if (!mud)
        return;

    while (mud->path) {
        struct mud_path *path = mud->path;
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

static int
mud_encrypt(struct mud *mud, uint64_t nonce,
            unsigned char *dst, size_t dst_size,
            const unsigned char *src, size_t src_size)
{
    if (!nonce)
        return 0;

    size_t size = src_size + MUD_PACKET_MIN_SIZE;

    if (size > dst_size)
        return 0;

    struct mud_crypto_opt opt = {
        .dst = dst + MUD_U48_SIZE,
        .src = {
            .data = src,
            .size = src_size,
        },
        .ad = {
            .data = dst,
            .size = MUD_U48_SIZE,
        },
    };

    mud_write48(opt.npub, nonce);
    memcpy(dst, opt.npub, MUD_U48_SIZE);

    if (mud->crypto.use_next) {
        mud_encrypt_opt(&mud->crypto.next, &opt);
    } else {
        mud_encrypt_opt(&mud->crypto.current, &opt);
    }

    return size;
}

static int
mud_decrypt(struct mud *mud,
            unsigned char *dst, size_t dst_size,
            const unsigned char *src, size_t src_size)
{
    size_t size = src_size - MUD_PACKET_MIN_SIZE;

    if (size > dst_size)
        return 0;

    struct mud_crypto_opt opt = {
        .dst = dst,
        .src = {
            .data = src + MUD_U48_SIZE,
            .size = src_size - MUD_U48_SIZE,
        },
        .ad = {
            .data = src,
            .size = MUD_U48_SIZE,
        },
    };

    memcpy(opt.npub, src, MUD_U48_SIZE);

    if (mud_decrypt_opt(&mud->crypto.current, &opt)) {
        if (!mud_decrypt_opt(&mud->crypto.next, &opt)) {
            mud->crypto.last = mud->crypto.current;
            mud->crypto.current = mud->crypto.next;
            mud->crypto.ready = 0;
            mud->crypto.use_next = 0;
        } else {
            if (mud_decrypt_opt(&mud->crypto.last, &opt) &&
                mud_decrypt_opt(&mud->crypto.private, &opt))
                return -1;
        }
    }

    return size;
}

static int
mud_localaddr(struct sockaddr_storage *addr, struct msghdr *msg, int family)
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

    memset(addr, 0, sizeof(struct sockaddr_storage));
    addr->ss_family = family;

    if (family == AF_INET) {
        memcpy(&((struct sockaddr_in *)addr)->sin_addr,
               MUD_PKTINFO_SRC(CMSG_DATA(cmsg)),
               sizeof(struct in_addr));
    } else {
        memcpy(&((struct sockaddr_in6 *)addr)->sin6_addr,
               &((struct in6_pktinfo *)CMSG_DATA(cmsg))->ipi6_addr,
               sizeof(struct in6_addr));
    }

    return 0;
}

static void
mud_packet_send(struct mud *mud, enum mud_packet_code code,
                struct mud_path *path, uint64_t now, int flags)
{
    struct mud_packet packet = {0};
    size_t size = 0;

    mud_write48(packet.hdr.time, now);
    packet.hdr.code = (unsigned char)code;

    switch (code) {
    case mud_conf:
        size = sizeof(packet.data.conf);
        memcpy(&packet.data.conf.kiss, &mud->kiss, size);
        mud_write48(packet.data.conf.mtu, path->conf.mtu.local);
        packet.data.conf.backup = (unsigned char)path->state.backup;
        memcpy(&packet.data.conf.public.local, &mud->crypto.public.local,
               sizeof(mud->crypto.public.local));
        memcpy(&packet.data.conf.public.remote, &mud->crypto.public.remote,
               sizeof(mud->crypto.public.remote));
        packet.data.conf.aes = (unsigned char)mud->crypto.aes;
        break;
    case mud_stat:
        size = sizeof(packet.data.stat);
        mud_write48(packet.data.stat.sdt, path->sdt);
        mud_write48(packet.data.stat.rdt, path->rdt);
        mud_write48(packet.data.stat.rst, path->rst);
        break;
    }

    struct mud_crypto_opt opt = {
        .dst = (unsigned char *)&packet.data + size,
        .ad = {
            .data = packet.hdr.zero,
            .size = size + sizeof(packet.hdr),
        },
    };

    mud_encrypt_opt(&mud->crypto.private, &opt);
    mud_send_path(mud, path, now, &packet, MUD_PACKET_SIZE(size), mud->tc, flags);
}

static void
mud_kiss_path(struct mud *mud, struct mud_path *path)
{
    struct mud_path **p = &mud->path;

    while (*p) {
        struct mud_path *t = *p;

        if ((t == path) ||
            !memcmp(t->conf.kiss, path->conf.kiss, sizeof(path->conf.kiss))) {
            p = &t->next;
            continue;
        }

        *p = t->next;
        free(t);
    }
}

static int
mud_packet_check_size(unsigned char *data, size_t size)
{
    struct mud_packet *packet = (struct mud_packet *)data;

    if (size <= MUD_PACKET_SIZE(0))
        return -1;

    // clang-format off

    const size_t sizes[] = {
        [mud_conf] = MUD_PACKET_SIZE(sizeof(packet->data.conf)),
        [mud_stat] = MUD_PACKET_SIZE(sizeof(packet->data.stat)),
    };

    // clang-format on

    return (packet->hdr.code >= sizeof(sizes)) ||
           (sizes[packet->hdr.code] != size);
}

static int
mud_packet_check(struct mud *mud, unsigned char *data, size_t size)
{
    unsigned char tmp[MUD_PACKET_MAX_SIZE];

    struct mud_crypto_opt opt = {
        .dst = tmp,
        .src = {
            .data = data + size - MUD_MAC_SIZE,
            .size = MUD_MAC_SIZE,
        },
        .ad = {
            .data = data,
            .size = size - MUD_MAC_SIZE,
        },
    };

    return mud_decrypt_opt(&mud->crypto.private, &opt);
}

static void
mud_packet_recv(struct mud *mud, struct mud_path *path,
                uint64_t now, unsigned char *data, size_t size)
{
    struct mud_packet *packet = (struct mud_packet *)data;

    switch (packet->hdr.code) {
    case mud_conf:
        path->conf.remote = 1;
        memcpy(path->conf.kiss, packet->data.conf.kiss,
               sizeof(path->conf.kiss));
        path->conf.mtu.remote = mud_read48(packet->data.conf.mtu);
        if (mud->peer.set) {
            if (!memcmp(mud->crypto.public.local,
                        packet->data.conf.public.remote, MUD_PUB_SIZE)) {
                mud_keyx(mud, packet->data.conf.public.local,
                         packet->data.conf.aes);
                mud->crypto.use_next = 1;
            }
        } else {
            mud_kiss_path(mud, path);
            mud_keyx(mud, packet->data.conf.public.local,
                     packet->data.conf.aes);
            path->state.backup = !!packet->data.conf.backup;
            mud_packet_send(mud, mud_conf, path, now, MSG_CONFIRM);
        }
        break;
    case mud_stat:
        path->r_sdt = mud_read48(packet->data.stat.sdt);
        path->r_rdt = mud_read48(packet->data.stat.rdt);
        path->r_rst = mud_read48(packet->data.stat.rst);
        path->r_dt = path->rst - path->r_rst;
        path->rtt = now - path->r_rst;
        break;
    default:
        break;
    }
}

int
mud_recv(struct mud *mud, void *data, size_t size)
{
    unsigned char packet[MUD_PACKET_MAX_SIZE];

    struct iovec iov = {
        .iov_base = packet,
        .iov_len = sizeof(packet),
    };

    struct sockaddr_storage addr;
    unsigned char ctrl[256];

    struct msghdr msg = {
        .msg_name = &addr,
        .msg_namelen = sizeof(addr),
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = ctrl,
        .msg_controllen = sizeof(ctrl),
    };

    ssize_t packet_size = recvmsg(mud->fd, &msg, 0);

    if (packet_size <= (ssize_t)MUD_PACKET_MIN_SIZE)
        return -(packet_size == (ssize_t)-1);

    uint64_t now = mud_now();
    uint64_t send_time = mud_read48(packet);

    int mud_packet = !send_time;
    int new_path = 0;

    if (mud_packet) {
        if (mud_packet_check_size(packet, packet_size))
            return 0;

        send_time = mud_read48(&packet[MUD_U48_SIZE]);
        new_path = ((struct mud_packet *)packet)->hdr.code == mud_conf;
    }

    if (mud_abs_diff(now, send_time) >= mud->time_tolerance)
        return 0;

    if (mud_packet && mud_packet_check(mud, packet, packet_size))
        return 0;

    mud_unmapv4(&addr);

    struct sockaddr_storage local_addr;

    if (mud_localaddr(&local_addr, &msg, addr.ss_family))
        return 0;

    struct mud_path *path = mud_path(mud, &local_addr, &addr, new_path);

    if (!path)
        return 0;

    int ret = 0;

    if (!mud_packet) {
        ret = mud_decrypt(mud, data, size, packet, packet_size);
        if (ret == -1) {
            // XXX
            return 0;
        }
    }

    if (path->rdt) {
        path->rdt = ((now - path->recv_time) + UINT64_C(7) * path->rdt) / UINT64_C(8);
        path->sdt = ((send_time - path->rst) + UINT64_C(7) * path->sdt) / UINT64_C(8);
    } else if (path->recv_time) {
        path->rdt = now - path->recv_time;
        path->sdt = send_time - path->rst;
    }

    path->rst = send_time;

    if ((!path->state.backup) && (path->recv_time) &&
        (mud_timeout(now, path->stat_time, MUD_STAT_TIMEOUT))) {
        mud_packet_send(mud, mud_stat, path, now, MSG_CONFIRM);
        path->stat_time = now;
    }

    path->recv_time = now;

    if (mud_packet)
        mud_packet_recv(mud, path, now, packet, packet_size);

    return ret;
}

static void
mud_update(struct mud *mud)
{
    if (!mud->peer.set)
        return;

    uint64_t now = mud_now();
    int update_keyx = !mud_keyx_init(mud, now);

    struct mud_path *path = mud->path;

    for (; path; path = path->next) {
        if (path->state.skip)
            continue;

        if (update_keyx || mud_timeout(now, path->recv_time, mud->send_timeout + MUD_ONE_SEC))
            path->conf.remote = 0;

        if ((!path->conf.remote) &&
            (mud_timeout(now, path->conf.send_time, mud->send_timeout))) {
            mud_packet_send(mud, mud_conf, path, now, 0);
            path->conf.send_time = now;
        }
    }
}

int
mud_send(struct mud *mud, const void *data, size_t size, int tc)
{
    mud_update(mud);

    if (!size)
        return 0;

    if (size > (size_t)mud_get_mtu(mud)) {
        errno = EMSGSIZE;
        return -1;
    }

    uint64_t now = mud_now();
    unsigned char packet[2048];

    int packet_size = mud_encrypt(mud, now, packet, sizeof(packet), data, size);

    if (!packet_size) {
        errno = EINVAL;
        return -1;
    }

    struct mud_path *path;
    struct mud_path *path_min = NULL;
    struct mud_path *path_backup = NULL;

    int64_t limit_min = INT64_MAX;

    for (path = mud->path; path; path = path->next) {
        if (path->state.skip)
            continue;

        if (path->state.backup) {
            path_backup = path;
            continue;
        }

        int64_t limit = path->limit;
        uint64_t elapsed = now - path->send_time;

        if (limit > elapsed) {
            limit += path->rtt / 2 - elapsed;
        } else {
            limit = path->rtt / 2;
        }

        if (mud_timeout(now, path->recv_time, mud->send_timeout + MUD_ONE_SEC)) {
            if (mud_timeout(now, path->send_time, mud->send_timeout)) {
                mud_send_path(mud, path, now, packet, packet_size, tc, 0);
                path->limit = limit;
            }
            continue;
        }

        if (limit_min > limit) {
            limit_min = limit;
            path_min = path;
        }
    }

    if (!path_min) {
        if (!path_backup)
            return 0;

        path_min = path_backup;
    }

    ssize_t ret = mud_send_path(mud, path_min, now, packet, packet_size, tc, 0);

    if (ret == packet_size)
        path_min->limit = limit_min;

    return (int)ret;
}

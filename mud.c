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
#include <netinet/in.h>

#include <sodium.h>

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

#define MUD_PACKET_MIN_SIZE (MUD_U48_SIZE + MUD_MAC_SIZE)
#define MUD_PACKET_MAX_SIZE (1472U)

#define MUD_PACKET_TC (192) // CS6

#define MUD_PACKET_SIZE(X) \
    (sizeof(((struct mud_packet *)0)->hdr) + (X) + MUD_MAC_SIZE)

#define MUD_STAT_TIMEOUT (100 * MUD_ONE_MSEC)
#define MUD_KEYX_TIMEOUT (60 * MUD_ONE_MIN)
#define MUD_SEND_TIMEOUT (MUD_ONE_SEC)
#define MUD_TIME_TOLERANCE (10 * MUD_ONE_MIN)

struct mud_crypto_opt {
    unsigned char *dst;
    struct {
        const unsigned char *data;
        size_t size;
    } src, ad;
    unsigned char npub[MUD_U48_SIZE + MUD_KISS_SIZE];
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
    mud_fake,
};

struct mud_public {
    unsigned char remote[MUD_PUB_SIZE];
    unsigned char local[MUD_PUB_SIZE];
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

struct mud_packet {
    struct {
        unsigned char zero[MUD_U48_SIZE];
        unsigned char time[MUD_U48_SIZE];
        unsigned char kiss[MUD_KISS_SIZE];
        struct mud_addr addr;
        unsigned char code;
    } hdr;
    union {
        struct {
            unsigned char state;
            struct mud_public public;
            unsigned char aes;
        } conf;
        struct {
            unsigned char rst[MUD_U48_SIZE];
            unsigned char rms[MUD_U48_SIZE];
            unsigned char rmt[MUD_U48_SIZE];
        } stat;
    } data;
    unsigned char _do_not_use_[MUD_MAC_SIZE];
};

struct mud {
    int fd;
    uint64_t send_timeout;
    uint64_t time_tolerance;
    uint64_t keyx_timeout;
    struct mud_path *paths;
    unsigned count;
    struct {
        uint64_t time;
        unsigned char secret[crypto_scalarmult_SCALARBYTES];
        struct mud_public public;
        struct mud_crypto_key private, last, next, current;
        int ready;
        int use_next;
        int aes;
    } crypto;
    size_t mtu;
    int tc;
    struct {
        int set;
        struct sockaddr_storage addr;
    } peer;
    struct {
        struct {
            struct sockaddr_storage addr;
            uint64_t time;
        } decrypt, difftime;
    } bad;
    struct {
        unsigned char kiss[MUD_KISS_SIZE];
    } remote, local;
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

static ssize_t
mud_send_path(struct mud *mud, struct mud_path *path, uint64_t now,
              void *data, size_t size, int tc, int flags)
{
    if (!size)
        return 0;

    unsigned char ctrl[64] = {0};

    struct iovec iov = {
        .iov_base = data,
        .iov_len = size,
    };

    struct msghdr msg = {
        .msg_name = &path->addr,
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = ctrl,
    };

    if (path->addr.ss_family == AF_INET) {
        msg.msg_namelen = sizeof(struct sockaddr_in);
        msg.msg_controllen = CMSG_SPACE(MUD_PKTINFO_SIZE) +
                             CMSG_SPACE(sizeof(int));

        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = IPPROTO_IP;
        cmsg->cmsg_type = MUD_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(MUD_PKTINFO_SIZE);

        memcpy(MUD_PKTINFO_DST(CMSG_DATA(cmsg)),
               &((struct sockaddr_in *)&path->local_addr)->sin_addr,
               sizeof(struct in_addr));

        cmsg = (struct cmsghdr *)((unsigned char *)cmsg +
                                  CMSG_SPACE(MUD_PKTINFO_SIZE));

        cmsg->cmsg_level = IPPROTO_IP;
        cmsg->cmsg_type = IP_TOS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));

        memcpy(CMSG_DATA(cmsg), &tc, sizeof(int));
    }

    if (path->addr.ss_family == AF_INET6) {
        msg.msg_namelen = sizeof(struct sockaddr_in6);
        msg.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo)) +
                             CMSG_SPACE(sizeof(int));

        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = IPPROTO_IPV6;
        cmsg->cmsg_type = IPV6_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));

        memcpy(&((struct in6_pktinfo *)CMSG_DATA(cmsg))->ipi6_addr,
               &((struct sockaddr_in6 *)&path->local_addr)->sin6_addr,
               sizeof(struct in6_addr));

        cmsg = (struct cmsghdr *)((unsigned char *)cmsg +
                                  CMSG_SPACE(sizeof(struct in6_pktinfo)));

        cmsg->cmsg_level = IPPROTO_IPV6;
        cmsg->cmsg_type = IPV6_TCLASS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));

        memcpy(CMSG_DATA(cmsg), &tc, sizeof(int));
    }

    ssize_t ret = sendmsg(mud->fd, &msg, flags);

    path->send_time = now;

    if (path->send_max <= size) {
        path->send_max = size;
        path->send_max_time = now;
    }

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

struct mud_path *
mud_get_paths(struct mud *mud, unsigned *ret_count)
{
    unsigned count = 0;

    if (!ret_count) {
        errno = EINVAL;
        return NULL;
    }

    for (unsigned i = 0; i < mud->count; i++) {
        struct mud_path *path = &mud->paths[i];

        if (path->state != MUD_EMPTY)
            count++;
    }

    size_t size = count * sizeof(struct mud_path);

    if (!size) {
        errno = 0;
        return NULL;
    }

    struct mud_path *paths = malloc(size);

    if (!paths)
        return NULL;

    count = 0;

    for (unsigned i = 0; i < mud->count; i++) {
        struct mud_path *path = &mud->paths[i];

        if (path->state != MUD_EMPTY)
            memcpy(&paths[count++], path, sizeof(struct mud_path));
    }

    *ret_count = count;

    return paths;
}

static struct mud_path *
mud_get_path(struct mud *mud, struct sockaddr_storage *local_addr,
             struct sockaddr_storage *addr, int create)
{
    if (local_addr->ss_family != addr->ss_family) {
        errno = EINVAL;
        return NULL;
    }

    for (unsigned i = 0; i < mud->count; i++) {
        struct mud_path *path = &mud->paths[i];

        if (path->state &&
            !mud_cmp_addr(local_addr, &path->local_addr) &&
            !mud_cmp_addr(addr, &path->addr))
            return path;
    }

    if (!create) {
        errno = 0;
        return NULL;
    }

    struct mud_path *path = NULL;

    for (unsigned i = 0; i < mud->count; i++) {
        if (mud->paths[i].state == MUD_EMPTY) {
            path = &mud->paths[i];
            break;
        }
    }

    if (!path) {
        struct mud_path *paths = realloc(mud->paths,
                                         (mud->count + 1) * sizeof(struct mud_path));

        if (!paths)
            return NULL;

        mud->count++;
        mud->paths = paths;

        path = &paths[mud->count - 1];
    }

    memset(path, 0, sizeof(struct mud_path));

    memcpy(&path->local_addr, local_addr, sizeof(*local_addr));
    memcpy(&path->addr, addr, sizeof(*addr));

    path->mtu.ok = mud->mtu;
    path->mtu.probe = mud->mtu;

    return path;
}

static int
mud_ss_from_sa(struct sockaddr_storage *ss, struct sockaddr *sa)
{
    if (!ss || !sa) {
        errno = EINVAL;
        return -1;
    }

    switch (sa->sa_family) {
    case AF_INET:
        memcpy(ss, sa, sizeof(struct sockaddr_in));
        break;
    case AF_INET6:
        memcpy(ss, sa, sizeof(struct sockaddr_in6));
        break;
    default:
        errno = EINVAL;
        return -1;
    }

    mud_unmapv4(ss);

    return 0;
}

int
mud_peer(struct mud *mud, struct sockaddr *peer)
{
    if (mud_ss_from_sa(&mud->peer.addr, peer))
        return -1;

    mud->peer.set = 1;

    return 0;
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
    if (key && (size < MUD_KEY_SIZE)) {
        errno = EINVAL;
        return -1;
    }

    unsigned char *enc = mud->crypto.private.encrypt.key;
    unsigned char *dec = mud->crypto.private.decrypt.key;

    if (key) {
        memcpy(enc, key, MUD_KEY_SIZE);
        sodium_memzero(key, size);
    } else {
        randombytes_buf(enc, MUD_KEY_SIZE);
    }

    memcpy(dec, enc, MUD_KEY_SIZE);

    mud->crypto.current = mud->crypto.private;
    mud->crypto.next = mud->crypto.private;
    mud->crypto.last = mud->crypto.private;

    return 0;
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
mud_set_send_timeout(struct mud *mud, unsigned long msec)
{
    if (!msec) {
        errno = EINVAL;
        return -1;
    }

    const uint64_t x = msec * MUD_ONE_MSEC;

    if ((uint64_t)msec != x / MUD_ONE_MSEC) {
        errno = ERANGE;
        return -1;
    }

    mud->send_timeout = x;

    return 0;
}

int
mud_set_time_tolerance(struct mud *mud, unsigned long msec)
{
    if (!msec) {
        errno = EINVAL;
        return -1;
    }

    const uint64_t x = msec * MUD_ONE_MSEC;

    if ((uint64_t)msec != x / MUD_ONE_MSEC) {
        errno = ERANGE;
        return -1;
    }

    mud->time_tolerance = x;

    return 0;
}

int
mud_set_keyx_timeout(struct mud *mud, unsigned long msec)
{
    if (!msec) {
        errno = EINVAL;
        return -1;
    }

    const uint64_t x = msec * MUD_ONE_MSEC;

    if ((uint64_t)msec != x / MUD_ONE_MSEC) {
        errno = ERANGE;
        return -1;
    }

    mud->keyx_timeout = x;

    return 0;
}

int
mud_set_state(struct mud *mud, struct sockaddr *peer, enum mud_state state)
{
    if (!mud->peer.set ||
        (state < MUD_DOWN) || (state > MUD_UP)) {
        errno = EINVAL;
        return -1;
    }

    struct sockaddr_storage addr;

    if (mud_ss_from_sa(&addr, peer))
        return -1;

    struct mud_path *path = mud_get_path(mud, &addr, &mud->peer.addr, state > MUD_DOWN);

    if (!path)
        return -1;

    if (path->state != state) {
        path->state = state;
        path->conf.remote = 0;
    }

    return 0;
}

size_t
mud_get_mtu(struct mud *mud)
{
    size_t mtu;

    if (mud->count) {
        mtu = MUD_PACKET_MAX_SIZE;

        for (unsigned i = 0; i < mud->count; i++) {
            struct mud_path *path = &mud->paths[i];

            if (mtu > path->mtu.ok)
                mtu = path->mtu.ok;
        }
    } else {
        mtu = mud->mtu;
    }

    if (mtu > MUD_PACKET_MAX_SIZE)
        mtu = MUD_PACKET_MAX_SIZE;

    if (mtu < sizeof(struct mud_packet))
        mtu = sizeof(struct mud_packet);

    return mtu - MUD_PACKET_MIN_SIZE;
}

void
mud_set_mtu(struct mud *mud, size_t mtu)
{
    if (mtu > MUD_PACKET_MAX_SIZE + 28U) {
        mtu = MUD_PACKET_MAX_SIZE;
    } else if (mtu < sizeof(struct mud_packet) + 28U) {
        mtu = sizeof(struct mud_packet);
    } else {
        mtu -= 28U;
    }

    mud->mtu = mtu;
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

    sodium_memzero(&state, sizeof(state));
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

    sodium_memzero(secret, sizeof(secret));

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

static void
mud_keyx_init(struct mud *mud)
{
    if (mud->crypto.ready)
        return;

    randombytes_buf(mud->crypto.secret, sizeof(mud->crypto.secret));
    crypto_scalarmult_base(mud->crypto.public.local, mud->crypto.secret);

    mud->crypto.ready = 1;
}

int
mud_set_aes(struct mud *mud)
{
    if (!crypto_aead_aes256gcm_is_available()) {
        errno = ENOTSUP;
        return -1;
    }

    mud->crypto.aes = 1;

    return 0;
}

struct mud *
mud_create(struct sockaddr *addr)
{
    if (!addr)
        return NULL;

    uint64_t now = mud_now();

    if (now >> 48)
        return NULL;

    int v4, v6;
    socklen_t addrlen = 0;

    switch (addr->sa_family) {
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

    if (sodium_init() == -1)
        return NULL;

    struct mud *mud = sodium_malloc(sizeof(struct mud));

    if (!mud)
        return NULL;

    memset(mud, 0, sizeof(struct mud));
    mud->fd = socket(addr->sa_family, SOCK_DGRAM, IPPROTO_UDP);

    if ((mud->fd == -1) ||
        (mud_setup_socket(mud->fd, v4, v6)) ||
        (bind(mud->fd, addr, addrlen))) {
        mud_delete(mud);
        return NULL;
    }

    mud->send_timeout = MUD_SEND_TIMEOUT;
    mud->time_tolerance = MUD_TIME_TOLERANCE;
    mud->keyx_timeout = MUD_KEYX_TIMEOUT;
    mud->tc = MUD_PACKET_TC;
    mud->mtu = sizeof(struct mud_packet);

    mud_keyx_init(mud);
    randombytes_buf(mud->local.kiss, sizeof(mud->local.kiss));

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

    if (mud->paths)
        free(mud->paths);

    if (mud->fd >= 0)
        close(mud->fd);

    sodium_free(mud);
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
    memcpy(&opt.npub[MUD_U48_SIZE], mud->local.kiss, sizeof(mud->local.kiss));
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
    memcpy(&opt.npub[MUD_U48_SIZE], mud->remote.kiss, sizeof(mud->remote.kiss));

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
    unsigned char data[MUD_PACKET_MAX_SIZE];
    struct mud_packet *packet = (struct mud_packet *)data;
    size_t size = 0;

    memset(data, 0, sizeof(data));

    mud_write48(packet->hdr.time, now);
    memcpy(packet->hdr.kiss, mud->local.kiss, sizeof(mud->local.kiss));

    if (path->addr.ss_family == AF_INET) {
        packet->hdr.addr.ff[0] = 0xFF;
        packet->hdr.addr.ff[1] = 0xFF;
        memcpy(packet->hdr.addr.v4,
               &((struct sockaddr_in *)&path->addr)->sin_addr, 4);
        memcpy(packet->hdr.addr.port,
               &((struct sockaddr_in *)&path->addr)->sin_port, 2);
    } else if (path->addr.ss_family == AF_INET6) {
        memcpy(packet->hdr.addr.v6,
               &((struct sockaddr_in6 *)&path->addr)->sin6_addr, 16);
        memcpy(packet->hdr.addr.port,
               &((struct sockaddr_in6 *)&path->addr)->sin6_port, 2);
    } else {
        return;
    }

    packet->hdr.code = (unsigned char)code;

    switch (code) {
    case mud_conf:
        size = sizeof(packet->data.conf);
        packet->data.conf.state = (unsigned char)path->state;
        memcpy(&packet->data.conf.public.local, &mud->crypto.public.local,
               sizeof(mud->crypto.public.local));
        memcpy(&packet->data.conf.public.remote, &mud->crypto.public.remote,
               sizeof(mud->crypto.public.remote));
        packet->data.conf.aes = (unsigned char)mud->crypto.aes;
        break;
    case mud_stat:
        size = sizeof(packet->data.stat);
        mud_write48(packet->data.stat.rst, path->rst);
        mud_write48(packet->data.stat.rms, path->recv_max);
        mud_write48(packet->data.stat.rmt, path->recv_max_time);
        break;
    case mud_fake:
        size = path->mtu.probe - MUD_PACKET_SIZE(0);
        break;
    }

    struct mud_crypto_opt opt = {
        .dst = data + sizeof(packet->hdr) + size,
        .ad = {
            .data = packet->hdr.zero,
            .size = sizeof(packet->hdr) + size,
        },
    };

    mud_encrypt_opt(&mud->crypto.private, &opt);
    mud_send_path(mud, path, now, packet, MUD_PACKET_SIZE(size), mud->tc, flags);
}

static void
mud_kiss_path(struct mud *mud, unsigned char *kiss)
{
    for (unsigned i = 0; i < mud->count; i++) {
        struct mud_path *path = &mud->paths[i];

        if (memcmp(path->conf.kiss, kiss, sizeof(path->conf.kiss)))
            path->state = MUD_EMPTY;
    }
}

static int
mud_packet_check_size(unsigned char *data, size_t size)
{
    struct mud_packet *packet = (struct mud_packet *)data;

    if (size <= MUD_PACKET_SIZE(0))
        return 1;

    if (packet->hdr.code == mud_conf)
        return size != MUD_PACKET_SIZE(sizeof(packet->data.conf));

    if (packet->hdr.code == mud_stat)
        return size != MUD_PACKET_SIZE(sizeof(packet->data.stat));

    return 0;
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

    memcpy(path->conf.kiss, packet->hdr.kiss,
           sizeof(path->conf.kiss));

    memcpy(mud->remote.kiss, packet->hdr.kiss,
           sizeof(path->conf.kiss));

    if (memcmp(packet->hdr.addr.v6, "\0\0\0\0\0\0\0\0\0\0\xff\xff", 12)) {
        path->r_addr.ss_family = AF_INET6;
        memcpy(&((struct sockaddr_in6 *)&path->r_addr)->sin6_addr,
               packet->hdr.addr.v6, 16);
        memcpy(&((struct sockaddr_in6 *)&path->r_addr)->sin6_port,
               packet->hdr.addr.port, 2);
    } else {
        path->r_addr.ss_family = AF_INET;
        memcpy(&((struct sockaddr_in *)&path->r_addr)->sin_addr,
               packet->hdr.addr.v4, 4);
        memcpy(&((struct sockaddr_in *)&path->r_addr)->sin_port,
               packet->hdr.addr.port, 2);
    }

    if (!mud->peer.set)
        mud_kiss_path(mud, mud->remote.kiss);

    switch (packet->hdr.code) {
    case mud_conf:
        path->conf.remote = 1;
        if (mud->peer.set) {
            if ((!memcmp(mud->crypto.public.local,
                         packet->data.conf.public.remote,
                         MUD_PUB_SIZE)) &&
                (memcmp(mud->crypto.public.remote,
                        packet->data.conf.public.local,
                        MUD_PUB_SIZE))) {
                mud_keyx(mud, packet->data.conf.public.local,
                         packet->data.conf.aes);
                mud->crypto.use_next = 1;
            }
        } else {
            if (memcmp(mud->crypto.public.remote,
                       packet->data.conf.public.local,
                       MUD_PUB_SIZE)) {
                mud_keyx_init(mud);
                mud_keyx(mud, packet->data.conf.public.local,
                         packet->data.conf.aes);
            }
            path->state = (enum mud_state)packet->data.conf.state;
            mud_packet_send(mud, mud_conf, path, now, MSG_CONFIRM);
        }
        break;
    case mud_stat:
        path->r_rst = mud_read48(packet->data.stat.rst);
        path->r_rms = mud_read48(packet->data.stat.rms);
        path->r_rmt = mud_read48(packet->data.stat.rmt);
        path->rtt = now - path->r_rst;
        if (path->mtu.ok < path->r_rms)
            path->mtu.ok = path->r_rms;
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
    unsigned char ctrl[64];

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

    if (mud_packet) {
        if (mud_packet_check_size(packet, packet_size))
            return 0;

        send_time = mud_read48(&packet[MUD_U48_SIZE]);
    }

    mud_unmapv4(&addr);

    if (mud_abs_diff(now, send_time) >= mud->time_tolerance) {
        mud->bad.difftime.addr = addr;
        mud->bad.difftime.time = now;
        return 0;
    }

    if (mud_packet && mud_packet_check(mud, packet, packet_size))
        return 0;

    struct sockaddr_storage local_addr;

    if (mud_localaddr(&local_addr, &msg, addr.ss_family))
        return 0;

    int ret = 0;

    if (!mud_packet) {
        ret = mud_decrypt(mud, data, size, packet, packet_size);
        if (ret == -1) {
            mud->bad.decrypt.addr = addr;
            mud->bad.decrypt.time = now;
            return 0;
        }
    }

    struct mud_path *path = mud_get_path(mud, &local_addr, &addr, 1);

    if (!path)
        return 0;

    path->rst = send_time;

    if ((path->state == MUD_UP) && (path->recv_time) &&
        (mud_timeout(now, path->stat_time, MUD_STAT_TIMEOUT))) {
        mud_packet_send(mud, mud_stat, path, now, MSG_CONFIRM);
        path->stat_time = now;
    }

    path->recv_time = now;

    if (path->recv_max <= packet_size) {
        path->recv_max = packet_size;
        path->recv_max_time = send_time;
        if (path->mtu.ok < path->recv_max)
            path->mtu.ok = path->recv_max;
    }

    if (mud_packet)
        mud_packet_recv(mud, path, now, packet, packet_size);

    return ret;
}

static void
mud_probe_mtu(struct mud *mud, struct mud_path *path, uint64_t now)
{
    if ((!path->rtt) ||
        (!mud_timeout(now, path->mtu.time, path->rtt)) ||
        (path->mtu.probe == path->r_rms + 1) ||
        (path->r_rms == MUD_PACKET_MAX_SIZE))
        return;

    if (path->mtu.probe > path->mtu.ok) {
        path->mtu.probe = (path->mtu.probe + path->mtu.ok) >> 1;
    } else {
        path->mtu.probe = (MUD_PACKET_MAX_SIZE + path->mtu.ok + 1) >> 1;
    }

    mud_packet_send(mud, mud_fake, path, now, 0);
    path->mtu.time = now;
}

static void
mud_update(struct mud *mud, uint64_t now)
{
    if (!mud->peer.set)
        return;

    int update_keyx = 0;

    if (mud_timeout(now, mud->crypto.time, mud->keyx_timeout)) {
        mud_keyx_init(mud);
        update_keyx = 1;
        mud->crypto.time = now;
    }

    for (unsigned i = 0; i < mud->count; i++) {
        struct mud_path *path = &mud->paths[i];

        if (path->state < MUD_DOWN)
            continue;

        if (update_keyx || mud_timeout(now, path->recv_time, mud->send_timeout + MUD_ONE_SEC))
            path->conf.remote = 0;

        if ((!path->conf.remote) &&
            (mud_timeout(now, path->conf.send_time, mud->send_timeout))) {
            mud_packet_send(mud, mud_conf, path, now, 0);
            path->conf.send_time = now;
        }

        mud_probe_mtu(mud, path, now);
    }
}

int
mud_send(struct mud *mud, const void *data, size_t size, int tc)
{
    unsigned char packet[MUD_PACKET_MAX_SIZE];
    uint64_t now = mud_now();

    mud_update(mud, now);

    if (!size)
        return 0;

    if (size > mud_get_mtu(mud)) {
        errno = EMSGSIZE;
        return -1;
    }

    int packet_size = mud_encrypt(mud, now, packet, sizeof(packet), data, size);

    if (!packet_size) {
        errno = EINVAL;
        return -1;
    }

    struct mud_path *path_min = NULL;
    struct mud_path *path_backup = NULL;

    int64_t limit_min = INT64_MAX;

    for (unsigned i = 0; i < mud->count; i++) {
        struct mud_path *path = &mud->paths[i];

        if (path->state <= MUD_DOWN) {
            if (path->state == MUD_BACKUP)
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

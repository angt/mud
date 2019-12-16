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
#include "aegis256/aegis256.h"

#if !defined MSG_CONFIRM
#define MSG_CONFIRM 0
#endif

#if defined __linux__
#define MUD_V4V6 1
#else
#define MUD_V4V6 0
#endif

#if defined __APPLE__
#include <mach/mach_time.h>
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

#define MUD_U48_SIZE (6U)
#define MUD_KEY_SIZE (32U)
#define MUD_MAC_SIZE (16U)

#define MUD_MSG(X)       ((X) & UINT64_C(1))
#define MUD_MSG_MARK(X)  ((X) | UINT64_C(1))
#define MUD_MSG_SENT_MAX (3)
#define MUD_MSG_TIMEOUT  (100 * MUD_ONE_MSEC)

#define MUD_PKT_MIN_SIZE (MUD_U48_SIZE + MUD_MAC_SIZE)
#define MUD_PKT_MAX_SIZE (1500U)

#define MUD_MTU_MIN (1280U + MUD_PKT_MIN_SIZE)
#define MUD_MTU_MAX (1450U + MUD_PKT_MIN_SIZE)

#define MUD_TIME_BITS    (48)
#define MUD_TIME_MASK(X) ((X) & ((UINT64_C(1) << MUD_TIME_BITS) - 2))

#define MUD_WINDOW_TIMEOUT     (MUD_ONE_MSEC)
#define MUD_KEYX_TIMEOUT       ( 60 * MUD_ONE_MIN)
#define MUD_KEYX_RESET_TIMEOUT (200 * MUD_ONE_MSEC)
#define MUD_TIME_TOLERANCE     ( 10 * MUD_ONE_MIN)

#define MUD_TC (192) // CS6

#define MUD_LOSS_LIMIT (20)
#define MUD_LOSS_COUNT (3)

#define MUD_CTRL_SIZE (CMSG_SPACE(MUD_PKTINFO_SIZE) + \
                       CMSG_SPACE(sizeof(struct in6_pktinfo)) + \
                       CMSG_SPACE(sizeof(int)))

struct mud_crypto_opt {
    unsigned char *dst;
    const unsigned char *src;
    size_t size;
};

struct mud_crypto_key {
    struct {
        unsigned char key[MUD_KEY_SIZE];
    } encrypt, decrypt;
    int aes;
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

struct mud_msg {
    unsigned char sent_time[MUD_U48_SIZE];
    unsigned char state;
    struct mud_addr addr;
    unsigned char pk[MUD_PUBKEY_SIZE];
    unsigned char aes;
    unsigned char fwd_tx[MUD_U48_SIZE];
    unsigned char tx[MUD_U48_SIZE];
    unsigned char rx[MUD_U48_SIZE];
 // unsigned char delay[MUD_U48_SIZE];
    unsigned char rate_max[MUD_U48_SIZE];
    unsigned char loss;
};

struct mud {
    int fd;
    uint64_t time_tolerance;
    uint64_t keyx_timeout;
    unsigned loss_limit;
    struct sockaddr_storage addr;
    struct mud_path *paths;
    unsigned count;
    struct {
        uint64_t time;
        unsigned char secret[crypto_scalarmult_SCALARBYTES];
        struct mud_pubkey pk;
        struct mud_crypto_key private, last, next, current;
        int ready;
        int use_next;
        int aes;
    } crypto;
    uint64_t last_recv_time;
    size_t mtu;
    int tc;
    struct {
        int set;
        struct sockaddr_storage addr;
    } peer;
    struct mud_bad bad;
    uint64_t window;
    uint64_t base_time;
};

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
mud_encrypt_opt(const struct mud_crypto_key *k,
                const struct mud_crypto_opt *c)
{
    if (k->aes) {
        unsigned char npub[AEGIS256_NPUBBYTES];

        memcpy(npub, c->dst, MUD_U48_SIZE);
        memset(npub + MUD_U48_SIZE, 0, sizeof(npub) - MUD_U48_SIZE);

        return aegis256_encrypt(
            c->dst + MUD_U48_SIZE,
            NULL,
            c->src,
            c->size,
            c->dst,
            MUD_U48_SIZE,
            npub,
            k->encrypt.key
        );
    } else {
        unsigned char npub[crypto_aead_chacha20poly1305_NPUBBYTES];

        memcpy(npub, c->dst, MUD_U48_SIZE);
        memset(npub + MUD_U48_SIZE, 0, sizeof(npub) - MUD_U48_SIZE);

        return crypto_aead_chacha20poly1305_encrypt(
            c->dst + MUD_U48_SIZE,
            NULL,
            c->src,
            c->size,
            c->dst,
            MUD_U48_SIZE,
            NULL,
            npub,
            k->encrypt.key
        );
    }
}

static int
mud_decrypt_opt(const struct mud_crypto_key *k,
                const struct mud_crypto_opt *c)
{
    if (k->aes) {
        unsigned char npub[AEGIS256_NPUBBYTES];

        memcpy(npub, c->src, MUD_U48_SIZE);
        memset(npub + MUD_U48_SIZE, 0, sizeof(npub) - MUD_U48_SIZE);

        return aegis256_decrypt(
            c->dst,
            NULL,
            c->src + MUD_U48_SIZE,
            c->size - MUD_U48_SIZE,
            c->src, MUD_U48_SIZE,
            npub,
            k->decrypt.key
        );
    } else {
        unsigned char npub[crypto_aead_chacha20poly1305_NPUBBYTES];

        memcpy(npub, c->src, MUD_U48_SIZE);
        memset(npub + MUD_U48_SIZE, 0, sizeof(npub) - MUD_U48_SIZE);

        return crypto_aead_chacha20poly1305_decrypt(
            c->dst,
            NULL,
            NULL,
            c->src + MUD_U48_SIZE,
            c->size - MUD_U48_SIZE,
            c->src, MUD_U48_SIZE,
            npub,
            k->decrypt.key
        );
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
mud_time(void)
{
#if defined CLOCK_REALTIME
    struct timespec tv;
    clock_gettime(CLOCK_REALTIME, &tv);
    return MUD_TIME_MASK(0
            + (uint64_t)tv.tv_sec * MUD_ONE_SEC
            + (uint64_t)tv.tv_nsec / MUD_ONE_MSEC);
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return MUD_TIME_MASK(0
            + (uint64_t)tv.tv_sec * MUD_ONE_SEC
            + (uint64_t)tv.tv_usec);
#endif
}

static uint64_t
mud_now(struct mud *mud)
{
#if defined __APPLE__
    static mach_timebase_info_data_t mtid;
    if (!mtid.denom)
        mach_timebase_info(&mtid);
    return MUD_TIME_MASK(mud->base_time
            + (mach_absolute_time() * mtid.numer / mtid.denom)
            / 1000ULL);
#elif defined CLOCK_MONOTONIC
    struct timespec tv;
    clock_gettime(CLOCK_MONOTONIC, &tv);
    return MUD_TIME_MASK(mud->base_time
            + (uint64_t)tv.tv_sec * MUD_ONE_SEC
            + (uint64_t)tv.tv_nsec / MUD_ONE_MSEC);
#else
    return mud_time();
#endif
}

static uint64_t
mud_abs_diff(uint64_t a, uint64_t b)
{
    return (a >= b) ? a - b : b - a;
}

static int
mud_timeout(uint64_t now, uint64_t last, uint64_t timeout)
{
    return (!last) || (MUD_TIME_MASK(now - last) >= timeout);
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

static struct mud_path *
mud_select_path(struct mud *mud, unsigned k)
{
    uint64_t window = 0;
    struct mud_path *last = NULL;

    for (unsigned i = 0; i < mud->count; i++) {
        struct mud_path *path = &mud->paths[i];

        if (!path->window)
            continue;

        window += ((path->window << 16) + (mud->window >> 1)) / mud->window;
        last = path;

        if ((uint64_t)k <= window)
            break;
    }

    return last;
}

static int
mud_send_path(struct mud *mud, struct mud_path *path, uint64_t now,
              void *data, size_t size, int flags)
{
    if (!size || !path)
        return 0;

    unsigned char ctrl[MUD_CTRL_SIZE];

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

    memset(ctrl, 0, sizeof(ctrl));

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

        memcpy(CMSG_DATA(cmsg), &mud->tc, sizeof(int));
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

        memcpy(CMSG_DATA(cmsg), &mud->tc, sizeof(int));
    }

    ssize_t ret = sendmsg(mud->fd, &msg, flags);

    path->tx.total++;
    path->tx.bytes += size;
    path->tx.time = now;

    if (path->window > size) {
        mud->window -= size;
        path->window -= size;
    } else {
        mud->window -= path->window;
        path->window = 0;
    }

    return (int)ret;
}

static int
mud_sso_int(int fd, int level, int optname, int opt)
{
    return setsockopt(fd, level, optname, &opt, sizeof(opt));
}

static int
mud_cmp_addr(struct sockaddr_storage *a, struct sockaddr_storage *b)
{
    if (a->ss_family != b->ss_family)
        return 1;

    if (a->ss_family == AF_INET) {
        struct sockaddr_in *_a = (struct sockaddr_in *)a;
        struct sockaddr_in *_b = (struct sockaddr_in *)b;

        return ((memcmp(&_a->sin_port, &_b->sin_port,
                        sizeof(_a->sin_port))) ||
                (memcmp(&_a->sin_addr, &_b->sin_addr,
                        sizeof(_a->sin_addr))));
    }

    if (a->ss_family == AF_INET6) {
        struct sockaddr_in6 *_a = (struct sockaddr_in6 *)a;
        struct sockaddr_in6 *_b = (struct sockaddr_in6 *)b;

        return ((memcmp(&_a->sin6_port, &_b->sin6_port,
                        sizeof(_a->sin6_port))) ||
                (memcmp(&_a->sin6_addr, &_b->sin6_addr,
                        sizeof(_a->sin6_addr))));
    }

    return 1;
}

struct mud_path *
mud_get_paths(struct mud *mud, unsigned *ret_count)
{
    if (!ret_count) {
        errno = EINVAL;
        return NULL;
    }

    unsigned count = 0;

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

static void
mud_copy_port(struct sockaddr_storage *d, struct sockaddr_storage *s)
{
    void *port;

    switch (s->ss_family) {
    case AF_INET:
        port = &((struct sockaddr_in *)s)->sin_port;
        break;
    case AF_INET6:
        port = &((struct sockaddr_in6 *)s)->sin6_port;
        break;
    default:
        return;
    }

    switch (d->ss_family) {
    case AF_INET:
        memcpy(&((struct sockaddr_in *)d)->sin_port,
               port, sizeof(in_port_t));
        break;
    case AF_INET6:
        memcpy(&((struct sockaddr_in6 *)d)->sin6_port,
               port, sizeof(in_port_t));
        break;
    }
}

static void
mud_reset_path(struct mud_path *path)
{
    path->window = 0;
    path->ok = 0;
    path->loss_count = 0;
    memset(&path->msg, 0, sizeof(path->msg));
}

static void
mud_remove_path(struct mud_path *path)
{
    memset(path, 0, sizeof(struct mud_path));
    path->state = MUD_EMPTY;
}

static struct mud_path *
mud_get_path(struct mud *mud, struct sockaddr_storage *local_addr,
             struct sockaddr_storage *addr, int create)
{
    if (local_addr->ss_family != addr->ss_family) {
        errno = EINVAL;
        return NULL;
    }

    mud_copy_port(local_addr, &mud->addr);

    for (unsigned i = 0; i < mud->count; i++) {
        struct mud_path *path = &mud->paths[i];

        if ((path->state != MUD_EMPTY) &&
            (!mud_cmp_addr(local_addr, &path->local_addr)) &&
            (!mud_cmp_addr(addr, &path->addr)))
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
        if (mud->count == MUD_PATH_MAX) {
            errno = ENOMEM;
            return NULL;
        }

        struct mud_path *paths = realloc(mud->paths,
                (mud->count + 1) * sizeof(struct mud_path));

        if (!paths)
            return NULL;

        path = &paths[mud->count];

        mud->count++;
        mud->paths = paths;
    }

    memset(path, 0, sizeof(struct mud_path));

    memcpy(&path->local_addr, local_addr, sizeof(*local_addr));
    memcpy(&path->addr, addr, sizeof(*addr));

    path->state = MUD_UP;

    path->mtu.ok = MUD_MTU_MIN;
    path->mtu.min = MUD_MTU_MIN;
    path->mtu.max = MUD_MTU_MAX;
    path->mtu.probe = MUD_MTU_MAX;

    path->msg.timeout = MUD_MSG_TIMEOUT;

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
        mud_unmapv4(ss);
        break;
    default:
        errno = EINVAL;
        return -1;
    }

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
mud_get_bad(struct mud *mud, struct mud_bad *bad)
{
    if (!bad) {
        errno = EINVAL;
        return -1;
    }

    memcpy(bad, &mud->bad, sizeof(struct mud_bad));

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
mud_set_loss_limit(struct mud *mud, unsigned loss)
{
    if (loss > 100) {
        errno = EINVAL;
        return -1;
    }

    mud->loss_limit = loss;

    return 0;
}

static int
mud_set_msec(uint64_t *dst, unsigned long msec)
{
    if (!msec) {
        errno = EINVAL;
        return -1;
    }

    const uint64_t x = msec * MUD_ONE_MSEC;

    if ((x >> MUD_TIME_BITS) ||
        ((uint64_t)msec != x / MUD_ONE_MSEC)) {
        errno = ERANGE;
        return -1;
    }

    *dst = x;

    return 0;
}

int
mud_set_time_tolerance(struct mud *mud, unsigned long msec)
{
    return mud_set_msec(&mud->time_tolerance, msec);
}

int
mud_set_keyx_timeout(struct mud *mud, unsigned long msec)
{
    return mud_set_msec(&mud->keyx_timeout, msec);
}

size_t
mud_get_mtu(struct mud *mud)
{
    return mud->mtu - MUD_PKT_MIN_SIZE;
}

void
mud_set_mtu(struct mud *mud, size_t mtu)
{
    mud->mtu = mtu + MUD_PKT_MIN_SIZE;
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
             unsigned char *pk0, unsigned char *pk1)
{
    crypto_generichash_state state;

    crypto_generichash_init(&state, mud->crypto.private.encrypt.key,
                            MUD_KEY_SIZE, MUD_KEY_SIZE);

    crypto_generichash_update(&state, secret, crypto_scalarmult_BYTES);
    crypto_generichash_update(&state, pk0, MUD_PUBKEY_SIZE);
    crypto_generichash_update(&state, pk1, MUD_PUBKEY_SIZE);

    crypto_generichash_final(&state, key, MUD_KEY_SIZE);

    sodium_memzero(&state, sizeof(state));
}

static void
mud_keyx_reset(struct mud *mud)
{
    if (memcmp(&mud->crypto.current, &mud->crypto.private,
               sizeof(struct mud_crypto_key))) {
        mud->crypto.last = mud->crypto.current;
        mud->crypto.current = mud->crypto.private;
    }

    mud->crypto.ready = 1;
    mud->crypto.use_next = 0;
}

static int
mud_keyx(struct mud *mud, unsigned char *remote, int aes)
{
    unsigned char secret[crypto_scalarmult_BYTES];

    if (crypto_scalarmult(secret, mud->crypto.secret, remote))
        return 1;

    unsigned char *local = mud->crypto.pk.local;

    mud_keyx_set(mud, mud->crypto.next.encrypt.key, secret, remote, local);
    mud_keyx_set(mud, mud->crypto.next.decrypt.key, secret, local, remote);

    sodium_memzero(secret, sizeof(secret));

    memcpy(mud->crypto.pk.remote, remote, MUD_PUBKEY_SIZE);

    mud->crypto.next.aes = mud->crypto.aes && aes;

    return 0;
}

static void
mud_keyx_init(struct mud *mud, uint64_t now)
{
    if (!mud_timeout(now, mud->crypto.time, mud->keyx_timeout))
        return;

    mud->crypto.time = now;

    if (mud->crypto.ready)
        return;

    static const unsigned char test[crypto_scalarmult_BYTES] = {
        0x9b, 0xf4, 0x14, 0x90, 0x0f, 0xef, 0xf8, 0x2d, 0x11, 0x32, 0x6e,
        0x3d, 0x99, 0xce, 0x96, 0xb9, 0x4f, 0x79, 0x31, 0x01, 0xab, 0xaf,
        0xe3, 0x03, 0x59, 0x1a, 0xcd, 0xdd, 0xb0, 0xfb, 0xe3, 0x49
    };

    unsigned char tmp[crypto_scalarmult_BYTES];

    do {
        randombytes_buf(mud->crypto.secret, sizeof(mud->crypto.secret));
        crypto_scalarmult_base(mud->crypto.pk.local, mud->crypto.secret);
    } while (crypto_scalarmult(tmp, test, mud->crypto.pk.local));

    sodium_memzero(tmp, sizeof(tmp));

    mud->crypto.ready = 1;
}

int
mud_set_aes(struct mud *mud)
{
    if (!aegis256_is_available()) {
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

    mud->time_tolerance = MUD_TIME_TOLERANCE;
    mud->keyx_timeout = MUD_KEYX_TIMEOUT;
    mud->tc = MUD_TC;
    mud->mtu = MUD_MTU_MIN;
    mud->loss_limit = MUD_LOSS_LIMIT;

    memcpy(&mud->addr, addr, addrlen);

    uint64_t now = mud_now(mud);
    uint64_t base_time = mud_time();

    if (base_time > now)
        mud->base_time = base_time - now;

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

    sodium_free(mud);
}

static int
mud_encrypt(struct mud *mud, uint64_t now,
            unsigned char *dst, size_t dst_size,
            const unsigned char *src, size_t src_size)
{
    const size_t size = src_size + MUD_PKT_MIN_SIZE;

    if (size > dst_size)
        return 0;

    const struct mud_crypto_opt opt = {
        .dst = dst,
        .src = src,
        .size = src_size,
    };

    mud_write48(dst, now);

    if (mud->crypto.use_next) {
        mud_encrypt_opt(&mud->crypto.next, &opt);
    } else {
        mud_encrypt_opt(&mud->crypto.current, &opt);
    }

    return (int)size;
}

static int
mud_decrypt(struct mud *mud,
            unsigned char *dst, size_t dst_size,
            const unsigned char *src, size_t src_size)
{
    const size_t size = src_size - MUD_PKT_MIN_SIZE;

    if (size > dst_size)
        return 0;

    const struct mud_crypto_opt opt = {
        .dst = dst,
        .src = src,
        .size = src_size,
    };

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

    return (int)size;
}

static int
mud_localaddr(struct sockaddr_storage *addr, struct msghdr *msg)
{
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg);

    for (; cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
        if ((cmsg->cmsg_level == IPPROTO_IP) &&
            (cmsg->cmsg_type == MUD_PKTINFO))
            break;
        if ((cmsg->cmsg_level == IPPROTO_IPV6) &&
            (cmsg->cmsg_type == IPV6_PKTINFO))
            break;
    }

    if (!cmsg)
        return 1;

    memset(addr, 0, sizeof(struct sockaddr_storage));

    if (cmsg->cmsg_level == IPPROTO_IP) {
        addr->ss_family = AF_INET;
        memcpy(&((struct sockaddr_in *)addr)->sin_addr,
               MUD_PKTINFO_SRC(CMSG_DATA(cmsg)),
               sizeof(struct in_addr));
    } else {
        addr->ss_family = AF_INET6;
        memcpy(&((struct sockaddr_in6 *)addr)->sin6_addr,
               &((struct in6_pktinfo *)CMSG_DATA(cmsg))->ipi6_addr,
               sizeof(struct in6_addr));
        mud_unmapv4(addr);
    }

    return 0;
}

static int
mud_send_msg(struct mud *mud, struct mud_path *path, uint64_t now,
             uint64_t sent_time, uint64_t fwd_tx, size_t size)
{
    unsigned char dst[MUD_PKT_MAX_SIZE];
    unsigned char src[MUD_PKT_MAX_SIZE];
    struct mud_msg *msg = (struct mud_msg *)src;

    memset(src, 0, sizeof(src));

    if (size < MUD_PKT_MIN_SIZE + sizeof(struct mud_msg))
        size = MUD_PKT_MIN_SIZE + sizeof(struct mud_msg);

    mud_write48(dst, MUD_MSG_MARK(now));
    mud_write48(msg->sent_time, sent_time);

    if (path->addr.ss_family == AF_INET) {
        msg->addr.ff[0] = 0xFF;
        msg->addr.ff[1] = 0xFF;
        memcpy(msg->addr.v4,
               &((struct sockaddr_in *)&path->addr)->sin_addr, 4);
        memcpy(msg->addr.port,
               &((struct sockaddr_in *)&path->addr)->sin_port, 2);
    } else if (path->addr.ss_family == AF_INET6) {
        memcpy(msg->addr.v6,
               &((struct sockaddr_in6 *)&path->addr)->sin6_addr, 16);
        memcpy(msg->addr.port,
               &((struct sockaddr_in6 *)&path->addr)->sin6_port, 2);
    } else {
        errno = EINVAL;
        return -1;
    }

    msg->state = (unsigned char)path->state;

    memcpy(msg->pk,
           mud->crypto.pk.local,
           sizeof(mud->crypto.pk.local));

    msg->aes = (unsigned char)mud->crypto.aes;

    mud_write48(msg->tx, path->tx.bytes);
    mud_write48(msg->rx, path->rx.bytes);
    mud_write48(msg->fwd_tx, fwd_tx);
    mud_write48(msg->rate_max, path->rx.rate_max);

    msg->loss = (unsigned char)path->tx.loss;

    if (!mud->peer.set || !sent_time) {
        if (path->msg.sent < MUD_MSG_SENT_MAX)
            path->msg.sent++;
    }

    const struct mud_crypto_opt opt = {
        .dst = dst,
        .src = src,
        .size = size - MUD_PKT_MIN_SIZE,
    };

    mud_encrypt_opt(&mud->crypto.private, &opt);

    return mud_send_path(mud, path, now, dst, size, sent_time ? MSG_CONFIRM : 0);
}

static int
mud_decrypt_msg(struct mud *mud,
                unsigned char *dst, size_t dst_size,
                const unsigned char *src, size_t src_size)
{
    const size_t size = src_size - MUD_PKT_MIN_SIZE;

    if (size < sizeof(struct mud_msg))
        return 0;

    const struct mud_crypto_opt opt = {
        .dst = dst,
        .src = src,
        .size = src_size,
    };

    if (mud_decrypt_opt(&mud->crypto.private, &opt))
        return -1;

    return (int)size;
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
mud_ss_from_packet(struct sockaddr_storage *ss, struct mud_msg *pkt)
{
    if (mud_addr_is_v6(&pkt->addr)) {
        ss->ss_family = AF_INET6;
        memcpy(&((struct sockaddr_in6 *)ss)->sin6_addr, pkt->addr.v6, 16);
        memcpy(&((struct sockaddr_in6 *)ss)->sin6_port, pkt->addr.port, 2);
    } else {
        ss->ss_family = AF_INET;
        memcpy(&((struct sockaddr_in *)ss)->sin_addr, pkt->addr.v4, 4);
        memcpy(&((struct sockaddr_in *)ss)->sin_port, pkt->addr.port, 2);
    }
}

static void
mud_update_window(struct mud *mud, struct mud_path *path, uint64_t now,
                  uint64_t send_dt, uint64_t send_bytes,
                  uint64_t recv_dt, uint64_t recv_bytes)
{
    if (recv_bytes && send_bytes >= recv_bytes) {
        uint64_t loss = send_bytes - recv_bytes;
        path->tx.loss = loss * 100 / send_bytes;
        if (path->tx.loss > mud->loss_limit) {
            if (path->loss_count < MUD_LOSS_COUNT) {
                path->loss_count++;
            } else {
                path->loss_count = 0;
                path->tx.rate -= loss * path->tx.rate / send_bytes;
            }
        } else {
            path->loss_count = 0;
        }
    }

    // TODO
}

static void
mud_recv_msg(struct mud *mud, struct mud_path *path,
             uint64_t now, uint64_t sent_time,
             unsigned char *data, size_t size)
{
    struct mud_msg *msg = (struct mud_msg *)data;

    const int rem = memcmp(msg->pk,
                           mud->crypto.pk.remote,
                           MUD_PUBKEY_SIZE);

    const int loc = memcmp(path->pk.local,
                           mud->crypto.pk.local,
                           MUD_PUBKEY_SIZE);

    if (rem || loc) {
        if (mud_keyx(mud, msg->pk, msg->aes)) {
            mud->bad.keyx.addr = path->addr;
            mud->bad.keyx.time = now;
            mud->bad.keyx.count++;
            return;
        }

        if (!mud->peer.set) {
            for (unsigned i = 0; i < mud->count; i++) {
                if (mud->paths[i].state == MUD_EMPTY)
                    continue;

                if (memcmp(mud->paths[i].pk.remote,
                           path->pk.remote,
                           MUD_PUBKEY_SIZE) &&
                    memcmp(mud->paths[i].pk.remote,
                           msg->pk,
                           MUD_PUBKEY_SIZE))
                    mud->paths[i].state = MUD_EMPTY;
            }
        }

        path->pk = mud->crypto.pk;
    } else {
        mud->crypto.use_next = 1;
    }

    mud_ss_from_packet(&path->r_addr, msg);

    const uint64_t tx_time = mud_read48(msg->sent_time);

    if (tx_time) {
        path->mtu.min = size + 1;

        if (!path->ok) {
            path->mtu.max = MUD_MTU_MAX;
            path->mtu.probe = MUD_MTU_MAX;
        } else {
            path->mtu.probe = (path->mtu.min + path->mtu.max) >> 1;
        }

        path->mtu.ok = size;

        const uint64_t rx_time = sent_time;
        const uint64_t tx = mud_read48(msg->fwd_tx);
        const uint64_t rx = mud_read48(msg->rx);

        if ((tx_time > path->tx.last_time) && (tx > path->tx.last) &&
            (rx_time > path->rx.last_time) && (rx > path->rx.last)) {
            if (path->msg.set) {
                mud_update_stat(&path->rtt, MUD_TIME_MASK(now - tx_time));
                mud_update_window(mud, path, now,
                        MUD_TIME_MASK(tx_time - path->tx.last_time),
                        tx - path->tx.last,
                        MUD_TIME_MASK(rx_time - path->rx.last_time),
                        rx - path->rx.last);
            }
            path->tx.last_time = tx_time;
            path->rx.last_time = rx_time;
            path->tx.last = tx;
            path->rx.last = rx;
            path->msg.set = 1;
        }

        path->rx.loss = (uint64_t)msg->loss;
        path->msg.sent = 0;
        path->ok = 1;

        if (!mud->peer.set)
            return;
    } else {
        mud_keyx_init(mud, now);
        path->state = (enum mud_state)msg->state;

        const uint64_t rate_max = mud_read48(msg->rate_max);

        if (path->tx.rate_max != rate_max) {
            path->tx.rate_max = rate_max;
            path->tx.rate = rate_max;
        }
    }

    mud_send_msg(mud, path, now, sent_time, mud_read48(msg->tx), size);
}

int
mud_recv(struct mud *mud, void *data, size_t size)
{
    unsigned char packet[MUD_PKT_MAX_SIZE];

    struct iovec iov = {
        .iov_base = packet,
        .iov_len = sizeof(packet),
    };

    struct sockaddr_storage addr;
    unsigned char ctrl[MUD_CTRL_SIZE];

    struct msghdr msg = {
        .msg_name = &addr,
        .msg_namelen = sizeof(addr),
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = ctrl,
        .msg_controllen = sizeof(ctrl),
    };

    const ssize_t packet_size = recvmsg(mud->fd, &msg, 0);

    if (packet_size == (ssize_t)-1)
        return -1;

    if ((msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) ||
        (packet_size <= (ssize_t)MUD_PKT_MIN_SIZE))
        return 0;

    const uint64_t now = mud_now(mud);
    const uint64_t sent_time = mud_read48(packet);

    mud_unmapv4(&addr);

    if ((MUD_TIME_MASK(now - sent_time) > mud->time_tolerance) &&
        (MUD_TIME_MASK(sent_time - now) > mud->time_tolerance)) {
        mud->bad.difftime.addr = addr;
        mud->bad.difftime.time = now;
        mud->bad.difftime.count++;
        return 0;
    }

    const int ret = MUD_MSG(sent_time)
                  ? mud_decrypt_msg(mud, data, size, packet, (size_t)packet_size)
                  : mud_decrypt(mud, data, size, packet, (size_t)packet_size);

    if (ret <= 0) {
        mud->bad.decrypt.addr = addr;
        mud->bad.decrypt.time = now;
        mud->bad.decrypt.count++;
        return 0;
    }

    struct sockaddr_storage local_addr;

    if (mud_localaddr(&local_addr, &msg))
        return 0;

    struct mud_path *path = mud_get_path(mud, &local_addr, &addr, 1);

    if (!path)
        return 0;

    if (path->state <= MUD_DOWN)
        return 0;

    if (MUD_MSG(sent_time))
        mud_recv_msg(mud, path, now, sent_time, data, (size_t)packet_size);

    path->rx.total++;
    path->rx.time = now;
    path->rx.bytes += (size_t)packet_size;

    mud->last_recv_time = now;

    return MUD_MSG(sent_time) ? 0 : ret;
}

static int
mud_update(struct mud *mud)
{
    uint64_t window = 0;
    size_t mtu = 0;
    unsigned ret = 0;

    uint64_t now = mud_now(mud);

    if (mud->peer.set) {
        mud_keyx_init(mud, now);

        if (mud_timeout(now, mud->last_recv_time, MUD_KEYX_RESET_TIMEOUT))
            mud_keyx_reset(mud);
    }

    now = mud_now(mud);

    for (unsigned i = 0; i < mud->count; i++) {
        struct mud_path *path = &mud->paths[i];

        if (path->state <= MUD_DOWN) {
            if (path->state == MUD_DOWN &&
                mud_timeout(now, path->rx.time, 10 * MUD_ONE_SEC))
                mud_remove_path(path);
            continue;
        }

        if (mud->peer.set) {
            if (path->msg.sent >= MUD_MSG_SENT_MAX) {
                if (path->mtu.probe == MUD_MTU_MIN) {
                    mud_reset_path(path);
                } else {
                    if (path->mtu.ok == path->mtu.probe) {
                        path->mtu.min = MUD_MTU_MIN;
                        path->mtu.ok = MUD_MTU_MIN;
                        mud_reset_path(path);
                    } else {
                        path->msg.sent = 0;
                    }
                    path->mtu.max = path->mtu.probe - 1;
                    path->mtu.probe = (path->mtu.min + path->mtu.max) >> 1;
                }
            }
        } else {
            if ((path->msg.sent >= MUD_MSG_SENT_MAX) ||
                (path->rx.time &&
                 mud->last_recv_time > path->rx.time + MUD_ONE_SEC)) {
                mud_remove_path(path);
                continue;
            }
        }

        if (path->ok) {
            if (!mtu || mtu > path->mtu.ok) {
                mtu = path->mtu.ok;
            }
            if (path->window_time + MUD_WINDOW_TIMEOUT <= now) {
                path->window += (path->tx.rate * (now - path->window_time))
                    / MUD_ONE_SEC;
                path->window_time = now;
                const uint64_t rate_tx_max = path->tx.rate >> 2; // use rtt
                if (path->window > rate_tx_max)
                    path->window = rate_tx_max;
            }
        }

        if (mud->peer.set) {
            if (mud_timeout(now, path->msg.time, path->msg.timeout)) {
                mud_send_msg(mud, path, now, 0, 0, path->mtu.probe);
                path->msg.time = now;
            }
        }

        if (path->window >= 1500)
            window += path->window;

        ret++;
    }

    mud->window = window;
    mud->mtu = mtu ?: MUD_MTU_MIN;

    return ret;
}

int
mud_set_state(struct mud *mud, struct sockaddr *addr,
              enum mud_state state,
              unsigned long rate_tx,
              unsigned long rate_rx,
              unsigned long msg_timeout)
{
    if (!mud->peer.set || state > MUD_UP) {
        errno = EINVAL;
        return -1;
    }

    struct sockaddr_storage local_addr;

    if (mud_ss_from_sa(&local_addr, addr))
        return -1;

    struct mud_path *path = mud_get_path(mud,
            &local_addr, &mud->peer.addr, state > MUD_DOWN);

    if (!path)
        return -1;

    if (rate_tx)
        path->tx.rate_max = path->tx.rate = rate_tx;

    if (rate_rx)
        path->rx.rate_max = path->rx.rate = rate_rx;

    if (msg_timeout)
        path->msg.timeout = msg_timeout;

    if (state && path->state != state) {
        path->state = state;
        mud_reset_path(path);
        mud_update(mud);
    }

    return 0;
}

long
mud_send_wait(struct mud *mud)
{
    if (!mud_update(mud))
        return -1;

    return !mud->window;
}

int
mud_send(struct mud *mud, const void *data, size_t size)
{
    if (!size)
        return 0;

    if (!mud->window) {
        errno = EAGAIN;
        return -1;
    }

    unsigned char packet[MUD_PKT_MAX_SIZE];
    const uint64_t now = mud_now(mud);
    const int packet_size = mud_encrypt(mud, now,
                                        packet, sizeof(packet),
                                        data, size);
    if (!packet_size) {
        errno = EMSGSIZE;
        return -1;
    }

    const unsigned a = packet[packet_size - 1];
    const unsigned b = packet[packet_size - 2];
    const unsigned k = (a << 8) | b;

    return mud_send_path(mud, mud_select_path(mud, k),
                         now, packet, (size_t)packet_size, 0);
}

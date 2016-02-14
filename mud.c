#include "mud.h"

#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <sodium.h>

struct addr {
    struct sockaddr_storage data;
    socklen_t size;
};

struct path_info {
    uint64_t dt;
    uint64_t time;
    unsigned count;
};

struct path {
    int fd;
    struct addr addr;
    uint64_t rtt;
    struct path_info recv;
    struct path_info send;
    struct path *next;
};

struct sock {
    int fd;
    struct addr addr;
    struct sock *next;
};

struct packet {
    unsigned char data[2048];
    size_t size;
};

struct queue {
    struct packet *packet;
    unsigned char start;
    unsigned char end;
};

struct crypto {
    crypto_aead_aes256gcm_state key;
};

struct mud {
    uint64_t base;
    struct queue tx;
    struct queue rx;
    struct sock *sock;
    struct path *path;
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
    return (now.tv_sec*UINT64_C(1000000)+now.tv_usec)-mud->base;
}

static
ssize_t mud_send_path (struct path *path, const void *data, size_t size)
{
    return sendto(path->fd, data, size, 0,
                  (struct sockaddr *)&path->addr.data, path->addr.size);
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
int mud_cmp_addr (struct addr *a, struct addr *b)
{
    if ((a->size != b->size) ||
        (a->data.ss_family != b->data.ss_family))
        return 1;

    if (a->data.ss_family == AF_INET) {
        struct sockaddr_in *_a = (struct sockaddr_in *)&a->data;
        struct sockaddr_in *_b = (struct sockaddr_in *)&b->data;

        return ((_a->sin_port != _b->sin_port) ||
                (memcmp(&_a->sin_addr.s_addr, &_b->sin_addr.s_addr,
                        sizeof(_a->sin_addr.s_addr))));
    }

    if (a->data.ss_family == AF_INET6) {
        struct sockaddr_in6 *_a = (struct sockaddr_in6 *)&a->data;
        struct sockaddr_in6 *_b = (struct sockaddr_in6 *)&b->data;

        return ((_a->sin6_port != _b->sin6_port) ||
                (memcmp(&_a->sin6_addr.s6_addr, &_b->sin6_addr.s6_addr,
                        sizeof(_a->sin6_addr.s6_addr))));
    }

    return 1;
}

static
struct sock *mud_get_sock (struct mud *mud, struct addr *addr)
{
    struct sock *sock;

    for (sock = mud->sock; sock; sock = sock->next) {
        if (!mud_cmp_addr(addr, &sock->addr))
            break;
    }

    return sock;
}

static
struct path *mud_get_path (struct mud *mud, int fd, struct addr *addr)
{
    struct path *path;

    for (path = mud->path; path; path = path->next) {
        if ((path->fd == fd) &&
            (!mud_cmp_addr(addr, &path->addr)))
            break;
    }

    return path;
}

static
struct path *mud_new_path (struct mud *mud, int fd, struct addr *addr)
{
    struct path *path = mud_get_path(mud, fd, addr);

    if (path)
        return path;

    path = calloc(1, sizeof(struct path));

    if (!path)
        return NULL;

    path->fd = fd;
    memcpy(&path->addr, addr, sizeof(struct addr));
    path->next = mud->path;
    mud->path = path;

    return path;
}

static
void mud_new_addr (struct mud *mud, struct addr *addr)
{
    struct sock *sock;

    for (sock = mud->sock; sock; sock = sock->next) {
        if (sock->addr.data.ss_family == addr->data.ss_family)
            mud_new_path(mud, sock->fd, addr);
    }
}

static
struct sock *mud_new_sock (struct mud *mud, struct addr *addr)
{
    struct sock *sock = mud_get_sock(mud, addr);

    if (sock)
        return sock;

    int fd = socket(addr->data.ss_family, SOCK_DGRAM, IPPROTO_UDP);

    if (fd == -1)
        return NULL;

    mud_set_nonblock(fd);

    if (bind(fd, (struct sockaddr *)&addr->data, addr->size)) {
        close(fd);
        return NULL;
    }

    sock = calloc(1, sizeof(struct sock));

    if (!sock) {
        close(fd);
        return NULL;
    }

    sock->fd = fd;
    memcpy(&sock->addr, addr, sizeof(struct addr));
    sock->next = mud->sock;
    mud->sock = sock;

    struct path *path;

    for (path = mud->path; path; path = path->next) {
        if (path->addr.data.ss_family == addr->data.ss_family)
            mud_new_path(mud, fd, &path->addr);
    }

    return sock;
}

int mud_peer (struct mud *mud, const char *host, const char *port)
{
    if (!host || !port)
        return -1;

    struct addrinfo *p, *ai = mud_addrinfo(host, port, AI_NUMERICSERV);

    if (!ai)
        return -1;

    for (p = ai; p; p = p->ai_next) {
        struct addr addr;

        memcpy(&addr.data, p->ai_addr, p->ai_addrlen);
        addr.size = p->ai_addrlen;

        mud_new_addr(mud, &addr);
    }

    freeaddrinfo(ai);

    return 0;
}

int mud_bind (struct mud *mud, const char *host, const char *port)
{
    if (!host || !port)
        return -1;

    struct addrinfo *p, *ai = mud_addrinfo(host, port, AI_NUMERICHOST|AI_NUMERICSERV|AI_PASSIVE);

    if (!ai)
        return -1;

    struct sock *sock = NULL;

    for (p = ai; p; p = p->ai_next) {
        struct addr addr;

        memcpy(&addr.data, p->ai_addr, p->ai_addrlen);
        addr.size = p->ai_addrlen;

        if (sock = mud_new_sock(mud, &addr), sock)
            break;
    }

    freeaddrinfo(ai);

    if (!sock)
        return -1;

    return sock->fd;
}

struct mud *mud_create (const unsigned char *key, size_t key_size)
{
    if (key_size != crypto_aead_aes256gcm_KEYBYTES)
        return NULL;

    struct mud *mud = calloc(1, sizeof(struct mud));

    if (!mud)
        return NULL;

    crypto_aead_aes256gcm_beforenm(&mud->crypto.key, key);

    mud->tx.packet = calloc(256, sizeof(struct packet));
    mud->rx.packet = calloc(256, sizeof(struct packet));

    if (!mud->tx.packet || !mud->rx.packet) {
        free(mud->tx.packet);
        free(mud->rx.packet);
        free(mud);
        return NULL;
    }

    mud->base = mud_now(mud);

    return mud;
}

void mud_delete (struct mud *mud)
{
    if (!mud)
        return;

    free(mud->tx.packet);
    free(mud->rx.packet);

    while (mud->sock) {
        struct sock *sock = mud->sock;

        if (sock->fd != -1)
            close(sock->fd);

        mud->sock = sock->next;
        free(sock);
    }

    while (mud->path) {
        struct path *path = mud->path;

        mud->path = path->next;
        free(path);
    }

    free(mud);
}

static
int mud_encrypt (struct mud *mud, uint64_t nonce,
                 unsigned char *dst, size_t dst_size,
                 const unsigned char *src, size_t src_size,
                 size_t ad_size)
{
    if (!src_size)
        return 0;

    if (ad_size > src_size)
        return 0;

    size_t size = src_size+6+crypto_aead_aes256gcm_ABYTES;

    if (size > dst_size)
        return 0;

    unsigned char npub[crypto_aead_aes256gcm_NPUBBYTES] = {0};

    mud_write48(npub, nonce);
    memcpy(dst, npub, 6);
    memcpy(dst+6, src, ad_size);

    crypto_aead_aes256gcm_encrypt_afternm(
            dst+ad_size+6, NULL,
            src+ad_size, src_size-ad_size,
            dst, ad_size+6,
            NULL,
            npub,
            (const crypto_aead_aes256gcm_state *)&mud->crypto.key);

    return size;
}

static
int mud_decrypt (struct mud *mud, uint64_t *nonce,
                 unsigned char *dst, size_t dst_size,
                 const unsigned char *src, size_t src_size,
                 size_t ad_size)
{
    if (!src_size)
        return 0;

    if (ad_size > src_size)
        return 0;

    size_t size = src_size-6-crypto_aead_aes256gcm_ABYTES;

    if (size > dst_size)
        return 0;

    unsigned char npub[crypto_aead_aes256gcm_NPUBBYTES] = {0};

    memcpy(npub, src, 6);
    memcpy(dst, src+6, ad_size);

    if (crypto_aead_aes256gcm_decrypt_afternm(
            dst+ad_size, NULL,
            NULL,
            src+ad_size+6, src_size-ad_size-6,
            src, ad_size+6,
            npub,
            (const crypto_aead_aes256gcm_state *)&mud->crypto.key))
        return -1;

    if (nonce)
        *nonce = mud_read48(src);

    return size;
}

int mud_pull (struct mud *mud)
{
    uint64_t now = mud_now(mud);

    struct sock *sock;

    for (sock = mud->sock; sock; sock = sock->next) {
        for (int i = 0; i < 16; i++) {
            unsigned char next = mud->rx.end+1;

            if (mud->rx.start == next)
                return 0;

            struct addr addr = {
                .size = sizeof(addr.data),
            };

            struct packet *packet = &mud->rx.packet[mud->rx.end];

            ssize_t ret = recvfrom(sock->fd, packet->data, sizeof(packet->data),
                                   0, (struct sockaddr *)&addr.data, &addr.size);

            if (ret <= 0)
                break;

            struct path *path = mud_new_path(mud, sock->fd, &addr);

            if (!path)
                return -1;

            uint64_t send_now = mud_read48(packet->data);

            if (!send_now) {
                send_now = mud_read48(&packet->data[6]);
                path->recv.dt = mud_read48(&packet->data[12]);
                path->rtt = now-send_now;
                continue;
            }

            if (path->recv.count == 256) {
                unsigned char reply[3*6];
                uint64_t dt = (now-path->recv.time)>>8;

                path->recv.count = 0;
                path->recv.time = now;

                memset(reply, 0, 6);
                memcpy(&reply[6], packet->data, 6);
                mud_write48(&reply[12], dt);

                mud_send_path(path, reply, sizeof(reply));
            } else {
                path->recv.count++;
            }

            packet->size = ret;
            mud->rx.end = next;
        }
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

    mud->rx.start++;

    if (ret == -1) {
        errno = EINVAL;
        return -1;
    }

    return ret;
}

int mud_push (struct mud *mud)
{
    while (mud->tx.start != mud->tx.end) {
        uint64_t now = mud_now(mud);

        struct packet *packet = &mud->tx.packet[mud->tx.start];

        struct path *path;

        struct path *path_min = NULL;
        int64_t dt_min = INT64_MAX;

        for (path = mud->path; path; path = path->next) {
            if (!path->recv.dt) {
                mud_send_path(path, packet->data, packet->size);
                continue;
            }

            int64_t dt = (int64_t)path->recv.dt-(int64_t)(now-path->send.time);

            if (dt_min > dt) {
                dt_min = dt;
                path_min = path;
            }
        }

        if (!path_min)
            return -1;

        ssize_t ret = mud_send_path(path_min, packet->data, packet->size);

        mud->tx.start++;

        if (ret != packet->size)
            return -1;

        path_min->send.time = now;
    }

    return 0;
}

int mud_send (struct mud *mud, const void *data, size_t size)
{
    uint64_t now = mud_now(mud);

    unsigned char next = mud->tx.end+1;

    if (mud->tx.start == next) {
        errno = EAGAIN;
        return -1;
    }

    struct packet *packet = &mud->tx.packet[mud->tx.end];

    int ret = mud_encrypt(mud, now,
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

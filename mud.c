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

#define MUD_PKT_SIZE (2048u)

struct addr {
    struct sockaddr_storage data;
    socklen_t size;
};

struct path_info {
    uint32_t dt;
    uint32_t time;
    unsigned count;
};

struct path {
    int fd;
    struct addr addr;
    uint32_t rtt;
    struct path_info recv;
    struct path_info send;
    struct path *next;
};

struct sock {
    int fd;
    int family;
    struct sock *next;
};

struct packet {
    unsigned char data[MUD_PKT_SIZE];
    size_t size;
//  uint32_t time;
//  struct path *path;
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
    struct queue tx;
    struct queue rx;
    struct sock *sock;
    struct path *path;
    struct crypto crypto;
};

static
void mud_write32 (unsigned char *dst, uint32_t src)
{
    dst[0] = (unsigned char)(UINT32_C(255)&(src));
    dst[1] = (unsigned char)(UINT32_C(255)&(src>>8));
    dst[2] = (unsigned char)(UINT32_C(255)&(src>>16));
    dst[3] = (unsigned char)(UINT32_C(255)&(src>>24));
}

static
uint32_t mud_read32 (const unsigned char *src)
{
    return ((uint32_t)src[0])
         | ((uint32_t)src[1]<<8)
         | ((uint32_t)src[2]<<16)
         | ((uint32_t)src[3]<<24);
}

static
uint32_t mud_now (void)
{
    struct timeval now;
    gettimeofday(&now, NULL);
    return now.tv_sec*UINT32_C(1000000)+now.tv_usec;
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
struct path *mud_get_path (struct mud *mud, int fd, struct addr *addr)
{
    struct path *path;

    for (path = mud->path; path; path = path->next) {
        if ((path->fd == fd) &&
            (path->addr.size == addr->size) &&
            (!memcmp(&path->addr.data, &addr->data, addr->size)))
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
    int family;

    switch (addr->size) {
    case INET_ADDRSTRLEN:
        family = AF_INET;
        break;
    case INET6_ADDRSTRLEN:
        family = AF_INET6;
        break;
    default:
        return;
    }

    struct sock *sock;

    for (sock = mud->sock; sock; sock = sock->next) {
        if (sock->family == family)
            mud_new_path(mud, sock->fd, addr);
    }
}

static
void mud_new_sock (struct mud *mud, int fd, int family)
{
    struct sock *sock = calloc(1, sizeof(struct sock));

    if (!sock)
        return;

    sock->fd = fd;
    sock->family = family;
    sock->next = mud->sock;
    mud->sock = sock;

    socklen_t addr_size;

    switch (family) {
    case AF_INET:
        addr_size = INET_ADDRSTRLEN;
        break;
    case AF_INET6:
        addr_size = INET6_ADDRSTRLEN;
        break;
    default:
        return;
    }

    struct path *path;

    for (path = mud->path; path; path = path->next) {
        if (path->addr.size == addr_size)
            mud_new_path(mud, fd, &path->addr);
    }
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

    int fd;

    for (p = ai; p; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);

        if (fd == -1)
            continue;

        if (mud_set_nonblock(fd))
            continue;

        if (!bind(fd, (struct sockaddr *)p->ai_addr, p->ai_addrlen)) {
            mud_new_sock(mud, fd, p->ai_family);
            break;
        }

        close(fd);
    }

    freeaddrinfo(ai);

    if (!p)
        return -1;

    return fd;
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
int mud_encrypt (struct mud *mud, uint32_t nonce,
                 unsigned char *dst, size_t dst_size,
                 const unsigned char *src, size_t src_size,
                 size_t ad_size)
{
    if (!src_size)
        return 0;

    if (ad_size > src_size)
        return 0;

    size_t size = src_size+4+crypto_aead_aes256gcm_ABYTES;

    if (size > dst_size)
        return 0;

    unsigned char npub[crypto_aead_aes256gcm_NPUBBYTES] = {0};

    mud_write32(npub, nonce);

    crypto_aead_aes256gcm_encrypt_afternm(
            dst+ad_size+4, NULL,
            src+ad_size, src_size-ad_size,
            src, ad_size,
            NULL,
            npub,
            (const crypto_aead_aes256gcm_state *)&mud->crypto.key);

    memcpy(dst, npub, 4);
    memcpy(dst+4, src, ad_size);

    return size;
}

static
int mud_decrypt (struct mud *mud, uint32_t *nonce,
                 unsigned char *dst, size_t dst_size,
                 const unsigned char *src, size_t src_size,
                 size_t ad_size)
{
    if (!src_size)
        return 0;

    if (ad_size > src_size)
        return 0;

    size_t size = src_size-4-crypto_aead_aes256gcm_ABYTES;

    if (size > dst_size)
        return 0;

    unsigned char npub[crypto_aead_aes256gcm_NPUBBYTES] = {0};

    memcpy(npub, src, 4);
    memcpy(dst, src+4, ad_size);

    if (crypto_aead_aes256gcm_decrypt_afternm(
            dst+ad_size, NULL,
            NULL,
            src+ad_size+4, src_size-ad_size-4,
            src+ad_size, ad_size,
            npub,
            (const crypto_aead_aes256gcm_state *)&mud->crypto.key))
        return -1;

    if (nonce)
        *nonce = mud_read32(src);

    return size;
}

int mud_pull (struct mud *mud)
{
    uint32_t now = mud_now();

    if (!now) {
        errno = EAGAIN;
        return -1;
    }

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

            uint32_t send_now = mud_read32(packet->data);

            if (!send_now) {
                send_now = mud_read32(&packet->data[4]);
                path->recv.dt = mud_read32(&packet->data[8]);
                path->rtt = now-send_now;
                continue;
            }

            if (path->recv.count == 256) {
                unsigned char reply[3*4];
                uint32_t dt = (now-path->recv.time)>>8;

                path->recv.count = 0;
                path->recv.time = now;

                memset(reply, 0, 4);
                memcpy(&reply[4], packet->data, 4);
                mud_write32(&reply[8], dt);

                mud_send_path(path, reply, sizeof(reply));
            } else {
                path->recv.count++;
            }

            packet->size = ret;
        //  packet->time = now;

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
        uint32_t now = mud_now();

        if (!now) {
            errno = EAGAIN;
            return -1;
        }

        struct packet *packet = &mud->tx.packet[mud->tx.start];

    //  if (packet->time > time)
    //      break;

        struct path *path;
        struct path *path_min = NULL;
        int32_t dt_min = INT32_MAX;

        for (path = mud->path; path; path = path->next) {
            int32_t dt = (int32_t)path->recv.dt-(int32_t)(now-path->send.time);

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
    uint32_t now = mud_now();

    if (!now) {
        errno = EAGAIN;
        return -1;
    }

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

//  packet->time = now;
    mud->tx.end = next;

    return size;
}

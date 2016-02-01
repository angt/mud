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

#define MUD_PKT_SIZE (2048u)

struct path {
    int fd;
    struct sockaddr_storage addr;
    socklen_t addrlen;
    unsigned count;
    uint32_t rtt;
    uint32_t dt;
    uint32_t send_dt;
    uint32_t recv_time;
    uint32_t send_time;
    struct path *next;
};

struct sock {
    int fd;
    int family;
    struct sock *next;
};

struct packet {
    unsigned char data[MUD_PKT_SIZE];
    uint32_t time;
    size_t size;
//  struct path *path;
};

struct queue {
    struct packet *packet;
    unsigned char start;
    unsigned char end;
};

struct mud {
    struct queue queue;
    struct sock *sock;
    struct path *path;
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
uint32_t mud_read32 (unsigned char *src)
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
    return sendto(path->fd, data, size, 0, (struct sockaddr *)&path->addr, path->addrlen);
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
struct path *mud_get_path (struct mud *mud, int fd, struct sockaddr_storage *addr, socklen_t addrlen)
{
    struct path *path;

    for (path = mud->path; path; path = path->next) {
        if ((path->fd == fd) &&
            (path->addrlen == addrlen) &&
            (!memcmp(&path->addr, addr, addrlen)))
            break;
    }

    return path;
}

static
struct path *mud_new_path (struct mud *mud, int fd, struct sockaddr_storage *addr, socklen_t addrlen)
{
    struct path *path = mud_get_path(mud, fd, addr, addrlen);

    if (path)
        return path;

    path = calloc(1, sizeof(struct path));

    if (!path)
        return NULL;

    path->fd = fd;
    memcpy(&path->addr, addr, addrlen);
    path->addrlen = addrlen;
    path->next = mud->path;
    mud->path = path;

    return path;
}

static
void mud_new_addr (struct mud *mud, struct sockaddr_storage *addr, socklen_t addrlen)
{
    int family;

    switch (addrlen) {
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
            mud_new_path(mud, sock->fd, addr, addrlen);
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

    socklen_t addrlen;

    switch (family) {
    case AF_INET:
        addrlen = INET_ADDRSTRLEN;
        break;
    case AF_INET6:
        addrlen = INET6_ADDRSTRLEN;
        break;
    default:
        return;
    }

    struct path *path;

    for (path = mud->path; path; path = path->next) {
        if (path->addrlen == addrlen)
            mud_new_path(mud, fd, &path->addr, path->addrlen);
    }
}

int mud_peer (struct mud *mud, const char *host, const char *port)
{
    if (!host || !port)
        return -1;

    struct addrinfo *p, *ai = mud_addrinfo(host, port, AI_NUMERICSERV);

    if (!ai)
        return -1;

    for (p = ai; p; p = p->ai_next)
        mud_new_addr(mud, (struct sockaddr_storage *)p->ai_addr, p->ai_addrlen);

    freeaddrinfo(ai);

    return 0;
}

int mud_bind (struct mud *mud, const char *host, const char *port)
{
    if (!host || !port)
        return -1;

    struct addrinfo *p, *ai = mud_addrinfo(host, port, AI_NUMERICSERV|AI_PASSIVE);

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

struct mud *mud_create (void)
{
    struct mud *mud = calloc(1, sizeof(struct mud));

    if (!mud)
        return NULL;

    mud->queue.packet = calloc(256, sizeof(struct packet));

    if (!mud->queue.packet) {
        free(mud);
        return NULL;
    }

    return mud;
}

void mud_delete (struct mud *mud)
{
    free(mud);
}

ssize_t mud_recv (struct mud *mud, void *data, size_t size)
{
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);

    uint32_t now = mud_now();

    if (!now) {
        errno = EAGAIN;
        return -1;
    }

    unsigned char buf[2048];
    struct sock *sock;
    ssize_t ret = 0;

    for (sock = mud->sock; sock; sock = sock->next) {
        ret = recvfrom(sock->fd, buf, sizeof(buf), 0, (struct sockaddr *)&addr, &addrlen);

        if (ret > 0)
            break;
    }

    if (ret <= 0)
        return ret;

    if (ret <= 4)
        return 0;

    struct path *path = mud_new_path(mud, sock->fd, &addr, addrlen);

    if (!path)
        return -1;

    uint32_t send_now = mud_read32(buf);

    if (!send_now) {
        send_now = mud_read32(&buf[4]);
        path->dt = mud_read32(&buf[8]);
        path->rtt = now-send_now;
        errno = EAGAIN;
        return -1;
    }

    if (path->count == 256) {
        unsigned char reply[3*4];
        uint32_t dt = (now-path->recv_time)>>8;
        path->count = 0;
        path->recv_time = now;
        memset(reply, 0, 4);
        memcpy(&reply[4], buf, 4);
        mud_write32(&reply[8], dt);
        mud_send_path(path, reply, sizeof(reply));
    } else {
        path->count++;
    }

    memcpy(data, &buf[4], ret-4);

    return ret-4;
}

void mud_flush (struct mud *mud, uint32_t time)
{
    while (mud->queue.start != mud->queue.end) {
        struct packet *packet = &mud->queue.packet[mud->queue.start];

        if (packet->time > time)
            break;

        mud->queue.start++;

        struct path *path = mud->path;
        ssize_t ret = mud_send_path(path, packet->data, packet->size);

        if (ret <= 0)
            continue;

        if (ret != packet->size)
            continue;

        if (path->count == 256) {
            path->count = 0;
            path->send_dt = (time-path->send_time)>>8;
            path->send_time = time;
        } else {
            path->count++;
        }
    }
}

ssize_t mud_send (struct mud *mud, const void *data, size_t size)
{
    if (size+4 > MUD_PKT_SIZE) {
        errno = EMSGSIZE;
        return -1;
    }

    uint32_t now = mud_now();

    if (!now) {
        errno = EAGAIN;
        return -1;
    }

    unsigned char next = mud->queue.end+1;

    if (mud->queue.start != next) {
        struct packet *packet = &mud->queue.packet[next];
        mud_write32(packet->data, now);
        memcpy(&packet->data[4], data, size);
        packet->size = size+4;
        packet->time = now;
        mud->queue.end = next;
    }

    mud_flush(mud, now);

    return size;
}

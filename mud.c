#include "mud.h"

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>

struct path {
    int fd;
    struct sockaddr_storage addr;
    socklen_t addrlen;
    struct path *next;
};

struct sock {
    int fd;
    int family;
    struct sock *next;
};

struct mud {
    struct sock *sock;
    struct path *path;
};

static
struct addrinfo *ai_create (const char *host, const char *port, int flags)
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

    for (path=mud->path; path; path=path->next) {
        if ((path->fd==fd) &&
            (path->addrlen==addrlen) &&
            (!memcmp(&path->addr, addr, addrlen)))
            break;
    }

    return path;
}

static
void mud_new_path (struct mud *mud, int fd, struct sockaddr_storage *addr, socklen_t addrlen)
{
    struct path *path = mud_get_path(mud, fd, addr, addrlen);

    if (path)
        return;

    path = malloc(sizeof(struct path));

    if (!path)
        return;

    path->fd = fd;
    memcpy(&path->addr, addr, addrlen);
    path->addrlen = addrlen;
    path->next = mud->path;
    mud->path = path;
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

    for (sock=mud->sock; sock; sock=sock->next) {
        if (sock->family==family)
            mud_new_path(mud, sock->fd, addr, addrlen);
    }
}

static
void mud_new_sock (struct mud *mud, int fd, int family)
{
    struct sock *sock = malloc(sizeof(struct sock));

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

    for (path=mud->path; path; path=path->next) {
        if (path->addrlen==addrlen)
            mud_new_path(mud, fd, &path->addr, path->addrlen);
    }
}

int mud_peer (struct mud *mud, const char *host, const char *port)
{
    if (!host || !port)
        return -1;

    struct addrinfo *p, *ai = ai_create(host, port, AI_NUMERICSERV);

    if (!ai)
        return -1;

    for (p=ai; p; p=p->ai_next)
        mud_new_addr(mud, (struct sockaddr_storage *)p->ai_addr, p->ai_addrlen);

    freeaddrinfo(ai);

    return 0;
}

int mud_bind (struct mud *mud, const char *host, const char *port)
{
    if (!host || !port)
        return -1;

    struct addrinfo *p, *ai = ai_create(host, port, AI_NUMERICSERV|AI_PASSIVE);

    if (!ai)
        return -1;

    for (p=ai; p; p=p->ai_next) {
        int fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);

        if (fd==-1)
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

    return 0;
}

// fake

struct mud *mud_create (void)
{
    return calloc(1, sizeof(struct mud));
}

void mud_delete (struct mud *mud)
{
    free(mud);
}

ssize_t mud_recv (struct mud *mud, void *data, size_t size)
{
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);

    if (!mud->sock)
        return 0;

    int fd = mud->sock->fd;

    ssize_t ret = recvfrom(fd, (uint8_t *)data, size, 0,
                               (struct sockaddr *)&addr, &addrlen);

    if (ret>0)
        mud_new_addr(mud, &addr, addrlen);

    return ret;
}

ssize_t mud_send (struct mud *mud, const void *data, size_t size)
{
    struct path *path = mud->path;

    if (!path)
        return 0;

    return sendto(path->fd, (uint8_t *)data, size, 0,
                            (struct sockaddr *)&path->addr, path->addrlen);
}

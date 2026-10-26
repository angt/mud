#pragma once

#include <stddef.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define MUD_PATH_MAX (32U)

struct mud;

enum mud_state {
    MUD_EMPTY = 0,
    MUD_DOWN,
    MUD_LISTENING,
    MUD_UP,
    MUD_LAST,
};

enum mud_path_status {
    MUD_DEAD = 0,
    MUD_PROBING,
    MUD_DEGRADED,
    MUD_LOSSY,
    MUD_BACKUP,
    MUD_READY,
};

struct mud_key {
    unsigned char b[32];
};

union mud_sockaddr {
    struct sockaddr sa;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
};

struct mud_path_conf {
    enum mud_state state;
    union mud_sockaddr local;
    union mud_sockaddr remote;
    uint64_t tx_max_rate;
    uint64_t rx_max_rate;
    uint64_t lat_limit;
    uint64_t beat;
    unsigned char pref;
    unsigned char loss_limit;
};

struct mud_path_info {
    struct mud_path_conf conf;
    union mud_sockaddr addr;
    enum mud_path_status status;
    uint64_t rtt;
};

struct mud_error {
    union mud_sockaddr addr;
    uint64_t time;
    uint64_t count;
};

struct mud_errors {
    struct mud_error decrypt;
    struct mud_error clocksync;
};

struct mud_paths {
    struct mud_path_info infos[MUD_PATH_MAX];
    unsigned count;
};

struct mud *mud_create (union mud_sockaddr, struct mud_key *);
void        mud_delete (struct mud *);

int mud_set_path (struct mud *, struct mud_path_conf);
int mud_update   (struct mud *);

ssize_t mud_recv (struct mud *, void *, size_t);
ssize_t mud_send (struct mud *, void *, size_t);

struct mud_errors mud_get_errors   (struct mud *);
int               mud_get_fd       (struct mud *);
uint64_t          mud_get_mtu      (struct mud *);
struct mud_paths  mud_get_paths    (struct mud *);
size_t            mud_get_overhead (struct mud *);

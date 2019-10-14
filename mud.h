#pragma once

#include <stddef.h>
#include <inttypes.h>
#include <sys/socket.h>

#define MUD_PATH_MAX    (32U)
#define MUD_PUBKEY_SIZE (32U)

struct mud;

enum mud_state {
    MUD_EMPTY = 0,
    MUD_DOWN,
    MUD_BACKUP,
    MUD_UP,
};

struct mud_pubkey {
    unsigned char remote[MUD_PUBKEY_SIZE];
    unsigned char local[MUD_PUBKEY_SIZE];
};

struct mud_stat {
    uint64_t val;
    uint64_t var;
    int setup;
};

struct mud_path {
    enum mud_state state;
    struct sockaddr_storage local_addr, addr, r_addr;
    struct mud_stat rtt;
    struct {
        uint64_t total;
        uint64_t bytes;
        uint64_t time;
        uint64_t msg_time;
        uint64_t rate;
        uint64_t rate_max;
        uint64_t loss;
    } tx, rx;
    struct {
        size_t min;
        size_t max;
        size_t probe;
        size_t ok;
    } mtu;
    uint64_t window;
    uint64_t window_time;
    struct mud_pubkey pk;
    unsigned char ok;
    unsigned msg_sent;
};

struct mud *mud_create (struct sockaddr *);
void        mud_delete (struct mud *);

int mud_get_fd  (struct mud *);

int mud_set_key (struct mud *, unsigned char *, size_t);
int mud_get_key (struct mud *, unsigned char *, size_t *);

void   mud_set_mtu (struct mud *, size_t);
size_t mud_get_mtu (struct mud *);

long mud_send_wait (struct mud *);

int mud_set_time_tolerance (struct mud *, unsigned long);
int mud_set_keyx_timeout   (struct mud *, unsigned long);
int mud_set_tc             (struct mud *, int);
int mud_set_aes            (struct mud *);

int mud_set_state (struct mud *, struct sockaddr *, enum mud_state,
                   unsigned long, unsigned long);

int mud_peer (struct mud *, struct sockaddr *);

int mud_recv (struct mud *, void *, size_t);
int mud_send (struct mud *, const void *, size_t, unsigned);

struct mud_path *mud_get_paths(struct mud *, unsigned *);

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
    MUD_LAST,
};

struct mud_stat {
    uint64_t val;
    uint64_t var;
    int setup;
};

struct mud_conf {
    uint64_t keepalive;
    uint64_t timetolerance;
    uint64_t kxtimeout;
    int tc;
};

struct mud_path_conf {
    enum mud_state state;
    uint64_t tx_max_rate;
    uint64_t rx_max_rate;
    uint64_t beat;
    unsigned char fixed_rate;
    unsigned char loss_limit;
};

struct mud_path {
    struct mud_path_conf conf;
    struct sockaddr_storage local_addr, addr, r_addr;
    struct mud_stat rtt;
    struct {
        uint64_t total;
        uint64_t bytes;
        uint64_t time;
        uint64_t rate;
        uint64_t loss;
    } tx, rx;
    struct {
        struct {
            uint64_t total;
            uint64_t bytes;
            uint64_t time;
            uint64_t acc;
            uint64_t acc_time;
        } tx, rx;
        uint64_t time;
        uint64_t sent;
        uint64_t set;
    } msg;
    struct {
        size_t min;
        size_t max;
        size_t probe;
        size_t last;
        size_t ok;
    } mtu;
    int passive;
    uint64_t idle;
    unsigned char ok;
};

struct mud_bad {
    struct {
        struct sockaddr_storage addr;
        uint64_t time;
        uint64_t count;
    } decrypt, difftime, keyx;
};

struct mud *mud_create (struct sockaddr *);
void        mud_delete (struct mud *);

int mud_update    (struct mud *);
int mud_send_wait (struct mud *);

int    mud_get_fd  (struct mud *);
size_t mud_get_mtu (struct mud *);
int    mud_get_bad (struct mud *, struct mud_bad *);

int mud_set      (struct mud *, struct mud_conf *);
int mud_set_key  (struct mud *, unsigned char *, size_t);
int mud_set_aes  (struct mud *);
int mud_set_path (struct mud *, struct sockaddr *, struct sockaddr *, struct mud_path_conf *);

int mud_recv (struct mud *, void *, size_t);
int mud_send (struct mud *, const void *, size_t);

struct mud_path *mud_get_paths(struct mud *, unsigned *);

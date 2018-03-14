#pragma once

#include <stddef.h>
#include <inttypes.h>
#include <sys/socket.h>

#define MUD_KISS_SIZE (8U)

struct mud;

enum mud_state {
    MUD_EMPTY = 0,
    MUD_DOWN,
    MUD_BACKUP,
    MUD_UP,
};

struct mud_path {
    enum mud_state state;
    struct sockaddr_storage local_addr, addr, r_addr;
    unsigned char kiss[MUD_KISS_SIZE];
    struct {
        uint64_t send_time;
        int remote;
    } conf;
    uint64_t send_max;
    uint64_t send_max_time;
    uint64_t recv_max;
    uint64_t recv_max_time;
    uint64_t rtt;
    uint64_t rst;
    uint64_t r_rst;
    uint64_t r_rms;
    uint64_t r_rmt;
    uint64_t limit;
    uint64_t recv_time;
    uint64_t send_time;
    uint64_t stat_time;
    struct {
        size_t ok;
        size_t probe;
        uint64_t time;
    } mtu;
};

struct mud *mud_create (struct sockaddr *);
void        mud_delete (struct mud *);

int mud_get_fd  (struct mud *);

int mud_set_key (struct mud *, unsigned char *, size_t);
int mud_get_key (struct mud *, unsigned char *, size_t *);

void   mud_set_mtu (struct mud *, size_t);
size_t mud_get_mtu (struct mud *);

int mud_set_send_timeout   (struct mud *, unsigned long);
int mud_set_time_tolerance (struct mud *, unsigned long);
int mud_set_keyx_timeout   (struct mud *, unsigned long);
int mud_set_tc             (struct mud *, int);
int mud_set_aes            (struct mud *);

int mud_set_state (struct mud *, struct sockaddr *, enum mud_state);

int mud_peer (struct mud *, struct sockaddr *);

int mud_recv (struct mud *, void *, size_t);
int mud_send (struct mud *, const void *, size_t, int);

struct mud_path *mud_get_paths(struct mud *, unsigned *);

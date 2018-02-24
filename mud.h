#pragma once

#include <stddef.h>

struct mud;
struct sockaddr;

enum mud_state {
    MUD_UP = 0,
    MUD_BACKUP,
    MUD_DOWN,
    MUD_LAST,
};

struct mud *mud_create (struct sockaddr *);
void        mud_delete (struct mud *);

int mud_get_fd  (struct mud *);

int mud_set_key (struct mud *, unsigned char *, size_t);
int mud_get_key (struct mud *, unsigned char *, size_t *);

size_t mud_set_mtu (struct mud *, size_t);
size_t mud_get_mtu (struct mud *);

int mud_set_send_timeout   (struct mud *, unsigned long);
int mud_set_time_tolerance (struct mud *, unsigned long);
int mud_set_tc             (struct mud *, int);
int mud_set_aes            (struct mud *);

int mud_set_state (struct mud *, struct sockaddr *, enum mud_state);

int mud_peer (struct mud *, struct sockaddr *);

int mud_recv (struct mud *, void *, size_t);
int mud_send (struct mud *, const void *, size_t, int);

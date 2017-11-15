#pragma once

#include <stddef.h>

struct mud;

struct mud *mud_create (int, int, int, int);
void        mud_delete (struct mud *);

int mud_get_fd  (struct mud *);

int mud_new_key (struct mud *);
int mud_set_key (struct mud *, unsigned char *, size_t);
int mud_get_key (struct mud *, unsigned char *, size_t *);

int mud_set_mtu (struct mud *, int mtu);
int mud_get_mtu (struct mud *);

int mud_set_send_timeout_msec  (struct mud *, unsigned);
int mud_set_time_tolerance_sec (struct mud *, unsigned);
int mud_set_tc                 (struct mud *, int);
int mud_set_aes                (struct mud *);

int mud_peer (struct mud *, const char *, const char *, int, int);

int mud_recv (struct mud *, void *, size_t);
int mud_send (struct mud *, const void *, size_t, int);

#pragma once

#include <stddef.h>

struct mud;
struct sockaddr;

struct mud *mud_create (struct sockaddr *, int, int);
void        mud_delete (struct mud *);

int mud_get_fd  (struct mud *);

int mud_set_key (struct mud *, unsigned char *, size_t);
int mud_get_key (struct mud *, unsigned char *, size_t *);

int mud_set_mtu (struct mud *, int mtu);
int mud_get_mtu (struct mud *);

int mud_set_send_timeout   (struct mud *, unsigned long);
int mud_set_time_tolerance (struct mud *, unsigned long);
int mud_set_tc             (struct mud *, int);
int mud_set_aes            (struct mud *);

int mud_peer (struct mud *, struct sockaddr *);

int mud_add_path (struct mud *, struct sockaddr *);
int mud_del_path (struct mud *, struct sockaddr *);

int mud_recv (struct mud *, void *, size_t);
int mud_send (struct mud *, const void *, size_t, int);

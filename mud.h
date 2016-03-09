#pragma once

#include <stddef.h>

struct mud;

struct mud *mud_create (const char *);
void        mud_delete (struct mud *);

int mud_set_key (struct mud *, unsigned char *, size_t);
int mud_get_fd  (struct mud *);

int mud_bind (struct mud *, const char *);
int mud_peer (struct mud *, const char *, const char *);

int mud_can_pull (struct mud *);

int mud_pull (struct mud *);
int mud_push (struct mud *);

int mud_recv (struct mud *, void *, size_t);
int mud_send (struct mud *, const void *, size_t);

#pragma once

#include <stddef.h>

struct mud;

struct mud *mud_create (const unsigned char *, size_t);
void        mud_delete (struct mud *);

int mud_bind (struct mud *, const char *, const char *);
int mud_peer (struct mud *, const char *, const char *);

int mud_pull (struct mud *);
int mud_push (struct mud *);

int mud_recv (struct mud *, void *, size_t);
int mud_send (struct mud *, const void *, size_t);

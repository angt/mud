#pragma once

#include <unistd.h>

struct mud;

struct mud *mud_create (void);
void        mud_delete (struct mud *);

int mud_bind (struct mud *, const char *, const char *);
int mud_peer (struct mud *, const char *, const char *);

ssize_t mud_recv (struct mud *, void *, size_t);
ssize_t mud_send (struct mud *, const void *, size_t);

# MUD standalone build (see also meson.build at repo root for glorytun).
CC     = cc
CFLAGS = -Wall -O2 -std=gnu99
LDLIBS = -lsodium

# Legacy loopback demo (manual two processes or single process with argv)
mudtest: test.c
	$(CC) $(CFLAGS) -o mudtest test.c $(LDLIBS)

# Reliable delivery integration tests (requires MUD_TEST hooks in mud.c)
t_reliable_echo: t_reliable_echo.c
	$(CC) $(CFLAGS) -DMUD_TEST -o t_reliable_echo t_reliable_echo.c $(LDLIBS)

test: t_reliable_echo
	@echo "[1/2] reliable echo (loopback)"
	./t_reliable_echo
	@echo "[2/2] reliable echo with first UDP recv dropped (retransmit)"
	@MUD_TEST_DROP_INCOMING=1 ./t_reliable_echo
	@echo "All MUD tests passed."

clean:
	rm -f mudtest t_reliable_echo test

.PHONY: test clean mudtest t_reliable_echo

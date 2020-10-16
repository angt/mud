CC     = cc
CFLAGS = -Wall -O2
LDLIBS = -lsodium

test:
	$(CC) $(CFLAGS) -o test test.c $(LDLIBS)

clean:
	rm -f test

.PHONY: test clean

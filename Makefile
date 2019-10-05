CFLAGS=-march=native -O2
LDLIBS=-lsodium

test:

.PHONY: clean
clean:
	rm -f test

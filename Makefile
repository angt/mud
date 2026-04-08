CFLAGS = -march=native -Wall -O2 -g -fsanitize=address,undefined
LDLIBS = -lsodium

all: clean test
	./test & ./test hello

clean:
	rm -f test

.PHONY: clean all

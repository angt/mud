CFLAGS = -march=native -Wall -O2 -g -fsanitize=address,undefined
LDLIBS = -lsodium

ifeq ($(shell uname -s),Darwin)
CFLAGS  += -I$(shell brew --prefix libsodium)/include
LDFLAGS += -L$(shell brew --prefix libsodium)/lib
endif

all: clean test
	./test & ./test hello

clean:
	rm -f test

.PHONY: clean all

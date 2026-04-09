CFLAGS  = -march=native -Wall -O2 -g -fsanitize=address,undefined
LDFLAGS = -fsanitize=address,undefined

COMMON_C = mud.c aegis256/aegis256.c charm/src/charm.c
COMMON_O = $(COMMON_C:.c=.o)

all: clean test
	./test & ./test hello

test: $(COMMON_O)

clean:
	rm -f test

.PHONY: clean all
.INTERMEDIATE: $(COMMON_O) test.o

CC=gcc
CFLAGS=-std=c11 -pedantic -Wall -Werror -Wextra -D_FORTIFY_SOURCE=2 -O3 -fPIC -fstack-protector-all -pie -s
LDFLAGS=-lgmp -lsqlite3 -lm


signed-clock: digital-seconds-ago.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clear:
	rm digital-seconds-ago

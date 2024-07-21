CC=gcc
CFLAGS=-Wall -Wpedantic -O3
LDLIBS=-lcjson -lkcgi -lsqlite3

objs=ksync.o db.o

ksync: $(objs)
	$(CC) -o $@ $(objs) $(CFLAGS) $(LDLIBS)

.c.o:
	$(CC) $< -o $@ -c $(CFLAGS)

.PHONY: clean
clean:
	rm ksync *.o

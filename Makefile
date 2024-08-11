CFLAGS=-Wall -Wextra -Wpedantic -O3 -I/usr/local/include
LDLIBS=-lcjson -lkcgi -lsqlite3 -L/usr/local/lib

objs=ksync.o db.o

ksync: $(objs)
	$(CC) -o $@ $(objs) $(CFLAGS) $(LDLIBS)

.c.o:
	$(CC) $< -o $@ -c $(CFLAGS)

.PHONY: clean
clean:
	rm -f ksync *.o

CC	:= gcc
CFLAGS	?= -O2 -g -Wall

COMPEL		:= ../compel/compel-host

all: dsm_client

clean:
	rm -f dsm_client
	rm -f parasite.h
	rm -f parasite.po
	rm -f parasite.o


dsm_client: dsm_client.c parasite.h 
	$(CC) $(CFLAGS) $(shell $(COMPEL) includes) -o $@ $<  parsemap.c $(shell $(COMPEL) --static libs) -lpthread

parasite.h: parasite.po
	$(COMPEL) hgen -o $@ -f $<

parasite.po: parasite.o
	ld $(shell $(COMPEL) ldflags) -o $@ $^ $(shell $(COMPEL) plugins) $(shell $(COMPEL) plugins fds)

parasite.o: parasite.c
	$(CC) $(CFLAGS) -c $(shell $(COMPEL) cflags) -o $@ $^

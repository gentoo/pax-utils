CFLAGS := -Wall

OBJS = paxelf.o isetdyn.o scanexec.o

all: depend $(OBJS) isetdyn scanexec

%.o: %.c
	$(CC) $(CFLAGS) -c $<

isetdyn:
	$(CC) $(CFLAGS) -o isetdyn paxelf.o isetdyn.o -ldl

scanexec:
	$(CC) $(CFLAGS) -o scanexec paxelf.o scanexec.o

depend:
	$(CC) $(CFLAGS) -M *.c > .depend
clean:
	@rm -f $(OBJS)
	@rm -f isetdyn scanexec

distclean: clean
	@rm -f *~ core
	echo -n > .depend

include .depend

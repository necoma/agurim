PREFIX?=	/usr/local
INSTALL?=	/usr/bin/install

PROGS = agurim aguri3
COMMON_OBJS = odflow.o hhh.o agurim_plot.o agurim_subr.o
AGURIM_OBJS = agurim.o $(COMMON_OBJS)
AGURI3_OBJS = aguri3.o pcap_parse.o ip_parse.o $(COMMON_OBJS)
DEFINES = -DINET6
CFLAGS = -O3 -Wall -DNDEBUG $(DEFINES)
#CFLAGS = -g -Wall $(DEFINES)

all: $(PROGS)

agurim: $(AGURIM_OBJS);   $(CC) $(CFLAGS) -o $@ $(AGURIM_OBJS) -lm

aguri3: $(AGURI3_OBJS);   $(CC) $(CFLAGS) -o $@ $(AGURI3_OBJS) -lpcap -lpthread -lm

install: $(PROG)
	$(INSTALL) -m 0755 $(PROGS) $(PREFIX)/bin

clean:;	-rm -f $(PROGS) *.o core *.core *~

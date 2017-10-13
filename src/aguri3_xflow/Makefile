PREFIX?=	/usr/local
INSTALL?=	/usr/bin/install

PROGS=	aguri3_xflow
OBJS=	aguri3_xflow.o sflow_parse.o ip_parse.o netflow_parse.o netflow_v9.o pcap_parse.o

CFLAGS=		-O3 -Wall
DEFINES=	-DINET6
INCLUDES=	-I. $(SYS_INCLUDES)
LIBS=		$(SYS_LIBS)

# pcap support
#DEFINES+=	-DPCAP
#LIBS+=		-lpcap

all: $(PROGS)

install: $(PROGS)
	$(INSTALL) -m 0755 aguri3_xflow $(PREFIX)/bin

aguri3_xflow: $(OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) $(DEFINES) -o $@ $(OBJS) $(LIBS)

.c.o: 
	$(CC) $(CFLAGS) $(INCLUDES) $(DEFINES) -c $*.c

clean:;	-rm -f $(PROGS) *.o core *.core *~

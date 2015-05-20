PREFIX?=	/usr/local
INSTALL?=	/usr/bin/install

PROG = agurim
OBJS = odflow.o hhh.o agurim_plot.o agurim_subr.o agurim.o
CFLAGS = -O3 -Wall -DNDEBUG
#CFLAGS = -g -Wall 

all: $(PROG)

agurim: $(OBJS);    $(CC) $(CFLAGS) -o $@ $(OBJS) -lm

install: $(PROG)
	$(INSTALL) -m 0755 $(PROG) $(PREFIX)/bin

clean:;	-rm -f $(PROG) *.o core *.core *~

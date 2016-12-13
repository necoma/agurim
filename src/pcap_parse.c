/*
 * Copyright (C) 2001-2016 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    - Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    - Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <pcap.h>

#include "aguri_flow.h"
#include "agurim.h"

void etherhdr_parse(const char *p, int len);

struct aguri_flow aguri_flow;

/*
 * The default snapshot length.  This value allows most printers to print
 * useful information while keeping the amount of unwanted data down.
 * In particular, it allows for an ethernet header, tcp/ip6 header, and
 * 14 bytes of data (assuming no ip options).
 */
#define DEFAULT_SNAPLEN 96

static pcap_t *pd;
static char errbuf[PCAP_ERRBUF_SIZE];
static int done = 0;

static void dump_reader(u_char *user, const struct pcap_pkthdr *h, const u_char *p);
static void ether_if_read(u_char *user, const struct pcap_pkthdr *h, const u_char *p);

/* a function switch to read different types of frames */
static void (*net_reader)(u_char *user, const struct pcap_pkthdr *h, const u_char *p);

struct printer {
	pcap_handler f;
	int type;
};

static struct printer printers[] = {
	{ ether_if_read,	DLT_EN10MB },
#if 0
	{ ppp_if_read,	DLT_PPP },
	{ null_if_read,	DLT_NULL },
#endif	
	{ NULL,			0 },
};

static pcap_handler
lookup_printer(int type)
{
	struct printer *p;

	for (p = printers; p->f; ++p)
		if (type == p->type)
			return p->f;

	errx(1, "lookup_printer: unknown data link type 0x%x", type);
	/* NOTREACHED */
	return NULL;
}

void
pcap_read(const char *dumpfile, const char *interface, 
	const char *filter_cmd, int snaplen)
{
	const char *device = NULL;
	struct bpf_program bprog;
	int n = 0;

	if (dumpfile != NULL) {
		/* read from a saved pcap file */
		pd = pcap_open_offline(dumpfile, errbuf);
		if (pd == NULL)
			err(1, "%s", errbuf);
	} else {
		if (interface != NULL) {
			device = interface;
		} else {
			device = pcap_lookupdev(errbuf);
			if (device == NULL)
				errx(1, "%s", errbuf);
		}
		if (snaplen == 0)
			snaplen = DEFAULT_SNAPLEN;
		fprintf(stderr, "pcap_read: reading from %s with snaplen:%d\n", 
			device, snaplen);
		pd = pcap_open_live(device, snaplen, 1, 0, errbuf);
		if (pd == NULL)
			errx(1, "%s", errbuf);
	}

	if (pcap_compile(pd, &bprog, filter_cmd, 0, 0) < 0)
		err(1, "pcap_compile: %s", pcap_geterr(pd));
	else if (pcap_setfilter(pd, &bprog) < 0)
		err(1, "pcap_setfilter: %s", pcap_geterr(pd));

	net_reader = lookup_printer(pcap_datalink(pd));

	if (device != NULL) {
		/* let user own process after interface has been opened */
		setuid(getuid());
#if defined(BSD) && defined(BPF_MAXBUFSIZE)
		{
			/* check the buffer size */
			u_int bufsize;
			int fd = pcap_fileno(pd);

			if (ioctl(fd, BIOCGBLEN, (caddr_t)&bufsize) < 0)
				perror("BIOCGBLEN");
			else
				fprintf(stderr, "bpf buffer size is %d\n", bufsize);
		}
#endif /* BSD */
	}

	while (1) {
		int cnt;

		cnt = pcap_dispatch(pd, 1, dump_reader, 0);
		if (cnt < 0 || done)
			break;
		if (dumpfile != NULL && cnt == 0)
			/* EOF */
			break;
		n += cnt;
		if (query.count != 0 && n >= query.count)
			break;
	}

	pcap_close(pd);
}

static void
dump_reader(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
	int rval;

	/* clear aguri_flow to be filled in parsers */
	memset(&aguri_flow, 0, sizeof(aguri_flow));
	aguri_flow.agflow_packets = htonl(1);
	aguri_flow.agflow_bytes = htonl(h->len);
	aguri_flow.agflow_first = aguri_flow.agflow_last = 
		htonl((u_int32_t)h->ts.tv_sec);

	(*net_reader)(user, h, p);

	if (aguri_flow.agflow_fs.fs_ipver == 0)
		/* not a IP packet */
		return;

	rval = check_flowtime(&aguri_flow);
	if (rval < 0)
		done = 1;
	else if (rval > 0)
		do_agflow(&aguri_flow);
}

static void
ether_if_read(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
	etherhdr_parse((const char *)p, h->caplen);
}

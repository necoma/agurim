/*
 * Copyright (C) 2014-2015 WIDE Project.
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

#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/queue.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <poll.h>
#include <errno.h>
#include <err.h>

#include "../aguri_flow.h"
#include "aguri3_xflow.h"

#define FLOWTYPE_SFLOW		1
#define FLOWTYPE_NETFLOW	2
#define FLOWTYPE_PCAP		3

#ifndef INFTIM	/* for linux */
#define	INFTIM		(-1)
#endif

/* agent_info is used to keep track of agents */
struct agent_info {
	int	agent_id;
	struct sockaddr_storage agent_addr;
	LIST_ENTRY(agent_info) entries;
};

LIST_HEAD(agent_list, agent_info) agent_head = LIST_HEAD_INITIALIZER(agent_head);
int	verbose;
int	debug;
int	port = 0;	/* port number to reveive flow records */
int	sflow_defport   = 6343;	/* default sFlow port */
int	netflow_defport = 2055;	/* default NetFlow port */
int	flow_type = 0;	/* FLOWTYPE_SFLOW or FLOWTYPE_NETFLOW */
int	default_samprate = 1;  /* default sampling rate */
int	family = AF_UNSPEC;	/* address family */
int	cur_agentid = 0;	/* current agent id */
char	*agentname = NULL;
char	buffer[8192];	/* buffer for flow datagram */
#ifdef PCAP
const char *dumpfile = NULL;
const char *interface = NULL;
const char *filter_cmd = NULL;
int	snaplen = 0;
#endif

static void usage(void);
static void *sockaddr2addr(const struct sockaddr *sa, int *plen);
static int is_addr_equal(const struct sockaddr *a, const struct sockaddr *b);
static int check_agent(struct sockaddr *sa, socklen_t sa_len);
int	read_from_socket(void);

static	void
usage(void)
{
	fprintf(stderr,
	    "usage: aguri2_xflow [-46dhv] [-t sflow | netflow] [-p port] [-s sampling_rate] [-a agent]\n");
#ifdef PCAP
	fprintf(stderr,
	    "       aguri2_xflow [-dhv] -t pcap [-i interface] [-r dumpfile] [-f filter_cmd] [-s snaplen]\n");
#endif	
	exit(1);
}

int
main(int argc, char **argv)
{
	int	i;
	char	*flow_typename = NULL;

	while ((i = getopt(argc, argv, "46a:df:i:p:r:s:t:v")) != -1) {
		switch (i) {
		case '4':
			family = AF_INET;
			break;
		case '6':
			family = AF_INET6;
			break;
	        case 'a':
			agentname = optarg;
			break;
		case 'd':
			debug++;
			break;
#ifdef PCAP
	        case 'f':
			filter_cmd = optarg;
			break;
	        case 'i':
			interface = optarg;
			break;
#endif
	        case 'p':
			port = atoi(optarg);
			break;
#ifdef PCAP
	        case 'r':
			dumpfile = optarg;
			break;
#endif
	        case 's':
			default_samprate = atoi(optarg);
#ifdef PCAP
			snaplen = atoi(optarg);
#endif			
			break;
	        case 't':
			flow_typename = optarg;
			break;
		case 'v':
			verbose++;
			break;
		default:
			usage();
		}
	}
	if (flow_typename == NULL || strcasecmp(flow_typename, "sflow") == 0) {
		flow_type = FLOWTYPE_SFLOW;
		if (port == 0)
			port = sflow_defport;
	} else if (strcasecmp(flow_typename, "netflow") == 0) {
		flow_type = FLOWTYPE_NETFLOW;
		if (port == 0)
			port = netflow_defport;
#ifdef PCAP
	} else if (strcasecmp(flow_typename, "pcap") == 0) {
		flow_type = FLOWTYPE_PCAP;
#endif		
	} else
		usage();

#ifdef PCAP
	if (flow_type == FLOWTYPE_PCAP) {
		pcap_read(dumpfile, interface, filter_cmd, snaplen);
		return (0);
	}
#endif	
	read_from_socket();

	return (0);
}

static void *
sockaddr2addr(const struct sockaddr *sa, int *plen)
{
	void *p = NULL;
	int len = 0;

	if (sa->sa_family == AF_INET) {
		p =  &((struct sockaddr_in *)sa)->sin_addr;
		len = 4;
	} else if (sa->sa_family == AF_INET6) {
		p = &((struct sockaddr_in6 *)sa)->sin6_addr;
		len = 16;
	}
	if (plen != NULL)
		*plen = len;
	return (p);
}

static int
is_addr_equal(const struct sockaddr *a, const struct sockaddr *b)
{
	void *a0, *a1;
	int len;

	if (a->sa_family != b->sa_family)
		return (-1);
	a0 = sockaddr2addr(a, &len);
	a1 = sockaddr2addr(b, NULL);
	return (memcmp(a0, a1, len));
}

static int
check_agent(struct sockaddr *sa, socklen_t sa_len)
{
	struct agent_info *ap;
	char name[INET6_ADDRSTRLEN];
	int error, ignore = 0;
	static int id4agent = 1;

	LIST_FOREACH(ap, &agent_head, entries) {
		if (is_addr_equal(sa, (struct sockaddr *)&ap->agent_addr) == 0) {
			/* matching entry found */
			cur_agentid = ap->agent_id;
			return(ap->agent_id);  /* save agent_id */
		}
	}

	/* this is a new agent */
	/* if agentname is specified, check it */
	if (agentname != NULL) {
		struct addrinfo hints, *res;
		static struct addrinfo *agent_res = NULL;

		if (agent_res == NULL) {
			memset(&hints, 0, sizeof(hints));
			hints.ai_socktype = SOCK_DGRAM;
			if ((error = getaddrinfo(agentname, NULL, &hints, &agent_res)) != 0)
				err(1, "getaddrinfo: %s", gai_strerror(error));
		}
		/* find a matching family */
		for (res = agent_res; res != NULL; res = res->ai_next)
			if (is_addr_equal(sa, (struct sockaddr *)res->ai_addr) == 0)
				break;  /* match found */
		if (res == NULL)
			ignore = 1;  /* no match, ignore this agent */
	}

#define MAX_AGENTS	20
	inet_ntop(sa->sa_family, sockaddr2addr(sa, NULL), name, sizeof(name));
	if (id4agent > MAX_AGENTS) {
		/* protection against dos attack */
		if (id4agent == MAX_AGENTS + 1) {
			fprintf(stderr, "too many agents:  [%s] ignored\n", name);
			id4agent++;
		}
		return (-(MAX_AGENTS + 1));
	}
	if (ignore)
		fprintf(stderr, "ignoring agent [%s] ....\n", name);
	else
		fprintf(stderr, "reading from agent [%s] ....\n", name);
	
	/* create a new entry and prepend to the list */
	if ((ap = malloc(sizeof(*ap))) == NULL)
		err(1, "malloc");
	ap->agent_id = id4agent++;
	if (ignore)
		ap->agent_id = 0 - ap->agent_id; /* set the negative value */
	memcpy(&ap->agent_addr, sa, sa_len);
	LIST_INSERT_HEAD(&agent_head, ap, entries);

	cur_agentid = ap->agent_id;  /* save agent_id */
	return(ap->agent_id);
}

int
read_from_socket(void)
{
	struct addrinfo hints, *res, *res0;
	struct	sockaddr_storage from_addr;
	socklen_t	fromlen;
	struct pollfd pfds[1];
	int	s, nbytes, i, error;
	int	nsockets = 0;
	char portname[16];

	memset(&hints, 0, sizeof(hints));
	hints.ai_family   = family;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags    = AI_PASSIVE | AI_NUMERICSERV;

	snprintf(portname, sizeof(portname), "%d", port);
	if ((error = getaddrinfo(NULL, portname, &hints, &res0)) != 0)
		err(1, "getaddrinfo: %s", gai_strerror(error));

	for (res = res0; res != NULL; res = res->ai_next) {
		if ((s = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0)
			err(1, "socket");
		if (res->ai_family == AF_INET6) {
			/* need to set V6ONLY to fix EADDRINUSE on linux */
			int on = 1;
			if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, 
			    &on, sizeof(on)) < 0)
				err(1, "setsockopt: V6ONLY");
		}
		if (bind(s, res->ai_addr, res->ai_addrlen) < 0)
			err(1, "bind");

		pfds[nsockets++].fd = s;
	}
	freeaddrinfo(res0);
	if (nsockets == 0)
		errx(1, "cannot connect to %s", agentname);

	while (1) {
		int nfound;

		for (i = 0; i < nsockets; i++) {
			pfds[i].events = POLLIN;
			pfds[i].revents = 0;
		}
		nfound = poll(pfds, nsockets, INFTIM);
		if (nfound == -1) {
			if (errno == EINTR) {
				/* interrupt occured */
				warn("poll interrupted");
				continue;
			} else
				err(1, "poll");
		}
		if (nfound == 0) {
			warnx("poll returns 0!");
			continue;
		}
		for (i = 0; i < nsockets; i++)
			if (pfds[i].revents & POLLIN) {
				s = pfds[i].fd;
				break;
			}
		if (i == nsockets)
			continue;
		fromlen = sizeof(from_addr);
		if ((nbytes = recvfrom(s, buffer, sizeof(buffer), 0,
				(struct sockaddr *)&from_addr, &fromlen)) == -1)
			err(1, "recvfrom");
		if (nbytes < 24) {
			warnx("packet too short! %d bytes\n", nbytes);
			continue;
		}

		if (check_agent((struct sockaddr *)&from_addr, fromlen) < 0)
			continue;

		if (flow_type == FLOWTYPE_SFLOW)
			parse_sflow_datagram(buffer, nbytes);
		else
			parse_netflow_datagram(buffer, nbytes);
	}

	close(s);

	return (0);
}

int
print_flow(struct aguri_flow *afp)
{
	struct flow_spec *fs = &afp->agflow_fs;
	char srcbuf[INET6_ADDRSTRLEN];
	char dstbuf[INET6_ADDRSTRLEN];
	char timestr[64];
	int af = AF_INET;
	time_t	ts;
	struct tm *tm;

	ts = ntohl(afp->agflow_last);
	tm = localtime(&ts);
	strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", tm);

	if (fs->fs_ipver == 6)
		af = AF_INET6;
	inet_ntop(af, &fs->fs_srcaddr, srcbuf, sizeof(srcbuf));
	inet_ntop(af, &fs->fs_dstaddr, dstbuf, sizeof(dstbuf));
	
	return printf("%s  %s %u > %s %u proto:%u bytes:%u packets:%u\n",
		timestr,
		srcbuf, ntohs(fs->fs_sport), dstbuf, ntohs(fs->fs_dport),
		fs->fs_prot, ntohl(afp->agflow_bytes), ntohl(afp->agflow_packets));
}

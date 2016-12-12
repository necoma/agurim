/* ip_parse.c -- a module to read ethernet packets.
   most parts are derived from tcpdump. */
/*
 * Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/*
 * tcpdump - monitor tcp/ip traffic on an ethernet.
 *
 * First written in 1987 by Van Jacobson, Lawrence Berkeley Laboratory.
 * Mercilessly hacked and occasionally improved since then via the
 * combined efforts of Van, Steve McCanne and Craig Leres of LBL.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#define __FAVOR_BSD
#include <netinet/tcp.h>
#include <netinet/udp.h>
#ifdef INET6
#include <netinet/ip6.h>
#endif
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>

#include "aguri_flow.h"
#include "agurim.h"
#include "ip_parse.h"

#ifndef IP_V
#define IP_V(ip)	((ip)->ip_v)
#define IP_HL(ip)	((ip)->ip_hl)
#endif
#define IP4F_TABSIZE		64	/* IPv4 fragment cache size */

void etherhdr_parse(const char *p, int len);
static int ether_encap_parse(const char *p, int len, const u_short ethtype);
static int llc_parse(const char *p, int le);
static int ip_parse(const char *p, int len);
static int do_ipproto(int proto, const char *bp, int len);
static void ip4f_cache(struct ip *, struct udphdr *, time_t ts);
static struct udphdr *ip4f_lookup(struct ip *);
static int ip4f_init(void);
static struct ip4_frag *ip4f_alloc(void);
static void ip4f_free(struct ip4_frag *);
#ifdef INET6
static int ip6_parse(const char *p, int len);
static int read_ip6hdr(struct ip6_hdr *ip6, int *proto, int len);
static int do_ip6nexthdr(int proto, const char *bp, int len);
#endif

extern struct aguri_flow aguri_flow;

struct ip4_frag {
	TAILQ_ENTRY(ip4_frag) ip4f_chain;
	char    ip4f_valid;
	u_char ip4f_proto;
	u_short ip4f_id;
	struct in_addr ip4f_src, ip4f_dst;
	struct udphdr ip4f_udphdr;
	time_t ip4f_time;
};

static TAILQ_HEAD(ip4f_list, ip4_frag) ip4f_list; /* IPv4 fragment cache */

void
etherhdr_parse(const char *p, int len)
{
	struct ether_header *eh;
	u_short ether_type;

	if (len < sizeof(struct ether_header)) {
		return;
	}

	eh = (struct ether_header *)p;
	ether_type = (u_short)ntohs(eh->ether_type);
	p += sizeof(struct ether_header);
	len -= sizeof(struct ether_header);
	
	if (verbose > 1)
		fprintf(stderr, "etherhdr: type:0x%x len:%u\n", ether_type, len);

#ifdef ETHERTYPE_VLAN
	if (ether_type == ETHERTYPE_VLAN) {
		if (len < sizeof(struct ether_header) + 4) {
			return;
		}
		ether_type = ntohs(*(u_int16_t *)(p + 2));
		p += 4;
		len -= 4;
	}
#endif

	if (ether_type < ETHERMTU) {
		if (llc_parse(p, len) == 0) {
			/* ether_type not known */
		}
	} else if (ether_encap_parse(p, len, ether_type) == 0) {
		/* ether_type not known */
	}
}

static int
ether_encap_parse(const char *p, int len, const u_short ethtype)
{
	switch (ethtype) {
	case ETHERTYPE_IP:
		ip_parse(p, len);
		break;
#ifdef INET6
	case ETHERTYPE_IPV6:
		ip6_parse(p, len);
		break;
#endif
	default:
		return (0);
	}
	return (1);
}

#ifndef min
#define min(a, b)	(((a)<(b))?(a):(b))
#endif
#define	ethertype	ctl.snap_ether.snap_ethertype

static int
llc_parse(const char *p, int len)
{
	struct llc llc;
	u_int16_t et;
	int ret;
    
	if (len < 3)
		return(0);

	/* Watch out for possible alignment problems */
	memcpy(&llc, p, min(len, sizeof(llc)));

	if (llc.ssap == LLCSAP_SNAP && llc.dsap == LLCSAP_SNAP
	    && llc.llcui == LLC_UI) {
		/* snap */
		if (len < sizeof(llc)) {
			return (0);
		}
		/* This is an encapsulated Ethernet packet */
#ifdef ALIGN_WORD
		{
			u_short tmp;
			memcpy(&tmp, &llc.ethertype[0], sizeof(u_int16_t));
			et = ntohs(tmp);
		}
#else
		et = ntohs(*(u_short *)&llc.ethertype[0]);
#endif
		ret = ether_encap_parse(p + sizeof(llc), len - sizeof(llc), et);
		if (ret)
			return (ret);
	}
	/* llcsap */
	return(0);
}
#undef ethertype

static int
ip_parse(const char *p, int len)
{
	struct ip *ip;
	int hlen, proto, off;
    
	ip = (struct ip *)p;
	if (len < sizeof(struct ip))
		return (0);
#ifdef ALIGN_WORD
	/*
	 * The IP header is not word aligned, so copy into abuf.
	 * This will never happen with BPF.  It does happen raw packet
	 * dumps from -r.
	 */
	if ((int)ip & (sizeof(u_int32_t)-1)) {
		static u_char *abuf;

		if (abuf == NULL)
			abuf = (u_char *)malloc(DEFAULT_SNAPLEN);
		memcpy(abuf, ip, len);
		ip = (struct ip *)abuf;
	}
#endif /* ALIGN_WORD */

	/* fill the ip info into aguri_flow */
	aguri_flow.agflow_fs.fs_ipver = 4;
	aguri_flow.agflow_fs.fs_srcaddr[0] = ip->ip_src.s_addr;
	aguri_flow.agflow_fs.fs_dstaddr[0] = ip->ip_dst.s_addr;
	aguri_flow.agflow_fs.fs_prot = ip->ip_p;

	hlen = IP_HL(ip) * 4;

	p = (char *)ip + hlen;
	len -= hlen;

	proto = ip->ip_p;
	if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
		/* if this is fragment zero, hand it to the next higher
		   level protocol. */
		off = ntohs(ip->ip_off);
		if (off & 0x1fff) {
			/* process fragments */
			if ((p = (char *)ip4f_lookup(ip)) == NULL)
				/* lookup failed */
				return (1);
			len = sizeof(struct udphdr);
		}

		do_ipproto(ip->ip_p, p, len);

		/* if this is a first fragment, cache it. */
		if ((off & IP_MF) && (off & 0x1fff) == 0) {
			ip4f_cache(ip, (struct udphdr *)p, aguri_flow.agflow_last);
		}
	} else {
		do_ipproto(ip->ip_p, p, len);
	}

	return (1);
}

static int
do_ipproto(int proto, const char *bp, int len)
{
	u_short sport, dport;

	sport = dport = 0;

	switch (proto) {
	case IPPROTO_TCP:
		if (len >= sizeof(struct tcphdr)) {
			/* long enough to get ports */
			struct tcphdr *tcp = (struct tcphdr *)bp;
			sport = tcp->th_sport;
			dport = tcp->th_dport;
		}
		break;
	case IPPROTO_UDP:
		if (len >= sizeof(struct udphdr)) {
			/* long enough to get ports */
			struct udphdr *udp = (struct udphdr *)bp;
			sport = udp->uh_sport;
			dport = udp->uh_dport;
		}
		break;
	case IPPROTO_ICMP:
		/* take icmp_type and icmp_code as port */
		if (len >= 2)
			sport = dport = *(u_short *)bp;
		break;
	}

	/* fill in the port info into aguri_flow */
	aguri_flow.agflow_fs.fs_sport = sport;
	aguri_flow.agflow_fs.fs_dport = dport;

	if (verbose > 0)
		fprintf(stderr, "ip proto:%u sport:%u dport:%u\n",
			      proto, ntohs(sport), ntohs(dport));

	return (1);
}

#ifdef INET6
/* this version doesn't handle fragments */
static int
ip6_parse(const char *p, int len)
{
	struct ip6_hdr *ip6;
	int hlen, proto;

	ip6 = (struct ip6_hdr *)p;
	if (len < sizeof(struct ip6_hdr))
		return (0);
#ifdef ALIGN_WORD
	/*
	 * The IP header is not word aligned, so copy into abuf.
	 * This will never happen with BPF.  It does happen raw packet
	 * dumps from -r.
	 */
	if ((int)ip6 & (sizeof(u_int32_t)-1)) {
		static u_char *abuf;

		if (abuf == NULL)
			abuf = (u_char *)malloc(DEFAULT_SNAPLEN);
		memcpy(abuf, ip6, len);
		ip6 = (struct ip6_hdr *)abuf;
	}
#endif /* ALIGN_WORD */

 	hlen = read_ip6hdr(ip6, &proto, len);

	/* fill the ip info into aguri_flow */
	aguri_flow.agflow_fs.fs_ipver = 6;
	memcpy(aguri_flow.agflow_fs.fs_srcaddr, &ip6->ip6_src, sizeof(struct in6_addr));
	memcpy(aguri_flow.agflow_fs.fs_dstaddr, &ip6->ip6_dst, sizeof(struct in6_addr));
	aguri_flow.agflow_fs.fs_prot = (u_int8_t)proto;

	p = (char *)ip6 + hlen;
	len -= hlen;

	do_ip6nexthdr(proto, p, len);

	return (1);
}

static int
read_ip6hdr(struct ip6_hdr *ip6, int *proto, int len)
{
	int hlen, opt_len;
	struct ip6_hbh *ip6ext;
	u_char nh;

	hlen = sizeof(struct ip6_hdr);
	nh = ip6->ip6_nxt;
	len -= hlen;
	ip6ext = (struct ip6_hbh *)(ip6 + 1);
	if (len < sizeof(struct ip6_hbh)) {
		*proto = (int)nh;
		return (hlen);
	}
	while (nh == IPPROTO_HOPOPTS || nh == IPPROTO_ROUTING ||
	       nh == IPPROTO_AH || nh == IPPROTO_DSTOPTS) {
		if (nh == IPPROTO_AH)
			opt_len = 8 + (ip6ext->ip6h_len * 4);
		else
			opt_len = (ip6ext->ip6h_len + 1) * 8;
		hlen += opt_len;
		nh = ip6ext->ip6h_nxt;
		len -= opt_len;
		ip6ext = (struct ip6_hbh *)((caddr_t)ip6ext  + opt_len);
		if (len < sizeof(struct ip6_hbh))
			break;
	}
	*proto = (int)nh;
	return (hlen);
}

static int
do_ip6nexthdr(int proto, const char *bp, int len)
{
	u_short sport, dport;

	sport = dport = 0;

	switch (proto) {
	case IPPROTO_TCP:
		if (len >= sizeof(struct tcphdr)) {
			/* long enough to get ports */
			struct tcphdr *tcp = (struct tcphdr *)bp;
			sport = tcp->th_sport;
			dport = tcp->th_dport;
		}
		break;
	case IPPROTO_UDP:
		if (len >= sizeof(struct udphdr)) {
			/* long enough to get ports */
			struct udphdr *udp = (struct udphdr *)bp;
			sport = udp->uh_sport;
			dport = udp->uh_dport;
		}
		break;
	case IPPROTO_ICMPV6:
		/* take icmp_type and icmp_code as port */
		if (len >= 2)
			sport = dport = *(u_short *)bp;
		break;
	}

	/* fill in the port info into aguri_flow */
	aguri_flow.agflow_fs.fs_sport = sport;
	aguri_flow.agflow_fs.fs_dport = dport;

	if (verbose > 0)
		fprintf(stderr, "ip6 proto:%u sport:%u dport:%u\n",
			      proto, ntohs(sport), ntohs(dport));
	return (1);
}
#endif /* INET6 */

/*
 * helper functions to handle IPv4 fragments.
 * currently only in-sequence fragments are handled.
 *	- fragment info is cached in a LRU list.
 *	- when a first fragment is found, cache its flow info.
 *	- when a non-first fragment is found, lookup the cache.
 */
static void
ip4f_cache(struct ip *ip, struct udphdr *udp, time_t ts)
{
	struct ip4_frag *fp;

	if (TAILQ_EMPTY(&ip4f_list)) {
		/* first time call, allocate fragment cache entries. */
		if (ip4f_init() < 0)
			/* allocation failed! */
			return;
	}

	fp = ip4f_alloc();
	fp->ip4f_proto = ip->ip_p;
	fp->ip4f_id = ip->ip_id;
	fp->ip4f_src = ip->ip_src;
	fp->ip4f_dst = ip->ip_dst;
	fp->ip4f_udphdr.uh_sport = udp->uh_sport;
	fp->ip4f_udphdr.uh_dport = udp->uh_dport;
	fp->ip4f_time = ts;
}

static struct udphdr *
ip4f_lookup(struct ip *ip)
{
	struct ip4_frag *fp;
	struct udphdr *udphdr;
	struct ip4_frag *old_frags[IP4F_TABSIZE];
	int i, n = 0;
    
	for (fp = TAILQ_FIRST(&ip4f_list); fp != NULL && fp->ip4f_valid;
	     fp = TAILQ_NEXT(fp, ip4f_chain)) {
		if (ip->ip_id == fp->ip4f_id &&
		    ip->ip_src.s_addr == fp->ip4f_src.s_addr &&
		    ip->ip_dst.s_addr == fp->ip4f_dst.s_addr &&
		    ip->ip_p == fp->ip4f_proto) {

			/* found the matching entry */
			udphdr = &fp->ip4f_udphdr;
			if ((ntohs(ip->ip_off) & IP_MF) == 0)
				/*
				 * this is the last fragment,
				 * release the entry.
				 */
				ip4f_free(fp);
			return (udphdr);
		}
		/* if the entry is more than 10 sec old, invalidate */
		if (fp->ip4f_time < aguri_flow.agflow_last - 10)
			old_frags[n++] = fp;
	}

	/* no matching entry found */
	for (i = 0; i < n; i++)
		ip4f_free(old_frags[i]); /* invalidate old entries */
	return (NULL);
}

static int
ip4f_init(void)
{
	struct ip4_frag *fp;
	int i;
    
	TAILQ_INIT(&ip4f_list);
	for (i=0; i<IP4F_TABSIZE; i++) {
		fp = (struct ip4_frag *)malloc(sizeof(struct ip4_frag));
		if (fp == NULL) {
			printf("ip4f_initcache: can't alloc cache entry!\n");
			return (-1);
		}
		fp->ip4f_valid = 0;
		TAILQ_INSERT_TAIL(&ip4f_list, fp, ip4f_chain);
	}
	return (0);
}

static struct ip4_frag *
ip4f_alloc(void)
{
	struct ip4_frag *fp;
	
	/* reclaim an entry at the tail, put it at the head */
	fp = TAILQ_LAST(&ip4f_list, ip4f_list);
	TAILQ_REMOVE(&ip4f_list, fp, ip4f_chain);
	fp->ip4f_valid = 1;
	TAILQ_INSERT_HEAD(&ip4f_list, fp, ip4f_chain);
	return (fp);
}

static void
ip4f_free(fp)
	struct ip4_frag *fp;
{
	TAILQ_REMOVE(&ip4f_list, fp, ip4f_chain);
	fp->ip4f_valid = 0;
	TAILQ_INSERT_TAIL(&ip4f_list, fp, ip4f_chain);
}

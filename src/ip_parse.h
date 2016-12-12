/*
 * Copyright (c) 1993, 1994
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
 *
 */

struct llc {
	u_int8_t dsap;
	u_int8_t ssap;
	union {
		u_int8_t u_ctl;
		u_int16_t is_ctl;
		struct {
			u_int8_t snap_ui;
			u_int8_t snap_pi[5];
		} snap;
		struct {
			u_int8_t snap_ui;
			u_int8_t snap_orgcode[3];
			u_int8_t snap_ethertype[2];
		} snap_ether;
	} ctl;
};
#define	llcui		ctl.snap.snap_ui

#define	LLC_UI			0x03
#define	LLCSAP_SNAP		0xaa

#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6		0x86dd
#endif

struct ip;
struct ip6_hdr;
struct tcphdr;
struct udphdr;
struct timeval;


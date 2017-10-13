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
#include <errno.h>
#include <err.h>

#include "../aguri_flow.h"
#include "aguri3_xflow.h"

extern struct aguri_flow aguri_flow;

u_int32_t sflow_version;
const char *endp;	/* end of the current sflow datagram */
const char *snapend;	/* end of the current sample record */
int	frame_length;   /* frame length of the current sampled paccket */
int	sampling_rate;	/* current sampling rate */
time_t	timestamp;	/* timestamp for the current sflow datagram */

u_int32_t buffer_read_4(const char **p);
u_int32_t buffer_skip(const char **pp, int len);
int parse_sflow_datagram(const char *bp, int len);
int parse_sflow4_sample(const char **p);
int parse_sflow5(const char **p);

u_int32_t
buffer_read_4(const char **p)
{
	const u_int32_t **q = (const u_int32_t **)p;

	if (*q >= (const u_int32_t *)endp)
		return (0);
	return (ntohl(*(*q)++));
}

u_int32_t
buffer_skip(const char **p, int len)
{
	len = roundup(len, 4);
	*p += len;
	return (len);
}

int
parse_sflow_datagram(const char *bp, int len)
{
	const char *p = bp;
	u_int32_t addr_type, agent_id = 0, seqno, uptime, nrecords;
	int	i;

	timestamp = time(NULL);	/* timestamp for this sflow datagram */
	endp = bp + len;

	/* sflow datagram header */
	sflow_version 	= buffer_read_4(&p);
	if (sflow_version != 4 && sflow_version != 5) {
		warnx("unkonwn sflow version 0x%x", sflow_version);
		return (len);
	}
	addr_type = buffer_read_4(&p);
	switch (addr_type) {
	case 1: /* IPv4 */
		buffer_skip(&p, 4);
		break;
	case 2: /* IPv6 */
		buffer_skip(&p, 16);
		break;
	default:
		return (-1);
	}
	if (sflow_version >= 5) {
		agent_id	= buffer_read_4(&p);
	}
	seqno	 	= buffer_read_4(&p);
	uptime	 	= buffer_read_4(&p);
	nrecords 	= buffer_read_4(&p);

#if 1
	if (verbose > 1)
		fprintf(stderr, "sflow datagram: ver=%u, agent_id=%u, addr_type=%u, nrecords=%u\n",
		    sflow_version, agent_id, addr_type, nrecords);
#endif

	for (i = 0; i < nrecords; i++) {
		if (sflow_version >= 5)
			parse_sflow5(&p);
		else {
			if (parse_sflow4_sample(&p) < 0) {
				/* if parsing failed for v4, give up */
				if (verbose > 0)
					fprintf(stderr, "parse_sflow4 failed\n");
				break;
			}
		}
	}

	return (len);
}

int
parse_sflow4_sample(const char **p)
{
	u_int32_t sample_type, packetdata_type;
	u_int32_t seqno, src_id, srate, total, drops, input, output;
	u_int32_t protocol, framelen, snaplen;
	u_int32_t interval, counters_version;
	u_int32_t nextended, extended_type, addr_type;
	u_int32_t aspath_len, asn_len, community_len, str_len;
	int i;

	sample_type	= buffer_read_4(p);
	if (verbose > 1)
		fprintf(stderr, "sflow4: sample_type:%u\n", sample_type);
	switch (sample_type) {
	case 1: /* flow sample */
		seqno 	= buffer_read_4(p);
		src_id 	= buffer_read_4(p);
		srate 	= buffer_read_4(p);
		total 	= buffer_read_4(p);
		drops 	= buffer_read_4(p);
		input 	= buffer_read_4(p);
		output 	= buffer_read_4(p);

		sampling_rate = srate;
		
		packetdata_type	= buffer_read_4(p);
		if (verbose > 1)
			fprintf(stderr, "flow_sample: packetdata_type:%u, srate:%u\n",
				packetdata_type, srate);

		switch (packetdata_type) {
		case 1: /* header */
			protocol = buffer_read_4(p);
			framelen = buffer_read_4(p);
			snaplen  = buffer_read_4(p);

			if (verbose > 0)
				fprintf(stderr, "header: framelen:%u, snaplen:%u, proto:%u\n",
			    		framelen, snaplen, protocol);

			/* clear aguri_flow to be filled in parsers */
			memset(&aguri_flow, 0, sizeof(aguri_flow));

			switch (protocol) {
			case 1: /* ethernet */
				snapend = *p + snaplen;
				etherhdr_parse(*p, snaplen);
				break;
			default:
				if (verbose > 0)
					fprintf(stderr, "unknown proto:%u\n",
			    			protocol);
				break;
			}

			buffer_skip(p, snaplen);

			if (aguri_flow.agflow_fs.fs_ipver != 0) {
				/* flow info was filled by the parser:
				 * for frame_length, we remove 4 bytes of FCS
				 * to be consistent with pcap
				 */
				aguri_flow.agflow_packets = htonl(1 * srate);
				aguri_flow.agflow_bytes = htonl((framelen - 4) * srate);
				aguri_flow.agflow_first = aguri_flow.agflow_last = htonl((u_int32_t)timestamp);

				if (debug == 0) {
					if (fwrite(&aguri_flow, sizeof(aguri_flow), 1, stdout) != 1)
						err(1, "fwrite failed!");
				} else
					print_flow(&aguri_flow);
			}
			
			break;
		case 2: /* IPv4 */
			buffer_skip(p, 8*4);
			if (verbose > 0)
				fprintf(stderr, "packetdata IPv4 not supported\n");
			break;
		case 3: /* IPv6 */
			buffer_skip(p, 14*4);
			if (verbose > 0)
				fprintf(stderr, "packetdata IPv6 not supported\n");
			break;
		default:
			if (verbose > 0)
				fprintf(stderr, "unknown packetdata_type:%u\n", packetdata_type);
			return (-1);
		}

		/* extended data */
		nextended = buffer_read_4(p);
		if (verbose > 0)
			fprintf(stderr, "extended data:%u\n", nextended);
		for (i = 0; i < nextended; i++) {
			extended_type = buffer_read_4(p);
			switch (extended_type) {
			case 1: /* switch */
				buffer_skip(p, 4*4);
				break;
			case 2: /* router */
				addr_type = buffer_read_4(p);
				switch (addr_type) {
				case 1: /* IPv4 */
					buffer_skip(p, 4);
					break;
				case 2: /* IPv6 */
					buffer_skip(p, 16);
					break;
				default:
					return (-1);
				}
				buffer_skip(p, 2*4);
				break;
			case 3: /* gateway */
				buffer_skip(p, 3*4);
				aspath_len = buffer_read_4(p);
				while (aspath_len-- > 0) {
					buffer_skip(p, 4);
					if (sflow_version >= 4) {
						asn_len = buffer_read_4(p);
						while (asn_len-- > 0)
							buffer_skip(p, 4);
					}
				}
				community_len = buffer_read_4(p);
				buffer_skip(p, community_len * 4);
				buffer_skip(p, 4);
				break;
			case 4: /* user */
				str_len = buffer_read_4(p);
				buffer_skip(p, str_len);
				str_len = buffer_read_4(p);
				buffer_skip(p, str_len);
				break;
			case 5: /* url */
				buffer_skip(p, 4);
				str_len = buffer_read_4(p);
				buffer_skip(p, str_len);
				break;
			default:
				return (-1);
			}
		}
		break;
	case 2: /* counter sample */
		seqno 	= buffer_read_4(p);
		src_id 	= buffer_read_4(p);
		interval = buffer_read_4(p);
		counters_version = buffer_read_4(p);
		if (verbose > 0)
			fprintf(stderr, "counter sample: type:%u\n", counters_version);
		switch (counters_version) {
		case 1: /* generic */
			buffer_skip(p, 22*4);
			break;
		case 2: /* ethernet */
			buffer_skip(p, 22*4);
			buffer_skip(p, 13*4);
			break;
		case 3: /* tokenring */
			buffer_skip(p, 22*4);
			buffer_skip(p, 18*4);
			break;
		case 4: /* fddi */
			buffer_skip(p, 22*4);
			break;
		case 5: /* 100basevg */
			buffer_skip(p, 22*4);
			buffer_skip(p, 20*4);
			break;
		case 6: /* wan */
			buffer_skip(p, 22*4);
			break;
		case 7: /* vlan */
			buffer_skip(p, 7*4);
			break;
		default:
			if (verbose > 0)
				fprintf(stderr, "counter sample %d not supported\n",
				    counters_version);
			return (-1);
		}
		break;
	default:
		if (verbose > 0)
			fprintf(stderr, "unknown sample_type %u\n", sample_type);
		return (-1);
	}
	
	return (0);
}

int
parse_sflow5(const char **p)
{
	u_int32_t format, len;
	u_int32_t seqno, src_id, srate, total, drops, input, output, nrecords;
	u_int32_t record_type, record_len;
	u_int32_t protocol, framelen, stripped;
	int snaplen, i;

	format	= buffer_read_4(p) & 0xfff;
	len	= buffer_read_4(p);
	if (verbose > 1)
		fprintf(stderr, "sflow5: format:%u, len:%u\n",
				format, len);
	switch (format) {
	case 1: /* flow sample */
		seqno 	= buffer_read_4(p);
		src_id 	= buffer_read_4(p);
		srate 	= buffer_read_4(p);
		total 	= buffer_read_4(p);
		drops 	= buffer_read_4(p);
		input 	= buffer_read_4(p);
		output 	= buffer_read_4(p);
		nrecords	= buffer_read_4(p);

		sampling_rate = srate;

		if (verbose > 1)
			fprintf(stderr, "flow sample: srate:%u, nrecords:%u\n",
				srate, nrecords);

		for (i = 0; i < nrecords; i++) {
			record_type	= buffer_read_4(p);
			record_len	= buffer_read_4(p);

			/* clear aguri_flow to be filled in parsers */
			memset(&aguri_flow, 0, sizeof(aguri_flow));

			switch (record_type) {
			case 1: /* raw packet header */
				protocol = buffer_read_4(p);
				framelen = buffer_read_4(p);
				stripped = buffer_read_4(p);
				record_len -= 12;
				if (verbose > 1)
					fprintf(stderr, "record type: raw header: proto:%u, rlen:%u flen:%u, stripped:%u\n",
				    		protocol, record_len, framelen, stripped);
				switch (protocol) {
				case 1: /* ethernet */
					/* read the first 4 bytes for snaplen */
					snaplen = ntohl(*((u_int32_t *)*p));
					snapend = *p + 4 + snaplen;
					/* frame_length holds ethernet frame
					 * length; we remove 4 bytes of FCS to
					 * be consistent with pcap
					 */
					frame_length = framelen - 4;
					etherhdr_parse(*p + 4, snaplen);
					break;
				default:
					break;
				}
				buffer_skip(p, record_len);
				break;
			default:
				if (verbose > 1)
					fprintf(stderr, "record type:%u, len:%u\n",
				    		record_type, record_len);
				buffer_skip(p, record_len);
				break;
			} /* switch */

			if (aguri_flow.agflow_fs.fs_ipver != 0) {
				/* flow info was filled by the parser:
				 * for frame_length, we remove 4 bytes of FCS
				 * to be consistent with pcap
				 */
				aguri_flow.agflow_packets = htonl(1 * srate);
				aguri_flow.agflow_bytes = htonl((framelen - 4) * srate);
				aguri_flow.agflow_first = aguri_flow.agflow_last = htonl((u_int32_t)timestamp);

				if (debug == 0) {
					if (fwrite(&aguri_flow, sizeof(aguri_flow), 1, stdout) != 1)
						err(1, "fwrite failed!");
				} else
					print_flow(&aguri_flow);
			}

		}  /* nrecords in sample */
		break;
	case 2: /* counter sample */
		buffer_skip(p, len);
		break;
	case 3: /* expanded flow sample */
		buffer_skip(p, len);
		break;
	case 4: /* expanded counter sample */
		buffer_skip(p, len);
		break;
	default:
		buffer_skip(p, len);
		break;
	}

	return (0);
}

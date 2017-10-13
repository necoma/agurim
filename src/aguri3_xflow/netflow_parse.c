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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <stdio.h>
#include <stdlib.h> 
#include <unistd.h>
#include <string.h>
#include <err.h>

#include <netinet/in.h>

#include "../aguri_flow.h"
#include "aguri3_xflow.h"

#include "netflow_v5_v7.h"
#include "netflow_v9.h"

#define MAX_UDPMSG_SIZ 65535 // Maximum UDP message size
#define UDP_PACKET_SIZE 1472 // UDP message size

struct netflow_common_header {
	u_int16_t version;
	u_int16_t count;
};

extern struct aguri_flow aguri_flow;

static void netflow_v5_parse(const char *bp, size_t len);
static void netflow_v9_parse(const char *bp, size_t len);

int
parse_netflow_datagram(const char *bp, int len)
{
	struct netflow_common_header *nf_header;
	int ret = 0;
	uint16_t version;

	nf_header = (struct netflow_common_header *)bp;
	version = ntohs(nf_header->version);

	switch (version) {
	case 5:
		netflow_v5_parse(bp, len);
		break;
	case 9:
		netflow_v9_parse(bp, len);
		break;
	default:
		warnx("netflow version %d not supported", version);
		ret = 1;
		break;
	}

	return ret;
}

static void
netflow_v5_parse(const char *bp, size_t len)
{
	const struct netflow_v5_header *header;
	const struct netflow_v5_record *record;
	int i, count;
	int sampmode;	/* sampling mode */
	int samprate;	/* sampling rate */
	u_int32_t packets, bytes;
	time_t	boottime, recvtime, first, last;

	header = (const struct netflow_v5_header *)bp;

	count = ntohs(header->count);
	sampmode = ntohs(header->sampling_interval);
	samprate = sampmode & 0x3fff;
	sampmode >>= 14;
	if (samprate == 0)
		samprate = default_samprate;
	recvtime = ntohl(header->unix_secs);
	boottime = recvtime - ntohl(header->SysUptime) / 1000;

	bp += NETFLOW_V5_HEADER_LENGTH;
#if 1
	if (verbose > 1)
		fprintf(stderr, "netflow_v5_parse: nrecords=%d sampling mode=%d rate=%d uptime=%d\n",
		    count, sampmode, samprate, ntohl(header->SysUptime) / 1000);
#endif
	for (i = 0; i < count; i++) {
		record = (const struct netflow_v5_record *)bp;

		/* copy the flow spec (note: in network byte order) */
		aguri_flow.agflow_fs.fs_ipver = 4;
		aguri_flow.agflow_fs.fs_srcaddr[0] = record->srcaddr;
		aguri_flow.agflow_fs.fs_dstaddr[0] = record->dstaddr;
		aguri_flow.agflow_fs.fs_prot  = record->prot;
		aguri_flow.agflow_fs.fs_sport = record->srcport;
		aguri_flow.agflow_fs.fs_dport = record->dstport;

		packets = ntohl(record->dPkts);
		bytes   = ntohl(record->dOctets);
		if (samprate > 1) {  /* note: samprate could be zero */
			packets *= samprate;
			bytes   *= samprate;
		}
		aguri_flow.agflow_packets = htonl(packets);
		aguri_flow.agflow_bytes = htonl(bytes);

		first = boottime + ntohl(record->First) / 1000;
		last  = boottime + ntohl(record->Last)  / 1000;
		aguri_flow.agflow_first = htonl(first);
		aguri_flow.agflow_last = htonl(last);
		
		if (debug == 0) {
			if (fwrite(&aguri_flow, sizeof(aguri_flow), 1, stdout) != 1)
				err(1, "fwrite failed!");
		} else
			print_flow(&aguri_flow);

		bp += sizeof(struct netflow_v5_record);
	}
}

static void
netflow_v9_parse(const char *bp, size_t len)
{
	const struct netflow_v9_header *header;
	const struct common_header *common_header;
	uint16_t flowset_id, flowset_length;
	uint32_t source_id;
	static uint32_t our_source;
	int count, records_parsed = 0;
	time_t	boottime, recvtime;

	if (len < sizeof(*header) + sizeof(*common_header)) {
		fprintf(stderr, "truncated datagram!\n");
		return;
	}

	header = (const struct netflow_v9_header *)bp;
	count = ntohs(header->count);
	recvtime = ntohl(header->unix_secs);
	boottime = recvtime - ntohl(header->SysUptime) / 1000;
	source_id = ntohl(header->source_id);

	if (our_source == 0)
		our_source = source_id;
	else if (source_id != our_source) {
		fprintf(stderr, "different source id:%d ignoring\n", source_id);
		return;
	}
#if 1
	if (verbose > 1)
		fprintf(stderr, "nf_v9_parse: src_id=%d nflowsets=%d uptime=%d len=%lu\n",
		    source_id, count, ntohl(header->SysUptime) / 1000, len);
#endif
	
	bp += NETFLOW_V9_HEADER_LENGTH;

	while (records_parsed < count) {
		common_header = (const struct common_header *)bp;
		flowset_id = ntohs(common_header->flowset_id);
		flowset_length = ntohs(common_header->length);

		if (flowset_length > len) {
			fprintf(stderr, "truncated datagram!\n");
			return;
		}
#if 1
		if (verbose > 1)
			fprintf(stderr, "nf_v9_parse: flowset_id=%d length=%d\n",
			    flowset_id, flowset_length);
#endif
#if 1		
		if (flowset_length == 0) {
			/* length should be at least 4, but somehow it happens
			 * (padding bug?).  ignore the rest of the sets.
			 */
			break;
		}
#endif		
		switch (flowset_id) {
		case NF9_TEMPLATE_FLOWSET_ID:
			records_parsed += nf9_parse_template(bp, flowset_length, source_id);
			break;
		case NF9_OPTIONS_FLOWSET_ID:
			records_parsed += nf9_parse_options(bp, flowset_length, source_id);
			break;
		default:
			/* if larger than 255, data record */
			if (flowset_id > 255) {
				records_parsed += nf9_parse_data(bp, 
					flowset_length, source_id, boottime);
			} else
				fprintf(stderr, "invalid flowset_id %d!\n", flowset_id);
			break;
		}

		bp += flowset_length;
	}
}

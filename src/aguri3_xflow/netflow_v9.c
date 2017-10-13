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
#include <sys/queue.h>
#ifdef __linux__
#include <byteswap.h>
#else
#include <sys/endian.h>
#endif

#include <netinet/in.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <assert.h>

#include "../aguri_flow.h"
#include "aguri3_xflow.h"
#include "netflow_v9.h"

struct tp_field {
	uint16_t  type;
	uint16_t  length;
};

struct template {
	int agent_id;
	int template_id;
	int source_id;
	int num_fields;	  /* # of fields */
	int field_size;   /* field size in bytes */
	int options_scope_count;  /* # of scopes for options */
	LIST_ENTRY(template) templates; /* for hash table */
	struct tp_field *fields;
};

LIST_HEAD(tp_head, template) template_head = LIST_HEAD_INITIALIZER(template_head);

#define NUM_FIELDS	64	/* initial field table size */

#ifdef __linux__
#define bswap64(x)	bswap_64(x)
#endif

static int sampling_rate = 1;  /* XXX */

static struct template *get_template(int agent_id, int source_id, int template_id);
void free_template(struct template *tp);

static struct template *
get_template(int agent_id, int source_id, int template_id)
{
	struct template *tp;
	
	LIST_FOREACH(tp, &template_head, templates) {
		if (tp->agent_id == agent_id && tp->source_id == source_id &&
			tp->template_id == template_id)
			break;
	}
	if (tp == NULL) {
		/* allocate a new template */
		if ((tp = calloc(1, sizeof(struct template))) == NULL)
			err(1, "calloc");
		tp->agent_id = agent_id;
		tp->source_id = source_id;
		tp->template_id = template_id;
		LIST_INSERT_HEAD(&template_head, tp, templates);
	}
	return (tp);
}

void
free_template(struct template *tp)
{
	LIST_REMOVE(tp, templates);
	if (tp->fields != NULL)
		free(tp->fields);
	free(tp);
}


int
nf9_parse_template(const char *bp, size_t len, int source_id)
{
	const struct template_flowset *template_fs;
	const struct template_record *template_record;
	const char *end = bp + len;
	int i, records_parsed = 0;

	template_fs = (const struct template_flowset *)bp;
	bp = (const char *)&template_fs->fields[0];
	len -= 4;  /* flowset_id and length */
	while (len > sizeof(struct template_record)) {
		int template_id;
		int field_count;
		const struct tp_field *fp;
		struct template *tp;
		size_t total_size;
		
		template_record = (const struct template_record *)bp;
		template_id = ntohs(template_record->template_id);
		field_count = ntohs(template_record->count);
		if (len < 4 + field_count * 4) {
			warnx("nf9_template: truncated datagram!");
			return (records_parsed);
		}
		
		fp = (const struct tp_field *)&template_record->record[0];

#if 1
		if (verbose > 1)
			printf("TEMPLATE template_id: %d, template_count: %d\n",
				template_id, field_count);
#endif
		tp = get_template(cur_agentid, source_id, template_id);
		/* allocate the field table */
		if (tp->fields != NULL)
			free(tp->fields);
		tp->fields = calloc(field_count, sizeof(struct tp_field));
		if (tp->fields == NULL)
			err(1, "calloc");

		total_size = 0;
		for (i = 0; i < field_count; i++) {
			uint16_t type, length;

			type   = ntohs(fp[i].type);
			length = ntohs(fp[i].length);
			tp->fields[i].type   = type;
			tp->fields[i].length = length;
			total_size += length;
#if 1
			if (verbose > 1)
				printf(" field: type:%u length:%u\n", type, length);
#endif
		}
		tp->num_fields = field_count;
		tp->field_size = total_size;

		records_parsed++;
		bp = (const char *)&fp[field_count];
		len = end - bp;
	}
	if (verbose > 1)
		printf("%d sets parsed residual=%zu\n", records_parsed, len);
	return (records_parsed);
}

int
nf9_parse_options(const char *bp, size_t len, int source_id)
{
	const char *end = bp + len;
	int i, records_parsed = 0;

	while (len > sizeof(struct option_template_flowset)) {
		const struct option_template_flowset *options;
		int flowset_id, template_id;
		int  record_length, scope_length, option_length;
		const struct tp_field *fp;
		struct template *tp;
		size_t total_size = 0;
		int field_count, scope_count = 0;

		/* parse each option template record */

		options = (const struct option_template_flowset *)bp;
		flowset_id = ntohs(options->flowset_id);
		record_length = ntohs(options->length);
		if (flowset_id != NF9_OPTIONS_FLOWSET_ID) {
			warnx("invalid options_flowset_id:%d", flowset_id);
			return (records_parsed);
		}
		template_id   = ntohs(options->template_id);
		scope_length  = ntohs(options->option_scope_length);
		option_length = ntohs(options->option_length);
		scope_count = scope_length / 4;
		field_count = scope_count + option_length / 4;

#if 1
		if (verbose > 1)
			printf("OPTIONS template_id:%d, scope_len:%d option_len:%d\n",
				template_id, scope_length, option_length);
#endif
		tp = get_template(cur_agentid, source_id, template_id);
		/* allocate the field table */
		if (tp->fields != NULL)
			free(tp->fields);
		tp->fields = calloc(field_count, sizeof(struct tp_field));
		if (tp->fields == NULL)
			err(1, "calloc");
	
		fp = (const struct tp_field *)&options->record[0];

		if (len < 10 + field_count * 4) {
			warnx("nf9_options: truncated datagram!");
			return (records_parsed);
		}
		/* read option fields */
		for (i = 0; i < field_count; i++) {
			uint16_t type, length;

			type   = ntohs(fp[i].type);
			length = ntohs(fp[i].length);
			tp->fields[i].type   = type;
			tp->fields[i].length = length;
			total_size += length;
#if 1
			if (verbose > 1) {
				if (i < scope_count)
					printf(" option scope:");
				else
					printf(" option field:");
				printf(" type:%u length:%u\n", type, length);
			}
#endif
		}
		tp->num_fields = field_count;
		tp->field_size = total_size;
		tp->options_scope_count = scope_count;

		records_parsed++;

		bp += record_length;
		len = end - bp;
	}
	if (verbose > 1)
		printf("%d records parsed residual=%zu\n", records_parsed, len);
	return (records_parsed);
}

int
nf9_parse_data(const char *bp, size_t len, int source_id, uint32_t boottime)
{
	const struct data_flowset *data_header;
	uint16_t template_id;
	struct template *tp;
	int records_parsed = 0;
	const uint8_t *dp;
	uint32_t value, bytes, packets;

	data_header = (const struct data_flowset *)bp;
	template_id = ntohs(data_header->flowset_id);
	if (template_id < NF9_MIN_RECORD_FLOWSET_ID)
		return 0;
#if 1
	if (verbose > 1)
		printf("DATA FLOWSET: template_id %u, len: %zu\n", 
			template_id, len);
#endif
	tp = get_template(cur_agentid, source_id, template_id);

	dp = (const uint8_t *)&data_header->data[0];
	len -= 4; /* template_id and length */
	while (len >= tp->field_size) {
		struct aguri_flow aguri_flow;
		int i;

		/* read a single flow record */
		memset(&aguri_flow, 0, sizeof(aguri_flow));
		bytes = packets = 0;
		for (i = 0; i < tp->num_fields; i++) {
			if (i < tp->options_scope_count) {
				/* this is option scope. just skip it for now */
				dp  += tp->fields[i].length;
				len -= tp->fields[i].length;
				continue;
			}

			switch (tp->fields[i].type) {
			case NF9_IN_BYTES:
			case NF9_IN_PACKETS:
#if 0  /* we don't need to count out bytes and packets, do we? */
			case NF9_OUT_BYTES:
			case NF9_OUT_PACKETS:
#endif
				assert(tp->fields[i].length == 4 || tp->fields[i].length == 8);
				value = 0;
				if (tp->fields[i].length == 4)
					value = ntohl(*(uint32_t *)dp);
				else if (tp->fields[i].length == 4)
					value = (uint32_t)bswap64(*(uint64_t *)dp);
				if (tp->fields[i].type == NF9_IN_BYTES)
					bytes = value;
				else if (tp->fields[i].type == NF9_IN_PACKETS)
					packets = value;
				break;
			case NF9_IN_PROTOCOL:
				assert(tp->fields[i].length == 1);
				aguri_flow.agflow_fs.fs_prot = *dp;
				break;
			case NF9_L4_SRC_PORT:
				assert(tp->fields[i].length == 2);
				memcpy(&aguri_flow.agflow_fs.fs_sport, dp, 2);
				break;
			case NF9_L4_DST_PORT:
				assert(tp->fields[i].length == 2);
				memcpy(&aguri_flow.agflow_fs.fs_dport, dp, 2);
				break;
			case NF9_IPV4_SRC_ADDR:
				assert(tp->fields[i].length == 4);
				memcpy(&aguri_flow.agflow_fs.fs_srcaddr, dp, 4);
				aguri_flow.agflow_fs.fs_ipver = 4;
				break;
			case NF9_IPV4_DST_ADDR:
				assert(tp->fields[i].length == 4);
				memcpy(&aguri_flow.agflow_fs.fs_dstaddr, dp, 4);
				break;
			case NF9_IPV6_SRC_ADDR:
				assert(tp->fields[i].length == 16);
				memcpy(&aguri_flow.agflow_fs.fs_srcaddr, dp, 16);
				aguri_flow.agflow_fs.fs_ipver = 6;
				break;
			case NF9_IPV6_DST_ADDR:
				assert(tp->fields[i].length == 16);
				memcpy(&aguri_flow.agflow_fs.fs_dstaddr, dp, 16);
				break;
			case NF9_FIRST_SWITCHED:
				assert(tp->fields[i].length == 4);
				value = ntohl(*(uint32_t *)dp);
				aguri_flow.agflow_first = htonl(boottime + value / 1000);
				break;
			case NF9_LAST_SWITCHED:
				assert(tp->fields[i].length == 4);
				value = ntohl(*(uint32_t *)dp);
				aguri_flow.agflow_last = htonl(boottime + value / 1000);
				break;
			case NF9_SAMPLING_INTERVAL:
				assert(tp->fields[i].length == 4);
				sampling_rate = ntohl(*(uint32_t *)dp);
				break;
			default:
				/* we don't use other types */
				break;
			}
			dp  += tp->fields[i].length;
			len -= tp->fields[i].length;
		}
		records_parsed++;

		if (sampling_rate == 0)
			sampling_rate = default_samprate;
		if (sampling_rate > 1) {  /* note: samprate could be zero */
			bytes   *= sampling_rate;
			packets *= sampling_rate;
		}
		aguri_flow.agflow_bytes   = htonl(bytes);
		aguri_flow.agflow_packets = htonl(packets);

		if (debug == 0) {
			if (fwrite(&aguri_flow, sizeof(aguri_flow), 1, stdout) != 1)
				err(1, "fwrite failed!");
		} else
			print_flow(&aguri_flow);
	}

	if (verbose > 1)
		printf("%d records parsed residual=%zu\n", records_parsed, len);
	return (records_parsed);
}


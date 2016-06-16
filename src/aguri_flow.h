/*
 * Copyright (C) 2001-2015 WIDE Project.
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

/*
 * aguri flow entry format.
 * aguri_xflow converts netflow/sflow entries into this format.
 * all fields are in the network byte order.
 */
struct flow_spec {
	u_int32_t  fs_srcaddr[4];	/* source IPv4/IPv6 address */
	u_int32_t  fs_dstaddr[4];	/* destination IPv4/IPv6 address */
	u_int16_t  fs_sport;		/* source port */
	u_int16_t  fs_dport;		/* destination port */
	u_int8_t   fs_ipver;		/* IP version, 4 or 6 */
	u_int8_t   fs_prot;		/* IP protocol */
	u_int16_t  fs_pad;		/* padding */
} __packed;

struct aguri_flow {
	struct flow_spec agflow_fs;	/* agurim flow spec */
	u_int32_t  agflow_packets;	/* number of packets in a flow */
	u_int32_t  agflow_bytes;	/* number of octets in a flow */
	u_int32_t  agflow_first;	/* start time of a flow in unix time */
	u_int32_t  agflow_last;		/* end time of a flow in unix time */
};

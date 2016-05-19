/*
 * Copyright (C) 2012-2016 WIDE Project.
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

#include <sys/socket.h>

#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>

#include "agurim.h"

static uint8_t prefixmask[8]
    = { 0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe };

/* helper for qsort: compare the sum of prefix length */
int
area_comp(const void *p0, const void *p1)
{
	struct odflow *e0, *e1;
	uint16_t len0, len1;

	e0 = *(struct odflow **)p0;
	e1 = *(struct odflow **)p1;

	len0 = e0->s.srclen + e0->s.dstlen;
	len1 = e1->s.srclen + e1->s.dstlen;

	if (len0 < len1)
		return (1);
	if (len0 > len1)
		return (-1);
	return (0);
}

/* select the larger one by fraction */
double
countfrac_select(struct odflow *odfp)
{
	double fv, fv2;

	fv = odfp->byte * 100 / response.total_byte;
	fv2 = odfp->packet * 100 / response.total_packet;
	return max(fv, fv2);
}

/* helper for qsort: compare the counters by the given criteria */
int
count_comp(const void *p0, const void *p1)
{
	struct odflow *odfp0, *odfp1;

	odfp0 = *(struct odflow **)p0;
	odfp1 = *(struct odflow **)p1;

	switch (query.criteria) {
	case BYTE:
		if (odfp0->byte < odfp1->byte)
			return (-1);
		else if (odfp0->byte > odfp1->byte)
			return (1);
		break;
	case PACKET:
		if (odfp0->packet < odfp1->packet)
			return (-1);
		else if (odfp0->packet > odfp1->packet)
			return (1);
		break;
	case COMBINATION:
	{
		double f0, f1;

		f0 = countfrac_select(odfp0);
		f1 = countfrac_select(odfp1);
		if (f0 < f1)
			return (-1);
		else if (f0 > f1)
			return (1);
		break;
	}
	}
	return (0);
}

/* helper for qsort: simpler one for protocols */
int
count_comp2(const void *p0, const void *p1)
{
	struct odflow *odpp0, *odpp1;

	odpp0 = *(struct odflow **)p0;
	odpp1 = *(struct odflow **)p1;

	switch (query.criteria) {
	case BYTE:
	case COMBINATION:
		if (odpp0->byte < odpp1->byte)
			return (-1);
		else if (odpp0->byte > odpp1->byte)
			return (1);
		break;
	case PACKET:
		if (odpp0->packet < odpp1->packet)
			return (-1);
		else if (odpp0->packet > odpp1->packet)
			return (1);
		break;
	}
	return (0);
}

/* compare prefixes for the given length */
int
prefix_comp(uint8_t *r, uint8_t *r2, uint8_t len)
{
	uint8_t bytes, bits, mask;

	if (!len)
		return (0);

	bytes = len / 8;
	bits = len & 7;

	while (bytes-- != 0) {
		if (*r++ != *r2++)
			return (*--r - *--r2);
	}

	if ((mask = prefixmask[bits]) == 0)
		return (0);

	return ((*r & mask) - (*r2 & mask));
}

/*
 * create new flow record r1 with specific prefix length
 * based on the flow record r0
 */
void
prefix_set(uint8_t *r0, uint8_t len, uint8_t *r1, int bytesize)
{
	uint8_t bits, bytes = len / 8;
	uint8_t pad = bytesize - bytes;

	bits = len & 7;
	if (bits)
		pad--;

	while (bytes-- != 0)
		*r1++ = *r0++;

	if (bits != 0)
		*r1++= *r0 & prefixmask[bits]; 

	while (pad--)
		*r1++ = 0;
}

static void
ip_print(uint8_t *ip, uint8_t len)
{
	char buf[BUFSIZ];

	if (len == 0)
		printf("*");
	else {
		inet_ntop(AF_INET, ip, buf, BUFSIZ);
		if (len < 32)
			printf("%s/%u", buf, len);
		else
			printf("%s", buf);
	}
}

static void
ip6_print(uint8_t *ip6, uint8_t len)
{
	char buf[BUFSIZ];

	if (len == 0)
		printf("*::");
	else {
		inet_ntop(AF_INET6, ip6, buf, BUFSIZ);
	if (len < 128)
		printf("%s/%u", buf, len);
	else
		printf("%s", buf);
	}
}

void
odflow_print(struct odflow *odfp)
{
	if (odfp->af == AF_INET) {
		ip_print(odfp->s.src, odfp->s.srclen);
		printf(" ");
		ip_print(odfp->s.dst, odfp->s.dstlen);
	} 
	if (odfp->af == AF_INET6) {
		ip6_print(odfp->s.src, odfp->s.srclen);
		printf(" ");
		ip6_print(odfp->s.dst, odfp->s.dstlen);
	}
	if (odfp->af == AF_LOCAL) {
		odproto_print(odfp);
	} 
}

void
odproto_print(struct odflow *odpp)
{
	int port;

	if (odpp->s.src[0] == 0)
		printf("*:");
	else
		printf("%d:", odpp->s.src[0]);
	port = (odpp->s.src[1] << 8) + odpp->s.src[2];
	if (port != 0) {
		printf("%d", port);
		if (odpp->s.srclen < 24) {  /* port range */
			int end = port + (1 << (24 - odpp->s.srclen)) - 1;
			printf("-%d", end);
		}
	} else
		printf("*");
	printf(":");

	port = (odpp->s.dst[1] << 8) + odpp->s.dst[2];
	if (port != 0)  {
		printf("%d", port);
		if (odpp->s.dstlen < 24) {  /* port range */
			int end = port + (1 << (24 - odpp->s.dstlen)) - 1;
			printf("-%d", end);
		}
	} else
		printf("*");
}

/*
 * cache_list implements dynamic array operations
 */
/* use simpler malloc/realloc */
#define CL_INITSIZE	64	/* initial array size */
struct cache_list *
cl_alloc(void)
{
	struct cache_list *clp;

	if ((clp = calloc(1, sizeof(struct cache_list))) == NULL)
		return NULL;
	return (clp);
}

void
cl_free(struct cache_list *clp)
{
	if (clp->cl_data != NULL)
		free(clp->cl_data);
	free(clp);
}

void
cl_clear(struct cache_list *clp)
{
	if (clp->cl_data != NULL) {
		free(clp->cl_data);
		clp->cl_data = NULL;
		clp->cl_max = 0;
	}
	clp->cl_size = 0;
}

int
cl_append(struct cache_list *clp, uint64_t val)
{
	if (clp->cl_size == clp->cl_max) {
		/* if full, double the size */
		int newsize;;

		if (clp->cl_max == 0)
			newsize = CL_INITSIZE;
		else
			newsize = clp->cl_max * 2;


		clp->cl_data = realloc(clp->cl_data, sizeof(uint64_t) * newsize);
		if (clp->cl_data == NULL)
			return (-1);
		clp->cl_max = newsize;
	}

	clp->cl_data[clp->cl_size] = val;
	clp->cl_size++;
	return (clp->cl_size - 1);  /* index of the appended value */
}

#ifndef CL_INLINE
int
cl_size(struct cache_list *clp)
{
	return (clp->cl_size);
}

int
cl_set(struct cache_list *clp, int i, uint64_t val)
{
	if (i > clp->cl_size - 1)
		return (-1);
	clp->cl_data[i] = val;
	return (0);
}

uint64_t
cl_get(struct cache_list *clp, int i)
{
	if (i > clp->cl_size - 1)
		return (0);
	return (clp->cl_data[i]);
}

int
cl_add(struct cache_list *clp, int i, uint64_t val)
{
	if (i > clp->cl_size - 1)
		return (-1);
	clp->cl_data[i] += val;
	return (0);
}
#endif /* !CL_INLINE */

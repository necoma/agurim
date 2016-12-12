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
#include <assert.h>
#ifndef NDEBUG	/* for thread-safe odflow accounting */
#include <pthread.h>
#endif

#include "agurim.h"

static struct odflow *odproto_lookup(struct odflow *odfp, struct odflow_spec *odpsp, int af);
static struct odflow *odproto_quickmerge(struct odf_tailq *odfq, struct odflow_spec *odpsp);

#ifndef NDEBUG	/* for thread-safe odflow accounting */
static long odflows_allocated = 0;
static long max_odflows_allocated = 0;
static pthread_mutex_t odflow_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

#define ODPQ_MAXENTRIES	1000  /* threshold to merge a protocol list */

/*
 * The following hash function is adapted from "Hash Functions" by Bob Jenkins
 * ("Algorithm Alley", Dr. Dobbs Journal, September 1997).
 *
 * http://www.burtleburtle.net/bob/hash/spooky.html
 */
#define mix(a, b, c)                                                    \
do {                                                                    \
	a -= b; a -= c; a ^= (c >> 13);                                 \
	b -= c; b -= a; b ^= (a << 8);                                  \
	c -= a; c -= b; c ^= (b >> 13);                                 \
	a -= b; a -= c; a ^= (c >> 12);                                 \
	b -= c; b -= a; b ^= (a << 16);                                 \
	c -= a; c -= b; c ^= (b >> 5);                                  \
	a -= b; a -= c; a ^= (c >> 3);                                  \
	b -= c; b -= a; b ^= (a << 10);                                 \
	c -= a; c -= b; c ^= (b >> 15);                                 \
} while (/*CONSTCOND*/0)

static inline uint32_t
slot_fetch(uint8_t *v1, uint8_t *v2, int n)
{
        uint32_t a = 0x9e3779b9, b = 0x9e3779b9, c = 0;
        uint8_t *p; 
    
        p = v1;
        b += p[3];
        b += p[2] << 24; 
        b += p[1] << 16; 
        b += p[0] << 8;
    
        p = v2;
        a += p[3];
        a += p[2] << 24; 
        a += p[1] << 16; 
        a += p[0] << 8;

        mix(a, b, c); 

        return (c & (n - 1));  /* n must be power of 2 */
}

void
odhash_init(struct response *resp)
{
	resp->ip_hash = odhash_alloc(1024);
	resp->ip6_hash = odhash_alloc(1024);
	if (proto_view)
		resp->proto_hash = odhash_alloc(512);
}

/*
 * allocate odflow hash with the given number of buckets, n.
 * n is rounded up to the next power of 2. limit the max to 4096.
 */
struct odflow_hash *
odhash_alloc(int n)
{
	struct odflow_hash *odfh;
	int i, buckets;

	if ((odfh = calloc(1, sizeof(struct odflow_hash))) == NULL)
		err(1, "odhash_alloc: calloc");

	/* round up n to the next power of 2 */
	buckets = 1;
	while (buckets < n) {
		buckets *= 2;
		if (buckets == 4096)
			break;	/* max size */
	}

	/* allocate a hash table */
	if ((odfh->tbl = calloc(buckets, sizeof(struct odf_tailq))) == NULL)
		err(1, "odhash_alloc: calloc");
	odfh->nbuckets = buckets;
	for (i = 0; i < buckets; i++) {
		TAILQ_INIT(&odfh->tbl[i].odfq_head);
		odfh->tbl[i].nrecord = 0;
	}

	/* initialize counters */
	odfh->byte = odfh->packet = 0;
	odfh->nrecord = 0;
	return (odfh);
}

void
odhash_free(struct odflow_hash *odfh)
{
	if (odfh->nrecord > 0)
		odhash_reset(odfh);
	free(odfh->tbl);
	free(odfh);
}

void
odhash_resetall(struct response *resp)
{
	/* reset hashes */
	odhash_reset(resp->ip_hash);
	odhash_reset(resp->ip6_hash);
	if (proto_view)
		odhash_reset(resp->proto_hash);
}


/* odhash_reset re-initialize the given odhash */
void
odhash_reset(struct odflow_hash *odfh)
{
	int i;
	struct odflow *odfp;

	if (odfh->nrecord == 0)
		return;
        for (i = 0; i < odfh->nbuckets; i++) {
                while ((odfp = TAILQ_FIRST(&odfh->tbl[i].odfq_head)) != NULL) {
			TAILQ_REMOVE(&odfh->tbl[i].odfq_head, odfp, odf_chain);
			odfh->tbl[i].nrecord--;
			odflow_free(odfp);
		}
	}
	/* initialize counters */
	odfh->byte = odfh->packet = 0;
	odfh->nrecord = 0;
}

/* add counts to upper odflow */
struct odflow *
odflow_addcount(struct odflow_spec *odfsp, int af,
    uint64_t byte, uint64_t packet, struct response *resp)
{
	struct odflow_hash *odfh = NULL;
	struct odflow *odfp;

	/* fetch a pointer to the corresponding odflow_hash */
	if (af == AF_INET)
		odfh = resp->ip_hash;
	else if  (af == AF_INET6)
		odfh = resp->ip6_hash;
	else
		odfh = resp->proto_hash;

	assert(odfh != NULL);

	odfp = odflow_lookup(odfh, odfsp);
	odfp->af = af;	/* set address family */

	/* update count in the hash */
	odfh->byte += byte;
	odfh->packet += packet;

	/* update count in this record */
	odfp->byte += byte;
	odfp->packet += packet;

	return (odfp);
}

/* add counts to lower odflow (odproto) */
void
odproto_addcount(struct odflow *odfp, struct odflow_spec *odpsp, int af,
    uint64_t byte, uint64_t packet)
{
	struct odflow *odpp;

	odpp = odproto_lookup(odfp, odpsp, af);
	odpp->byte += byte;
	odpp->packet += packet;
}

struct odflow *
odflow_alloc(struct odflow_spec *odfsp)
{
	struct odflow *odfp;

	if ((odfp = calloc(1, sizeof(struct odflow))) == NULL)
		err(1, "cannot allocate entry cache");

	TAILQ_INIT(&odfp->odf_odpq.odfq_head);
	odfp->odf_odpq.nrecord = 0;
	memcpy(&(odfp->s), odfsp, sizeof(struct odflow_spec));

	odfp->odf_cache = cl_alloc();
#ifndef NDEBUG	/* for thread-safe odflow accounting */
	pthread_mutex_lock(&odflow_mutex);
	if (++odflows_allocated > max_odflows_allocated)
		max_odflows_allocated = odflows_allocated;
	pthread_mutex_unlock(&odflow_mutex);
#endif
	return (odfp);
}

void
odflow_free(struct odflow *odfp)
{
	struct odflow *odpp;

	cl_free(odfp->odf_cache);
	while ((odpp = TAILQ_FIRST(&odfp->odf_odpq.odfq_head)) != NULL) {
		TAILQ_REMOVE(&odfp->odf_odpq.odfq_head, odpp, odf_chain);
		odfp->odf_odpq.nrecord--;
		odflow_free(odpp);
	}
#ifndef NDEBUG	/* for thread-safe odflow accounting */
	pthread_mutex_lock(&odflow_mutex);
	odflows_allocated--;
	pthread_mutex_unlock(&odflow_mutex);
#endif
	free(odfp);
}

/*
 * look up odflow matching the given spec in the hash.
 * if not found, allocate one.
 */
struct odflow *
odflow_lookup(struct odflow_hash *odfh, struct odflow_spec *odfsp)
{
        struct odflow *odfp;
	int slot;

	/* get slot id */
	slot = slot_fetch(odfsp->src, odfsp->dst, odfh->nbuckets);

	/* find entry */
        TAILQ_FOREACH(odfp, &(odfh->tbl[slot].odfq_head), odf_chain) {
                if (!memcmp(odfsp, &(odfp->s), sizeof(struct odflow_spec)))
                        break;
	}

	if (odfp == NULL) {
		odfp = odflow_alloc(odfsp);
		odfh->nrecord++;
		TAILQ_INSERT_HEAD(&odfh->tbl[slot].odfq_head, odfp, odf_chain);
		odfh->tbl[slot].nrecord++;
	}
	return (odfp);
}

/*
 * look up odproto in the odflow tailq.
 * if not found, allocate one.
 */
static struct odflow *
odproto_lookup(struct odflow *odfp, struct odflow_spec *odpsp, int af)
{
	struct odflow *odpp;

	TAILQ_FOREACH(odpp, &(odfp->odf_odpq.odfq_head), odf_chain) {
		if (odpp->af == af) {
			if (odpp->s.srclen == odpsp->srclen &&
				odpp->s.dstlen == odpsp->dstlen) {
				if (memcmp(&odpp->s, odpsp, sizeof(struct odflow_spec)) == 0)
					break;
			} else {
				/* is this a superset? (after quickmerege) */
				if (odflowspec_is_overlapped(&odpp->s, odpsp))
					break;
			}
		}
	}

	if (odpp == NULL && odfp->odf_odpq.nrecord >= ODPQ_MAXENTRIES &&
		!disable_heuristics) {
		/* protection against port scans: */
		odpp = odproto_quickmerge(&odfp->odf_odpq, odpsp);
	}

	/* if this record is not in the table, create new entry */
	if (odpp == NULL) {
		odpp = odflow_alloc(odpsp);
		odpp->af = af;
		TAILQ_INSERT_HEAD(&odfp->odf_odpq.odfq_head, odpp, odf_chain);
		odfp->odf_odpq.nrecord++;
	}

	return (odpp);
}

/*
 * protection against port scan (for aguri3 mode)
 * when the list of protocols becomes too long, add a wildcard.
 * the wildcard is selected 
 *  wildcard[0]: proto:sport:*
 *  wildcard[1]: proto:*:dport
 *  wildcard[2]: proto:*:*
 * then, merge the existing entries into this wildcard.
 */
static struct odflow *
odproto_quickmerge(struct odf_tailq *odfq, struct odflow_spec *odpsp)
{
	struct odflow *odpp, *wildcard[3], **candidates[3];
	int i, n, idx, nrecord;


	/* create 3 wildcard entries */
	nrecord = odfq->nrecord;
	for (i = 0; i < 3; i++) {
		struct odflow_spec odf_spec;
		int label[2];

		/* create a wildcard labels */
		label[0] = label[1] = 8;
		if (i < 2)
			label[i] += 16; /* sport or dport */
		odf_spec = odflowspec_gen(odpsp, label, 24/8);

		wildcard[i] = odflow_alloc(&odf_spec);
		wildcard[i]->af = AF_LOCAL;
		if ((candidates[i] = calloc(nrecord, sizeof(odpp))) == NULL)
			err(1, "odproto_quickmerge: calloc failed!");
	}

	/* first, go through the list to select one of the wildcards */
	n = 0;
	TAILQ_FOREACH(odpp, &odfq->odfq_head, odf_chain) {
		for (i = 0; i < 3; i++)
			if (odflowspec_is_overlapped(&wildcard[i]->s, &odpp->s)) {
				wildcard[i]->byte   += odpp->byte;
				wildcard[i]->packet += odpp->packet;
				candidates[i][n] = odpp;
			}
		n++;
	}
	assert(n == nrecord);
	
	/* select the best wildcard */
	idx = 0;
	if (wildcard[0]->packet < wildcard[1]->packet)
		idx = 1;
	if (wildcard[idx]->packet < wildcard[2]->packet / 2)
		idx = 2;  /* use proto:*:* if either port is not a majority */

	/* remove the merged entries */
	n = 0;
	for (i = 0; i < nrecord; i++) {
		odpp = candidates[idx][i];
		if (odpp != NULL) {
			TAILQ_REMOVE(&odfq->odfq_head, odpp, odf_chain);
			odfq->nrecord--;
			odflow_free(odpp);
			n++;
		}
	}

	/* add the wildcard to the list (in the reverse order of prefixlens) */
	if (TAILQ_EMPTY(&odfq->odfq_head)) {
		TAILQ_INSERT_HEAD(&odfq->odfq_head, wildcard[idx], odf_chain);
	} else {
		int len = wildcard[idx]->s.srclen + wildcard[idx]->s.dstlen;
		odpp = TAILQ_LAST(&odfq->odfq_head, odfqh);
		while (odpp->s.srclen + odpp->s.dstlen < len)
			odpp = TAILQ_PREV(odpp, odfqh, odf_chain);
		TAILQ_INSERT_AFTER(&odfq->odfq_head, odpp, wildcard[idx], odf_chain);
	}
	odfq->nrecord++;
	/* clean up: */
	for (i = 0; i < 3; i++) {
		if (i != idx)
			odflow_free(wildcard[i]);
		free(candidates[i]);
	}
	if (debug) {
		fprintf(stderr, "odproto_quickmerge: %d/%d merged\n",
			n, nrecord);
	}

	return (wildcard[idx]);
}

void
odflow_stats(void)
{
#ifndef NDEBUG	/* for thread-safe odflow accounting */
	fprintf(stderr, "odflow_stats: %ld currently allocated (max %ld)\n",
		odflows_allocated, max_odflows_allocated);
#endif
}

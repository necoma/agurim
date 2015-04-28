/*
 * Copyright (C) 2012-2015 WIDE Project.
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

#include "agurim.h"

struct odflow_hash *ip_hash;
struct odflow_hash *ip6_hash;
struct odflow_hash *proto_hash;

static struct odflow *odflow_alloc(struct odflow_spec *odfsp);
static struct odflow *odproto_lookup(struct odflow *odfp, struct odflow_spec *odpsp, int af);

void
odhash_init()
{
	ip_hash = odhash_alloc();
	ip6_hash = odhash_alloc();
	if (proto_view)
		proto_hash = odhash_alloc();
}

struct odflow_hash *
odhash_alloc(void)
{
	struct odflow_hash *odfh;
	int i;

	if ((odfh = calloc(1, sizeof(struct odflow_hash))) == NULL)
		err(1, "odhash_alloc: malloc");
	/* allocate a hash table */
	if ((odfh->tbl = calloc(NBUCKETS, sizeof(struct odf_tailq))) == NULL)
		err(1, "odhash_alloc: malloc");
	for (i = 0; i < NBUCKETS; i++) {
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
	free(odfh->tbl);
	free(odfh);
}

void
odhash_reset(struct odflow_hash *odfh)
{
	int i;
	struct odflow *odfp;

	if (odfh->nrecord == 0)
		return;
        for (i = 0; i < NBUCKETS; i++) {
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
    uint64_t byte, uint64_t packet)
{
	struct odflow_hash *odfh = NULL;
	struct odflow *odfp;

	/* fetch a pointer to the corresponding odflow_hash */
	if (af == AF_INET)
		odfh = ip_hash;
	else if  (af == AF_INET6)
		odfh = ip6_hash;
	else
		odfh = proto_hash;

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

static struct odflow *
odflow_alloc(struct odflow_spec *odfsp)
{
	struct odflow *odfp;

	odfp = malloc(sizeof(struct odflow));
	if (odfp == NULL)
		err(1, "cannot allocate entry cache");

	memset(odfp, 0, sizeof(struct odflow));
	TAILQ_INIT(&odfp->odf_odpq.odfq_head);
	odfp->odf_odpq.nrecord = 0;
	memcpy(&(odfp->s), odfsp, sizeof(struct odflow_spec));

	odfp->odf_cache = cl_alloc();

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
	slot = slot_fetch(odfsp->src, odfsp->dst);

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
		if (odpp->af == af &&
		    memcmp(&odpp->s, odpsp, sizeof(struct odflow_spec)) == 0)
			break;
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

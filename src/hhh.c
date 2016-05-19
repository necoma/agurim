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

/*
 * The aggregation method is based on the HHH algorithm published in IMC 2004.
 * See the paper titled as "Online identification of hierarchical heavy
 * hitters: algorithms, evaluation, and applications."
 */

#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <err.h>

#include "agurim.h"

static int do_overlapping(struct odflow_hash *_odfh, int bitlen);
static int do_overlapping2(struct odflow *odfp, int bitlen);
static int hhh_alloc(struct odflow_hash *old, struct odflow_hash **new,
    struct odflow ***fl);
static int hhh_alloc2(struct odflow *odfp, int af, struct odflow_hash **new, struct odflow ***fl);
static void hhh_finish(struct odflow_hash **odfh, struct odflow ***fl);
static int odflow_aggregate(struct odflow_hash *odfh, struct odflow **fl,
    int label[], int bytesize, int n);
static int level_check(struct odflow_spec *odfsp, int label[]);
static int label_check(struct odflow_spec *odfsp, int label[]);
static struct odflow_spec
odflowspec_gen(struct odflow_spec *odfsp, int label[], int bytesize);
static int odflow_extract(struct odflow_hash *h, struct odflow **fl,
	struct odf_tailq *odfqp, uint64_t thresh, uint64_t thresh2, int phase);
static int criteria_check(struct odflow *odfp, uint64_t thresh, uint64_t thresh2);

void hhh_run()
{
	struct odflow *odfp;
	int nflows;
	
	if (proto_view == 0) {
		/* calculate total bytes/packets and thresholds */
		response.total_byte = ip_hash->byte + ip6_hash->byte;
		response.thresh_byte = response.total_byte * query.threshold / 100;
		response.total_packet = ip_hash->packet + ip6_hash->packet;
		response.thresh_packet = response.total_packet * query.threshold / 100;

		/* for IPv4, aggregate 32 bits by 8-bit unit */
		response.nflows = do_overlapping(ip_hash, 32);
		/* for IPv6, aggregate 128 bits by 16-bit unit */
		response.nflows += do_overlapping(ip6_hash, 128);
	} else {
		/* calculate total bytes/packets and thresholds */
		response.total_byte = proto_hash->byte;
		response.thresh_byte = response.total_byte * query.threshold / 100;
		response.total_packet = proto_hash->packet;
		response.thresh_packet = response.total_packet * query.threshold / 100;

		response.nflows = do_overlapping(proto_hash, 24);
	}

	/* if # of entries is specified, further reduce the list */
	if (query.nflows != 0 && query.nflows < response.nflows) {
		/* get ranking */
		odfq_countsort(&response.odfq);
		odfq_listreduce(&response.odfq, query.nflows);
		/* update the total flows in the response */
		response.nflows = query.nflows;
#if 1
		/* XXX we can replace nflows by nrecord */
		assert(response.nflows == response.odfq.nrecord);
#endif		
		/* restore the area order */
		odfq_areasort(&response.odfq);
	}

	/* aggregate protocols */
        TAILQ_FOREACH(odfp, &response.odfq.odfq_head, odf_chain) {
		if (proto_view == 0)
			nflows = do_overlapping2(odfp, 24);
		else {
			nflows = do_overlapping2(odfp, 32);
			nflows += do_overlapping2(odfp, 128);
		}

		if (query.nflows != 0 && query.nflows < nflows) {
			/* get ranking */
			odfq_countsort(&odfp->odf_odpq);
			odfq_listreduce(&odfp->odf_odpq, query.nflows);
			/* restore the area order */
			odfq_areasort(&odfp->odf_odpq);
		}
	}
}

/*
 * the HHH overlapping algorithm for odflow fields.
 */
/*
 * prefix combination table, label[prefixlen1][prefixlen2],
 * for walking through a HHH diamond mesh from bottom to top (level), and
 * from left to right (position).
 * note: must be inversely ordered by the sum of the prefix lengths
 */
static int ipv4_labels[25][2] = {
  {32,32},{32,24},{24,32},{32,16},{16,32},{24,24}, 
  {32,8},{8,32},{24,16},{16,24},{32,0},{0,32},{24,8},{8,24},{16,16},
  {24,0},{0,24},{16,8},{8,16},{16,0},{0,16},{8,8},{8,0},{0,8},{0,0}
};

/* IPv6 heuristics: use only 39/81 combinations */
static int ipv6_labels[39][2] = {
  {128,128},{128,112},{112,128},/*{128,96},{96,128},*/{112,112},
  /*{128,80},{80,128},{112,96},{96,112},*/
  {128,64},{64,128},/*{112,80},{80,112},{96,96},*/
  {128,48},{48,128},{112,64},{64,112},/*{96,80},{80,96},*/
  {128,32},{32,128},/*{112,48},{48,112},{96,64},{64,96},{80,80},*/
  {128,16},{16,128},/*{112,32},{32,112},{96,48},{48,96},{80,64},{64,80},*/
  {128,0},{0,128},/*{112,16},{16,112},{96,32},{32,96},{80,48},{48,80},*/{64,64},
  /*{112,0},{0,112},{96,16},{16,96},{80,32},{32,80},{64,48},{48,64},*/
  /*{96,0},{0,96},{80,16},{16,80},*/{64,32},{32,64},{48,48},
  /*{80,0},{0,80},*/{64,16},{16,64},{48,32},{32,48},
  {64,0},{0,64},{48,16},{16,48},{32,32},
  {48,0},{0,48},{32,16},{16,32},{32,0},{0,32},{16,16},{16,0},{0,16},{0,0}
};

static int proto_labels[5][2] = {
  {24,24},{24,8},{8,24},{8,8},{0,0}
};

static int
do_overlapping(struct odflow_hash *_odfh, int bitlen)
{
	struct odflow_hash *odfh = NULL;
	struct odflow **odflow_list = NULL;
	int pos_id = 0;
	int *label, n, nflows = 0;
	int (*labels)[2];
	
	/*
	 * init new odflow_hash and list, and then, move all the
	 * odflow entries to the list sorted by the sum of prefix lengths
	 */
	n = hhh_alloc(_odfh, &odfh, &odflow_list);

	assert(odfh != NULL);
	assert(odflow_list != NULL);

	labels = ipv4_labels;
	if (bitlen == 128)
		labels = ipv6_labels;  /* XXX */
	else if (bitlen == 24)
		labels = proto_labels;  /* XXX */

	/* go throuth the label combinations, [prefilen1][prefixlen2] */
	while (1) {
		/*
		 * at this point, all the remaining odflow entries are
		 * on the list, and odfh is empty
		 */
		/* select a prefix length label for aggregation */
		label = &labels[pos_id][0];

		/* 
		 * aggregate each flow entry up to the corresponding
		 * upper node given by the label
		 */
		if (odflow_aggregate(odfh, odflow_list, label, bitlen / 8, n) > 0) {
			/* move entries bigger than threshold to response */
			nflows += odflow_extract(odfh, odflow_list, &response.odfq,
				response.thresh_byte, response.thresh_packet, 1);
		}
		/* reset the counters in the hash */
		odhash_reset(odfh);

		if (label[0] == 0 && label[1] == 0)
			break;
		pos_id++;  /* move the position to the next */
	}
	hhh_finish(&odfh, &odflow_list);

	return (nflows);
}

/* this version is for (lower odflow or odproto) subentries */
static int
do_overlapping2(struct odflow *odfp, int bitlen)
{
	struct odflow_hash *odfh = NULL;
	struct odflow **odflow_list = NULL;
	int pos_id = 0;
	int *label, n, af, nflows = 0;
	int (*labels)[2];
	uint64_t thresh, thresh2;

	labels = proto_labels;
	af = AF_LOCAL;
	if (bitlen == 32) {
		labels = ipv4_labels;  /* XXX */
		af = AF_INET;
	} else if (bitlen == 128) {
		labels = ipv6_labels;  /* XXX */
		af = AF_INET6;
	}
	n = hhh_alloc2(odfp, af, &odfh, &odflow_list);
	assert(odfh != NULL);
	assert(odflow_list != NULL);

	/* calculate threshold */
	thresh  = odfp->byte   * query.threshold / 100;
	thresh2 = odfp->packet * query.threshold / 100;

	/* go throuth the label combinations, [prefilen1][prefixlen2] */
	while (1) {
		label = &labels[pos_id][0];

		if (odflow_aggregate(odfh, odflow_list, label, bitlen / 8, n) > 0)
			nflows += odflow_extract(odfh, odflow_list, &odfp->odf_odpq,
				thresh, thresh2, 2);
		/* reset the counters in the hash */
		odhash_reset(odfh);
		
		if (label[0] == 0 && label[1] == 0)
			break;
		pos_id++;  /* move the position to the next */
	}
	hhh_finish(&odfh, &odflow_list);

	return (nflows);
}

/* 
 * preapre for the hhh algorithm: allocate a new hash and odflow_list,
 * and then, move all odflows from the old hash to the sorted list.
 */
static int
hhh_alloc(struct odflow_hash *old, struct odflow_hash **new,
    struct odflow ***fl)
{
	struct odflow_hash *_new; 
	struct odflow *odfp;
	struct odflow **_fl;
	int i, n = 0;

	_new = odhash_alloc(2048);

	/* allocate flow buffer to store all the flow entries */
	_fl = malloc(sizeof(struct odflow *) * old->nrecord);
	if (_fl == NULL)
		err(1, "malloc(odflows) fails.");

	/* move all odflow entries from odflow_hash to odflow_list */
	if (old->nrecord > 0)
		for (i = 0; i < old->nbuckets; i++) {
			while ((odfp = TAILQ_FIRST(&old->tbl[i].odfq_head)) != NULL) {
				TAILQ_REMOVE(&old->tbl[i].odfq_head, odfp, odf_chain);
				old->tbl[i].nrecord--;
				_fl[n++] = odfp;
			}
		}
        assert(n == old->nrecord);

        /* sort odflow entries by the sum of prefix length in the reverse order */
        qsort(_fl, n, sizeof(struct odflow *), area_comp);

	*fl = _fl;
	*new = _new;

	return (n);
}

/* this version is for (odproto) subentries */
static int
hhh_alloc2(struct odflow *odfp, int af, struct odflow_hash **new, struct odflow ***fl)
{
	struct odflow_hash *newhash; 
	struct odflow *odpp;
	struct odflow **newfl;
	int bufsize, n = 0;

	newhash = odhash_alloc(2048);
	/*
	 * move odflow's odproto entries to odproto_list
	 */
	bufsize = 256; /* XXX */
	newfl = malloc(sizeof(struct odflow *) * bufsize);
	if (newfl == NULL)
		err(1, "malloc(odflows) fails.");
	odpp = TAILQ_FIRST(&odfp->odf_odpq.odfq_head);
	while (odpp != NULL) {
		if (odpp->af == af) {
			TAILQ_REMOVE(&odfp->odf_odpq.odfq_head, odpp, odf_chain);
			odfp->odf_odpq.nrecord--;
			if (n == bufsize) {
				bufsize *= 2; /* double the size */
				newfl = realloc(newfl, sizeof(struct odflow *) * bufsize);
			}
			newfl[n++] = odpp;
		}
		odpp = TAILQ_NEXT(odpp, odf_chain);
	}

        qsort(newfl, n, sizeof(struct odflow *), area_comp);

	*fl = newfl;
	*new = newhash;

	return (n);
}

static void
hhh_finish(struct odflow_hash **odfh, struct odflow ***fl)
{
	odhash_free(*odfh);
	free(*fl);
}

/*
 * try to aggregate odflows in the list for the given label.
 * new entries matching for the label are created on the hash.
 */
static int
odflow_aggregate(struct odflow_hash *odfh, struct odflow **fl, int label[],
    int bytesize, int listsize)
{
	int i, n = 0;
	struct odflow *odfp, *_odfp;
	struct odflow_spec odfsp;

	/* walk through the odflow_list */
	for (i = 0; i < listsize; i++) {
		if ((_odfp = fl[i]) == NULL)
			continue;  /* removed subentry */
		if (!level_check(&(_odfp->s), label))
			break;	/* skip the remaining entries */
		if (!label_check(&(_odfp->s), label))
			continue;  /* doesn't fit the label */

#ifdef notyet
		/*
		 * if the entry is large enough, we should keep the current
		 * prefixes.
		 */
#endif

		/* make a new flow_spec with the corresponding label value */
		odfsp = odflowspec_gen(&(_odfp->s), label, bytesize);

		/* insert the new odflow to a temporal hash */
		odfp = odflow_lookup(odfh, &odfsp);
		odfp->byte += _odfp->byte;
		odfp->packet += _odfp->packet;
		odfp->af = _odfp->af;

		/* save this index in the subentry list for proto aggregation */
		cl_append(odfp->odf_cache, i);
		n++;
	}
	return (n);
}

static int
level_check(struct odflow_spec *odfsp, int label[])
{
	int level, len;

	level = label[0] + label[1];
	len = odfsp->srclen + odfsp->dstlen;
	if (level > len)
		return (0);
	return (1);
}

static int
label_check(struct odflow_spec *odfsp, int label[])
{
	if (odfsp->srclen < label[0] || odfsp->dstlen < label[1])
		return (0);
	return (1);
}

/*
 * create new odflow record based on the flowspec and the label
 */
static struct odflow_spec
odflowspec_gen(struct odflow_spec *odfsp, int label[], int bytesize)
{
	struct odflow_spec _odfsp; 
	
	memset(&(_odfsp), 0, sizeof(struct odflow_spec));
	_odfsp.srclen = label[0];
	_odfsp.dstlen = label[1];
	prefix_set(odfsp->src, _odfsp.srclen, _odfsp.src, bytesize);
	prefix_set(odfsp->dst, _odfsp.dstlen, _odfsp.dst, bytesize);

	return (_odfsp);	/* struct return */
}

/*
 * extract odflows from odflow_hash to tailq.
 * returns the number of flows extracted.
 */
static int
odflow_extract(struct odflow_hash *odfh, struct odflow **fl,
    struct odf_tailq *odfqp, uint64_t thresh, uint64_t thresh2, int phase)
{
	int i, j, size, nflows = 0;
	struct odflow *odfp;

	/* walk through the odflow_hash */
        for (i = 0; i < odfh->nbuckets; i++) {
                while ((odfp = TAILQ_FIRST(&odfh->tbl[i].odfq_head)) != NULL) {
                        TAILQ_REMOVE(&odfh->tbl[i].odfq_head, odfp, odf_chain);
			odfh->tbl[i].nrecord--;
			if (criteria_check(odfp, thresh, thresh2)) {
				/* add this entry to the tail of response */
				TAILQ_INSERT_TAIL(&odfqp->odfq_head, odfp, odf_chain);
				odfqp->nrecord++;
				nflows++;
				
				/* remove prcoessed odflows from the list */
				size = cl_size(odfp->odf_cache);
				for (j = 0; j < size; j++) {
					int idx = cl_get(odfp->odf_cache, j);
					if (fl[idx] != NULL) {
						if (phase < 2)
							odfq_moveall(&fl[idx]->odf_odpq, &odfp->odf_odpq);
						odflow_free(fl[idx]);
						fl[idx] = NULL;
					}
				}
				cl_clear(odfp->odf_cache);
			}
		}
	}
	return (nflows);
}

static int
criteria_check(struct odflow *odfp, uint64_t thresh, uint64_t thresh2)
{
	switch (query.criteria) { 
	case PACKET:
		if (odfp->packet >= thresh2)
			return (1);
		break;
	case BYTE:
		if (odfp->byte >= thresh)
			return (1);
		break;
	case COMBINATION:
		if (odfp->packet >= thresh2 || odfp->byte >= thresh)
			return (1);
		break;
	}

	/* keep the wildcard */
	if (!query.f_af && odfp->s.srclen == 0 && odfp->s.dstlen == 0)
		return (1);
	return (0);
}

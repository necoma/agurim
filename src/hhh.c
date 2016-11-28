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
#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "agurim.h"

/*
 * parameters used for the recursive lattice search
 */
struct hhh_params {
	struct odflow **flow_list;  /* list of original odflows to aggregate */
	uint64_t thresh, thresh2;	/* threshold values for aggregation */
	int	maxsize;    /* max size to detect the edge: 32 for IPv4 */
	int	minsize;    /* granularity */
	int	prefixlen;  /* prefix length: 32 for IPv4 addres */
	int	cutoff;	    /* apply coarser granularity when prefixlen is 
			     shorter than this value */
	int	cutoffres;  /* resolution for cutoff region */
	struct odf_tailq *odfqp;/* queue for placing extracted odflows */
};

inline static int label_check(struct odflow_spec *odfsp, int label[]);
inline static int thresh_check(struct odflow *odfp, 
				uint64_t thresh, uint64_t thresh2);
static struct odflow_spec odflowspec_gen(struct odflow_spec *odfsp, 
				int label[], int bytesize);
static int odflow_aggregate(struct odflow_hash *odfh, struct odflow *parent,
		int label[], struct hhh_params *params);
static int odflow_extract(struct odflow_hash *odfh, struct odflow *parent,
				struct hhh_params *params);
static int lattice_search(struct odflow *parent, int pl0, int pl1, int size,
			int pos, struct hhh_params *params);
static int find_hhh(struct odflow_hash *hash, int bitlen,
		uint64_t thresh, uint64_t thresh2, struct odf_tailq *odfqp);

static struct odflow_hash *dummy_hash;  /* used in lattice_search for
					 * dummy iteration */
int disable_heuristics = 0;  /* do not use label heuristics */

/*
 * check if the odflow fits into the given label pair
 */
inline static int
label_check(struct odflow_spec *odfsp, int label[])
{
	if (odfsp->srclen < label[0] || odfsp->dstlen < label[1])
		return (0);
	return (1);
}

/*
 * check if the odflow is above the threshold
 */
inline static int
thresh_check(struct odflow *odfp, uint64_t thresh, uint64_t thresh2)
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

/* 4 positions for sub-areas in the recursive lattice search */
#define POS_LOWER	0
#define POS_LEFT	1
#define POS_RIGHT	2
#define POS_UPPER	3

/*
 * try to aggregate odflows in the list for the given label.
 * new entries matching for the label are created on the hash.
 * returns the number of original flows aggregated.
 */
static int
odflow_aggregate(struct odflow_hash *odfh, struct odflow *parent,
	int label[], struct hhh_params *params)
{
	int i, n = 0, listsize;
	struct odflow *odfp, *_odfp, **fl;
	struct odflow_spec odfsp;

	/* walk through the odflow cache_list of parent */
	fl = params->flow_list;
	listsize = cl_size(parent->odf_cache);
	for (i = 0; i < listsize; i++) {
		int index = cl_get(parent->odf_cache, i);
		if ((_odfp = fl[index]) == NULL)
			continue;  /* removed subentry */
		if (!label_check(&(_odfp->s), label))
			continue;  /* doesn't fit the label */

		/* make a new flow_spec with the corresponding label value */
		odfsp = odflowspec_gen(&_odfp->s, label, params->prefixlen/8);

		/* insert the new odflow to a temporal hash */
		odfp = odflow_lookup(odfh, &odfsp);
		odfp->byte += _odfp->byte;
		odfp->packet += _odfp->packet;
		odfp->af = _odfp->af;

		/* save this index in the cache list for sub-attr aggregation */
		cl_append(odfp->odf_cache, index);
		n++;
	}
	return (n);
}

/*
 * extract odflows from odflow_hash to tailq.
 * returns the number of flows extracted.
 */
static int
odflow_extract(struct odflow_hash *odfh,
	struct odflow *parent, struct hhh_params *params)
{
	int i, j, size, nflows = 0;
	struct odflow *odfp, **fl;

	/* walk through the odflow_hash */
	fl = params->flow_list;
	for (i = 0; i < odfh->nbuckets; i++) {
                while ((odfp = TAILQ_FIRST(&odfh->tbl[i].odfq_head)) != NULL) {
                        TAILQ_REMOVE(&odfh->tbl[i].odfq_head, odfp, odf_chain);
			odfh->tbl[i].nrecord--;
			if (!thresh_check(odfp, params->thresh, params->thresh2)) {
				/* under the threshold, discard this entry */
				odflow_free(odfp);
				continue;
			}
#if 1	/* for debug */
			if (verbose) {
				printf("# extract: ");
				odflow_print(odfp);
				printf(" packet:%" PRIu64 "\n", odfp->packet);
			}
#endif

			/* book keeping extracted packets/bytes */
			parent->packet -= odfp->packet;
			parent->byte   -= odfp->byte;

			/* add this entry to the tail of the queue */
			TAILQ_INSERT_TAIL(&params->odfqp->odfq_head, odfp, odf_chain);
			params->odfqp->nrecord++;
			nflows++;
				
			/* remove prcoessed odflows from the list */
			size = cl_size(odfp->odf_cache);
			for (j = 0; j < size; j++) {
				int idx = cl_get(odfp->odf_cache, j);
				if (fl[idx] != NULL) {
					if (fl[idx]->odf_odpq.nrecord > 0)
						/* move the sub-odflows (for main attribute) */
						odfq_moveall(&fl[idx]->odf_odpq, &odfp->odf_odpq);
					odflow_free(fl[idx]);
					fl[idx] = NULL;
				}
			}
			cl_clear(odfp->odf_cache);
		} /* while */
	} /* for */
	return (nflows);
}

/*
 * recursive lattice search algorithm for fiding HHH.
 * aggregate flows in the parent cache_list by the given label [pl0,pl1].
 * for each created aggregated odflow, if it is larger than the threshold,
 * subdivide the odflow into 4 sub-areas, and recursively search for
 * longer label pairs larger then the threshold.
 *
 * to give preferences to the full prefix length in either label,
 * the algorithm runs first on the left bottom edge, then, on the
 * right bottom edge.  finally run on the entire lattice space.
 *
 * other protocol specific heuristics:
 *  IPv4:
 *   - when prefixlen < 16, do not aggregate beyond 8 bit boundary
 *  IPv6:
 *   - do not aggregate the lower 64 bits (inside interface ID)
 *   - when prefixlen < 32, do not aggregate beyond 16 bit boundary
 *  protocols:
 *   - do not aggregate the protocols and ports
 */
#define ON_LEFTEDGE	1
#define ON_RIGHTEDGE	2

static int
lattice_search(struct odflow *parent, int pl0, int pl1, int size, int pos,
	struct hhh_params *params)
{
	int nflows = 0;	/* how many odflows extracted */
	struct odflow_hash *my_hash = NULL;
	int on_edge = 0;
	int do_aggregate = 1, do_recurse = 1;

	/* check if this is on the bottom edge */
	if (pl0 == params->maxsize)
		on_edge = ON_LEFTEDGE;
	else if (pl1 == params->maxsize)
		on_edge = ON_RIGHTEDGE;

	if (size <= params->minsize) {
		do_recurse = 0;
		if (on_edge == ON_LEFTEDGE) {
			/* need to visit the very bottom */
			if (size != 0)
				do_recurse = 1;
		}
	}
	/* don't extract for upper area, to be done later at an higher level */
	if (pos == POS_UPPER)
		do_aggregate = 0;

	if (!disable_heuristics) {
		int pl_max = max(pl0, pl1);  /* longer prefixlen */

		/* 
		 * if both prefixlens are shorter than cutoff, do not
		 * split beyond cutoff resolution
		 */
		if (pl_max < params->cutoff && size == params->cutoffres)
			do_recurse = 0;
	}
	if (!do_aggregate && !do_recurse)
		return 0;

#if 1	/* for debug */
	if (verbose && do_aggregate) {
		printf("# lattice_search:[%d,%d] size=%d pos=%d do:%d,%d parent:",
			pl0, pl1, size, pos, do_aggregate, do_recurse);
		odflow_print(parent);
		printf(": %" PRIu64 " (%.2f%%)\t%" PRIu64 " (%.2f%%)\n",
			parent->byte, (double)parent->byte / response.total_byte * 100,
			parent->packet, (double)parent->packet / response.total_packet * 100);
	}
#endif	
	if (do_aggregate) {
		int n, label[2] = {pl0, pl1};

		/* create new odflows in the hash by the given label pair */
		n = cl_size(parent->odf_cache) / 8;  /* estimate hash size */
		my_hash = odhash_alloc(n);
		n = odflow_aggregate(my_hash, parent, label, params);
		if (n == 0) {
			/* no aggregate flow was created */
			odhash_free(my_hash);
			return 0;
		}
	} else {
		my_hash = dummy_hash;  /* used just for iteration */
	}

	/*
	 * go through the odflows created, recursively visit 4 sub-areas
	 * in the order: lower, left, right, upper.
	 * note: for the bottom edge, only lower and upper are used
	 */
	if (do_recurse) {
		int i, delta, subsize;

		if (size == params->minsize) { 	/* minimum aggregation unit */
			delta = size; subsize = 0;
		} else {
			delta = size / 2; subsize = delta;
		}
#if 1	/* XXX special case for IPv6, do not subdivide the lower 64 bits */
		if (!disable_heuristics && (pl0 + pl1 == 192)) {
			delta = size; subsize = 0;
		}
#endif
		for (i = 0; i < my_hash->nbuckets; i++) {
			struct odflow *odfp;

			TAILQ_FOREACH(odfp, &(my_hash->tbl[i].odfq_head), odf_chain) {
				/* recursively visit sub-areas */
				int n, subpos, subpl0, subpl1;
				uint64_t packet, byte;

				if (!do_aggregate) /* dummy iteration */
					odfp = parent; /* use parent's */
				for (subpos = 0; subpos < 4; subpos++) {
					if (on_edge &&
					    (subpos == POS_LEFT || subpos == POS_RIGHT))
						/* if on edge, skip left/right */
						continue;
					if (thresh_check(odfp, params->thresh, params->thresh2) == 0)
						break; /* residual < thresh */
					/* adjust prefixlen pair for sub-area */
					subpl0 = pl0; subpl1 = pl1;
					switch (subpos) {
					case POS_LOWER:
						if (on_edge) {
							if (on_edge == ON_LEFTEDGE)
								subpl1 += delta;
							else
								subpl0 += delta;
						} else {
							subpl0 += delta; subpl1 += delta;
						}
						break;
					case POS_LEFT:
						subpl0 += delta; break;
					case POS_RIGHT:
						subpl1 += delta; break;
					}

					if (!disable_heuristics) {
						int subpl_min = min(subpl0, subpl1);
						if (subpl_min < params->cutoff &&
							(subpl_min & (params->cutoffres - 1)) != 0)
							continue;  /* skip this area */
					}

					/* visit this sub-area */
					packet = odfp->packet;
					byte   = odfp->byte;
					n = lattice_search(odfp, subpl0, subpl1, subsize, subpos, params);
					nflows += n;
					if (n > 0 && do_aggregate) {
						/* propagate extracted pkts/bytes to parent */
						parent->packet -= packet - odfp->packet;
						parent->byte -= byte - odfp->byte;
					}
				}
				if (!do_aggregate) /* XXX for dummy_hash */
					break; /* out of TAILQ_FOREACH */
			}
		} /* for */
	} /* do_recurse */
	/*
	 * walk through the hash again, and extract remaining odflows
	 * larger than the threshold.
	 * skip if the parent becomes smaller than the threshold
	 */
	if (do_aggregate) {
		if (thresh_check(parent, params->thresh, params->thresh2))
			nflows += odflow_extract(my_hash, parent, params);
		odhash_free(my_hash);
	}

	return nflows;
}

static int
find_hhh(struct odflow_hash *hash, int bitlen, uint64_t thresh, uint64_t thresh2,
	struct odf_tailq *odfqp)
{
	struct odflow *root, *odfp, *next;
	struct odflow_spec spec;
	struct hhh_params params;
	int i, n, nrecord, nflows = 0;

	/* create a dummy top node */
	memset(&spec, 0, sizeof(spec));
	root = odflow_alloc(&spec);

	/* allocate flow buffer to store all the flow entries */
	params.thresh  = thresh;
	params.thresh2 = thresh2;
	params.minsize = 1;
	params.maxsize = bitlen;
	params.prefixlen = bitlen;
	params.cutoff = 0;	/* no cutoff */
	params.cutoffres = 1;
	params.odfqp = odfqp;

	switch (bitlen) {
	case 32: /* IPv4 address */
		root->af = AF_INET;
		if (!disable_heuristics) {
#if 0
			params.minsize = 8; /* for backward compatibility */
#else
			params.minsize = 1;
#endif
			params.cutoff = 16;
			params.cutoffres = 8;
		}
		break;
	case 128: /* IPv6 address */
		root->af = AF_INET6;
		if (!disable_heuristics) {
#if 1
			params.minsize = 1;
#else
			params.minsize = 4;
#endif
			params.cutoff = 32;
			params.cutoffres = 16;
		}
		break;
	case 24:  /* protocol and port */
		root->af = AF_LOCAL;
		if (!disable_heuristics) {
			params.minsize = 16;
		}
		break;
	}
	/* create flow_list from hash or tailq */
	if (hash != NULL) {
		/* main-attribute: */
		params.flow_list = malloc(sizeof(struct odflow *) * hash->nrecord);
		if (params.flow_list == NULL)
			err(1, "malloc(flow_list) failed!");
		/* move all odflows in hash to odflow_list, and 
		 * make them pointed from root's cache_list */
		n = 0;
		if (hash->nrecord > 0)
			for (i = 0; i < hash->nbuckets; i++) {
				while ((odfp = TAILQ_FIRST(&hash->tbl[i].odfq_head)) != NULL) {
					TAILQ_REMOVE(&hash->tbl[i].odfq_head, odfp, odf_chain);
					hash->tbl[i].nrecord--;
			
					params.flow_list[n] = odfp;
					cl_append(root->odf_cache, n);
					root->packet += odfp->packet;
					root->byte   += odfp->byte;
					n++;
				}
			}
		assert(n == hash->nrecord);
	} else {
		/* sub-attribute: */
		/* first, find how many odflows are in the tailq */
		nrecord = 0;
		TAILQ_FOREACH(odfp, &odfqp->odfq_head, odf_chain) {
			if (odfp->af == root->af) /* only for matching af */
				nrecord++;
		}
		params.flow_list = malloc(sizeof(struct odflow *) * nrecord);
		if (params.flow_list == NULL)
			err(1, "malloc(flow_list) failed!");
		/* then, move the odflows in the tailq to the flow list */
		n = 0;
		odfp = TAILQ_FIRST(&odfqp->odfq_head);
		while (odfp != NULL) {
			next = TAILQ_NEXT(odfp, odf_chain);
			if (odfp->af == root->af) { /* only for matching af */
				TAILQ_REMOVE(&odfqp->odfq_head, odfp, odf_chain);
				odfqp->nrecord--;

				params.flow_list[n] = odfp;
				cl_append(root->odf_cache, n);
				root->packet += odfp->packet;
				root->byte   += odfp->byte;
				n++;
			}
			odfp = next;
		}
		assert(n == nrecord);
	}

	/* protocol specific recursive lattice search */
	switch (bitlen) {
	case 32: /* IPv4 address */
		/* left bottom edge */
		nflows += lattice_search(root, 32, 0, 32, POS_LOWER, &params);
		/* right bottom edge */
		nflows += lattice_search(root, 0, 32, 32, POS_LOWER, &params);
		/* sub-areas */
		nflows += lattice_search(root, 0, 0, 32, POS_LOWER, &params);
		break;
	case 128: /* IPv6 address */
		params.maxsize = 128;
		/* left bottom edge for /128 */
		nflows += lattice_search(root, 128, 0, 128, POS_LOWER, &params);
		/* right bottom edge for /128 */
		nflows += lattice_search(root, 0, 128, 128, POS_LOWER, &params);

		params.maxsize = 64;
		/* left bottom edge for /64 */
		nflows += lattice_search(root, 64, 0, 64, POS_LOWER, &params);
		/* right bottom edge for /64 */
		nflows += lattice_search(root, 0, 64, 64, POS_LOWER, &params);
		/* sub-areas for [64,64] */
		nflows += lattice_search(root, 0, 0, 64, POS_LOWER, &params);
		break;
	case 24:  /* protocol and port */
		/* left bottom edge */
		nflows += lattice_search(root, 24, 8, 16, POS_LOWER, &params);
		/* right bottom edge */
		nflows += lattice_search(root, 8, 24, 16, POS_LOWER, &params);
		/* sub-areas */
		nflows += lattice_search(root, 8, 8, 16, POS_LOWER, &params);

		/* for protocols, need to clean up the remaining odflows */
		for (i = 0; i < n; i++)
			if (params.flow_list[i] != NULL)
				odflow_free(params.flow_list[i]);
		break;
	}
	
	free(params.flow_list);
	return nflows;
}

/* run the HHH algorithm on the inputs */
void hhh_run()
{
	struct odflow *odfp;
	int nflows;
	uint64_t thresh, thresh2;

	/* create a dummy hash containing one dummy entry */
	if (dummy_hash == NULL) {
		struct odflow_spec spec;

		dummy_hash = odhash_alloc(1);
		if (dummy_hash == NULL)
			err(1, "odhash_alloc failed!");
		memset(&spec, 0, sizeof(spec));
		(void)odflow_lookup(dummy_hash, &spec);
	}
	
	if (proto_view == 0) {
		/* calculate total bytes/packets and thresholds */
		response.total_byte = ip_hash->byte + ip6_hash->byte;
		response.thresh_byte = response.total_byte * query.threshold / 100;
		response.total_packet = ip_hash->packet + ip6_hash->packet;
		response.thresh_packet = response.total_packet * query.threshold / 100;

		/* for IPv4, aggregate 32 bits */
		response.nflows = find_hhh(ip_hash, 32, response.thresh_byte,
				    response.thresh_packet, &response.odfq);
		/* for IPv6, aggregate 128 bits */
		response.nflows += find_hhh(ip6_hash, 128, response.thresh_byte,
				    response.thresh_packet, &response.odfq);
	} else {
		/* calculate total bytes/packets and thresholds */
		response.total_byte = proto_hash->byte;
		response.thresh_byte = response.total_byte * query.threshold / 100;
		response.total_packet = proto_hash->packet;
		response.thresh_packet = response.total_packet * query.threshold / 100;

		response.nflows = find_hhh(proto_hash, 24, response.thresh_byte,
				    response.thresh_packet, &response.odfq);
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
		/* calculate threshold */
		thresh  = odfp->byte   * query.threshold / 100;
		thresh2 = odfp->packet * query.threshold / 100;
		if (disable_heuristics < 2) {
			/* increase the threshold for sub-attributes */
			thresh *= 4;
			thresh2 *= 4;
		}
		if (proto_view == 0) {
			nflows = find_hhh(NULL, 24, thresh, thresh2,
					&odfp->odf_odpq);
		} else {
			nflows = find_hhh(NULL, 32, thresh, thresh2,
					&odfp->odf_odpq);
			nflows = find_hhh(NULL, 128, thresh, thresh2,
					&odfp->odf_odpq);
		}

		if (query.nflows != 0 && query.nflows < nflows) {
			/* get ranking */
			odfq_countsort(&odfp->odf_odpq);
			odfq_listreduce(&odfp->odf_odpq, query.nflows);
			/* restore the area order */
			odfq_areasort(&odfp->odf_odpq);
		}
	}

	if (dummy_hash != NULL) {
		odhash_free(dummy_hash);
		dummy_hash = NULL;
	}
}

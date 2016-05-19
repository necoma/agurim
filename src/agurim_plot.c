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

#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <assert.h>
#include <string.h>
#include <time.h>
#include <math.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "agurim.h"

static int calc_interval();
static int is_overlapped(struct odflow_spec *s0, struct odflow_spec *s1);
static struct odflow *odfq_parentlookup(struct odf_tailq *odfq, struct odflow *odfp);
static void odfq_insert(struct odf_tailq *odfq, struct odflow *odfp, enum aggr_criteria criteria);
static void odproto_countsort();
static void aguri_preamble_print();
static void aguri_odflow_print();
static void json_preamble_print();
static void json_odflow_print();
static void debug_preamble_print();
static void debug_odflow_print();

int time_slot;
time_t *plot_timestamps;

void plot_init()
{
	int duration;

	/* reset hashes */
	odhash_reset(ip_hash);
	odhash_reset(ip6_hash);
	if (proto_view)
		odhash_reset(proto_hash);

	if (query.outfmt == REAGGREGATION)
		return;

	/* calculate time buffers */
	response.interval = calc_interval();
	/* if the calclated interval is much smaller than the recorded
	 * one, increase it.
	 */
	while (response.interval < response.max_interval * 3/4)
		response.interval *= 2;

	/* allocate time buffers */
	duration = response.end_time - response.start_time;
	response.timeslots = (int)(duration / response.interval);
	if (plot_timestamps == NULL)
		plot_timestamps = calloc(response.timeslots+1, sizeof(time_t));

	/* insert the first timestamp */
	plot_timestamps[0] = response.start_time;

#if 0  /* we don't need this */
	/* clear idx cache of odflows in the response */
	TAILQ_FOREACH(odfp, &response.odfq.odfq_head, odf_chain) {
		cl_clear(odfp->odf_cache);
	}
#endif	
}

void plot_finish()
{
	struct odflow *odfp;

	while ((odfp = TAILQ_FIRST(&response.odfq.odfq_head)) != NULL) {
		TAILQ_REMOVE(&response.odfq.odfq_head, odfp, odf_chain);
		response.odfq.nrecord--;
		odflow_free(odfp);
	}
	response.nflows = 0;
}

/* create a new slot in the cache list for plotting */
void
plot_addslot()
{
	struct odflow *odfp;

	TAILQ_FOREACH(odfp, &response.odfq.odfq_head, odf_chain) {
		cl_append(odfp->odf_cache, 0);  /* add a new entry */
	}
}

/*
 * walk through the flow hash and add odflow's counts to the
 * corresponding slot of odflow's cache list in the response
 */
void
plot_addcount(struct odflow_hash *odfh)
{
	struct odflow *odfp0, *odfp1;
	int i, size;

	/* lookup overlapped label and update counts */
	if (odfh->nrecord == 0)  /* no traffic? */
		return;

        for (i = 0; i < odfh->nbuckets; i++) {
                while ((odfp1 = TAILQ_FIRST(&odfh->tbl[i].odfq_head)) != NULL) {
                        TAILQ_REMOVE(&odfh->tbl[i].odfq_head, odfp1, odf_chain);
			odfh->tbl[i].nrecord--;
			TAILQ_FOREACH(odfp0, &response.odfq.odfq_head, odf_chain) {
				if (odfp0->af == odfp1->af &&
				    is_overlapped(&(odfp0->s), &(odfp1->s))) {
					uint64_t cnt;
					if (query.criteria == BYTE)
						cnt = odfp1->byte;
					if (query.criteria == PACKET)
						cnt = odfp1->packet;
					/* add cnt to the last cache entry */
					size = cl_size(odfp0->odf_cache);
					cl_add(odfp0->odf_cache, size - 1, cnt);
					break;
				}
			}
		}
	}
}

void
plot_showdata()
{
	odfq_countsort(&response.odfq);

	switch (query.outfmt) {
	case REAGGREGATION:
		aguri_preamble_print();
		aguri_odflow_print();
		break;
	case JSON:
		printf("{\n");
		json_preamble_print();
		json_odflow_print();
		printf("}\n");
		break;
	case DEBUG:
		debug_preamble_print();
		debug_odflow_print();
		break;
	}
}

/* compute the appropriate interval from the duration */
static int
calc_interval()
{
	double duration;
	int d;

	duration = response.end_time - response.start_time;
	int interval;

	/*
	 * Guideline for a plotting interval
	 * +---------------------------------------+
	 * | duration | interval   (sec) | # of pt |
	 * +---------------------------------------+
	 * |  1year   |   1day   (86400) |  365pt  |
	 * |  1month  |   4hour  (14400) |  180pt  |
	 * |  1week   |   60min   (3600) |  168pt  |
	 * |  1day    |   10min    (600) |  144pt  |
	 * |  1hour   |   30sec     (30) |  120pt  |  	
	 * +---------------------------------------+
	 */
	d = (int)ceil(duration/3600);
	if (d <= 24) {
		/* shorter than 24hours: hours * 30 */
		interval = d * 30;
		return (interval < 600 ? interval : 600);
	}

	d = (int)ceil(duration/3600/24);
	if (d <= 7) {
		/* shorter than 7days: days * 600 */
		interval = d * 600;
		return (interval < 3600 ? interval : 3600);
	}
	if (d <= 31) {
		/* shorter than 31days: 14400 */
		return (14400);
	}

	d = (int)ceil(duration/3600/24/31);
	if (d <= 12) {
		/* shorter than 12months: months * 10800 */
		interval = d * 14400;
		return (interval < 86400 ? interval : 86400);
	}

	/* longer than 12months: years * 86400 */
	d = (int)ceil(duration/3600/24/366);
	interval = (int)duration * 86400;
	return (interval); 
}

/* sort the tailq by the count */
void
odfq_countsort(struct odf_tailq *odfq)
{
	struct odflow **odflow_list;
	struct odflow *odfp;
	int n = 0, i;
	int nflows = odfq->nrecord;

	odflow_list = malloc(sizeof(struct odflow *) * nflows);
	if (odflow_list == NULL)
		err(1, "odfq_countsort:malloc");

	while ((odfp = TAILQ_FIRST(&odfq->odfq_head)) != NULL) {
		TAILQ_REMOVE(&odfq->odfq_head, odfp, odf_chain);
		odfq->nrecord--;
		odflow_list[n++] = odfp;
	}

	assert(nflows == n);
	assert(odfq->nrecord == 0);

        /* sort flow entries in order */
        qsort(odflow_list, n, sizeof(struct odflow *), count_comp);

	for (i = 0; i < n; i++) {
		TAILQ_INSERT_HEAD(&odfq->odfq_head, odflow_list[i], odf_chain);
		odfq->nrecord++;
	}
	free(odflow_list);
}

/* aggregate the tailq to the specified numbers */
void
odfq_listreduce(struct odf_tailq *odfq, int nflows)
{
	struct odflow *odfp, *par;
	int n;

	n = odfq->nrecord;
	
	/* reduce # of entries from the tail */
	odfp = TAILQ_LAST(&odfq->odfq_head, odfqh);
	assert(odfp != NULL);
	while (n > nflows) {
		/* don't aggregate the wildcard */
		if (odfp->s.srclen == 0 && odfp->s.dstlen == 0) {
			odfp = TAILQ_PREV(odfp, odfqh, odf_chain);
			continue;
		}
		/* lookup a parent of this entry */
		TAILQ_REMOVE(&odfq->odfq_head, odfp, odf_chain);
		odfq->nrecord--;
		par = odfq_parentlookup(odfq, odfp);

		if (par != NULL) {
			/* update a parent */
			par->byte += odfp->byte;
			par->packet += odfp->packet;

			/* move protocols as well */
			odfq_moveall(&odfp->odf_odpq, &par->odf_odpq);

			/* insert this parent to the proper position */
			odfq_insert(odfq, par, query.criteria);
		} else {
			/* XXX can't do much here, just discard the entry */
		}
		/* free this entry */
		odflow_free(odfp);
		n--;

		odfp = TAILQ_LAST(&odfq->odfq_head, odfqh);
	}
	assert(n == nflows);
	assert(n == odfq->nrecord);
}

/* move all odflows from one tailq to another */
int
odfq_moveall(struct odf_tailq *from, struct odf_tailq *to)
{
	struct odflow *odpp;
	int n = 0;
	
        while ((odpp = TAILQ_FIRST(&from->odfq_head)) != NULL) {
                TAILQ_REMOVE(&from->odfq_head, odpp, odf_chain);
		from->nrecord--;
                TAILQ_INSERT_TAIL(&to->odfq_head, odpp, odf_chain);
		to->nrecord++;
		n++;
	}
	return (n);
}

/* look for a parent odflow in the given tailq */
static struct odflow *
odfq_parentlookup(struct odf_tailq *odfq, struct odflow *odfp)
{
	struct odflow *par, *_odfp;

	par = NULL;
	TAILQ_FOREACH(_odfp, &odfq->odfq_head, odf_chain) {
		if (_odfp->af != odfp->af)
			continue;
		if (is_overlapped(&(_odfp->s), &(odfp->s))) {
			if (par == NULL) {
				par = _odfp;
				continue;
			}
			if (par->s.srclen + par->s.dstlen < _odfp->s.srclen + _odfp->s.dstlen) 
				par = _odfp;
		}
	}
	return (par);
}

static int
is_overlapped(struct odflow_spec *s0, struct odflow_spec *s1)
{
	if (s0->srclen > s1->srclen || s0->dstlen > s1->dstlen)
		return (0);

	if (prefix_comp(s0->src, s1->src, s0->srclen) != 0 || 
	    prefix_comp(s0->dst, s1->dst, s0->dstlen) != 0)
		return (0);

	return (1);
}

/* insert this parent to the proper position in the sorted tailq */
static void
odfq_insert(struct odf_tailq *odfq, struct odflow *odfp, enum aggr_criteria criteria)
{
        struct odflow *_odfp;

        _odfp = TAILQ_PREV(odfp, odfqh, odf_chain);
        while (_odfp != NULL) {
		if (criteria == PACKET) {
                        if (odfp->packet <= _odfp->packet)
                                break;
		}
		if (criteria == BYTE) {
                        if (odfp->byte <= _odfp->byte)
                                break;
                }
		if (criteria == COMBINATION) {
			double f, _f;
			f = countfrac_select(odfp);
			_f = countfrac_select(_odfp);
			if (f <= _f)
				break;
		}
                _odfp = TAILQ_PREV(_odfp, odfqh, odf_chain);
        }
        if (_odfp != NULL) {
                if (TAILQ_NEXT(odfp, odf_chain) != _odfp) {
                        TAILQ_REMOVE(&odfq->odfq_head, odfp, odf_chain);
                        TAILQ_INSERT_AFTER(&odfq->odfq_head, _odfp, odfp, odf_chain);
                }
        } else if (TAILQ_FIRST(&odfq->odfq_head) != odfp) {
                TAILQ_REMOVE(&odfq->odfq_head, odfp, odf_chain);
                TAILQ_INSERT_HEAD(&odfq->odfq_head, odfp, odf_chain);
        }
}

/* sort the tailq by the sum of prefix lengths */
void
odfq_areasort(struct odf_tailq *odfq)
{
	struct odflow **odflow_list;
	struct odflow *odfp;
	int n = 0, i;
	int nflows = odfq->nrecord;

	odflow_list = malloc(sizeof(struct odflow *) * nflows);
	if (odflow_list == NULL)
		err(1, "odfq_areasort:malloc");

	while ((odfp = TAILQ_FIRST(&odfq->odfq_head)) != NULL) {
		TAILQ_REMOVE(&odfq->odfq_head, odfp, odf_chain);
		odfq->nrecord--;
		odflow_list[n++] = odfp;
	}

	assert(odfq->nrecord == 0);

        /* sort flow entries */
        qsort(odflow_list, n, sizeof(struct odflow *), area_comp);

	for (i = 0; i < n; i++) {
		TAILQ_INSERT_TAIL(&odfq->odfq_head, odflow_list[i], odf_chain);
		odfq->nrecord++;
	}
	free(odflow_list);
}

/* sort the lower odflows (odprotos) by count */
static void
odproto_countsort(struct odflow *odfp)
{
	struct odflow **odproto_list;
	struct odflow *odpp;
	int n = 0, m = 0, i;

	n = odfp->odf_odpq.nrecord;

	odproto_list = malloc(sizeof(struct odflow *) * n);
	if (odproto_list == NULL)
		err(1, "malloc(entry_list) fails.");

	while ((odpp = TAILQ_FIRST(&odfp->odf_odpq.odfq_head)) != NULL) {
		TAILQ_REMOVE(&odfp->odf_odpq.odfq_head, odpp, odf_chain);
		odfp->odf_odpq.nrecord--;
		odproto_list[m++] = odpp;
	}

	assert(m == n);

        /* sort flow entries by counts */
        qsort(odproto_list, n, sizeof(struct odproto *), count_comp2);

	for (i = 0; i < n; i++) {
		TAILQ_INSERT_HEAD(&odfp->odf_odpq.odfq_head, odproto_list[i], odf_chain);
		odfp->odf_odpq.nrecord++;
	}
	free(odproto_list);
}

static void
aguri_preamble_print()
{
	char buf[128];
	double avg_byte, avg_pkt;

	printf("\n");
	printf("%%!AGURI-2.0\n");

	strftime(buf, sizeof(buf), "%a %b %d %T %Y",
	    localtime(&response.start_time));
	printf("%%%%StartTime: %s ", buf);
	strftime(buf, sizeof(buf), "%Y/%m/%d %T",
	    localtime(&response.start_time));
	printf("(%s)\n", buf);
	strftime(buf, sizeof(buf), "%a %b %d %T %Y",
	    localtime(&response.end_time));
	printf("%%%%EndTime: %s ", buf);
	strftime(buf, sizeof(buf), "%Y/%m/%d %T",
	    localtime(&response.end_time));
	printf("(%s)\n", buf);

	double sec =
	    (double)(response.end_time - response.start_time);
	if (sec != 0.0) {
		avg_pkt = (double)response.total_packet / sec;
		avg_byte = (double)response.total_byte * 8 / sec;

		if (avg_byte > 1000000000.0)
			printf("%%AvgRate: %.2fGbps %.2fpps\n",
			    avg_byte/1000000000.0, avg_pkt);
		else if (avg_byte > 1000000.0)
			printf("%%AvgRate: %.2fMbps %.2fpps\n",
			    avg_byte/1000000.0, avg_pkt);
		else if (avg_byte > 1000.0)
			printf("%%AvgRate: %.2fKbps %.2fpps\n",
			    avg_byte/1000.0, avg_pkt);
		else
			printf("%%AvgRate: %.2fbps %.2fpps\n",
			    avg_byte, avg_pkt);
	}

	if (query.criteria == BYTE)
		printf("%% criteria: byte counter ");
	else if (query.criteria == PACKET)
		printf("%% criteria: pkt counter ");
	else if (query.criteria == COMBINATION)
		printf("%% criteria: combination ");

	printf("(%.f %% for addresses, %.f %% for protocol data)\n",
	    (double)query.threshold, (double)query.threshold);
	printf("\n");
}

static void
aguri_odflow_print()
{
	struct odflow *odfp;
	struct odflow *odpp;
	int i = 1, n;
	
        TAILQ_FOREACH(odfp, &response.odfq.odfq_head, odf_chain) {
		printf("[%2d] ", i++);
		odflow_print(odfp);
		printf(": %" PRIu64 " (%.2f%%)\t%" PRIu64 " (%.2f%%)\n",
		    odfp->byte, (double)odfp->byte / response.total_byte * 100,
		    odfp->packet, (double)odfp->packet / response.total_packet * 100);
		printf("\t");

		odproto_countsort(odfp);

		n = 0;
		while ((odpp = TAILQ_FIRST(&odfp->odf_odpq.odfq_head)) != NULL) {
			TAILQ_REMOVE(&odfp->odf_odpq.odfq_head, odpp, odf_chain);
			odfp->odf_odpq.nrecord--;
			if (odpp->s.srclen != 0 || odpp->s.dstlen != 0) {
#if 1
				printf("[");
				odflow_print(odpp);
				printf("]");
#else				
				odproto_print(odpp);
#endif
				printf(" %.2f%% %.2f%% ",
				    (double)odpp->byte / odfp->byte * 100,
				    (double)odpp->packet / odfp->packet * 100);
				n++;
			}
			odflow_free(odpp);
		}
		if (n == 0)
			printf("[*:*:*] 100.00%% 100.00%%");
		printf("\n");
	}
}

static void
json_preamble_print()
{
	if (query.criteria == BYTE)
		printf("\"criteria\": \"byte\", \n");
	if (query.criteria == PACKET)
		printf("\"criteria\": \"packet\", \n");

	printf("\"duration\": %ld, \n",
	    response.end_time - response.start_time);
	printf("\"start_time\": %ld, \n", response.start_time);
	printf("\"end_time\": %ld, \n", response.end_time);

	/* XXXkatoon remove comment out if needed
	if (sec != 0.0) {
		avg_byte = total_bytes/sec;
		avg_pkt = total_packets/sec;
		printf("\"avgRate\": [%.2f, %.2f],\n", avg_byte, avg_pkt);
	}
	*/

	printf("\"nflows\": %d, \n", response.nflows);
	
	printf("\"interval\": %d, \n", response.interval);
}

static void
json_odflow_print()
{
	struct odflow *odfp;
	struct odflow *odpp;
	uint64_t tmp_total;
	int i = 0, n;

	printf("\"labels\":[ ");
        TAILQ_FOREACH(odfp, &response.odfq.odfq_head, odf_chain) {
		printf("\"[%2d] ", ++i);
		odflow_print(odfp);
		printf(" %.2f%%",
		    (query.criteria == BYTE) ?
		    (double)odfp->byte / response.total_byte *100 :
		    (double)odfp->packet / response.total_packet * 100);
		printf("  ");
		odproto_countsort(odfp);
		n = 0;
		while ((odpp = TAILQ_FIRST(&odfp->odf_odpq.odfq_head)) != NULL) {
			TAILQ_REMOVE(&odfp->odf_odpq.odfq_head, odpp, odf_chain);
			odfp->odf_odpq.nrecord--;
			if (odpp->s.srclen != 0 || odpp->s.dstlen != 0) {
				printf("[");
				odflow_print(odpp);
				printf("]");
				printf(" %.2f%% ",
				    (query.criteria == BYTE) ?
				    (double)odpp->byte / odfp->byte * 100 :
				    (double)odpp->packet / odfp->packet * 100);
			}
			odflow_free(odpp);
			n++;
		}
#if 1	/* kjc: use the same trick as the reaggregation case */
		if (n == 0)
			printf("[*:*:*] 100.00%% ");
#endif
		printf("\", ");
	}
	printf(" \"TOTAL\" ");
	printf("],\n");

	printf("\"data\": [");
	for (i = 0; i < time_slot - 1; i++) {
		tmp_total = 0;
		printf("[%ld, ", plot_timestamps[i]);
		TAILQ_FOREACH(odfp, &response.odfq.odfq_head, odf_chain) {
			uint64_t cnt = cl_get(odfp->odf_cache, i);
			tmp_total += cnt;
			printf("%" PRIu64 ", ", cnt);
		}
		printf("%" PRIu64 "]", tmp_total);
		if (i != time_slot - 2)
			printf(", ");
	}
	printf("]\n");
}

static void
debug_preamble_print()
{
	printf("# ");
	if (query.criteria == BYTE)
		printf("criteria: byte, ");
	if (query.criteria == PACKET)
		printf("criteria: packet, ");

	printf("interval: %d, ", response.interval);
	printf("nflows: %d, ", response.nflows);
	
	printf("duration: %ld, ",
	    response.end_time - response.start_time);

	printf("start_time: %ld, ", response.start_time); 
	printf("end_time: %ld \n", response.end_time); 

}

static void
debug_odflow_print()
{
	struct odflow *odfp;
	struct odflow *odpp;
	uint64_t tmp_total;
	int i = 0, n;

	/* print labels */
	printf("# labels:"); 
        TAILQ_FOREACH(odfp, &response.odfq.odfq_head, odf_chain) {
		printf("\"[%2d] ", ++i);
		odflow_print(odfp);
		printf(" %.2f%%",
		    (query.criteria == BYTE) ?
		    (double)odfp->byte / response.total_byte *100 :
		    (double)odfp->packet / response.total_packet * 100);
		printf("  ");
		odproto_countsort(odfp);
		n = 0;
		while ((odpp = TAILQ_FIRST(&odfp->odf_odpq.odfq_head)) != NULL) {
			TAILQ_REMOVE(&odfp->odf_odpq.odfq_head, odpp, odf_chain);
			odfp->odf_odpq.nrecord--;
			if (odpp->s.srclen != 0 || odpp->s.dstlen != 0) {
				printf("[");
				odflow_print(odpp);
				printf("]");
				printf(" %.2f%% ",
				    (query.criteria == BYTE) ?
				    (double)odpp->byte / odfp->byte * 100 :
				    (double)odpp->packet / odfp->packet * 100);
			}
			odflow_free(odpp);
			n++;
		}
#if 1	/* kjc: use the same trick as the reaggregation case */
		if (n == 0)
			printf("[*:*:*] 100.00%% ");
#endif
		printf("\"");
		printf(", ");
	}
	printf("\"TOTAL\"\n");
	printf("\n");

	/* print plot data */
	for (i = 0; i < time_slot - 1; i++) {
		tmp_total = 0;
		printf("%ld, ", plot_timestamps[i]);
		TAILQ_FOREACH(odfp, &response.odfq.odfq_head, odf_chain) {
			uint64_t cnt;
			cnt = cl_get(odfp->odf_cache, i);
			tmp_total += cnt;
			printf("%" PRIu64 ", ", cnt);
		}
		printf("%" PRIu64 "\n", tmp_total);
	}
}

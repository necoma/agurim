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

extern int timeoffset;

static void addupcounts(struct response *resp, struct odflow_hash *odfh);
static int calc_interval(int duration);
static struct odflow *odfq_parentlookup(struct odf_tailq *odfq, struct odflow *odfp);
static void odfq_insert(struct odf_tailq *odfq, struct odflow *odfp, enum aggr_criteria criteria);
static void odproto_countsort(struct odflow *odfp);
static int area_comp(const void *p0, const void *p1);
static int count_comp(const void *p0, const void *p1);
static void aguri_preamble_print(struct response *resp);
static void aguri_odflow_print(struct response *resp);
static void json_preamble_print(struct response *resp);
static void json_odflow_print(struct response *resp);
static void debug_preamble_print(struct response *resp);
static void debug_odflow_print(struct response *resp);
/* XXX total byte/packet ratio used for count sort.  need to set this 
 * value (total_byte/total_packet) before qsort (ugly...) */
static double bpratio4sort;

static int time_slot = 0;
static time_t *plot_timestamps;

void plot_prepare(struct response *resp)
{
	struct odflow *odfp;
	int duration;
	    
	/* calculate time buffers */
	duration = resp->end_time - resp->start_time;
	resp->interval = calc_interval(duration);
	/* if the calclated interval is much smaller than the recorded
	 * one, increase it.
	 */
	while (resp->interval < resp->max_interval * 3/4)
		resp->interval *= 2;

	/* allocate time buffers */
	resp->timeslots = (int)(duration / resp->interval) + 1;
	if (plot_timestamps == NULL)
		plot_timestamps = calloc(resp->timeslots, sizeof(time_t));

	/* make zero entries in the cl caches for plot values */
	TAILQ_FOREACH(odfp, &resp->odfq.odfq_head, odf_chain) {
		int i, n = cl_size(odfp->odf_cache);
		for (i = 0; i < resp->timeslots; i++)
			if (i < n)
				cl_set(odfp->odf_cache, i, 0);
			else
				cl_append(odfp->odf_cache, 0);
	}

	/* create the first time slot */
	plot_addslot(resp->start_time, 0);
}

/* create a new time slot for plotting */
void
plot_addslot(time_t t, int inc_timeslot)
{
	plot_timestamps[time_slot] = t; /* for new slot */

	if (inc_timeslot)
		/* inc_timeslot creates a slot with zero values */
		time_slot++;
}

/* get the current slot time */
time_t
plot_getslottime(void)
{
	return (plot_timestamps[time_slot]);
}

/*
 * walk through the flow hash and add up odflow's counts to the
 * corresponding slot of odflow's cache list in the response
 */
static void
addupcounts(struct response *resp, struct odflow_hash *odfh)
{
	struct odflow *odfp0, *odfp1;
	int i;

	/* lookup overlapped label and update counts */
	if (odfh->nrecord == 0)  /* no traffic? */
		return;

        for (i = 0; i < odfh->nbuckets; i++) {
                while ((odfp1 = TAILQ_FIRST(&odfh->tbl[i].odfq_head)) != NULL) {
                        TAILQ_REMOVE(&odfh->tbl[i].odfq_head, odfp1, odf_chain);
			odfh->tbl[i].nrecord--;
			/* find the first matching odflow in the list assuming
			 * the list is already ordered by the prefix lengths */
			TAILQ_FOREACH(odfp0, &resp->odfq.odfq_head, odf_chain) {
				if (odfp0->af == odfp1->af &&
				    odflowspec_is_overlapped(&(odfp0->s), &(odfp1->s))) {
					uint64_t cnt;
					/* add count to this entry */
					if (query.criteria == BYTE)
						cnt = odfp1->byte;
					else
						cnt = odfp1->packet;
					cl_add(odfp0->odf_cache, time_slot, cnt);
					break;
				}
			}
			odflow_free(odfp1);
		}
	}
}

/*
 * aggregate odflows in the hash(es) for the current interval,
 * and place the resulted values into the corresponding slot of
 * the cl_list in the odflows in the response odfq.
 */
void
plot_addupinterval(struct response *resp)
{
	if (proto_view == 0) {
		addupcounts(resp, resp->ip_hash);
		addupcounts(resp, resp->ip6_hash);
	} else
		addupcounts(resp, resp->proto_hash);
	time_slot++; /* advance the time slot */
	assert(time_slot <= resp->timeslots);
}

void
make_output(struct response *resp)
{
	struct odflow *odfp;

	odfq_countsort(&resp->odfq, resp->total_byte, resp->total_packet);

	switch (query.outfmt) {
	case REAGGREGATION:
		aguri_preamble_print(resp);
		aguri_odflow_print(resp);
		break;
	case JSON:
		fprintf(wfp, "{\n");
		json_preamble_print(resp);
		json_odflow_print(resp);
		fprintf(wfp, "}\n");
		break;
	case DEBUG:
		debug_preamble_print(resp);
		debug_odflow_print(resp);
		break;
	}
	fflush(wfp);

	/* release the odflows in the response queue */
	while ((odfp = TAILQ_FIRST(&resp->odfq.odfq_head)) != NULL) {
		TAILQ_REMOVE(&resp->odfq.odfq_head, odfp, odf_chain);
		resp->odfq.nrecord--;
		odflow_free(odfp);
	}
	assert(resp->odfq.nrecord == 0);
	resp->nflows = 0;
}

/* compute the appropriate interval from the duration */
static int
calc_interval(int duration)
{
	double dd = (double)duration;
	int d, interval;

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
	d = (int)ceil(dd/3600);
	if (d <= 24) {
		/* shorter than 24hours: hours * 30 */
		interval = d * 30;
		return (interval < 600 ? interval : 600);
	}

	d = (int)ceil(dd/3600/24);
	if (d <= 7) {
		/* shorter than 7days: days * 600 */
		interval = d * 600;
		return (interval < 3600 ? interval : 3600);
	}
	if (d <= 31) {
		/* shorter than 31days: 14400 */
		return (14400);
	}

	d = (int)ceil(dd/3600/24/31);
	if (d <= 12) {
		/* shorter than 12months: months * 14400 */
		interval = d * 14400;
		return (interval < 86400 ? interval : 86400);
	}

	/* longer than 12months: years * 86400 */
	d = (int)ceil(dd/3600/24/366);
	interval = d * 86400;
	return (interval); 
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
		if (odflowspec_is_overlapped(&(_odfp->s), &(odfp->s))) {
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

/* is the first flow_spec is a superset of the second one? */
int
odflowspec_is_overlapped(struct odflow_spec *s0, struct odflow_spec *s1)
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
			/* XXX assuming bpratio4sort is set in odfq_countsort() */
			uint64_t c, _c, scaledpkt;
			scaledpkt = (uint64_t)(bpratio4sort * odfp->packet);
			c = max(odfp->byte, scaledpkt);
			scaledpkt = (uint64_t)(bpratio4sort * _odfp->packet);
			_c = max(_odfp->byte, scaledpkt);
			if (c <= _c)
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

/* helper for qsort: compare the sum of prefix length */
static int
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

/*
 * sort the tailq by the sum of prefix lengths
 * from more specific to less specific
 */
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

/* helper for qsort: compare the counters by the given criteria */
static int
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
		uint64_t c0, c1, scaledpkt;

		scaledpkt = (uint64_t)(bpratio4sort * odfp0->packet);
		c0 = max(odfp0->byte, scaledpkt);
		scaledpkt = (uint64_t)(bpratio4sort * odfp1->packet);
		c1 = max(odfp1->byte, scaledpkt);

		if (c0 < c1)
			return (-1);
		else if (c0 > c1)
			return (1);
		break;
	}
	}
	return (0);
}

/* sort the tailq by the count */
void
odfq_countsort(struct odf_tailq *odfq, uint64_t total_byte, uint64_t total_packet)
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

	/* XXX for sort */
	if (total_packet != 0)
		bpratio4sort = (double)total_byte / total_packet;
	else 
		bpratio4sort = 0.0;
        /* sort flow entries in order */
        qsort(odflow_list, n, sizeof(struct odflow *), count_comp);

	for (i = 0; i < n; i++) {
		TAILQ_INSERT_HEAD(&odfq->odfq_head, odflow_list[i], odf_chain);
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
	if (odfp->packet != 0)
		bpratio4sort = (double)odfp->byte / odfp->packet; /* XXX for count_comp */
	else 
		bpratio4sort = 0.0;
        qsort(odproto_list, n, sizeof(struct odproto *), count_comp);

	for (i = 0; i < n; i++) {
		TAILQ_INSERT_HEAD(&odfp->odf_odpq.odfq_head, odproto_list[i], odf_chain);
		odfp->odf_odpq.nrecord++;
	}
	free(odproto_list);
}

static void
aguri_preamble_print(struct response *resp)
{
	char buf[128];
	double avg_byte, avg_pkt;
	time_t t;

	fprintf(wfp, "\n");
	fprintf(wfp, "%%!AGURI-2.0\n");

	t = resp->start_time + timeoffset;
	strftime(buf, sizeof(buf), "%a %b %d %T %Y", localtime(&t));
	fprintf(wfp, "%%%%StartTime: %s ", buf);
	strftime(buf, sizeof(buf), "%Y/%m/%d %T", localtime(&t));
	fprintf(wfp, "(%s)\n", buf);
	t = resp->end_time + timeoffset;
	strftime(buf, sizeof(buf), "%a %b %d %T %Y", localtime(&t));
	fprintf(wfp, "%%%%EndTime: %s ", buf);
	strftime(buf, sizeof(buf), "%Y/%m/%d %T", localtime(&t));
	fprintf(wfp, "(%s)\n", buf);

	double sec =
	    (double)(resp->end_time - resp->start_time);
	if (sec != 0.0) {
		avg_pkt = (double)resp->total_packet / sec;
		avg_byte = (double)resp->total_byte * 8 / sec;

		if (avg_byte > 1000000000.0)
			fprintf(wfp, "%%AvgRate: %.2fGbps %.2fpps\n",
			    avg_byte/1000000000.0, avg_pkt);
		else if (avg_byte > 1000000.0)
			fprintf(wfp, "%%AvgRate: %.2fMbps %.2fpps\n",
			    avg_byte/1000000.0, avg_pkt);
		else if (avg_byte > 1000.0)
			fprintf(wfp, "%%AvgRate: %.2fKbps %.2fpps\n",
			    avg_byte/1000.0, avg_pkt);
		else
			fprintf(wfp, "%%AvgRate: %.2fbps %.2fpps\n",
			    avg_byte, avg_pkt);
#if 1
		fprintf(wfp, "%%total: %"PRIu64" bytes  %"PRIu64" packets\n",
			resp->total_byte, resp->total_packet);
#endif
	}

	if (query.criteria == BYTE)
		fprintf(wfp, "%% criteria: byte counter ");
	else if (query.criteria == PACKET)
		fprintf(wfp, "%% criteria: pkt counter ");
	else if (query.criteria == COMBINATION)
		fprintf(wfp, "%% criteria: combination ");

	fprintf(wfp, "(threshold %d%% for addresses, %d%% for protocol)\n",
            query.threshold,
	    disable_heuristics < 2 ? query.threshold * 4 : query.threshold);
	fprintf(wfp, "%%input odflows: IPv4:%"PRIu64" IPv6:%"PRIu64"\n",
	    resp->input_odflows, resp->input_odflows6);
	fprintf(wfp, "%%aggregated in %d ms", resp->processing_time);
	if (blocking_count > 0)
		fprintf(wfp, ", blocking_count:%u", blocking_count);
	fprintf(wfp, "\n\n");
}

static void
aguri_odflow_print(struct response *resp)
{
	struct odflow *odfp;
	struct odflow *odpp;
	int i = 1, n;
	
        TAILQ_FOREACH(odfp, &resp->odfq.odfq_head, odf_chain) {
		fprintf(wfp, "[%2d] ", i++);
		odflow_print(odfp);
		fprintf(wfp, ": %" PRIu64 " (%.2f%%)\t%" PRIu64 " (%.2f%%)\n",
		    odfp->byte, (double)odfp->byte / resp->total_byte * 100,
		    odfp->packet, (double)odfp->packet / resp->total_packet * 100);
		fprintf(wfp, "\t");

		odproto_countsort(odfp);

		n = 0;
		while ((odpp = TAILQ_FIRST(&odfp->odf_odpq.odfq_head)) != NULL) {
			TAILQ_REMOVE(&odfp->odf_odpq.odfq_head, odpp, odf_chain);
			odfp->odf_odpq.nrecord--;
			if (odpp->s.srclen != 0 || odpp->s.dstlen != 0) {
#if 1
				fprintf(wfp, "[");
				odflow_print(odpp);
				fprintf(wfp, "]");
#else				
				odproto_print(odpp);
#endif
				fprintf(wfp, " %.2f%% %.2f%% ",
				    (double)odpp->byte / odfp->byte * 100,
				    (double)odpp->packet / odfp->packet * 100);
				n++;
			}
			odflow_free(odpp);
		}
		if (n == 0)
			fprintf(wfp, "[*:*:*] 100.00%% 100.00%%");
		fprintf(wfp, "\n");
	}
}

static void
json_preamble_print(struct response *resp)
{
	if (query.criteria == BYTE)
		fprintf(wfp, "\"criteria\": \"byte\", \n");
	if (query.criteria == PACKET)
		fprintf(wfp, "\"criteria\": \"packet\", \n");

	fprintf(wfp, "\"duration\": %ld, \n",
	    resp->end_time - resp->start_time);
	fprintf(wfp, "\"start_time\": %ld, \n", resp->start_time);
	fprintf(wfp, "\"end_time\": %ld, \n", resp->end_time);

	/* XXXkatoon remove comment out if needed
	if (sec != 0.0) {
		avg_byte = total_bytes/sec;
		avg_pkt = total_packets/sec;
		fprintf(wfp, "\"avgRate\": [%.2f, %.2f],\n", avg_byte, avg_pkt);
	}
	*/

	fprintf(wfp, "\"nflows\": %d, \n", resp->nflows);
	
	fprintf(wfp, "\"interval\": %d, \n", resp->interval);
}

static void
json_odflow_print(struct response *resp)
{
	struct odflow *odfp;
	struct odflow *odpp;
	uint64_t tmp_total;
	int i = 0, n;

	fprintf(wfp, "\"labels\":[ ");
        TAILQ_FOREACH(odfp, &resp->odfq.odfq_head, odf_chain) {
		fprintf(wfp, "\"[%2d] ", ++i);
		odflow_print(odfp);
		fprintf(wfp, " %.2f%%",
		    (query.criteria == BYTE) ?
		    (double)odfp->byte / resp->total_byte *100 :
		    (double)odfp->packet / resp->total_packet * 100);
		fprintf(wfp, "  ");
		odproto_countsort(odfp);
		n = 0;
		while ((odpp = TAILQ_FIRST(&odfp->odf_odpq.odfq_head)) != NULL) {
			TAILQ_REMOVE(&odfp->odf_odpq.odfq_head, odpp, odf_chain);
			odfp->odf_odpq.nrecord--;
			if (odpp->s.srclen != 0 || odpp->s.dstlen != 0) {
				fprintf(wfp, "[");
				odflow_print(odpp);
				fprintf(wfp, "]");
				fprintf(wfp, " %.2f%% ",
				    (query.criteria == BYTE) ?
				    (double)odpp->byte / odfp->byte * 100 :
				    (double)odpp->packet / odfp->packet * 100);
			}
			odflow_free(odpp);
			n++;
		}
#if 1	/* kjc: use the same trick as the reaggregation case */
		if (n == 0)
			fprintf(wfp, "[*:*:*] 100.00%% ");
#endif
		fprintf(wfp, "\", ");
	}
	fprintf(wfp, " \"TOTAL\" ");
	fprintf(wfp, "],\n");

	fprintf(wfp, "\"data\": [");
	for (i = 0; i < time_slot; i++) {
		tmp_total = 0;
		fprintf(wfp, "[%ld, ", plot_timestamps[i]);
		TAILQ_FOREACH(odfp, &resp->odfq.odfq_head, odf_chain) {
			uint64_t cnt = cl_get(odfp->odf_cache, i);
			tmp_total += cnt;
			fprintf(wfp, "%" PRIu64 ", ", cnt);
		}
		fprintf(wfp, "%" PRIu64 "]", tmp_total);
		if (i != time_slot - 1)
			fprintf(wfp, ", ");
	}
	fprintf(wfp, "]\n");
}

static void
debug_preamble_print(struct response *resp)
{
	fprintf(wfp, "# ");
	if (query.criteria == BYTE)
		fprintf(wfp, "criteria: byte, ");
	if (query.criteria == PACKET)
		fprintf(wfp, "criteria: packet, ");

	fprintf(wfp, "interval: %d, ", resp->interval);
	fprintf(wfp, "nflows: %d, ", resp->nflows);
	
	fprintf(wfp, "duration: %ld, ",
	    resp->end_time - resp->start_time);

	fprintf(wfp, "start_time: %ld, ", resp->start_time); 
	fprintf(wfp, "end_time: %ld \n", resp->end_time); 

}

static void
debug_odflow_print(struct response *resp)
{
	struct odflow *odfp;
	struct odflow *odpp;
	uint64_t tmp_total;
	int i = 0, n;

	/* print labels */
	fprintf(wfp, "# labels:"); 
        TAILQ_FOREACH(odfp, &resp->odfq.odfq_head, odf_chain) {
		fprintf(wfp, "\"[%2d] ", ++i);
		odflow_print(odfp);
		fprintf(wfp, " %.2f%%",
		    (query.criteria == BYTE) ?
		    (double)odfp->byte / resp->total_byte *100 :
		    (double)odfp->packet / resp->total_packet * 100);
		fprintf(wfp, "  ");
		odproto_countsort(odfp);
		n = 0;
		while ((odpp = TAILQ_FIRST(&odfp->odf_odpq.odfq_head)) != NULL) {
			TAILQ_REMOVE(&odfp->odf_odpq.odfq_head, odpp, odf_chain);
			odfp->odf_odpq.nrecord--;
			if (odpp->s.srclen != 0 || odpp->s.dstlen != 0) {
				fprintf(wfp, "[");
				odflow_print(odpp);
				fprintf(wfp, "]");
				fprintf(wfp, " %.2f%% ",
				    (query.criteria == BYTE) ?
				    (double)odpp->byte / odfp->byte * 100 :
				    (double)odpp->packet / odfp->packet * 100);
			}
			odflow_free(odpp);
			n++;
		}
#if 1	/* kjc: use the same trick as the reaggregation case */
		if (n == 0)
			fprintf(wfp, "[*:*:*] 100.00%% ");
#endif
		fprintf(wfp, "\"");
		fprintf(wfp, ", ");
	}
	fprintf(wfp, "\"TOTAL\"\n");
	fprintf(wfp, "\n");

	/* print plot data */
	for (i = 0; i < time_slot; i++) {
		tmp_total = 0;
		fprintf(wfp, "%ld, ", plot_timestamps[i]);
		TAILQ_FOREACH(odfp, &resp->odfq.odfq_head, odf_chain) {
			uint64_t cnt;
			cnt = cl_get(odfp->odf_cache, i);
			tmp_total += cnt;
			fprintf(wfp, "%" PRIu64 ", ", cnt);
		}
		fprintf(wfp, "%" PRIu64 "\n", tmp_total);
	}
}

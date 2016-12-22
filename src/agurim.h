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

#include <sys/queue.h>
#include <sys/types.h>

#include <stdint.h>
#include <time.h>

#define MAXLEN		16

enum aggr_criteria {
	PACKET = 1,
	BYTE,
	COMBINATION
};

enum out_format {
	REAGGREGATION,
	DEBUG,
	JSON
};

/* origin-destination flow spec */
struct odflow_spec {
	uint8_t src[MAXLEN];	/* source ip */
	uint8_t dst[MAXLEN];	/* destination ip */
	uint8_t srclen;		/* prefix length of source ip */
	uint8_t dstlen;		/* prefix length of destination ip */
};

/* cl_list implements dynamic lists used in 2 ways:
 *  - to store odflow indices in hhh.c
 *  - to store plot counts in agurim_plot.c
 */
struct cache_list {
	uint64_t *cl_data;	/* uint64_t data array */
	int	cl_size;	/* current data size in use */
	int	cl_max;		/* current allocation */
};

/* odflow_hash is used for odflow accounting */
struct odf_tailq {
	TAILQ_HEAD(odfqh, odflow) odfq_head;
	int nrecord;	/* number of record */
};

struct odflow_hash {
	struct odf_tailq *tbl;
	uint64_t packet;
	uint64_t byte;
	int nrecord;	/* number of records */
	int nbuckets;	/* number of buckets for tbl */
};

struct odflow {
	struct odflow_spec s;
	int af;
	uint64_t packet;
	uint64_t byte;
	struct cache_list *odf_cache; /* keeps odflow indices during
				       * aggregation (and plot counts
				       * during plotting)
				       */
	TAILQ_ENTRY(odflow) odf_chain;  /* for hash table */
	struct odf_tailq odf_odpq;  /* list of lower odflows for this flow */
};

struct query {
	/* essential parameters */
	enum aggr_criteria criteria;
	int interval;	/* aggregation interval */
	int output_interval; /* interval for outputs in 2-stage aggregation */
	int threshold;	/* threshold in percent */
	int nflows;	/* the number of result flows */
	int duration;	/* total duration */
	int count;	/* if non-zero, exit after processing 'count' packets */
	time_t start_time;
	time_t end_time;

	/* subsequent parameters */
	enum out_format outfmt;
	struct odflow_spec f; /* odflow filter */
	int f_af;
};

struct response {
	/* essential parameters */
	int interval;
	int threshold;
	int nflows;
	int duration;
	time_t start_time;
	time_t end_time;
	struct odf_tailq odfq;  /* odflow queue for results */
	/* internal parameters */
	int timeslots; /* number of time slots for for plotting */
	int max_interval; /* max interval captured from logs (for plotting) */
	time_t current_time; /* current log time (for plotting) */
	uint64_t total_byte, total_packet;
	uint64_t thresh_byte, thresh_packet;
	uint64_t input_odflows;  /* # of input IPv4 odflows */
	uint64_t input_odflows6; /* (for IPv6, these are just informational) */
	int	processing_time;	/* processing time in ms */
	struct odflow_hash *ip_hash;
	struct odflow_hash *ip6_hash;
	struct odflow_hash *proto_hash;
};

extern struct query query;
extern struct response *resp;

extern int proto_view;
extern int disable_heuristics;	/* do not use label heuristics */
extern int verbose;
extern int debug;
extern unsigned int blocking_count; /* thread blocking counter for aguri3 */
extern FILE *wfp;

/* agurim_subr.c */
int prefix_comp(uint8_t *r, uint8_t *r2, uint8_t len);
void prefix_set(uint8_t *r0, uint8_t len, uint8_t *r1, int bytesize);
void odflow_print(struct odflow *odfp);
void odproto_print(struct odflow *odpp);
void odproto_countfrac_print(struct odflow *odpp);
void odflow_countfrac_print(struct odflow *odfp);

#define CL_INLINE	/* use inline macros */
struct cache_list *cl_alloc(void);
void cl_free(struct cache_list *clp);
void cl_clear(struct cache_list *clp);
int cl_append(struct cache_list *clp, uint64_t val);
#ifdef CL_INLINE
#define cl_size(clp)	((clp)->cl_size)
#define cl_get(clp, i)	((clp)->cl_data[(i)])
#define cl_set(clp, i, val)	do { (clp)->cl_data[(i)] = (val); } while (0)
#define cl_add(clp, i, val)	do { (clp)->cl_data[(i)] += (val); } while (0)
#else
int cl_size(struct cache_list *clp);
int cl_set(struct cache_list *clp, int i, uint64_t val);
uint64_t cl_get(struct cache_list *clp, int i);
int cl_add(struct cache_list *clp, int i, uint64_t val);
#endif

/* odflow.c */
void odhash_init(struct response *resp);
struct odflow_hash *odhash_alloc(int n);
void odhash_free(struct odflow_hash *odfh);
void odhash_reset(struct odflow_hash *odfh);
void odhash_resetall(struct response *resp);
struct odflow *
odflow_addcount(struct odflow_spec *odfsp, int af, uint64_t byte,
    uint64_t packet, struct response *resp);
void odproto_addcount(struct odflow *odfp, struct odflow_spec *odpsp, int af,
    uint64_t byte, uint64_t packet);
struct odflow *
odflow_lookup(struct odflow_hash *odfh, struct odflow_spec *odfsp);
struct odflow *odflow_alloc(struct odflow_spec *odfsp);
void odflow_free(struct odflow *odfp);
void odflow_stats(void);

#define max(a, b)	(((a)>(b))?(a):(b))
#define min(a, b)	(((a)<(b))?(a):(b))

/* hhh.c */
int hhh_run(struct response *resp);
struct odflow_spec odflowspec_gen(struct odflow_spec *odfsp, int label[], int bytesize);

/* agurim_plot.c */
void odfq_listreduce(struct odf_tailq *odfq, int nflows);
void odfq_areasort(struct odf_tailq *odfq);
void odfq_countsort(struct odf_tailq *odfq, uint64_t total_byte, uint64_t total_packet);
int odfq_moveall(struct odf_tailq *from, struct odf_tailq *to);
int odflowspec_is_overlapped(struct odflow_spec *s0, struct odflow_spec *s1);

void plot_prepare(struct response *resp);
time_t plot_getslottime(void);
void plot_addslot(time_t t, int inc_timeslot);
void plot_addupinterval(struct response *resp);
void make_output(struct response *resp);

/* aguri3.c */
struct aguri_flow;
int check_flowtime(const struct aguri_flow *agf);
int do_agflow(const struct aguri_flow *agf);


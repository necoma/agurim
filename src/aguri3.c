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

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/socket.h>
#ifdef __FreeBSD__
#include <sys/rtprio.h>
#endif

#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <math.h>
#include <time.h>
#include <unistd.h>
#include <paths.h>
#include <signal.h>
#include <pthread.h>

#include "agurim.h"
#include "aguri_flow.h"

/*
 * when the 2-stage aggregation is used, a subset of response is
 * saved and restored.
 */
struct saved_results {
	time_t start_time;
	time_t end_time;
	uint64_t total_byte, total_packet;
	struct odf_tailq odfq;  /* odflow queue for results */
};

void pcap_read(const char *dumpfile, const char *interface,
	const char *filter_cmd, int snaplen);

static void sig_close(int signal);
static void sig_hup(int signal);
static void init(int argc, char **argv);
static void finish(void);
static void query_init(void);
static struct response *response_alloc(void);
static void option_parse(int argc, void *argv);
static int read_flow(FILE *fp);
static void switch_response(void);
static void save_results(struct response *resp, struct saved_results *prev);
static int restore_results(struct response *resp, struct saved_results *prev);
static void *aggregator(void *thdata);
static int pidfile(const char *pid_file);

static struct response *responses[2];
static struct response *cur_resp;  /* current response for the main thread */

static const char *wfile = NULL;
static const char *pid_file = NULL;
static const char *pcapfile = NULL;
static const char *pcap_interface = NULL;
static const char *pcapfilters = NULL;
static int pcap_snaplen;

static volatile sig_atomic_t gotsig_close, gotsig_hup;
static uint64_t epoch = 0;	/* interval epoch for the main thread */
static int exiting = 0;
static pthread_mutex_t resp_mutex[2];

struct query query;
int plot_phase;
int is_finish;
int proto_view = 0;
int verbose = 0;
int debug = 0;
int use_rtprio = 0;
int max_hashentries = 1000000; /* max odflows in a hash: 1M entries.
				* make a summary when a hash exeeds this
				* value so as to avoid slowdown */
FILE *wfp;

static void
usage()
{
	fprintf(stderr, "usage:\n");
	fprintf(stderr, "  aguri3 [-dhvD]\n");
	fprintf(stderr, "         [-c count] [-f 'pcapfilters']\n");
	fprintf(stderr, "         [-i interval[,output_interval]]\n"); 
	fprintf(stderr, "         [-m byte|packet]\n"); 
	fprintf(stderr, "         [-p pid_file] \n");
	fprintf(stderr, "         [-r pcapfile] [-s pcap_snaplen]\n");
	fprintf(stderr, "         [-t thresh_percentage] [-w outputfile]\n");
	fprintf(stderr, "         [-H max_hashentries] [-I pcap_interface]\n");
	fprintf(stderr, "         [-P rtprio] [-S start_time] [-E end_time]\n");
	exit(1);
}

static void
sig_close(int signal)
{
	gotsig_close = 1;
}

static void
sig_hup(int signal)
{
	gotsig_hup = 1;
}

int main(int argc, char **argv)
{
	int rval;
	struct sigaction act;
	pthread_t aggregator_thread;
	pthread_attr_t attr;

	init(argc, argv);

	argc -= optind;
	argv += optind;

	if (pid_file != NULL)
		pidfile(pid_file);

	/* set up signal handlers */
	act.sa_handler = sig_close;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGQUIT, &act, NULL);
	act.sa_handler = sig_hup;
	sigaction(SIGHUP, &act, NULL);

#ifdef __FreeBSD__
	/* set the realtime priority */
	if (use_rtprio > 0) {
		struct rtprio srtp;

		srtp.type = RTP_PRIO_REALTIME;
		srtp.prio = use_rtprio;  /* 0 (hi) -> RTP_PRIO_MAX (31,lo) */

		if (rtprio(RTP_SET, getpid(), &srtp) < 0)
			err(1, "rtprio");
		else
			fprintf(stderr, "set realtime priority:%d\n", use_rtprio);
	}
#endif
	
	if (isatty(fileno(stdin))) {
		if (pcapfile != NULL)
			fprintf(stderr, "reading pcap data from %s...\n", 
				pcapfile);
		else if (pcap_interface != NULL)
			fprintf(stderr, "reading from interface %s...\n",
				pcap_interface);
		else
			fprintf(stderr, "reading flow data from stdin...\n");
	}

	/* lock the respponse one before starting aggregator thread */
	if ((rval = pthread_mutex_lock(&resp_mutex[epoch & 1])) != 0)
		err(1, "mutex_lock returned %d", rval);
		
	pthread_attr_init(&attr);
	if (pthread_create(&aggregator_thread, &attr, aggregator, (void *)NULL) != 0)
		err(1, "pthread_create failed!");

	if (pcapfile != NULL || pcap_interface != NULL)
		pcap_read(pcapfile, pcap_interface, pcapfilters, pcap_snaplen);
	else
		read_flow(stdin); /* read binary aguri_flow */

	sleep(1); /* give the aggregator a chance to catch up */
	
	/* let the aggregator process remaining data if any */
	exiting = 1;
	pthread_mutex_unlock(&resp_mutex[epoch & 1]);

	pthread_join(aggregator_thread, NULL);
	
	finish();

	return (0);
}

static void
init(int argc, char **argv)
{
	int i;

	option_parse(argc, argv);
	query_init();
	for (i = 0; i < 2; i++) {
		responses[i] = response_alloc();
		pthread_mutex_init(&resp_mutex[i], NULL);
	}
	cur_resp  = responses[0];
}

static void
finish(void)
{
	if (wfp != stdout)
		if (fclose(wfp) != 0)
			err(1, "fclose failed");
#ifndef NDEBUG	/* for thread-safe odflow accounting */
	if (debug)
		odflow_stats();
#endif
}

static void
query_init(void)
{
	if (!query.criteria)
		query.criteria = COMBINATION;
	if (!query.outfmt) 
		query.outfmt = REAGGREGATION;
	if (!query.threshold)
		query.threshold = 1; /* 1% for the thresh */
}

static struct response *
response_alloc(void)
{
	struct response *resp;

	if ((resp = calloc(1, sizeof(struct response))) == NULL)
		err(1, "calloc failed!");
	resp->interval = query.interval;
	resp->threshold = query.threshold;
	resp->duration = query.duration;
	TAILQ_INIT(&resp->odfq.odfq_head);
	resp->odfq.nrecord = 0;
	odhash_init(resp);
	return (resp);
}

static void
option_parse(int argc, void *argv)
{
	int ch;
	char *cp;

	while ((ch = getopt(argc, argv, "c:df:hi:m:p:r:s:t:vw:DE:H:I:P:S:")) != -1) {
		switch (ch) {
		case 'c':
			query.count = strtol(optarg, NULL, 10);
			break;
		case 'd':
			debug++;
			break;
		case 'f':
			pcapfilters = optarg;
			break;
		case 'h':
			usage();
			break;
		case 'i':
			query.interval = strtol(optarg, &cp, 10);
			if (cp != NULL && *cp == ',')
				query.output_interval = strtol(cp+1, NULL, 10);
			else
				query.output_interval = 0;
			break;
		case 'm':
			if (!strncmp(optarg, "byte", 4))
				query.criteria = BYTE;
			else if (!strncmp(optarg, "packet", 6))
				query.criteria = PACKET;
			else
				usage();
			break;
		case 'p':
			pid_file = optarg;
			break;
		case 'r':
			pcapfile = optarg;
			break;
		case 's':
			pcap_snaplen = strtol(optarg, NULL, 10);
			break;
		case 't':
			query.threshold = strtod(optarg, NULL);
			break;
		case 'v':
			verbose++;
			break;
		case 'w':
			wfile = optarg;
			break;
		case 'D':
			disable_heuristics++;  /* disable label heuristics */
			break;
		case 'E':
			query.end_time = strtol(optarg, NULL, 10);
			break;
		case 'H':
			max_hashentries = strtol(optarg, NULL, 10);
			break;
		case 'I':
			pcap_interface = optarg;
			break;
		case 'P':
			use_rtprio = strtol(optarg, NULL, 10);
			break;
		case 'S':
			query.start_time = strtol(optarg, NULL, 10);
			break;
		default:
			usage();
			break;
		}
	}

	if (wfile == NULL || !strcmp(wfile, "-"))
		wfp = stdout;
	else if ((wfp = fopen(wfile, "w")) == NULL)
		err(1, "can't open %s", wfile);
}

static void
switch_response(void)
{
	int rval;

	/* release the current response */
	if ((rval = pthread_mutex_unlock(&resp_mutex[epoch & 1])) != 0)
		err(1, "mutex_lock returned %d", rval);
	
	epoch++;
	cur_resp = responses[epoch & 1];

	/* lock the other response */
	if ((rval = pthread_mutex_trylock(&resp_mutex[epoch & 1])) != 0) {
		if (rval != EBUSY)
			err(1, "mutex_trylock returned %d", rval);
		fprintf(stderr, "response is still locked by aggregator!! epoch:%lu\n", epoch);
		if ((rval = pthread_mutex_lock(&resp_mutex[epoch & 1])) != 0)
			err(1, "mutex_lock returned %d", rval);
	}
}

static void
save_results(struct response *resp, struct saved_results *prev)
{
	prev->start_time   = resp->start_time;
	prev->end_time     = resp->end_time;
	prev->total_byte   = resp->total_byte;
	prev->total_packet = resp->total_packet;

	/* move all odflows from the response to the results */
	odfq_moveall(&resp->odfq, &prev->odfq);
}

/* resrore saved results.  returns 1 when output is required */
static int
restore_results(struct response *resp, struct saved_results *prev)
{
	struct odflow *odfp;
	struct odflow_hash *odfh;
	int resid, need_output = 0;

	/* if end_time is close to the output interval boundary, output */
	resid = resp->end_time % query.output_interval;
	if (resid == 0 || resid >= query.output_interval - 2)
		need_output = 1;

	/* if idle for more than output_interval, discard the saved results */
	if (resp->end_time - prev->start_time > query.output_interval + 2) {
		while ((odfp = TAILQ_FIRST(&prev->odfq.odfq_head)) != NULL) {
			TAILQ_REMOVE(&prev->odfq.odfq_head, odfp, odf_chain);
			prev->odfq.nrecord--;
			odflow_free(odfp);
		}
		prev->start_time = 0;
		return (need_output);
	}
	
	resp->start_time    = prev->start_time;
	resp->total_byte   += prev->total_byte;
	resp->total_packet += prev->total_packet;

	/* move all the odflows from the saved results to the
	 * corresponding hash in the response.
	 * XXX place all odflows onto slot 0 of the hash table since 
	 *  the odflows are soon moved to the flow_list for aggregation
	 */
	while ((odfp = TAILQ_FIRST(&prev->odfq.odfq_head)) != NULL) {
		TAILQ_REMOVE(&prev->odfq.odfq_head, odfp, odf_chain);
		prev->odfq.nrecord--;
		if (odfp->af == AF_INET)
			odfh = resp->ip_hash;
		else
			odfh = resp->ip6_hash;

		TAILQ_INSERT_TAIL(&odfh->tbl[0].odfq_head, odfp, odf_chain);
		odfh->nrecord++;
		odfh->tbl[0].nrecord++;
		odfh->byte   += odfp->byte;
		odfh->packet += odfp->packet;
	}

	prev->start_time = 0;
	return (need_output);
}

static void *
aggregator(void *thdata)
{
	int rval;
	uint64_t my_epoch = 0;
	struct response *my_resp;
	struct saved_results results, *prev;

	memset(&results, 0, sizeof(results));
	prev = &results;
	TAILQ_INIT(&prev->odfq.odfq_head);
	prev->odfq.nrecord = 0;
	
	while (1) {
		int need_output = 0;

		if ((rval = pthread_mutex_lock(&resp_mutex[my_epoch & 1])) != 0)
			err(1, "mutex_lock returned %d", rval);

		my_resp = responses[my_epoch & 1];

		if (query.output_interval != 0 && prev->start_time != 0)
			/* 2-stage aggregation mode */
			need_output = restore_results(my_resp, prev);
		
		if (hhh_run(my_resp) > 0) {
			/* results have been produced */
			if (query.output_interval != 0 && need_output == 0)
				/* save results for 2-stage aggregation */
				save_results(my_resp, prev);
			else
				make_output(my_resp);
		}
		odhash_resetall(my_resp);
#ifndef NDEBUG	/* for thread-safe odflow accounting */
		if (debug) {
			fprintf(stderr, "aggregator ");
			odflow_stats();
		}
#endif
		if (gotsig_hup) {
			/* reopen the outpufile for log rotation */
			if (wfp != stdout && freopen(wfile, "a", wfp) == NULL)
				err(1, "can't freopen %s", wfile);
			gotsig_hup = 0;
		}

		if ((rval = pthread_mutex_unlock(&resp_mutex[my_epoch & 1])) != 0)
			err(1, "mutex_unlock returned %d", rval);

		my_epoch++;

		if (exiting)
			break;
	}
	pthread_exit(NULL);
}

/*
 * check aguri flow timestamp: returns 1 to process this packets, 0 to
 * skip, and -1 to finish.
 * XXX works only for REAGGREGATION at the moment.
 */
int
check_flowtime(const struct aguri_flow *agf)
{
	static time_t ts_next, ts_max;
	time_t ts;

	if (gotsig_close)
		return (-1);
	
	ts = (time_t)ntohl(agf->agflow_last);
	if (ts < ts_max)
		ts = ts_max;	/* XXX we want ts to be monotonic */
	else
		ts_max = ts;	/* keep track of the max value of ts */

	if (query.start_time == 0 && query.interval != 0) {
		/* align the start time to the boundary */
		int interval = query.interval;

		if (query.output_interval > interval)
			interval = query.output_interval;
		query.start_time = (ts + interval - 1) / interval * interval;
	}
	if (query.start_time > ts)
		return (0);
	if (cur_resp->start_time == 0) {
		cur_resp->start_time = ts;
		if (cur_resp->interval != 0)
			ts_next = query.start_time + query.interval;
	}

	if ((cur_resp->interval != 0 && ts >= ts_next) ||
		(!disable_heuristics &&
		(cur_resp->ip_hash->nrecord  > max_hashentries ||
		cur_resp->ip6_hash->nrecord > max_hashentries))) {
		/* done with the current interval (or the hash entries
		 * exceed the threshold): aggregate and make a summary
		 */
		if (debug && ts < ts_next)
			fprintf(stderr, "early summary output:"
				"ip_hash:%d ip6_hash:%d max_hashentries:%d\n",
				cur_resp->ip_hash->nrecord,
				cur_resp->ip6_hash->nrecord, max_hashentries);

		switch_response();
		cur_resp->start_time = ts;
		if (ts >= ts_next)
			ts_next += cur_resp->interval;
	}
	if (query.end_time && query.end_time < ts)
		return (-1);  /* we are beyond the end time */
	if (query.duration && ts - cur_resp->start_time > query.duration)
		return (-1);  /* ditto */

	cur_resp->end_time = ts;
	
	return (1);  /* process this flow record */
}

/* convert an aguri_flow record into address/port odflows */
int
do_agflow(const struct aguri_flow *agf)
{
	struct odflow *odfp;
	struct odflow_spec odfsp;
	struct odflow_spec odpsp;
	uint64_t byte, packet;
	int af = AF_INET, len = 0;

	byte   = ntohl(agf->agflow_bytes);
	packet = ntohl(agf->agflow_packets);

	memset(&odfsp, 0, sizeof(odfsp));
	memset(&odpsp, 0, sizeof(odpsp));
	switch(agf->agflow_fs.fs_ipver) {
	case 4:
		af = AF_INET;
		len = 32;
		break;
	case 6:
		af = AF_INET6;
		len = 128;
		break;
	}
	memcpy(&odfsp.src, agf->agflow_fs.fs_srcaddr, len / 8);
	memcpy(&odfsp.dst, agf->agflow_fs.fs_dstaddr, len / 8);
	odfsp.srclen = len;
	odfsp.dstlen = len;
	odfp = odflow_addcount(&odfsp, af, byte, packet, cur_resp);

	odpsp.src[0] = agf->agflow_fs.fs_prot;
	odpsp.dst[0] = agf->agflow_fs.fs_prot;
	memcpy(&odpsp.src[1], &agf->agflow_fs.fs_sport, 2);
	memcpy(&odpsp.dst[1], &agf->agflow_fs.fs_dport, 2);
	odpsp.srclen = 24;
	odpsp.dstlen = 24;
	odproto_addcount(odfp, &odpsp, AF_LOCAL, byte, packet);

	return (1);
}

static int
read_flow(FILE *fp)
{
	struct aguri_flow agflow;
	int rval;
	unsigned long n = 0;

	while (1) {
		if (fread(&agflow, sizeof(agflow), 1, fp) != 1) {
			if (feof(fp)) {
				if (debug)
					fprintf(stderr, "\n read %lu flows\n", n);
				return (0);
			}
			warn("fread failed!");
			return (-1);
		}

		rval = check_flowtime(&agflow);
		if (rval < 0)	/* the duration is expired */
			break;
		if (rval > 0)
			do_agflow(&agflow);
		n++;
		if (query.count != 0 && n >= query.count)
			break;
	}
	return (0);
}

static int
pidfile(const char *pid_file)
{
	FILE *fp;

	if ((fp = fopen(pid_file, "w")) == NULL)
		return (-1);
	fprintf(fp, "%ld\n", (long)getpid());
	fclose(fp);
	return (0);
}

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

#ifdef __linux__
#define _XOPEN_SOURCE	500 /* for strptime in linux */
#define _DEFAULT_SOURCE	/* for strsep in linux */
#endif

#include <sys/stat.h>
#include <sys/socket.h>

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

#include "agurim.h"
#include "aguri_flow.h"


static void init(int argc, char **argv);
static void finish(void);
static void query_init(void);
static struct response *response_alloc(void);
static void option_parse(int argc, void *argv);
static int filter_parse(char *str);
static void file_parse(char **files);
static void read_file(FILE *fp);
static int is_preambles(char *buf);
static int ip_addrparser(char *buf, void *ip, uint8_t *prefixlen);
static int address_parse(char *buf, struct odflow_spec *odfsp,
                            uint64_t *byte, uint64_t *packet);
static int protospec_parse(char *buf, struct odflow_spec *odpsp,
		double *perc, double *perc2);
static char *proto_parse(char **strp, uint64_t byte, uint64_t packet,
    struct odflow_spec *odpsp, uint64_t *byte2, uint64_t *packet2);
static int match_filter(struct odflow_spec *r);
static int read_flow(FILE *fp);
static struct response *response;

struct query query;
int plot_phase;
int is_finish;
int proto_view = 0;
int verbose = 0;
int debug = 0;
int timeoffset = 0;
unsigned int blocking_count; /* thread blocking counter for aguri3 */
FILE *wfp;

static int flow_mode = 0;  /* read binary aguri_flow inputs from stdin */
static char *filter_str = NULL;

static void
usage()
{
	fprintf(stderr, "usage:\n");
	fprintf(stderr, "  agurim [-dhpFP]\n");
	fprintf(stderr, "         [-f '<src> <dst>' or '<proto>:<sport>:<dport>'\n");
	fprintf(stderr, "         [-i interval]\n"); 
	fprintf(stderr, "         [-m criteria (byte/packet)]\n"); 
	fprintf(stderr, "         [-n nflows] [-s duration] \n");
	fprintf(stderr, "         [-t thresh_percentage] [-w outputfile]\n");
	fprintf(stderr, "         [-S start_time] [-E end_time]\n");
	fprintf(stderr, "         files or directories\n");
	exit(1);
}

int main(int argc, char **argv)
{
	int i, n, nflows;
	char **files;

	init(argc, argv);

	argc -= optind;
	argv += optind;

	for (i = 0; i < 2; i++) {
		n = argc;
		files = argv;

		if (n == 0) {
			if (query.outfmt != REAGGREGATION)
				usage();
			if (isatty(fileno(stdin)))
				fprintf(stderr, "reading %s data from stdin...\n",
					flow_mode ? "binary": "aguri");
			if (flow_mode)
				read_flow(stdin); /* read binary aguri_flow */
			else
				read_file(stdin); /* read from stdin */
		} else {
			while (n > 0) {
				file_parse(files);
				++files;
				--n;
			}
		}

		/*
		 * all inputs are read and placed in the flow hash(es)
		 */
		if (plot_phase) {
			/* add up remaining counts for the last interval */
			if (response->ip_hash->nrecord > 0 ||
			    response->ip6_hash->nrecord > 0 ||
			    (response->proto_hash != NULL &&
				response->proto_hash->nrecord > 0))
				plot_addupinterval(response);
			break;
		}

		/* aggregate odflows in the hash(es) */
		nflows = hhh_run(response);
		if (nflows == 0)
			/* no output produced */
			break;

		if (query.outfmt == REAGGREGATION)
			/* only one pass for reaggregation */
			break;

		/* for plotting, need to re-read the files in the 2nd pass */
		odhash_resetall(response);
		plot_prepare(response);
		is_finish = 0;
		response->start_time = 0;
		plot_phase = 1;
	}
	if (nflows > 0)
		make_output(response);

	finish();

	return (0);
}

static void 
init(int argc, char **argv)
{
	option_parse(argc, argv);
	query_init();
	response = response_alloc();
}

static void
finish(void)
{
	if (wfp != stdout)
		if (fclose(wfp) != 0)
			err(1, "fclose failed");
}

static void
query_init(void)
{
	if (!query.criteria)
		query.criteria = COMBINATION;
	if (!query.outfmt) 
		query.outfmt = REAGGREGATION;
	if (!query.threshold) {
		if (query.outfmt == REAGGREGATION)
			query.threshold = 1; /* 1% for the thresh */
		else
			query.threshold = 3; /* 3% otherwise */
	}
	if (query.outfmt == REAGGREGATION)
		return;
	if (!query.nflows)
		query.nflows = 7;
	if (!query.start_time && !query.end_time && !query.duration)
		query.duration = 60*60*24;
	else {
		if ((!query.start_time || !query.end_time) && !query.duration)
			query.duration = 60*60*24;
		if (query.duration && query.end_time)
			 query.start_time = query.end_time - query.duration;
		if (query.duration && query.start_time)
			 query.end_time = query.start_time + query.duration;
		if (query.start_time && query.end_time)
			query.duration = query.end_time - query.start_time;
	}
}

static struct response *
response_alloc(void)
{
	struct response *resp;

	if ((resp = calloc(1, sizeof(struct response))) == NULL)
		err(1, "calloc failed!");
	resp->interval = query.interval;
	resp->threshold = query.threshold;
	resp->nflows = 0;
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
	const char *wfile = NULL;

	while ((ch = getopt(argc, argv, "df:hi:m:n:ps:t:vw:DE:FPS:")) != -1) {
		switch (ch) {
		case 'd':	/* Set the output format = txt */
			query.outfmt = DEBUG;
			query.criteria = BYTE;
			break;
		case 'f':	/* Filter */
			filter_str = optarg;
			break;
		case 'h':
			usage();
			break;
		case 'i':
			query.interval = strtol(optarg, NULL, 10);
			break;
		case 'm':
			if (!strncmp(optarg, "byte", 4))
				query.criteria = BYTE;
			else if (!strncmp(optarg, "packet", 6))
				query.criteria = PACKET;
			else
				usage();
			break;
		case 'n':
			query.nflows = strtol(optarg, NULL, 10);
			break;
		case 'p':	/* Set the output format = json */
			/* If -d and -p are input at the same time, use -d */
			if (query.outfmt != DEBUG) {
				query.outfmt = JSON;
				query.criteria = BYTE;
			}
			break;
		case 's':
			query.duration = strtol(optarg, NULL, 10);
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
		case 'F':
			flow_mode = 1;
			break;
		case 'P':
			proto_view = 1;
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

	if (filter_str != NULL && filter_parse(filter_str) < 0)
		usage();

}

/* filter format: '<src> <dst>' */
static int
filter_parse(char *str)
{
	int af, af2;
	char *cp, *sp;

	cp = str;
	while (isspace(*cp))
		cp++;
	
	if (proto_view != 0) {
		double dummy, dummy2;
		char buf[64];

		snprintf(buf, sizeof(buf), "[%s]0%% 0%%", cp);
		if (protospec_parse(buf, &query.f, &dummy, &dummy2) < 0)
			return (-1);
		query.f_af = AF_LOCAL;
		return (0);
	}

	sp = cp;
	if ((cp = strsep(&sp, " ")) == NULL)
		return (-1);
	af = ip_addrparser(cp, &query.f.src, &query.f.srclen);
	if ((cp = strsep(&sp, " ")) == NULL)
		return (-1);
	af2 = ip_addrparser(cp, &query.f.dst, &query.f.dstlen);
	if (af != af2)
		return (-1);
	query.f_af = af;
	return (0);
}

static void
file_parse(char **files)
{
	struct stat st;
	FILE *fp;
        int i, m;
	char file[254];

        if (stat(*files, &st) < 0) {
#if 1
		/* don't exit when cgi passes file names beyond the latest */
		warn("stat(%s) fails", *files);
		return;
#else
		err(1, "stat(%s) fails", *files);
#endif
	}

        if ((st.st_mode & S_IFMT) == S_IFDIR) {
        	struct dirent **flist;
                if ((m = scandir(*files, &flist, NULL, alphasort)) < 0)
                        err(1, "scandir(%s) is failed", *files);
                for (i = 0; i < m; i++) {
                        if (!strncmp(flist[i]->d_name, ".", 1)) 
                                continue;
                        if (!strncmp(flist[i]->d_name, "..", 2)) 
                                continue;
                        sprintf(file, "%s/%s", *files, flist[i]->d_name);
			if ((fp = fopen(file, "r")) == NULL)
				err(1, "can't open %s", file);
			read_file(fp);
			(void)fclose(fp);
                }   
        } else  {
		memcpy(file, *files, sizeof(file));
		if ((fp = fopen(file, "r")) == NULL)
			err(1, "can't open %s", file);
		read_file(fp);
		(void)fclose(fp);
	}
}

static void
read_file(FILE *fp)
{
	struct odflow *odfp = NULL;
	struct odflow_spec odfsp;
	struct odflow_spec odpsp;
	uint64_t byte, byte2;
	uint64_t packet, packet2;
	int af;
	char *buf, *cp;
	int bufsz;
	static struct odflow_spec zero;	/* wildcard odflow_spec */

	bufsz = BUFSIZ*2;
	buf = malloc(bufsz);

	while (fgets(buf, bufsz, fp)) {
		if (is_preambles(buf))
			continue;
		if (is_finish)	/* the duration is expired */
			break;
		/* skip until the specified start_time */
		if (response->start_time == 0)
			continue;
		if (buf[0] != '[')  /* address line starts with "[rank]" */
			continue;

		af = address_parse(buf, &odfsp, &byte, &packet);
		if (af < 0)
			err(1, "address_parse() finds wrong address type.");

		/* filter the entry insertion by address type */
		if (query.f_af == AF_INET || query.f_af == AF_INET6) {
			if (query.f_af != af)
				continue;
			/* filter the entry insertion by an record matching */
			if (!match_filter(&odfsp))
				continue;
		}

		/* insert a record into a hash table */
		if (proto_view == 0)
			odfp = odflow_addcount(&odfsp, af, byte, packet, response);

		/* add decomposition of the origin and destination flow */
		if (fgets(buf, bufsz, fp) == NULL)
			err(1, "fgets error\n");

		if (plot_phase != 0 && proto_view == 0)
			continue;

		/*
		 * for the first round, add a sub-record into a hash table.
		 */
		cp = buf;
		while (proto_parse(&cp, byte, packet, &odpsp, &byte2, &packet2) != NULL) {
			if (query.f_af == AF_LOCAL)
				if (!match_filter(&odpsp))
					continue;

			if (proto_view == 0) {
				odproto_addcount(odfp, &odpsp, AF_LOCAL, byte2, packet2);
			} else {
				odfp = odflow_addcount(&odpsp, AF_LOCAL, byte2, packet2, response);
				if (!plot_phase)
					odproto_addcount(odfp, &odfsp, af, byte2, packet2);
				byte -= byte2;
				packet -= packet2;
			}
		}
		if (proto_view != 0 && query.f_af == 0
			&& (byte > 0 || packet > 0)) {
			/* add remaining counts to the wildcard proto */
			odfp = odflow_addcount(&zero, AF_LOCAL, byte, packet, response);
			if (!plot_phase)
				odproto_addcount(odfp, &odfsp, af, byte, packet);
		}
	}
	free(buf);
}

/*
 * read start time and end time in the preamble.
 * also produce output at the end of the current period.
 */
static int
is_preambles(char *buf)
{
	char *cp;
        struct tm tm;
        time_t t = 0;
	static time_t ts_next;

	if (buf[0] == '\0' || buf[0] == '#')
		return (1);
	if (buf[0] != '%')
		return (0); 
	/* parse predefined comments in each aguri log */
	if (!strncmp("StartTime:", &buf[2], 10)) {
		cp = strchr(&buf[2], ':');
		cp++;
		cp += strspn(cp, " \t");
		memset(&tm, 0, sizeof(tm));
		if (strptime(cp, "%a %b %d %T %Y", &tm) == NULL)
			err(1, "date format is incorrect.");
		if ((t = mktime(&tm)) < 0)
			warnx("mktime failed.");

		if (query.start_time > t)
			return (1);
		if (response->start_time == 0) {
			response->start_time = t;
			if (response->interval != 0) {
				/* try to align the interval */
				int interval = response->interval;
				if (interval > 3600)
					interval = 3600; /* for timezone */
				ts_next = t / interval * interval + response->interval;
			}
		}
		if (!plot_phase)
			response->current_time = t;
		if (query.outfmt == REAGGREGATION && response->interval != 0 &&
		    t >= ts_next) {
			if (hhh_run(response) > 0)
				make_output(response);
			odhash_resetall(response);
			response->start_time = t;
			if (t >= ts_next)
				ts_next += response->interval;
		}
		if (plot_phase) {
			time_t slottime = plot_getslottime();
			if (t - slottime >= response->interval) {
				plot_addupinterval(response);

				/* check empty period. if there exists
				 * a blank interval, insert blank timeslots
				 */
				if (t - slottime >= response->interval * 2)
					plot_addslot(slottime + response->interval, 1);
				if (t - slottime >= response->interval * 3)
					plot_addslot(t - response->interval, 1);
				/* for next interval */
				plot_addslot(t, 0);
				odhash_resetall(response);
			}
		}
		return (1);
	}   
	if (!strncmp("EndTime:", &buf[2], 8)) {
		if (!response->start_time)
			return (1);
		cp = strchr(&buf[2], ':');
		cp++;
		cp += strspn(cp, " \t");
		memset(&tm, 0, sizeof(tm));
		if (strptime(cp, "%a %b %d %T %Y", &tm) == NULL)
			return (-1);
		if ((t = mktime(&tm)) < 0)
			warnx("mktime failed.");
		if (query.end_time && query.end_time < t) {
			is_finish = 1;
			return (1);
		}
		if (!plot_phase) {
			response->end_time = t;
			response->max_interval = max(response->max_interval,
			    t - response->current_time);
			if (t - response->start_time > query.duration)
				return (1);
		}
		if (plot_phase && t > response->end_time) {
			is_finish = 1;
			return (1);
		}
		return (1);
	}
	return (0);
}

/* parse IP address */
static int
ip_addrparser(char *buf, void *ip, uint8_t *prefixlen)
{
	char *cp, *ap;
	uint8_t len;
	int i, af = AF_UNSPEC;

	cp = buf;
	if (cp[0] == '*') {
		if (cp[1] == ':' && cp[2] == ':') {
			/* "*::" is the wildcard for IPv6 */
			af = AF_INET6;
			ap = "::";
			len = 0;
		} else {
			/* "*" is the wildcard for IPv4 */
			af = AF_INET;
			ap = "0.0.0.0";
			len = 0;
		}
	} else {
		ap = cp;
		/* check the first 5 chars for address family (v4 or v6) */
		for (i = 1; i < 5; i++) {
			if (cp[i] == '.') {
				af = AF_INET;
				break;
			} else if (cp[i] == ':') {
				af = AF_INET6;
				break;
			}
		}
		if (af == AF_UNSPEC)
			return (-1);

		if ((cp = strchr(ap, '/')) != NULL) {
			*cp++ = '\0';
			len = strtol(cp, NULL, 10);
		} else {
			if (af == AF_INET)
				len = 32;
			else if (af == AF_INET6)
				len = 128;
		}
	}
	if (inet_pton(af, ap, ip) < 0)
		return (-1);
	*prefixlen = len;
	return (af);
}

/*
 * parse src_ip and dst_ip bytes packets from a src-dst pair line, e.g.,
 * [ 8] 10.178.141.0/24 *: 21817049 (3.19%) 17852 (1.21%)
 * [39] *:: 2001:df0:2ed:::13: 979274 (0.15%)  901 (0.06%)
 */
static int
address_parse(char *buf, struct odflow_spec *odfsp, uint64_t *byte, uint64_t *packet)
{
	char *cp, *sp;
	int af, af2;

	cp = buf;
	while (isspace(*cp))
		cp++;
	if (*cp == '\0' || *cp == '%')
		return (-1);

	memset(odfsp, 0, sizeof(struct odflow_spec));
	cp = strchr(&cp[2], ' ');
	sp = cp + 1;
	if ((cp = strsep(&sp, " ")) == NULL)
		return (-1);
	if ((af = ip_addrparser(cp, &odfsp->src, &odfsp->srclen)) < 0)
		return (-1);
	if ((cp = strsep(&sp, " ")) == NULL)
		return (-1);
	assert(sp[-2] == ':');
	sp[-2] = '\0';	/* trim the delimiter ':' */
	if ((af2 = ip_addrparser(cp, &odfsp->dst, &odfsp->dstlen)) < 0)
		return (-1);

	/* address type must be same */
	assert(af == af2);
	if ((cp = strsep(&sp, " ")) == NULL)
		return (-1);
	*byte = strtouq(cp, NULL, 10);
	if ((cp = strsep(&sp, "\t")) == NULL)
		return (-1);
	if ((cp = strsep(&sp, " ")) == NULL)
		return (-1);
	*packet = strtouq(cp, NULL, 10);
	return (af);
}

/*
 * parse the protocol spec: e.g.,
 *	[6:80:*]92.8% 77.0% [6:443:49152-49279]1.9% 4.6%
 */
static int
protospec_parse(char *buf, struct odflow_spec *odpsp, double *perc, double *perc2)
{
	char *cp, *cp2, *ep, *sp, *sp2;
	long val;

	memset(odpsp, 0, sizeof(struct odflow_spec));
	cp = buf;
	if (*cp == '[')
		cp++;
	val = strtol(cp, &ep, 10); /* note: 0 for '*' */
	odpsp->src[0] = odpsp->dst[0] = val;
	/* note: no prefix notation for protocol */
	if (*ep == '*')
		ep++;
	cp = ep + 1;  /* *ep == ':' */
	/* src port */
	sp = cp;
	if ((cp = strsep(&sp, ":")) == NULL)
		return (-1);
	sp2 = cp;
	cp2 = strsep(&sp2, "-");
	if (sp2 != NULL) {
		/* port range */
		uint16_t end;
		val = strtol(cp2, NULL, 10);
		odpsp->src[1] = val >> 8;
		odpsp->src[2] = val & 0xff;
		end = strtol(sp2, NULL, 10);
		odpsp->srclen = 8 + 17 - ffs(end - val + 1);
	} else {
		/* single port */
		val = strtol(cp, NULL, 10);
		if (val == 0) {
			if (odpsp->src[0] == 0)
				odpsp->srclen = 0;
			else
				odpsp->srclen = 8;
		} else {
			odpsp->src[1] = val >> 8;
			odpsp->src[2] = val & 0xff;
			odpsp->srclen = 24;
		}
	}
	/* dest port */
	if ((cp = strsep(&sp, "]")) == NULL)
		return (-1);
	sp2 = cp;
	cp2 = strsep(&sp2, "-");
	if (sp2 != NULL) {
		/* port range */
		uint16_t end;
		val = strtol(cp2, NULL, 10);
		odpsp->dst[1] = val >> 8;
		odpsp->dst[2] = val & 0xff;
		end = strtol(sp2, NULL, 10);
		odpsp->dstlen = 8 + 17 - ffs(end - val + 1);
	} else {
		/* single port */
		val = strtol(cp, NULL, 10);
		if (val == 0) {
			if (odpsp->dst[0] == 0)
				odpsp->dstlen = 0;
			else
				odpsp->dstlen = 8;
		} else {
			odpsp->dst[1] = val >> 8;
			odpsp->dst[2] = val & 0xff;
			odpsp->dstlen = 24;
		}
	}
	
	if ((cp = strsep(&sp, "%"))== NULL)
		return (-1);
	*perc = strtod(cp, NULL);
	if ((cp = strsep(&sp, "%")) == NULL || sp == NULL)
		return (-1);
	*perc2 = strtod(cp, NULL);
	return (0);
}

/*
 * parse src_proto, dst_proto and port, e.g.,
 *      [6:80:*]92.8% 77.0% [6:443:*]6.3% 11.1% [*:*:*]0.6% 9.7%
 */
static char *
proto_parse(char **strp, uint64_t byte, uint64_t packet,
    struct odflow_spec *odpsp, uint64_t *byte2, uint64_t *packet2)
{
	char *cp, *ap;
	double perc, perc2;

	if (strp == NULL || (cp = *strp) == NULL)
		return (NULL);
	while (isspace(*cp))
		cp++;
	if (*cp == '\0')
		return (NULL);

	ap = strchr(&cp[1], '[');
	*strp = ap;	/* set the ptr to the next token, or NULL */
	if (ap != NULL) {
		ap[-1] = '\0';  /* terminate the token string */
	} else {
		/* last entry */
		if (strchr(cp, ']') == NULL)
			return (NULL);
	}
	protospec_parse(cp, odpsp, &perc, &perc2);
	*byte2 = (uint64_t)(perc * byte / 100);
	*packet2 = (uint64_t)(perc2 * packet / 100);
	return (cp);
}

static int
match_filter(struct odflow_spec *odfsp)
{
	int len, len2;

	if (odfsp->srclen < query.f.srclen || odfsp->dstlen < query.f.dstlen)
		return (0);
	len = prefix_comp(odfsp->src, query.f.src, query.f.srclen); 
	if (len != 0)
		return (0);
	len2 = prefix_comp(odfsp->dst, query.f.dst, query.f.dstlen);
	if (len2 != 0)
		return (0);
	return (1);
}

#if 1 /* experimental: read aguri flows for evaluation purposes */
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

	ts = (time_t)ntohl(agf->agflow_last);
	if (ts < ts_max)
		ts = ts_max;  /* XXX we want ts to be monotonic */
	else
		ts_max = ts;	/* keep track of the max value of ts */

	if (query.start_time > ts)
		return (0);
	if (response->start_time == 0) {
		response->start_time = ts;
		if (response->interval != 0)
			ts_next = query.start_time + query.interval;
	}

	if (response->interval != 0 && ts >= ts_next) {
		if (hhh_run(response) > 0)
			make_output(response);
		odhash_resetall(response);
		response->start_time = ts;
		ts_next += response->interval;
	}
	if (query.end_time && query.end_time < ts)
		return (-1);  /* we are beyond the end time */
	if (query.duration && ts - response->start_time > query.duration)
		return (-1);  /* ditto */

	response->end_time = ts;
	
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
	odfp = odflow_addcount(&odfsp, af, byte, packet, response);

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
		if (verbose && n % 10000 == 0)
			fprintf(stderr, "+");
	}
	return (0);
}
#endif /*experimental */

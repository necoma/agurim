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

static void init(int argc, char **argv);
static void finish();
static void query_init();
static void response_init();
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

struct _query query;
struct _response response;
int plot_phase;
int is_finish;
int proto_view = 0;
static char *filter_str = NULL;

static void
usage()
{
	fprintf(stderr, "usage:\n");
	fprintf(stderr, "  agurim2 [-dhpP]\n");
	fprintf(stderr, "          [-f '<src> <dst>' or '<proto>:<sport>:<dport>'\n");
	fprintf(stderr, "          [-m criteria (byte/packet)]\n"); 
	fprintf(stderr, "          [-n nflows] [-s duration] \n");
	fprintf(stderr, "          [-t thresh_percentage]\n");
	fprintf(stderr, "          [-S start_time] [-E end_time]\n");
	fprintf(stderr, "          files or directories\n");
	exit(1);
}

int main(int argc, char **argv)
{
	int n;
	char **files;

	init(argc, argv);

	argc -= optind;
	argv += optind;

again:
	n = argc;
	files = argv;

	if (n == 0) {
		if (query.outfmt == REAGGREGATION) {
			if (isatty(fileno(stdin)))
				fprintf(stderr, "reading from stdin...\n");
			read_file(stdin); /* read from stdin */
		} else
			usage();
	}
	while (n > 0) {
		file_parse(files);
		++files;
		--n;
	}

	if (!plot_phase) {
		hhh_run();
		plot_init();
		if (query.outfmt != REAGGREGATION) {
			/* reset internal parameters for text processing */
			is_finish = 0;
			response.start_time = 0;

			/* need to re-read the files for plotting */
			/* set the second pass */
			plot_phase = 1;
			goto again;
		}
	}
	plot_showdata();

	finish();

	return (0);
}

static void 
init(int argc, char **argv)
{
	option_parse(argc, argv);
	query_init();
	response_init();
	odhash_init();
}

static void
finish()
{
	plot_finish();
}

static void
query_init()
{
	if (!query.criteria)
		query.criteria = COMBINATION;
	if (!query.interval) 
		query.interval = 60;
	if (!query.outfmt) 
		query.outfmt = REAGGREGATION;
	if (!query.threshold) {
		if (query.outfmt == REAGGREGATION)
			query.threshold = 1;
		else
			query.threshold = 3; // or query.threshold = 10;
	}
	if (!query.nflows && query.outfmt != REAGGREGATION)
		query.nflows = 7;
	if (query.outfmt == REAGGREGATION)
		return;
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

static void
response_init()
{
	response.criteria = COMBINATION;
	response.interval = query.interval;
	response.threshold = query.threshold;
	response.nflows = 0;
	response.duration = query.duration;
	TAILQ_INIT(&response.odfq.odfq_head);
	response.odfq.nrecord = 0;
}

static void
option_parse(int argc, void *argv)
{
	int ch;

	while ((ch = getopt(argc, argv, "df:hi:m:n:ps:t:E:PS:")) != -1) {
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
			if (optarg[0] == '-')
				usage();
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
			if (optarg[0] == '-')
				usage();
			query.duration = strtol(optarg, NULL, 10);
			break;
		case 't':
			if (optarg[0] == '-')
				usage();
			query.threshold = strtod(optarg, NULL);
			break;
		case 'E':
			if (optarg[0] == '-')
				usage();
			query.end_time = strtol(optarg, NULL, 10);
			break;
		case 'P':
			proto_view = 1;
			break;
		case 'S':
			if (optarg[0] == '-')
				usage();
			query.start_time = strtol(optarg, NULL, 10);
			break;
		default:
			usage();
			break;
		}
	}

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
		return;
#else
		err(1, "stat(%s) fails.", *files);
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
	struct odflow *odfp;
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
		if (response.start_time == 0)
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
			odfp = odflow_addcount(&odfsp, af, byte, packet);

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
				odfp = odflow_addcount(&odpsp, AF_LOCAL, byte2, packet2);
				if (!plot_phase)
					odproto_addcount(odfp, &odfsp, af, byte2, packet2);
				byte -= byte2;
				packet -= packet2;
			}
		}
		if (proto_view != 0 && query.f_af == 0
			&& (byte > 0 || packet > 0)) {
			/* add remaining counts to the wildcard proto */
			odfp = odflow_addcount(&zero, AF_LOCAL, byte, packet);
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
		if (response.start_time == 0)
			response.start_time = t;
		if (!plot_phase)
			response.current_time = t;
		if (query.outfmt == REAGGREGATION &&
		    t - response.start_time >= response.interval) {
			hhh_run();
			plot_showdata();
			plot_finish();
			odhash_reset(ip_hash);
			odhash_reset(ip6_hash);
			if (proto_view)
				odhash_reset(proto_hash);
			response.start_time = t;
		}
		if (plot_phase && query.outfmt != REAGGREGATION &&
		    t - plot_timestamps[time_slot] >= response.interval) {
			plot_addslot();
			if (proto_view == 0) {
				plot_addcount(ip_hash);
				plot_addcount(ip6_hash);
			} else
				plot_addcount(proto_hash);

			/* check empty period */
			if (t - plot_timestamps[time_slot] >= response.interval * 2) {
				/* there exists a blank interval,
				 * insert blank timeslots
				 */
				time_t t2;

				plot_addslot();
				t2 = plot_timestamps[time_slot] + response.interval; 
				plot_timestamps[++time_slot] = t2;
				if (t - t2 > response.interval) {
					plot_addslot();
					t2 = t - response.interval; 
					plot_timestamps[++time_slot] = t2;
				}
			}

			plot_timestamps[++time_slot] = t;
			odhash_reset(ip_hash);
			odhash_reset(ip6_hash);
			if (proto_view)
				odhash_reset(proto_hash);
		}
		return (1);
	}   
	if (!strncmp("EndTime:", &buf[2], 8)) {
		cp = strchr(&buf[2], ':');
		cp++;
		cp += strspn(cp, " \t");
		memset(&tm, 0, sizeof(tm));
		if (strptime(cp, "%a %b %d %T %Y", &tm) == NULL)
			return (-1);
		if ((t = mktime(&tm)) < 0)
			warnx("mktime failed.");
		if (!response.start_time)
			return (1);
		if (query.end_time && query.end_time < t) {
			is_finish = 1;
			return (1);
		}
		if (!plot_phase) {
			response.end_time = t;

			response.max_interval = max(response.max_interval,
			    t - response.current_time);

			if (t - response.start_time > query.duration)
				return (1);
		}
		if (plot_phase) {
			/* int duration = t - plot_timestamps[time_slot]; */
			if (t > response.end_time) {
				is_finish = 1;
				return (1);
			}
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

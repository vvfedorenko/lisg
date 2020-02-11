/* Shared library add-on to iptables for ISG match
 * (C) 2020 by Vadim Fedorenko <vadimjunk@gmail.com>
 *
 * This program is distributed under the terms of GNU GPL
 */
#include <stdio.h>
#include <string.h>
#include <getopt.h>

#define __EXPORTED_HEADERS__
#include <xtables.h>

#include "isg.h"

static const struct option opts[] = {
	{ .name = "service-name", .has_arg = true, .val = '1' },
	{ }
};

static void help(void) {
	printf(
"ISG match options:\n"
" --service-name <name>		Check session service name:\n"
"				 name - serivce name to check\n"
"				        not more than 32 charactes\n");
}

static int parse(int c, char **argv, int invert, unsigned int *flags,
                 const void *entry, struct xt_entry_match **match) {

	struct ipt_ISG_mt_info *isg = (struct ipt_ISG_mt_info *)(*match)->data;

	switch (c) {
		case '1':
			if (*flags & INIT_SESSION) {
				xtables_error(PARAMETER_PROBLEM, "Can't specify --service-name twice\n");
			}
			if (invert) {
				xtables_error(PARAMETER_PROBLEM, "Can't invert --service-name value\n");
			}
			if (!strnlen(optarg, MAX_SERVICE_NAME)) {
				xtables_error(PARAMETER_PROBLEM, "Service name must be specified with --service-name\n");
			}
			*flags |= INIT_SESSION;
			strncpy(isg->service_name, optarg, strnlen(optarg, MAX_SERVICE_NAME));
			break;

		default:
			return 0;
	}

	return 1;
}

static void save(const void *ip, const struct xt_entry_match *match) {
	struct ipt_ISG_mt_info *isg = (struct ipt_ISG_mt_info *)match->data;

	printf(" --service-name %.32s", isg->service_name);
}

static void print(const void *ip,
                  const struct xt_entry_match *match,
                  int numeric) {

	struct ipt_ISG_mt_info *isg = (struct ipt_ISG_mt_info *)match->data;

	printf("isg match service %.32s ", isg->service_name);
}

static void check(unsigned int flags) {
	if (!flags) {
		xtables_error(PARAMETER_PROBLEM, "Service name must be specified with --service-name parameter\n");
	}
}

static struct xtables_match isg_mt_info = { 
	.name          = "isg",
	.version       = XTABLES_VERSION,
	.family        = NFPROTO_IPV4,
	.size          = XT_ALIGN(sizeof(struct ipt_ISG_mt_info)),
	.userspacesize = XT_ALIGN(sizeof(struct ipt_ISG_mt_info)),
	.help          = help,
	.parse         = parse,
	.final_check   = check,
	.print         = print,
	.save          = save,
	.extra_opts    = opts
};

void _init(void) {
	xtables_register_match(&isg_mt_info);
}

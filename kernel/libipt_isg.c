#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <getopt.h>

#define __EXPORTED_HEADERS__
#include <xtables.h>

#include <linux/netfilter_ipv4/ip_tables.h>
#include "isg.h"

static const struct option opts[] = {
	{ "session-init", 0, NULL, '1' },
	{ "init-mode", 1, NULL, '2' },
	{ .name = NULL }
};

static void help(void) {
	printf(
"ISG target options:\n"
" --session-init		This rule match can be session initiator\n"
" --init-mode <mode>		Session initialization mode:\n"
"				  src - use src IP-address as username\n"
"				  dst - use dst IP-address as username\n"
"				If --init-mode is not specified, `src' is assumed\n");
}

static int parse(int c, char **argv, int invert, unsigned int *flags,
                 const void *entry,
                 struct xt_entry_target **target) {

	struct ipt_ISG_info *isg = (struct ipt_ISG_info *)(*target)->data;

	switch (c) {
		case '1':
			if (*flags & INIT_SESSION) {
				xtables_error(PARAMETER_PROBLEM, "Can't specify --session-init twice\n");
			}

			*flags |= INIT_SESSION;
			isg->flags |= INIT_SESSION;
			isg->flags |= INIT_BY_SRC;

			break;

		case '2':
			if (!(*flags & INIT_SESSION)) {
				xtables_error(PARAMETER_PROBLEM, "--init-mode parameter must be used with --session-init option\n");
			}

			if (!strcmp(optarg, "src")) {
				isg->flags |= INIT_BY_SRC;
			} else if (!strcmp(optarg, "dst")) {
				isg->flags &= ~INIT_BY_SRC;
				isg->flags |= INIT_BY_DST;
			} else {
				xtables_error(PARAMETER_PROBLEM, "Unknown session init mode '%s'\n", optarg);
			}

			break;

		default:
			return 0;
	}

	return 1;
}

static void save(const void *ip, const struct xt_entry_target *target) {
	struct ipt_ISG_info *isg = (struct ipt_ISG_info *)target->data;

	if (isg->flags & INIT_SESSION) {
		printf(" --session-init ");

		if (isg->flags & INIT_BY_SRC) {
			printf("--init-mode src");
		} else if (isg->flags & INIT_BY_DST) {
			printf("--init-mode dst");
		}
	}
}

static void print(const void *ip,
                  const struct xt_entry_target *target,
                  int numeric) {

	struct ipt_ISG_info *isg = (struct ipt_ISG_info *)target->data;

	printf("ISG ");

	if (isg->flags & INIT_SESSION) {
		printf("initiator ");

		if (isg->flags & INIT_BY_SRC) {
			printf("src mode");
		} else if (isg->flags & INIT_BY_DST) {
			printf("dst mode");
		}
	}
}

static void check(unsigned int flags) {

}

static struct xtables_target isg_info = { 
	.name          = "ISG",
	.version       = XTABLES_VERSION,
	.family        = PF_INET,
	.size          = XT_ALIGN(sizeof(struct ipt_ISG_info)),
	.userspacesize = XT_ALIGN(sizeof(struct ipt_ISG_info)),
	.help          = help,
	.parse         = parse,
	.final_check   = check,
	.print         = print,
	.save          = save,
	.extra_opts    = opts
};

void _init(void) {
	xtables_register_target(&isg_info);
}

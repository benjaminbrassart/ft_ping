/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   options.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bbrassar <bbrassar@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/05/17 17:01:59 by bbrassar          #+#    #+#             */
/*   Updated: 2025/05/18 12:20:05 by bbrassar         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "options.h"
#include "args.h"
#include "display.h"

#include <ctype.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tgmath.h>

#define sizeof_array(Arr) (sizeof(Arr) / sizeof(Arr[0]))

struct opt_parser {
	struct arg_iterator it;
	struct options opts;
	unsigned accept_opt : 1;
};

typedef int(option_handler_func_t)(struct opt_parser *, char const[]);

struct option_table {
	char const *name_long;
	char name_short;
	unsigned value_required;
	option_handler_func_t *handler;
	char const *param_name;
	char const *description;
};

static int opt_ttl(struct opt_parser *parser, char const *value)
{
	char *end;
	uintmax_t ttl;

	ttl = strtoumax(value, &end, 10);
	if (end == value || *end != '\0') {
		ERR("ttl: %s: invalid value", value);
		return EXIT_FAILURE;
	}

	if (ttl == 0) {
		ERR("ttl: value too small");
		return EXIT_FAILURE;
	}

	if (ttl > UINT8_MAX) {
		ERR("ttl: value too big");
		return EXIT_FAILURE;
	}

	parser->opts.ttl = (uint8_t)ttl;
	return EXIT_SUCCESS;
}

static int opt_count(struct opt_parser *parser, char const *value)
{
	uintmax_t count;
	char *end;

	count = strtoumax(value, &end, 10);
	if (end == value || *end != '\0') {
		ERR("count: %s: invalid value", value);
		return EXIT_FAILURE;
	}

	if (count > SIZE_MAX) {
		ERR("count: value too big");
		return EXIT_FAILURE;
	}

	parser->opts.count = (size_t)count;
	return EXIT_SUCCESS;
}

static int opt_debug(struct opt_parser *parser, char const *value)
{
	(void)value;
	parser->opts.debug = 1;
	return EXIT_SUCCESS;
}

static int opt_interval(struct opt_parser *parser, char const *value)
{
	long double interval;
	char *end;

	interval = strtold(value, &end);
	if (end == value || *end != '\0') {
		ERR("interval: %s: invalid value", value);
		return EXIT_FAILURE;
	}

	if (interval < 0) {
		ERR("interval: value too big");
		return EXIT_FAILURE;
	}

	parser->opts.interval.tv_nsec = (long)(fmod(interval, 1.0) * 1e9);
	parser->opts.interval.tv_sec = (time_t)(interval - fmod(interval, 1.0));
	return EXIT_SUCCESS;
}

static int opt_pattern(struct opt_parser *parser, char const *value)
{
	for (size_t i = 0; value[i] != '\0'; i += 1) {
		if (!isxdigit(value[i])) {
			ERR("pattern: error near %c", value[i]);
			return EXIT_FAILURE;
		}
	}

	parser->opts.pattern = value;
	return EXIT_SUCCESS;
}

static int opt_quiet(struct opt_parser *parser, char const *value)
{
	(void)value;
	parser->opts.quiet = 1;
	return EXIT_SUCCESS;
}

static int opt_routing_ignore(struct opt_parser *parser, char const *value)
{
	(void)value;
	parser->opts.routing_ignore = 1;
	return EXIT_SUCCESS;
}

static int opt_size(struct opt_parser *parser, char const *value)
{
	uintmax_t size;
	char *end;

	size = strtoumax(value, &end, 10);
	if (end == value || *end != '\0') {
		ERR("size: %s: invalid value", value);
		return EXIT_FAILURE;
	}

	if (size > UINT16_MAX) {
		ERR("size: value too big");
		return EXIT_FAILURE;
	}

	parser->opts.size = (size_t)size;
	return EXIT_SUCCESS;
}

static int opt_verbose(struct opt_parser *parser, char const *value)
{
	(void)value;
	parser->opts.verbose = 1;
	return EXIT_SUCCESS;
}

static int opt_linger(struct opt_parser *parser, char const *value)
{
	long double linger;
	char *end;

	linger = strtold(value, &end);
	if (end == value || *end != '\0') {
		ERR("linger: %s: invalid value", value);
		return EXIT_FAILURE;
	}

	if (linger < 0) {
		ERR("linger: value too big");
		return EXIT_FAILURE;
	}

	parser->opts.linger.tv_nsec = (long)(fmod(linger, 1.0) * 1e9);
	parser->opts.linger.tv_sec = (time_t)(linger - fmod(linger, 1.0));
	return EXIT_SUCCESS;
}

static int opt_help(struct opt_parser *parser, char const *value)
{
	(void)value;
	parser->opts.help = 1;
	return -1;
}

static struct option_table const OPTION_TABLE[] = {
	{
		.name_long = "ttl",
		.name_short = '\0',
		.value_required = 1,
		.handler = opt_ttl,
		.param_name = "N",
		.description = "specify N as time-to-live",
	},
	{
		.name_long = "count",
		.name_short = 'c',
		.value_required = 1,
		.handler = opt_count,
		.param_name = "NUMBER",
		.description = "stop after sending NUMBER packets",
	},
	{
		.name_long = "debug",
		.name_short = 'd',
		.value_required = 0,
		.handler = opt_debug,
		.param_name = NULL,
		.description = "set the SO_DEBUG option",
	},
	{
		.name_long = "interval",
		.name_short = 'i',
		.value_required = 1,
		.handler = opt_interval,
		.param_name = "NUMBER",
		.description =
			"wait NUMBER seconds between sending each packet",
	},
	{
		.name_long = "pattern",
		.name_short = 'p',
		.value_required = 1,
		.handler = opt_pattern,
		.param_name = "PATTERN",
		.description = "fill ICMP packet with given pattern (hex)",
	},
	{
		.name_long = "quiet",
		.name_short = 'q',
		.value_required = 0,
		.handler = opt_quiet,
		.param_name = NULL,
		.description = "quiet output",
	},
	{
		.name_long = "routing-ignore",
		.name_short = 'r',
		.value_required = 0,
		.handler = opt_routing_ignore,
		.param_name = NULL,
		.description = "send directly to a host on an attached network",
	},
	{
		.name_long = "size",
		.name_short = 's',
		.value_required = 1,
		.handler = opt_size,
		.param_name = "NUMBER",
		.description = "send NUMBER data octets",
	},
	{
		.name_long = "verbose",
		.name_short = 'v',
		.value_required = 0,
		.handler = opt_verbose,
		.param_name = NULL,
		.description = "verbose output",
	},
	{
		.name_long = "linger",
		.name_short = 'W',
		.value_required = 1,
		.handler = opt_linger,
		.param_name = "N",
		.description = "number of seconds to wait for response",
	},
	{
		.name_long = "help",
		.name_short = '?',
		.value_required = 0,
		.handler = opt_help,
		.param_name = NULL,
		.description = "give this help list",
	},
};

/*
Possible options:
      --ttl <N>
  -c, --count <N>
  -d, --debug
  -i, --interval <N>
  -p, --pattern <PATTERN>
  -q, --quiet
  -r, --routing-ignore
  -s, --size <N>
  -v, --verbose
  -W, --linger <N>
  -?, --help
*/

static unsigned opt_equals(char const arg[], char const opt[])
{
	size_t i;

	i = 0;
	for (;; i += 1) {
		if (arg[i] == '\0' || arg[i] != opt[i]) {
			break;
		}
	}

	return arg[i] == opt[i] || (arg[i] == '=' && opt[i] == '\0');
}

static char const *opt_get_value(struct opt_parser *parser, char const s[],
				 unsigned consume_next)
{
	char const *eq = strchr(s, '=');

	if (eq != NULL) {
		return eq + 1;
	}

	if (consume_next) {
		char const *next = argit_peek(&parser->it);

		argit_shift(&parser->it);
		return next;
	}

	return NULL;
}

static struct option_table const *opt_get_short(char c)
{
	for (size_t i = 0; i < sizeof_array(OPTION_TABLE); i += 1) {
		if (c == OPTION_TABLE[i].name_short) {
			return &OPTION_TABLE[i];
		}
	}

	return NULL;
}

static struct option_table const *opt_get_long(char const name[])
{
	for (size_t i = 0; i < sizeof_array(OPTION_TABLE); i += 1) {
		DBG("checking opt -%c --%s", OPTION_TABLE[i].name_short,
		    OPTION_TABLE[i].name_long);
		if (opt_equals(name, OPTION_TABLE[i].name_long)) {
			DBG("Yes!");
			return &OPTION_TABLE[i];
		}
		DBG("nop!");
	}

	return NULL;
}

static int opts_parse_next(struct opt_parser *parser)
{
	char const *arg = argit_peek(&parser->it);

	if (arg == NULL) {
		DBG("end");
		return -1;
	}

	DBG("arg = %s, accept = %d", arg, parser->accept_opt);

	if (!parser->accept_opt || arg[0] != '-' || arg[1] == '\0') {
		argit_advance(&parser->it);
		return EXIT_SUCCESS;
	}

	if (arg[1] == '-') { // long option
		DBG("long option");
		if (arg[2] == '\0') {
			DBG("we no longer accept options");
			parser->accept_opt = 0;
			return EXIT_SUCCESS;
		}

		struct option_table const *entry = opt_get_long(&arg[2]);

		if (entry == NULL) {
			ERR("unrecognized option '%s'", arg);
			return EXIT_FAILURE;
		}

		DBG("got option -%c --%s", entry->name_short, entry->name_long);

		char const *value =
			opt_get_value(parser, arg, entry->value_required);

		if (entry->value_required && value == NULL) {
			ERR("option '--%s' requires an argument",
			    entry->name_long);
			return EXIT_FAILURE;
		}

		if (!entry->value_required && value != NULL) {
			ERR("option '--%s' doesn't allow an argument",
			    entry->name_long);
			return EXIT_FAILURE;
		}

		return entry->handler(parser, value);
	}

	// short option(s)
	for (size_t i = 1; arg[i] != '\0'; i += 1) {
		struct option_table const *entry = opt_get_short(arg[i]);

		if (entry == NULL) {
			ERR("invalid option -- '%c'", arg[i]);
			return EXIT_FAILURE;
		}

		unsigned value_same_arg = 0;
		char const *value = NULL;

		argit_shift(&parser->it);

		if (entry->value_required) {
			if (arg[i + 1] == '\0') {
				value = argit_peek(&parser->it);
				if (value == NULL) {
					ERR("option requires an argument -- '%c'",
					    entry->name_short);
					return EXIT_FAILURE;
				}
				argit_shift(&parser->it);
			} else {
				value = &arg[i + 1];
				value_same_arg = 1;
			}
		}

		int handler_res = entry->handler(parser, value);

		if (handler_res != EXIT_SUCCESS || value_same_arg) {
			return handler_res;
		}
	}

	return EXIT_SUCCESS;
}

static struct options const OPTS_DEFAULT = {
	.ttl = 0,
	.count = 0,
	.debug = 0,
	.help = 0,
	.interval = {
		.tv_sec = 1,
		.tv_nsec = 0,
	},
	.linger = {
		.tv_sec = 0,
		.tv_nsec = 0,
	},
	.pattern = NULL,
	.quiet = 0,
	.routing_ignore = 0,
	.size = 56,
	.verbose = 0,
	.hostnames = NULL,
};

int opts_parse(int argc, char const *argv[], struct options *opt_out)
{
	struct opt_parser parser = {
		.accept_opt = 1,
		.opts = OPTS_DEFAULT,
		.it = {},
	};
	int res;

	DBG("init");
	argit_init(&parser.it, argc, argv);
	argit_advance(&parser.it);

	for (;;) {
		DBG("next arg");
		res = opts_parse_next(&parser);
		if (res == EXIT_SUCCESS) {
			continue;
		}

		if (res < 0) {
			break;
		}

		return res;
	}

	parser.opts.hostname_count = (size_t)(parser.it.length - 1);
	parser.opts.hostnames = &parser.it.args[1];
	*opt_out = parser.opts;
	return EXIT_SUCCESS;
}

void opts_print_help(void)
{
	printf("Usage: ft_ping [OPTION...] HOST ...\n");
	printf("Send ICMP ECHO_REQUEST packets to network hosts.\n");
	printf("\n");
	printf("Options:\n");

	struct option_table const *longest_option = &OPTION_TABLE[0];
	size_t longest_option_len = strlen(longest_option->name_long);

	for (size_t i = 0; i < sizeof_array(OPTION_TABLE); i += 1) {
		struct option_table const *option = &OPTION_TABLE[i];
		size_t option_len = strlen(option->name_long);

		if (option->param_name != NULL) {
			// append "=<param_name>"
			option_len += strlen(option->param_name) + 1;
		}

		if (option_len > longest_option_len) {
			longest_option = option;
			longest_option_len = option_len;
		}
	}

	size_t left_column_length = longest_option_len + 4;

	for (size_t i = 0; i < sizeof_array(OPTION_TABLE); i += 1) {
		char buffer[81];
		struct option_table const *option = &OPTION_TABLE[i];
		char name_short_buf[4] = "   ";

		buffer[0] = '\0';
		if (option->name_short != '\0') {
			name_short_buf[0] = '-';
			name_short_buf[1] = option->name_short;
			name_short_buf[2] = ',';
			name_short_buf[3] = '\0';
		}

		strlcat(buffer, "  ", sizeof(buffer));
		strlcat(buffer, name_short_buf, sizeof(buffer));
		strlcat(buffer, " ", sizeof(buffer));

		size_t option_len = 0;

		if (option->name_long != NULL) {
			strlcat(buffer, "--", sizeof(buffer));
			strlcat(buffer, option->name_long, sizeof(buffer));

			option_len = strlen(option->name_long);

			if (option->param_name != NULL) {
				// append "=<param_name>"
				strlcat(buffer, "=", sizeof(buffer));
				strlcat(buffer, option->param_name,
					sizeof(buffer));
				option_len += strlen(option->param_name) + 1;
			}
		}

		for (size_t i = option_len; i < left_column_length; i += 1) {
			strlcat(buffer, " ", sizeof(buffer));
		}
		strlcat(buffer, option->description, sizeof(buffer));
		puts(buffer);
	}
}

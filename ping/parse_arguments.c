/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parse_arguments.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bbrassar <bbrassar@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/04/14 15:17:59 by bbrassar          #+#    #+#             */
/*   Updated: 2024/04/26 20:17:02 by bbrassar         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ping.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#define DEFAULT_TTL ((uint8_t)64U)

int parse_arguments(struct ft_ping *ping, int argc, char const *argv[])
{
	unsigned delimiter = 0;

	ping->flags.quiet = 0;
	ping->flags.debug = 0;
	ping->flags.verbose = 0;
	ping->flags.flood = 0;
	ping->flags.help = 0;
	ping->flags.version = 0;
	ping->flags.no_route = 0;
	ping->flags.ttl = DEFAULT_TTL;
	ping->host = NULL;

	for (int i = 1; i < argc; i += 1) {
		if (!delimiter && argv[i][0] == '-' && argv[i][1] != '\0') {
			if (argv[i][1] == '-') {
				if (argv[i][2] == '\0') {
					delimiter = 1;
					continue;
				}

				char const *optname = &argv[i][2];
				char const *optval = strchr(optname, '=');
				int samearg;
				size_t optnamelen;

				if (optval == NULL) {
					if (i < argc - 1) {
						optval = argv[i + 1];
					}
					optnamelen = strlen(optname);
					samearg = 0;
				} else {
					optnamelen = (size_t)(optval - optname);
					optval += 1; // skip =
					samearg = 1;
				}

				int optoffset = 0;

				if (strncmp("help", optname, optnamelen) == 0) {
					if (optval != NULL && samearg) {
						goto _long_opt_argument_boolean;
					}
					ping->flags.help = 1;
					return 0;
				} else if (strncmp("version", optname,
						   optnamelen) == 0) {
					if (optval != NULL && samearg) {
						goto _long_opt_argument_boolean;
					}
					ping->flags.version = 1;
					return 0;
				} else if (strncmp("verbose", optname,
						   optnamelen) == 0) {
					if (optval != NULL && samearg) {
						goto _long_opt_argument_boolean;
					}
					ping->flags.verbose = 1;
				} else if (strncmp("quiet", optname,
						   optnamelen) == 0) {
					if (optval != NULL && samearg) {
						goto _long_opt_argument_boolean;
					}
					ping->flags.quiet = 1;
				} else if (strncmp("debug", optname,
						   optnamelen) == 0) {
					if (optval != NULL && samearg) {
						goto _long_opt_argument_boolean;
					}
					ping->flags.debug = 1;
				} else if (strncmp("flood", optname,
						   optnamelen) == 0) {
					if (optval != NULL && samearg) {
						goto _long_opt_argument_boolean;
					}
					ping->flags.flood = 1;
				} else if (strncmp("ignore-routing", optname,
						   optnamelen) == 0) {
					if (optval != NULL && samearg) {
						goto _long_opt_argument_boolean;
					}
					ping->flags.no_route = 1;
				} else if (strncmp("ttl", optname,
						   optnamelen) == 0) {
					if (optval == NULL) {
						ERR("missing parameter for option --ttl");
						return -1;
					}

					uint8_t ttl = 0x00;
					int j = 0;
					uint8_t digit;

					while (isdigit(optval[j])) {
						digit = (uint8_t)(optval[j] -
								  '0');

						// ttl * 10 + digit > MAX
						// <=> ttl * 10 > MAX - digit
						// <=> ttl > (MAX - digit) / 10
						if (ttl > (255 - digit) / 10) {
							ERR("value too big for option --ttl");
							return -1;
						}
						ttl = (uint8_t)(ttl * 10 +
								digit);
						j += 1;
					}

					if (j == 0 || optval[j] != '\0') {
						ERR("invalid value for option --ttl");
						return -1;
					}

					ping->flags.ttl = ttl;
					optoffset += 1;
				} else {
					ERR("unknown option '--%s'", optname);
					return -1;
				}

				if (!samearg) {
					i += optoffset;
				}

				continue;

_long_opt_argument_boolean:
				ERR("option '--%.*s' does not allow an argument",
				    (int)optnamelen, optname);
				return -1;
			} else {
				// short options
				for (int j = 1; argv[i][j] != '\0'; j += 1) {
					switch (argv[i][j]) {
					case 'f':
						ping->flags.flood = 1;
						break;
					case 'd':
						ping->flags.debug = 1;
						break;
					case 'v':
						ping->flags.verbose = 1;
						break;
					case 'q':
						ping->flags.quiet = 1;
						break;
					case 'r':
						ping->flags.no_route = 1;
						break;
					case 'V':
						ping->flags.version = 1;
						return 0;
					case '?':
						ping->flags.help = 1;
						return 0;
					default:
						ERR("unknown option -- '%c'",
						    argv[i][j]);
						return -1;
					}
				}
			}
		} else {
			if (ping->host == NULL) {
				ping->host = argv[i];
			} else {
				ERR("too many hosts");
				return -1;
			}
		}
	}

	if (ping->host == NULL) {
		ERR("missing host");
		return -1;
	}

	return 0;
}

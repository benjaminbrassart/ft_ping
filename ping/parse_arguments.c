/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parse_arguments.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bbrassar <bbrassar@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/04/14 15:17:59 by bbrassar          #+#    #+#             */
/*   Updated: 2024/04/27 15:23:00 by bbrassar         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ping.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_TTL ((uint8_t)64U)
#define DEFAULT_DATA_SIZE ((uint16_t)56)

static int _parse_ttl(char const *s, uint8_t *out_p)
{
	char const *it = s;
	uint8_t sum = 0;
	uint8_t digit;

	while (isdigit(*it)) {
		digit = (uint8_t)(*it - '0');
		if (sum > (255 - digit) / 10) {
			ERR("value too big for option --ttl");
			return -1;
		}
		sum = (uint8_t)(sum * 10 + digit);
		it++;
	}

	if (it == s || *it != '\0') {
		ERR("invalid value for option --ttl");
		return -1;
	}

	*out_p = sum;
	return 0;
}

static int _parse_data_size(char const *s, uint16_t *out_p)
{
	char const *it = s;
	uint16_t sum = 0;
	uint8_t digit;

	while (isdigit(*it)) {
		digit = (uint8_t)(*it - '0');

		if (sum > (65535 - digit) / 10) {
			ERR("value too big for option --size");
			return -1;
		}
		sum = (uint16_t)(sum * 10 + digit);
		it++;
	}

	if (it == s || *it != '\0') {
		ERR("invalid value for option --size");
		return -1;
	}

	*out_p = sum;
	return 0;
}

/*
static int _validate_padding(char const *s, uint16_t *size_p)
{
	size_t index = 0;
	uint16_t size = 0;

	while (isxdigit(s[index])) {
		if ((index % 2) == 0) {
			size += 1;
		}
		index += 1;
	}

	if (s[index] != '\0') {
		ERR("error in pattern near %s", &s[index]);
		return -1;
	}

	*size_p = size;
	return 0;
}
*/

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
	ping->flags.data_size = DEFAULT_DATA_SIZE;
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

					if (_parse_ttl(optval, &ttl) == -1) {
						return -1;
					}

					ping->flags.ttl = ttl;
					optoffset += 1;
				} else if (strncmp("size", optname,
						   optnamelen) == 0) {
					if (optval == NULL) {
						ERR("missing parameter for option --size");
						return -1;
					}

					uint16_t data_size;

					if (_parse_data_size(
						    optval, &data_size) == -1) {
						return -1;
					}

					ping->flags.data_size = data_size;
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
					char const *optval = NULL;
					int samearg = 0;

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
					case 's':
						if (argv[i][j + 1] != '\0') {
							optval =
								&argv[i][j + 1];
							samearg = 1;
						} else if (i < argc - 1) {
							optval = argv[i + 1];
						} else {
							ERR("missing parameter for option --size");
							return -1;
						}

						uint16_t data_size;

						if (_parse_data_size(
							    optval,
							    &data_size) == -1) {
							return -1;
						}

						ping->flags.data_size =
							data_size;
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

					if (optval != NULL) {
						if (!samearg) {
							i += 1;
						}
						break;
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

	if (ping->flags.data_size > 0) {
		ping->data_buffer = malloc((size_t)ping->flags.data_size);
		if (ping->data_buffer == NULL) {
			ERR("cannot allocate data buffer: %m");
			return -1;
		}

		for (uint16_t i = 0; i < ping->flags.data_size; i += 1) {
			ping->data_buffer[i] = (uint8_t)(i % 255);
		}
	} else {
		ping->data_buffer = NULL;
	}

	return 0;
}

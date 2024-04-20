/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parse_arguments.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bbrassar <bbrassar@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/04/14 15:17:59 by bbrassar          #+#    #+#             */
/*   Updated: 2024/04/20 16:06:36 by bbrassar         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ping.h"

#include <stdio.h>
#include <string.h>

#define DEFAULT_TTL ((uint8_t)64U)

int parse_arguments(struct ft_ping *ping, int argc, char const *argv[])
{
	ping->flags.quiet = 0;
	ping->flags.debug = 0;
	ping->flags.verbose = 0;
	ping->flags.flood = 0;
	ping->flags.help = 0;
	ping->flags.ttl = DEFAULT_TTL;
	ping->host = NULL;

	for (int i = 1; i < argc; i += 1) {
		if (argv[i][0] == '-' && argv[i][1] != '\0') {
			if (strcmp("-?", argv[i]) == 0) {
				ping->flags.help = 1;
				return 0;
			} else if (strcmp("-v", argv[i]) == 0) {
				ping->flags.verbose = 1;
			} else if (strcmp("-q", argv[i]) == 0) {
				ping->flags.quiet = 1;
			} else if (strcmp("-d", argv[i]) == 0) {
				ping->flags.debug = 1;
			} else if (strcmp("-f", argv[i]) == 0) {
				ping->flags.flood = 1;
			} else {
				ERR("unknown option '%s'", argv[i]);
				return -1;
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

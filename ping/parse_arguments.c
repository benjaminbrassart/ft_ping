/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   parse_arguments.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bbrassar <bbrassar@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/04/14 15:17:59 by bbrassar          #+#    #+#             */
/*   Updated: 2024/04/14 15:29:01 by bbrassar         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ping.h"

#include <stdio.h>
#include <string.h>

int parse_arguments(struct ft_ping *ping, int argc, char const *argv[])
{
	ping->flag_verbose = 0;
	ping->flag_help = 0;
	ping->host = NULL;

	for (int i = 1; i < argc; i += 1) {
		if (argv[i][0] == '-' && argv[i][1] != '\0') {
			if (strcmp("-v", argv[i]) == 0) {
				ping->flag_verbose = 1;
			} else if (strcmp("-?", argv[i]) == 0) {
				ping->flag_help = 1;
				return 0;
			} else {
				fprintf(stderr,
					"ft_ping: unknown option '%s'\n",
					argv[i]);
				return -1;
			}
		} else {
			if (ping->host == NULL) {
				ping->host = argv[i];
			} else {
				fprintf(stderr, "ft_ping: too many hosts\n");
				return -1;
			}
		}
	}

	if (ping->host == NULL) {
		fprintf(stderr, "ft_ping: missing host\n");
		return -1;
	}

	return 0;
}

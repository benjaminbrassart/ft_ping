/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bbrassar <bbrassar@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/04/14 15:03:37 by bbrassar          #+#    #+#             */
/*   Updated: 2024/04/14 15:29:32 by bbrassar         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ping.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char const *argv[])
{
	struct ft_ping ping;

	if (parse_arguments(&ping, argc, argv) == -1) {
		return EXIT_FAILURE;
	}

	if (ping.flag_help) {
		printf("Usage: ft_ping [-v] <host>\n");
		return EXIT_SUCCESS;
	}

	return EXIT_SUCCESS;
}

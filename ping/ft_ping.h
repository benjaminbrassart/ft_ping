/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_ping.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bbrassar <bbrassar@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/04/14 15:18:17 by bbrassar          #+#    #+#             */
/*   Updated: 2024/04/14 15:26:41 by bbrassar         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#pragma once

struct ft_ping {
	unsigned flag_verbose: 1;
	unsigned flag_help: 1;
	char const *host;
};

/**
 * Return 0 on success, -1 on failure
 */
int parse_arguments(struct ft_ping *ping, int argc, char const *argv[]);

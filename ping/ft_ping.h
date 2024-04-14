/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_ping.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bbrassar <bbrassar@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/04/14 15:18:17 by bbrassar          #+#    #+#             */
/*   Updated: 2024/04/14 16:20:05 by bbrassar         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#pragma once

#include <stdint.h>

#include <netinet/in.h>

#define ERR(Format, ...) \
	(fprintf(stderr, "ft_ping: " Format "\n", ##__VA_ARGS__))

struct ft_ping {
	unsigned flag_verbose : 1;
	unsigned flag_help : 1;
	char const *host;
	struct sockaddr_in addr;
	char saddr[INET_ADDRSTRLEN];
};

/**
 * Return 0 on success, -1 on failure
 */
int parse_arguments(struct ft_ping *ping, int argc, char const *argv[]);

/**
 * Return 0 on success, -1 on failure
 */
int resolve_hostname(struct ft_ping *ping);

/**
 * Return a valid socket file descriptor on success, -1 on failure
 */
int create_socket(uint8_t ttl);

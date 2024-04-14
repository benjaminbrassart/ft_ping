/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   resolve_hostname.c                                 :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bbrassar <bbrassar@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/04/14 15:44:28 by bbrassar          #+#    #+#             */
/*   Updated: 2024/04/14 16:17:54 by bbrassar         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ping.h"

#include <stdio.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>

int resolve_hostname(struct ft_ping *ping)
{
	struct addrinfo const hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_RAW,
		.ai_protocol = IPPROTO_ICMP,
	};
	struct addrinfo *result;
	int err;

	err = getaddrinfo(ping->host, NULL, &hints, &result);
	if (err != 0) {
		ERR("cannot resolve '%s': %s", ping->host, gai_strerror(err));
		return -1;
	}

	ping->addr = *(struct sockaddr_in *)result->ai_addr;
	freeaddrinfo(result);
	inet_ntop(AF_INET, &ping->addr.sin_addr.s_addr, ping->saddr,
		  sizeof(ping->saddr));

	return 0;
}

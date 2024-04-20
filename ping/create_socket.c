/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   create_socket.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bbrassar <bbrassar@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/04/14 16:01:40 by bbrassar          #+#    #+#             */
/*   Updated: 2024/04/20 15:52:11 by bbrassar         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ping.h"

#include <stdio.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

int create_socket(struct ft_ping const *ping)
{
	static int const SOCKOPT_ON = 1;

	int fd;

	fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (fd == -1) {
		ERR("cannot create socket: %m");
		return -1;
	}

	if (setsockopt(fd, SOL_IP, IP_TTL, &ping->flags.ttl,
		       sizeof(ping->flags.ttl)) == -1) {
		ERR("cannot set ip option IP_TTL: %m");
		goto _close_socket;
	}

	if (ping->flags.debug &&
	    setsockopt(fd, SOL_SOCKET, SO_DEBUG, &SOCKOPT_ON,
		       sizeof(SOCKOPT_ON)) == -1) {
		ERR("cannot set socket option SO_DEBUG: %m");
		goto _close_socket;
	}

	return fd;

_close_socket:
	if (close(fd) == -1) {
		ERR("cannot close socket: %m");
	}
	return -1;
}

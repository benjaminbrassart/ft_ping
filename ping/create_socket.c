/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   create_socket.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bbrassar <bbrassar@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/04/14 16:01:40 by bbrassar          #+#    #+#             */
/*   Updated: 2024/04/14 16:24:03 by bbrassar         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ping.h"

#include <stdio.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

int create_socket(uint8_t ttl)
{
	int fd;

	fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (fd == -1) {
		ERR("cannot create socket: %m");
		return -1;
	}

	if (setsockopt(fd, SOL_IP, IP_TTL, &ttl, sizeof(ttl)) == -1) {
		ERR("cannot set socket option: %m");
		if (close(fd) == -1) {
			ERR("cannot close socket: %m");
		}
		return -1;
	}

	return fd;
}

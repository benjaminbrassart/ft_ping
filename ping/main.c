/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bbrassar <bbrassar@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/04/14 15:03:37 by bbrassar          #+#    #+#             */
/*   Updated: 2024/04/14 17:17:28 by bbrassar         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ping.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>

static int ft_ping(struct ft_ping const *ping, int fd);

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

	if (resolve_hostname(&ping) == -1) {
		return EXIT_FAILURE;
	}

	int fd;

	fd = create_socket(64);
	if (fd == -1) {
		return EXIT_FAILURE;
	}

	int result;

	result = ft_ping(&ping, fd);

	if (close(fd) == -1) {
		ERR("cannot close socket: %m");
		return EXIT_FAILURE;
	}

	return result == -1 ? EXIT_FAILURE : EXIT_SUCCESS;
}

static volatile sig_atomic_t _SEND = 1;
static volatile sig_atomic_t _RUN = 1;

static void _handle_sigint(int sig)
{
	(void)sig;
	_RUN = 0;
}

static void _handle_sigalrm(int sig)
{
	(void)sig;
	_SEND = 1;
}

static void _send_ping_packet(struct ft_ping const *ping, int fd)
{
	(void)ping;
	(void)fd;
}

static void _receive_ping_packet(struct ft_ping const *ping, int fd)
{
	(void)ping;
	(void)fd;
}

static int ft_ping(struct ft_ping const *ping, int fd)
{
	printf("PING %s (%s): %d data bytes", ping->host, ping->saddr, 56);
	if (ping->flag_verbose) {
		printf(", id 0x%1$04hx = %1$hu", (uint16_t)getpid());
	}
	printf("\n");

	signal(SIGINT, _handle_sigint);

	while (_RUN)
	{
		if (_SEND) {
			_SEND = 0;
			alarm(1U);
			signal(SIGALRM, _handle_sigalrm);
			_send_ping_packet(ping, fd);
		}
		_receive_ping_packet(ping, fd);
	}
	alarm(0U);

	return 0;
}

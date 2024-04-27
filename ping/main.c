/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bbrassar <bbrassar@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/04/14 15:03:37 by bbrassar          #+#    #+#             */
/*   Updated: 2024/04/27 15:23:33 by bbrassar         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ping.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>

struct packet_response {
	struct iphdr ip;
	struct icmphdr icmp;
	uint8_t data[sizeof(struct iphdr) + 64];
};

static int ft_ping(struct ft_ping *ping, int fd);

int main(int argc, char const *argv[])
{
	struct ft_ping ping = {};
	int result;

	if (parse_arguments(&ping, argc, argv) == -1) {
		result = -1;
		goto _return;
	}

	if (ping.flags.help) {
		printf("Usage: ft_ping [-v] <host>\n");
		result = 0;
		goto _free_arguments;
	}

	if (ping.flags.version) {
		printf("ft_ping version 1.0.0\n");
		printf("Copyright (C) 2024 Benjamin Brassart.\n");
		printf("License MIT <https://spdx.org/licenses/MIT.html>.\n");
		printf("This is free software: you are free to change and redistribute it.\n");
		printf("There is NO WARRANTY, to the extent permitted by law.\n");
		printf("\n");
		printf("Written by Benjamin Brassart.\n");
		result = 0;
		goto _free_arguments;
	}

	if (resolve_hostname(&ping) == -1) {
		result = -1;
		goto _free_arguments;
	}

	int fd;

	fd = create_socket(&ping);
	if (fd == -1) {
		result = -1;
		goto _free_arguments;
	}

	result = ft_ping(&ping, fd);

	if (close(fd) == -1) {
		ERR("cannot close socket: %m");
		result = -1;
	}

_free_arguments:
	free(ping.data_buffer);
	free(ping.flags.padding);

_return:
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

static double _timespec_diff(struct timespec const *t1,
			     struct timespec const *t2)
{
	double s1 = ((double)t1->tv_sec * 1e3) + ((double)t1->tv_nsec / 1e6);
	double s2 = ((double)t2->tv_sec * 1e3) + ((double)t2->tv_nsec / 1e6);

	if (s1 > s2) {
		return s1 - s2;
	} else {
		return s2 - s1;
	}
}

static int _send_ping_packet(struct ft_ping *ping, int fd)
{
	struct icmphdr icmp = {
		.type = ICMP_ECHO,
		.code = 0x00U,
		.checksum = 0x0000U,
		.un = {
			.echo = {
				.id = (uint16_t)getpid(),
				.sequence = ping->sequence,
			},
		},
	};

	struct iovec iovs[] = {
		{ &icmp, sizeof(icmp) },
		{ ping->data_buffer, (size_t)ping->flags.data_size },
	};
	size_t iovc = sizeof(iovs) / sizeof(iovs[0]);
	struct msghdr message = {
		.msg_iov = iovs,
		.msg_iovlen = iovc,
		.msg_name = &ping->addr,
		.msg_namelen = sizeof(ping->addr),
	};
	size_t bytec = 0;

	for (size_t i = 0; i < iovc; i += 1) {
		bytec += iovs[i].iov_len;
	}

	icmp.checksum = icmp_checksum(iovs, iovc, bytec);

	ssize_t rr;

	rr = sendmsg(fd, &message, MSG_DONTWAIT);
	if (rr == -1) {
		int err;

		err = errno;
		if (err != EWOULDBLOCK && err != EAGAIN) {
			ERR("sendto: %m");
			return -1;
		}

		return 0;
	}

	struct packet_list_node *node = calloc(1, sizeof(*node));

	if (node == NULL) {
		return -1;
	}

	clock_gettime(CLOCK_MONOTONIC, &node->send_time);
	node->seq = ping->sequence;

	if (ping->packets_sent.size == 0) {
		ping->packets_sent.first = node;
	} else {
		ping->packets_sent.last->next = node;
	}

	node->prev = ping->packets_sent.last;
	ping->packets_sent.last = node;
	ping->packets_sent.size += 1;

	ping->sequence += 1;
	return 0;
}

static int _receive_ping_packet(struct ft_ping *ping, int fd)
{
	struct packet_response response = {};
	struct iovec iov = {
		.iov_base = &response,
		.iov_len = sizeof(response),
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	ssize_t rr;

	rr = recvmsg(fd, &msg, MSG_DONTWAIT);
	if (rr == -1) {
		int err;

		err = errno;
		if (err != EWOULDBLOCK && err != EAGAIN) {
			ERR("recvmsg: %m");
			return -1;
		}

		return 0;
	}

	switch (response.icmp.type) {
	case ICMP_ECHOREPLY: {
		if (response.icmp.un.echo.id != (uint16_t)getpid()) {
			return 0;
		}

		uint16_t seq = response.icmp.un.echo.sequence;
		char src_ip[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, &response.ip.saddr, src_ip, sizeof(src_ip));

		struct packet_list_node *it = ping->packets_sent.first;

		while (it != NULL && it->seq != seq) {
			it = it->next;
		}

		if (it == NULL) {
			ERR("duplicate packet");
			// TODO packet seq was not found, what do we do here??
			return 0;
		}

		struct timespec recv_time;

		clock_gettime(CLOCK_MONOTONIC, &recv_time);

		double time_diff = _timespec_diff(&recv_time, &it->send_time);

		if (it->prev != NULL) {
			it->prev->next = it->next;
		}

		if (it->next != NULL) {
			it->next->prev = it->prev;
		}

		free(it);

		ping->packets_sent.size -= 1;

		if (ping->packets_sent.size == 0) {
			ping->packets_sent.first = NULL;
			ping->packets_sent.last = NULL;
		}

		if (ping->stats.recv_count == 0 ||
		    time_diff > ping->stats.time_max) {
			ping->stats.time_max = time_diff;
		}

		if (ping->stats.recv_count == 0 ||
		    time_diff < ping->stats.time_min) {
			ping->stats.time_min = time_diff;
		}

		ping->stats.time_sum += time_diff;
		ping->stats.time_sum_squared += (time_diff * time_diff);
		ping->stats.recv_count += 1;

		if (!ping->flags.quiet && !ping->flags.flood) {
			printf("%ld bytes from %s: icmp_seq=%hu ttl=%hhu time=%.3f ms\n",
			       rr - (ssize_t)sizeof(struct iphdr), src_ip,
			       response.icmp.un.echo.sequence, response.ip.ttl,
			       time_diff);
		}
		break;
	}
	case ICMP_ECHO:
		break;
	default: {
		struct iphdr const *origin_ip =
			(struct iphdr const *)&response.data[0];
		struct icmphdr const *origin_icmp =
			(struct icmphdr const *)(origin_ip + 1);

		if (origin_icmp->un.echo.id != (uint16_t)getpid()) {
			return 0;
		}

		char const *type_str = icmp_description(response.icmp.type,
							response.icmp.code);
		char src_ip[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, &response.ip.saddr, src_ip, sizeof(src_ip));

		printf("%ld bytes from %s: %s\n",
		       rr - (ssize_t)sizeof(struct iphdr), src_ip, type_str);
		if (ping->flags.verbose) {
			dump_header(&response.ip, &response.icmp,
				    response.data);
		}
		break;
	}
	}

	return 0;
}

static void _print_roundtrip(struct ft_ping const *ping)
{
	double time_avg = ping->stats.time_sum / (double)ping->stats.recv_count;
	double time_stddev = ft_sqrt(
		ping->stats.time_sum_squared / (double)ping->stats.recv_count -
			(time_avg * time_avg),
		0.0005);

	printf("round-trip min/avg/max/stddev = %.3f/%.3f/%.3f/%.3f ms\n",
	       ping->stats.time_min, ping->stats.time_max, time_avg,
	       time_stddev);
}

static void _print_stats(struct ft_ping const *ping)
{
	size_t transmit_count =
		ping->packets_sent.size + ping->stats.recv_count;
	size_t receive_count = ping->stats.recv_count;
	size_t packet_loss = 0;

	if (transmit_count != 0) {
		packet_loss = 100 - (receive_count / transmit_count) * 100;
	}

	printf("--- %s ping statistics ---\n", ping->host);
	printf("%lu packets transmitted, %lu packets received, %lu%% packet loss\n",
	       transmit_count, receive_count, packet_loss);
	if (receive_count != 0) {
		_print_roundtrip(ping);
	}
}

static void _packet_list_free(struct packet_list *list)
{
	struct packet_list_node *it;
	struct packet_list_node *next;

	it = list->first;
	while (it != NULL) {
		next = it->next;
		free(it);
		it = next;
	}
}

static int ft_ping(struct ft_ping *ping, int fd)
{
	int status = EXIT_SUCCESS;

	printf("PING %s (%s): %hu data bytes", ping->host, ping->saddr,
	       ping->flags.data_size);
	if (ping->flags.verbose) {
		printf(", id 0x%1$04hx = %1$hu", (uint16_t)getpid());
	}
	printf("\n");

	timer_t timer_id;

	if (!ping->flags.flood) {
		struct sigevent sev = {
			.sigev_notify = SIGEV_SIGNAL,
			.sigev_signo = SIGALRM,
		};

		if (timer_create(CLOCK_MONOTONIC, &sev, &timer_id) == -1) {
			return EXIT_FAILURE;
		}

		struct itimerspec const timer_conf = {
			.it_interval = {
				.tv_sec = 1,
				.tv_nsec = 0,
			},
			.it_value = {
				.tv_sec = 1,
				.tv_nsec = 0,
			},
		};

		if (timer_settime(timer_id, 0, &timer_conf, NULL) == -1) {
			status = EXIT_FAILURE;
			goto _delete_timer;
		}

		struct sigaction sa = {};

		sa.sa_flags = 0;
		sa.sa_restorer = NULL;
		sigemptyset(&sa.sa_mask);

		sa.sa_handler = _handle_sigalrm;
		sigaction(SIGALRM, &sa, NULL);
	}

	struct sigaction sa = {};

	sa.sa_flags = 0;
	sa.sa_restorer = NULL;
	sigemptyset(&sa.sa_mask);

	sa.sa_handler = _handle_sigint;
	sigaction(SIGINT, &sa, NULL);

	while (_RUN) {
		if (ping->flags.flood || _SEND) {
			_SEND = 0;
			if (_send_ping_packet(ping, fd) == -1) {
				status = EXIT_FAILURE;
				goto _cleanup;
			}
		}
		if (_receive_ping_packet(ping, fd) == -1) {
			status = EXIT_FAILURE;
			goto _cleanup;
		}
	}

	_print_stats(ping);

_cleanup:
	_packet_list_free(&ping->packets_sent);

_delete_timer:
	if (!ping->flags.flood) {
		timer_delete(timer_id);
	}

	return status;
}

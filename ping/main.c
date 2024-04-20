/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bbrassar <bbrassar@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/04/14 15:03:37 by bbrassar          #+#    #+#             */
/*   Updated: 2024/04/20 18:54:26 by bbrassar         ###   ########.fr       */
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

struct icmp_packet {
	struct icmphdr hdr;
	uint8_t data[64 - sizeof(struct icmphdr)];
};

static int ft_ping(struct ft_ping *ping, int fd);

int main(int argc, char const *argv[])
{
	struct ft_ping ping = {};

	if (parse_arguments(&ping, argc, argv) == -1) {
		return EXIT_FAILURE;
	}

	if (ping.flags.help) {
		printf("Usage: ft_ping [-v] <host>\n");
		return EXIT_SUCCESS;
	}

	if (resolve_hostname(&ping) == -1) {
		return EXIT_FAILURE;
	}

	int fd;

	fd = create_socket(&ping);
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
	static uint16_t seq = 0;
	/* struct icmp_packet packet; */

	static uint8_t PAYLOAD[56] = {};

	for (uint8_t i = 0; i < sizeof(PAYLOAD); i += 1) {
		PAYLOAD[i] = i % 256;
	}

	struct icmphdr icmp = {
		.type = ICMP_ECHO,
		.code = 0,
		.checksum = 0,
		.un = {
			.echo = {
				.id = (uint16_t)getpid(),
				.sequence = seq,
			},
		},
	};
	struct iovec iov[] = {
		{ &icmp, sizeof(icmp) },
		{ &PAYLOAD[0], sizeof(PAYLOAD) },
	};
	struct msghdr msg = {
		.msg_iov = iov,
		.msg_iovlen = sizeof(iov) / sizeof(iov[0]),
		.msg_name = &ping->addr,
		.msg_namelen = sizeof(ping->addr),
	};

	/* packet.hdr.type = ICMP_ECHO; */
	/* packet.hdr.code = 0x00U; */
	/* packet.hdr.checksum = 0x0000U; */
	/* packet.hdr.un.echo.id = (uint16_t)getpid(); */
	/* packet.hdr.un.echo.sequence = seq; */

	icmp.checksum = icmp_checksum(msg.msg_iov, msg.msg_iovlen);

	ssize_t rr;

	rr = sendmsg(fd, &msg, MSG_DONTWAIT);
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
	node->seq = seq;

	if (ping->packets_sent.size == 0) {
		ping->packets_sent.first = node;
	} else {
		ping->packets_sent.last->next = node;
	}

	node->prev = ping->packets_sent.last;
	ping->packets_sent.last = node;
	ping->packets_sent.size += 1;

	seq += 1;
	return 0;
}

static int _receive_ping_packet(struct ft_ping *ping, int fd)
{
	struct iphdr ip;
	struct icmphdr icmp;
	uint8_t payload[sizeof(struct iphdr) + 64];
	struct iovec iov[] = {
		{ &ip, sizeof(ip) },
		{ &icmp, sizeof(icmp) },
		{ &payload, sizeof(payload) },
	};
	struct msghdr msg = {
		.msg_iov = iov,
		.msg_iovlen = sizeof(iov) / sizeof(iov[0]),
	};
	ssize_t rr;

	rr = recvmsg(fd, &msg, MSG_DONTWAIT | MSG_TRUNC);
	if (rr == -1) {
		int err;

		err = errno;
		if (err != EWOULDBLOCK && err != EAGAIN) {
			ERR("recvmsg: %m");
			return -1;
		}

		return 0;
	}

	if ((size_t)rr < (iov[0].iov_len + iov[1].iov_len)) {
		fprintf(stderr, "packet too small\n");
		return 0;
	}

	size_t total_length = 0;
	for (size_t i = 0; i < msg.msg_iovlen; i += 1) {
		total_length += msg.msg_iov[i].iov_len;
	}

	if ((size_t)rr > total_length) {
		fprintf(stderr, "packet too big\n");
	}

	if (icmp.type == ICMP_ECHO) {
		return 0;
	}

	char src_ip[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &ip.saddr, src_ip, sizeof(src_ip));

	switch (icmp.type) {
	case ICMP_ECHOREPLY: {
		if (icmp.un.echo.id != (uint16_t)getpid()) {
			return 0;
		}

		uint16_t seq = icmp.un.echo.sequence;

		uint16_t expected_checksum =
			icmp_checksum(&msg.msg_iov[1], msg.msg_iovlen - 1);

		if (expected_checksum != icmp.checksum) {
			fprintf(stderr,
				"checksum mismatch for %s (expected 0x%04hx, got 0x%04hx)\n",
				src_ip, expected_checksum, icmp.checksum);
		}

		struct packet_list_node *it = ping->packets_sent.first;

		while (it != NULL && it->seq != seq) {
			it = it->next;
		}

		if (it == NULL) {
			ping->stats.dup_count += 1;
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
			       icmp.un.echo.sequence, ip.ttl, time_diff);
		}
		break;
	}
	default: {
		struct iphdr const *origin_ip =
			(struct iphdr const *)&payload[0];
		struct icmphdr const *origin_icmp =
			(struct icmphdr const *)(origin_ip + 1);

		if (origin_icmp->un.echo.id != (uint16_t)getpid()) {
			return 0;
		}

		char const *type_str = icmp_description(icmp.type, icmp.code);
		char src_ip[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, &ip.saddr, src_ip, sizeof(src_ip));

		printf("%ld bytes from %s: %s\n",
		       rr - (ssize_t)sizeof(struct iphdr), src_ip, type_str);
		if (ping->flags.verbose) {
			dump_header(&ip, &icmp, payload);
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
	printf("%zu packets transmitted, ", transmit_count);
	printf("%zu packets received, ", receive_count);
	if (ping->stats.dup_count != 0) {
		printf("%zu duplicates, ", receive_count);
	}
	printf("%zu%% packet loss\n", packet_loss);
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

	printf("PING %s (%s): %d data bytes", ping->host, ping->saddr, 56);
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

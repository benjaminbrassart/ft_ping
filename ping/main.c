/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bbrassar <bbrassar@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/04/14 15:03:37 by bbrassar          #+#    #+#             */
/*   Updated: 2024/04/19 13:24:36 by bbrassar         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ping.h"

#include <errno.h>
#include <math.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>

#define DEFAULT_TTL ((uint8_t)64U)

struct icmp_packet {
	struct icmphdr hdr;
	uint8_t data[64 - sizeof(struct icmphdr)];
};

struct packet_response {
	struct iphdr ip;
	struct icmphdr icmp;
	uint8_t data[128];
};

static int ft_ping(struct ft_ping *ping, int fd);

int main(int argc, char const *argv[])
{
	struct ft_ping ping = {};

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

	fd = create_socket(DEFAULT_TTL);
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
	struct icmp_packet packet;

	packet.hdr.type = ICMP_ECHO;
	packet.hdr.code = 0x00U;
	packet.hdr.checksum = 0x0000U;
	packet.hdr.un.echo.id = (uint16_t)getpid();
	packet.hdr.un.echo.sequence = seq;

	for (uint8_t i = 0; i < sizeof(packet.data); i += 1) {
		packet.data[i] = i;
	}

	packet.hdr.checksum = icmp_checksum(&packet, sizeof(packet));

	ssize_t rr;

	rr = sendto(fd, &packet, sizeof(packet), MSG_DONTWAIT,
		    (struct sockaddr const *)&ping->addr, sizeof(ping->addr));
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

	if (response.icmp.type == ICMP_ECHOREPLY) {
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
			// TODO packet seq was not found, what do we do here??
			return 0;
		}

		struct timespec recv_time;

		clock_gettime(CLOCK_MONOTONIC, &recv_time);

		double time_diff = _timespec_diff(&recv_time, &it->send_time);

		it->recv_delta = time_diff;

		// remove packet from sent list
		if (it->prev != NULL) {
			it->prev->next = it->next;
		}

		if (it->next != NULL) {
			it->next->prev = it->prev;
		}

		ping->packets_sent.size -= 1;

		if (ping->packets_sent.size == 0) {
			ping->packets_sent.first = NULL;
			ping->packets_sent.last = NULL;
		}

		// add packet to received list
		if (ping->packets_received.size == 0) {
			ping->packets_received.first = it;
		} else {
			ping->packets_received.last->next = it;
		}

		it->prev = ping->packets_received.last;
		ping->packets_received.last = it;
		ping->packets_received.size += 1;

		printf("%ld bytes from %s: icmp_seq=%hu ttl=%hhu time=%.3f ms\n",
		       rr - (ssize_t)sizeof(struct iphdr), src_ip,
		       response.icmp.un.echo.sequence, response.ip.ttl,
		       it->recv_delta);
	} else {
		char const *type_str;

		switch (response.icmp.type) {
		case ICMP_TIME_EXCEEDED:
			type_str = "Time to live exceeded";
			break;
		default:
			return -1;
		}

		char src_ip[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, &response.ip.saddr, src_ip, sizeof(src_ip));

		printf("%ld bytes from %s: %s\n",
		       rr - (ssize_t)sizeof(struct iphdr), src_ip, type_str);
		if (ping->flag_verbose) {
			dump_header(&response.ip, &response.icmp);
		}
	}

	return 0;
}

static void _print_roundtrip(struct ft_ping const *ping)
{
	double time_min;
	double time_max;
	double time_total = 0.0;
	double time_total_squared = 0.0;

	for (struct packet_list_node *it = ping->packets_received.first;
	     it != NULL; it = it->next) {
		double time_diff = it->recv_delta;

		if (it == ping->packets_received.first ||
		    time_diff < time_min) {
			time_min = time_diff;
		}

		if (it == ping->packets_received.first ||
		    time_diff > time_max) {
			time_max = time_diff;
		}

		time_total += time_diff;
		time_total_squared += (time_diff * time_diff);
	}

	double time_avg = time_total / (double)ping->packets_received.size;
	double time_stddev = ft_sqrt(
		time_total_squared / (double)ping->packets_received.size -
			(time_avg * time_avg),
		0.0005);

	printf("round-trip min/avg/max/stddev = %.3f/%.3f/%.3f/%.3f ms\n",
	       time_min, time_max, time_avg, time_stddev);
}

static void _print_stats(struct ft_ping const *ping)
{
	size_t transmit_count =
		ping->packets_sent.size + ping->packets_received.size;
	size_t receive_count = ping->packets_received.size;
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

	printf("PING %s (%s): %d data bytes", ping->host, ping->saddr, 56);
	if (ping->flag_verbose) {
		printf(", id 0x%1$04hx = %1$hu", (uint16_t)getpid());
	}
	printf("\n");

	signal(SIGINT, _handle_sigint);

	while (_RUN) {
		if (_SEND) {
			_SEND = 0;
			alarm(1U);
			signal(SIGALRM, _handle_sigalrm);
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
	alarm(0U);
	_packet_list_free(&ping->packets_received);
	_packet_list_free(&ping->packets_sent);

	return status;
}

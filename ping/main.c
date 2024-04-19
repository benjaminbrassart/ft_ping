/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bbrassar <bbrassar@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/04/14 15:03:37 by bbrassar          #+#    #+#             */
/*   Updated: 2024/04/19 10:07:49 by bbrassar         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ping.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

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

static uint16_t _icmp_checksum(void const *buffer, size_t len)
{
	uint16_t const *addr = buffer;
	uint32_t sum = 0;
	size_t count = len;

	while (count > 1) {
		sum += *addr;
		addr++;
		count -= 2;
	}

	if (count > 0) {
		sum += *(uint8_t const *)addr;
	}

	return (uint16_t) ~((sum & 0xffff) + (sum >> 16));
}

static void _send_ping_packet(struct ft_ping const *ping, int fd)
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

	packet.hdr.checksum = _icmp_checksum(&packet, sizeof(packet));

	ssize_t rr;

	rr = sendto(fd, &packet, sizeof(packet), MSG_DONTWAIT,
		    (struct sockaddr const *)&ping->addr, sizeof(ping->addr));
	if (rr == -1) {
		int err;

		err = errno;
		if (err != EWOULDBLOCK && err != EAGAIN) {
			// TODO handle real send error
		}

		return;
	}

	seq += 1;
}

static void _receive_ping_packet(struct ft_ping const *ping, int fd)
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
			// TODO handle real recv error
		}

		return;
	}

	if (response.icmp.type == ICMP_ECHOREPLY) {
		if (response.icmp.un.echo.id != (uint16_t)getpid()) {
			return;
		}

		char src_ip[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, &response.ip.saddr, src_ip, sizeof(src_ip));

		printf("%ld bytes from %s: icmp_seq=%hu ttl=%hhu time=%.3f ms\n",
		       rr, src_ip, response.icmp.un.echo.sequence,
		       response.ip.ttl, 0.000f);
	} else {
		char const *type_str;

		switch (response.icmp.type) {
		case ICMP_TIME_EXCEEDED:
			type_str = "Time to live exceeded";
			break;
		default:
			return;
		}

		char src_ip[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, &response.ip.saddr, src_ip, sizeof(src_ip));

		printf("%ld bytes from %s: %s\n",
		       rr - (ssize_t)sizeof(struct iphdr), src_ip, type_str);
		if (ping->flag_verbose) {
			dump_header(&response.ip, &response.icmp);
		}
	}
}

static int ft_ping(struct ft_ping const *ping, int fd)
{
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
			_send_ping_packet(ping, fd);
		}
		_receive_ping_packet(ping, fd);
	}
	alarm(0U);

	return 0;
}

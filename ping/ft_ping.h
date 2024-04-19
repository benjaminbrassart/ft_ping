/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_ping.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bbrassar <bbrassar@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/04/14 15:18:17 by bbrassar          #+#    #+#             */
/*   Updated: 2024/04/19 13:24:21 by bbrassar         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#pragma once

#include <stdint.h>
#include <time.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#define ERR(Format, ...) \
	(fprintf(stderr, "ft_ping: " Format "\n", ##__VA_ARGS__))

struct packet_list_node {
	struct packet_list_node *next;
	struct packet_list_node *prev;
	uint16_t seq;
	union {
		struct timespec send_time;
		double recv_delta;
	};
};

struct packet_list {
	struct packet_list_node *first;
	struct packet_list_node *last;
	size_t size;
};

struct ft_ping {
	unsigned flag_verbose : 1;
	unsigned flag_help : 1;
	char const *host;
	struct sockaddr_in addr;
	char saddr[INET_ADDRSTRLEN];
	struct packet_list packets_sent;
	struct packet_list packets_received;
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

/**
 * Dump an IPv4 header and an ICMP header to the standard output
 */
void dump_header(struct iphdr const *ip, struct icmphdr const *icmp);

/**
 * Return the ICMP checksum for a given buffer
 */
uint16_t icmp_checksum(void const *buffer, size_t len);

/**
 * Calculate the square root of a number using the Babylonian method
 */
double ft_sqrt(double n, double precision);

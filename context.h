/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   context.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bbrassar <bbrassar@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/05/18 12:16:22 by bbrassar          #+#    #+#             */
/*   Updated: 2025/05/21 17:02:23 by bbrassar         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#pragma once

#include "options.h"

#include <stddef.h>
#include <time.h>

#include <netinet/in.h>
#include <netinet/ip_icmp.h>

struct options;

struct ping_stats {
	size_t send_count;
	size_t recv_count;
	size_t dup_count;
	double time_min;
	double time_max;
	double time_sum;
	double time_sum_squared;
};

struct packet_list_node {
	struct packet_list_node *next;
	struct packet_list_node *prev;
	struct timespec sent_at;
	struct timespec received_at;
	unsigned received : 1;
	uint16_t seq;
};

struct packet_list {
	struct packet_list_node *begin;
	struct packet_list_node *end;
	size_t size;
};

struct ping_context {
	struct options const *opts;
	struct ping_stats stats;
	char const *hostname;
	struct packet_list packets;
	unsigned running : 1;
	int sock_fd;
	int epoll_fd;
	int timer_fd;
	int signal_fd;
	int timeout_fd;
	struct sockaddr_in addr;
	char addr_s[INET_ADDRSTRLEN];
	pid_t pid;
	uint16_t seq;
	size_t payload_size;
	uint8_t *payload;
};

int context_create(struct ping_context *ctx, struct options const *opts,
		   char const hostname[]);

void context_free(struct ping_context *ctx);

int context_execute(struct ping_context *ctx);

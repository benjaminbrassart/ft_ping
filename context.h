/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   context.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bbrassar <bbrassar@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/05/18 12:16:22 by bbrassar          #+#    #+#             */
/*   Updated: 2025/05/18 12:22:02 by bbrassar         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#pragma once

#include "options.h"

#include <netinet/in.h>
#include <stddef.h>

struct options;

struct ping_stats {
	size_t send_count;
	size_t recv_count;
	double time_min;
	double time_max;
	double time_sum;
	double time_sum_squared;
};

struct ping_context {
	struct options const *opts;
	char const *hostname;
	struct ping_stats stats;
	unsigned running : 1;
	int sock_fd;
	int epoll_fd;
	int timer_fd;
	int signal_fd;
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

/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bbrassar <bbrassar@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/05/14 13:35:57 by bbrassar          #+#    #+#             */
/*   Updated: 2025/05/18 12:22:11 by bbrassar         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "context.h"
#include "display.h"
#include "options.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

struct packet_info {
	char src[INET6_ADDRSTRLEN];
	uint8_t const *raw;
	size_t len;
};

int main(int argc, char const *argv[])
{
	struct options opts;
	int res;

	res = opts_parse(argc, argv, &opts);
	if (res != EXIT_SUCCESS) {
		return res;
	}

	if (opts.help) {
		opts_print_help();
		return EXIT_SUCCESS;
	}

	if (opts.hostname_count == 0) {
		ERR("missing host operand");
		return EXIT_FAILURE;
	}

	struct ping_context ctx;

	for (size_t i = 0; i < opts.hostname_count; i += 1) {
		res = context_create(&ctx, &opts, opts.hostnames[i]);
		if (res != EXIT_SUCCESS) {
			break;
		}

		res = context_execute(&ctx);
		context_free(&ctx);
		if (res != EXIT_SUCCESS) {
			break;
		}
	}

	return res;
}

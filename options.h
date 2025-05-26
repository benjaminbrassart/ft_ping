/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   options.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bbrassar <bbrassar@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/05/17 17:00:59 by bbrassar          #+#    #+#             */
/*   Updated: 2025/05/26 16:42:21 by bbrassar         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#define OPTIONAL(Ty)                  \
	struct {                      \
		unsigned present : 1; \
		Ty value;             \
	}

#define DEFAULT_PAYLOAD_SIZE 56
#define MAX_PAYLOAD_SIZE 65399

struct options {
	OPTIONAL(size_t) count;
	unsigned debug : 1;
	unsigned help : 1;
	OPTIONAL(struct timespec) interval;
	OPTIONAL(struct timespec) timeout;
	OPTIONAL(struct timespec) linger;
	char const *pattern;
	unsigned quiet : 1;
	unsigned routing_ignore : 1;
	OPTIONAL(size_t) size;
	OPTIONAL(uint8_t) ttl;
	OPTIONAL(uint8_t) tos;
	unsigned verbose : 1;
	char const **hostnames;
	size_t hostname_count;
};

int opts_parse(int argc, char const *argv[], struct options *opt_out);

void opts_print_help(void);

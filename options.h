/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   options.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bbrassar <bbrassar@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/05/17 17:00:59 by bbrassar          #+#    #+#             */
/*   Updated: 2025/05/17 17:34:44 by bbrassar         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <time.h>

struct options {
	uint8_t ttl;
	size_t count;
	unsigned debug : 1;
	unsigned help : 1;
	struct timespec interval;
	struct timespec linger;
	char const *pattern;
	unsigned quiet : 1;
	unsigned routing_ignore : 1;
	size_t size;
	unsigned verbose : 1;
	char const *hostname;
};

int opts_parse(int argc, char const *argv[], struct options *opt_out);

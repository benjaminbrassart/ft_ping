/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bbrassar <bbrassar@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/05/14 13:35:57 by bbrassar          #+#    #+#             */
/*   Updated: 2025/05/18 12:24:35 by bbrassar         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "context.h"
#include "display.h"
#include "options.h"

#include <stdlib.h>

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
	unsigned running = 1;

	for (size_t i = 0; i < opts.hostname_count; i += 1) {
		res = context_create(&ctx, &opts, opts.hostnames[i]);
		if (res != EXIT_SUCCESS) {
			break;
		}

		ctx.running = running;
		res = context_execute(&ctx);
		running = ctx.running;

		context_free(&ctx);
		if (res != EXIT_SUCCESS) {
			break;
		}
	}

	return res;
}

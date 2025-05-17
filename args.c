/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   args.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bbrassar <bbrassar@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/05/14 13:46:05 by bbrassar          #+#    #+#             */
/*   Updated: 2025/05/17 19:48:39 by bbrassar         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "args.h"

#include <stddef.h>

void argit_init(struct arg_iterator *it, int argc, char const *argv[])
{
	it->args = argv;
	it->index = 0;
	it->length = argc;
}

void argit_shift(struct arg_iterator *it)
{
	// include terminating NULL
	for (int i = it->index; i < it->length; i += 1) {
		it->args[i] = it->args[i + 1];
	}
	it->length -= 1;
}

char const *argit_next(struct arg_iterator *it)
{
	char const *arg = argit_peek(it);

	argit_advance(it);
	return arg;
}

char const *argit_peek(struct arg_iterator *it)
{
	if (it->index >= it->length) {
		return NULL;
	}

	return it->args[it->index];
}

void argit_advance(struct arg_iterator *it)
{
	if (it->index >= it->length) {
		return;
	}

	it->index += 1;
}

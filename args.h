/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   args.h                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bbrassar <bbrassar@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/05/14 13:41:43 by bbrassar          #+#    #+#             */
/*   Updated: 2025/05/14 13:45:59 by bbrassar         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#pragma once

struct arg_iterator {
	char const **args;
	int index;
	int length;
};

void argit_init(struct arg_iterator *it, int argc, char const *argv[]);

char const *argit_next(struct arg_iterator *it);

char const *argit_peek(struct arg_iterator *it);

void argit_advance(struct arg_iterator *it);

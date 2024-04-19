/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_sqrt.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bbrassar <bbrassar@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/04/19 13:18:25 by bbrassar          #+#    #+#             */
/*   Updated: 2024/04/19 13:23:30 by bbrassar         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ping.h"

static inline double _abs(double n)
{
	return n < 0.0 ? -n : n;
}

double ft_sqrt(double n, double precision)
{
	if (n < 0.0) {
		return 0.0;
	}

	double x = n;
	double y = 1.0;

	while (_abs(x - y) / _abs(x) > precision) {
		x = (x + y) / 2.0;
		y = n / x;
	}

	return x;
}

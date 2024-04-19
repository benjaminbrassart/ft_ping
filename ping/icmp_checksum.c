/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   icmp_checksum.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bbrassar <bbrassar@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/04/19 10:09:15 by bbrassar          #+#    #+#             */
/*   Updated: 2024/04/19 10:12:29 by bbrassar         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ping.h"

#include <stdint.h>

uint16_t icmp_checksum(void const *buffer, size_t len)
{
	uint16_t const *addr = buffer;
	uint32_t sum = 0;
	size_t count = len;

	while (count > 1) {
		sum += *addr;
		addr++;
		count -= 2;
	}

	if (count > 0) {
		sum += *(uint8_t const *)addr;
	}

	return (uint16_t) ~((sum & 0xffff) + (sum >> 16));
}

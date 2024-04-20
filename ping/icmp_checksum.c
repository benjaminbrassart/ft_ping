/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   icmp_checksum.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bbrassar <bbrassar@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/04/19 10:09:15 by bbrassar          #+#    #+#             */
/*   Updated: 2024/04/20 18:51:53 by bbrassar         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ping.h"

#include <stdint.h>

uint16_t icmp_checksum(struct iovec const *iovs, size_t iovc, size_t bytec)
{
	uint32_t sum = 0;
	int has_leftover = 0;
	uint8_t leftover;

	for (size_t i = 0; i < iovc; i += 1) {
		struct iovec const *iov = &iovs[i];
		uint16_t const *addr = iov->iov_base;
		size_t count = iov->iov_len;

		if (has_leftover && count > 0 && count <= bytec) {
			uint8_t const *byte_addr = (uint8_t const *)addr;

			sum += (uint16_t)((leftover << 8) | *byte_addr);
			addr = (uint16_t const *)(((uint8_t const *)addr) + 1);
			count -= 1;
			bytec -= 1;
			has_leftover = 0;
		}

		while (count > 1 && count <= bytec) {
			sum += *addr;
			addr++;
			count -= 2;
			bytec -= 2;
		}

		if (count > 0) {
			has_leftover = 1;
			leftover = *(uint8_t const *)addr;
		} else {
			has_leftover = 0;
		}
	}

	if (has_leftover && bytec > 0) {
		sum += leftover;
	}

	return (uint16_t) ~((sum & 0xffff) + (sum >> 16));
}

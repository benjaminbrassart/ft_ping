/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   icmp_checksum.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bbrassar <bbrassar@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/04/19 10:09:15 by bbrassar          #+#    #+#             */
/*   Updated: 2024/04/27 14:52:49 by bbrassar         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ping.h"

#include <stdint.h>

void icmp_checksum_init(struct icmp_checksum *chk)
{
	chk->has_leftover = 0;
	chk->leftover = 0x00U;
	chk->sum = 0x00000000U;
}

void icmp_checksum_update(struct icmp_checksum *chk, void const *buffer,
			  size_t len)
{
	if (len == 0) {
		return;
	}

	uint16_t const *addr = buffer;
	size_t count = len;

	if (chk->has_leftover) {
		uint8_t const *byte_addr = (uint8_t const *)addr;

		chk->sum = (uint16_t)((chk->leftover << 8) | *byte_addr);
		// TODO probably an error on big endian systems
		addr = (uint16_t const *)(byte_addr + 1);
		chk->has_leftover = 0;
		count -= 1;
	}

	while (count > 1) {
		chk->sum += *addr;
		addr++;
		count -= 2;
	}

	if (count > 0) {
		chk->has_leftover = 1;
		chk->leftover = *(uint8_t const *)addr;
	} else {
		chk->has_leftover = 0;
		chk->leftover = 0x00U;
	}
}

uint16_t icmp_checksum_digest(struct icmp_checksum *chk)
{
	if (chk->has_leftover) {
		chk->sum += chk->leftover;
	}

	return (uint16_t) ~((chk->sum & 0xffff) + (chk->sum >> 16));
}

uint16_t icmp_checksum(struct iovec const *iovs, size_t iovc, size_t len)
{
	struct icmp_checksum chk;
	struct iovec const *iov;
	size_t count = len;
	size_t n;
	size_t i = 0;

	icmp_checksum_init(&chk);
	while (i < iovc && count > 0) {
		iov = &iovs[i];
		n = iov->iov_len;

		if (n > count) {
			n = count;
		}

		count -= n;
		icmp_checksum_update(&chk, iov->iov_base, n);
		i += 1;
	}
	return icmp_checksum_digest(&chk);
}

/* uint16_t icmp_checksum(void const *buffer, size_t len) */
/* { */
/* 	uint16_t const *addr = buffer; */
/* 	uint32_t sum = 0; */
/* 	size_t count = len; */

/* 	while (count > 1) { */
/* 		sum += *addr; */
/* 		addr++; */
/* 		count -= 2; */
/* 	} */

/* 	if (count > 0) { */
/* 		sum += *(uint8_t const *)addr; */
/* 	} */

/* 	return (uint16_t) ~((sum & 0xffff) + (sum >> 16)); */
/* } */

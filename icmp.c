/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   icmp.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bbrassar <bbrassar@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/05/18 12:11:15 by bbrassar          #+#    #+#             */
/*   Updated: 2025/05/26 16:35:56 by bbrassar         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "icmp.h"

#include <stddef.h>
#include <stdint.h>

#include <netinet/ip_icmp.h>

uint16_t compute_icmp_checksum(struct iovec const iovs[], size_t iovs_len)
{
	uint32_t sum = 0;

	for (size_t i = 0; i < iovs_len; i++) {
		struct iovec const *iov = &iovs[i];
		uint8_t const *data = iov->iov_base;
		size_t len = iov->iov_len;

		/* Sum up all 16-bit words */
		while (len > 1) {
			sum += (uint16_t)((data[0] << 8) | data[1]);
			data += 2;
			len -= 2;
		}

		/* If there's a trailing byte, pad with zero */
		if (len == 1) {
			sum += (uint16_t)(data[0] << 8);
		}
	}

	/* Fold 32-bit sum to 16 bits */
	while (sum >> 16) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}

	/* One's complement and return */
	return htons((uint16_t)~sum);
}

char const *icmp_code_tostring(uint8_t type, uint8_t code)
{
	switch (type) {
	case ICMP_DEST_UNREACH:
		switch (code) {
		case ICMP_NET_UNREACH:
			return "Network unreachable";
		case ICMP_HOST_UNREACH:
			return "Host unreachable";
		case ICMP_PROT_UNREACH:
			return "Protocol unreachable";
		case ICMP_PORT_UNREACH:
			return "Port unreachable";
		case ICMP_FRAG_NEEDED:
			return "Fragmentation needed";
		case ICMP_SR_FAILED:
			return "Source Route failed";
		case ICMP_NET_UNKNOWN:
			return "Network unknown";
		case ICMP_HOST_UNKNOWN:
			return "Host unknown";
		case ICMP_HOST_ISOLATED:
			return "Host isolated";
		case ICMP_NET_ANO:
			return "Network anonymous";
		case ICMP_HOST_ANO:
			return "Host anonymous";
		case ICMP_NET_UNR_TOS:
			return "Network unreachable for TOS";
		case ICMP_HOST_UNR_TOS:
			return "Host unreachable for TOS";
		case ICMP_PKT_FILTERED:
			return "Packet filtered";
		case ICMP_PREC_VIOLATION:
			return "Host precedence violation";
		case ICMP_PREC_CUTOFF:
			return "Precedence cutoff in effect";
		default:
			return NULL;
		}

	case ICMP_SOURCE_QUENCH:
		return "Source quench";

	case ICMP_REDIRECT:
		switch (code) {
		case ICMP_REDIRECT_NET:
			return "Redirect Network";
		case ICMP_REDIRECT_HOST:
			return "Redirect Host";
		case ICMP_REDIRECT_TOSNET:
			return "Redirect Type of Service and Network";
		case ICMP_REDIRECT_TOSHOST:
			return "Redirect Type of Service and Host";
		default:
			return NULL;
		}

	case ICMP_TIME_EXCEEDED:
		switch (code) {
		case ICMP_EXC_TTL:
			return "Time to live exceeded";
		case ICMP_EXC_FRAGTIME:
			return "Frag reassembly time exceeded";
		default:
			return NULL;
		}

	case ICMP_PARAMETERPROB:
		return "Parameter problem";

	default:
		return NULL;
	}
}

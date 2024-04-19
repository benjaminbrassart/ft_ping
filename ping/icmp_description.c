/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   icmp_description.c                                 :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bbrassar <bbrassar@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/04/19 13:32:35 by bbrassar          #+#    #+#             */
/*   Updated: 2024/04/19 13:47:33 by bbrassar         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ping.h"

#include <stdint.h>

#include <netinet/ip_icmp.h>

#define D(type, code) ((((type) << 4) & 0xf0) | ((code) & 0x0f))

char const *icmp_description(uint8_t type, uint8_t code)
{
	switch (D(type, code)) {
	case D(ICMP_DEST_UNREACH, ICMP_NET_UNREACH):
		return "Destination network unreachable";
	case D(ICMP_DEST_UNREACH, ICMP_HOST_UNREACH):
		return "Destination host unreachable";
	case D(ICMP_DEST_UNREACH, ICMP_PROT_UNREACH):
		return "Destination protocol unreachable";
	case D(ICMP_DEST_UNREACH, ICMP_PORT_UNREACH):
		return "Destination port unreachable";
	case D(ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED):
		return "Fragmentation needed";
	case D(ICMP_DEST_UNREACH, ICMP_SR_FAILED):
		return "Source route failed";
	case D(ICMP_DEST_UNREACH, ICMP_NET_UNKNOWN):
		return "Network unknown";
	case D(ICMP_DEST_UNREACH, ICMP_HOST_UNKNOWN):
		return "Host unknown";
	case D(ICMP_DEST_UNREACH, ICMP_HOST_ISOLATED):
		return "Host isolated";
	case D(ICMP_DEST_UNREACH, ICMP_NET_UNR_TOS):
		return "Destination network unreachable for TOS";
	case D(ICMP_DEST_UNREACH, ICMP_HOST_UNR_TOS):
		return "Destination host unreachable for TOS";
	case D(ICMP_DEST_UNREACH, ICMP_PKT_FILTERED):
		return "Packet filtered";
	case D(ICMP_DEST_UNREACH, ICMP_PREC_VIOLATION):
		return "Precedence violation";
	case D(ICMP_DEST_UNREACH, ICMP_PREC_CUTOFF):
		return "Precedence cutoff";

	case D(ICMP_REDIRECT, ICMP_REDIR_NET):
		return "Redirect network";
	case D(ICMP_REDIRECT, ICMP_REDIR_HOST):
		return "Redirect host";
	case D(ICMP_REDIRECT, ICMP_REDIR_NETTOS):
		return "Redirect TOS and network";
	case D(ICMP_REDIRECT, ICMP_REDIR_HOSTTOS):
		return "Redirect TOS and host";

	case D(ICMP_TIME_EXCEEDED, ICMP_EXC_TTL):
		return "Time to live exceeded";
	case D(ICMP_TIME_EXCEEDED, ICMP_EXC_FRAGTIME):
		return "Frag reassembly time exceeded";

	default:
		return "Unknown";
	}
}

#undef D

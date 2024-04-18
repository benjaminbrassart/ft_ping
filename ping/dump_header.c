/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   dump_header.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bbrassar <bbrassar@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2024/04/18 20:58:19 by bbrassar          #+#    #+#             */
/*   Updated: 2024/04/18 22:21:13 by bbrassar         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ft_ping.h"

#include <stdint.h>
#include <stdio.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

static void _ip_header_hexdump(struct iphdr const *ip)
{
	uint8_t const *byte = (uint8_t const *)ip;
	size_t len = sizeof(*ip);

	printf("IP Hdr Dump:\n");

	while (len > 1) {
		printf(" %04x", *(uint16_t const *)&byte[len]);
		len -= 2;
	}

	if (len == 1) {
		printf(" %02x", byte[sizeof(*ip) - 1]);
	}

	printf("\n");
}

static void _ip_header_dump(struct iphdr const *ip)
{
	uint16_t total_length = ip->tot_len;

	if (total_length > 0x2000) {
		total_length = ntohs(total_length);
	}

	uint16_t flags = ntohs(ip->frag_off & 0xe000) >> 13;
	uint16_t fragmentation_offset = ntohs(ip->frag_off) & 0x1fff;

	char src[INET_ADDRSTRLEN];
	char dst[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &ip->saddr, src, sizeof(src));
	inet_ntop(AF_INET, &ip->daddr, dst, sizeof(dst));

	printf("Vr HL TOS  Len   ID Flg  off TTL Pro  cks      Src\tDst\tData\n");
	printf(" %1x  %1x  %02x %04x %04x   %1x %04x  %02x  %02x %04x %s %s\n",
	       ip->version, ip->ihl, ip->tos, total_length, ip->id, flags,
	       fragmentation_offset, ip->ttl, ip->protocol, ntohs(ip->check),
	       src, dst);
}

void dump_header(struct iphdr const *ip, struct icmphdr const *icmp)
{
	uint16_t id = 0x0000; // TODO
	uint16_t seq = 0x0000; // TODO

	_ip_header_hexdump(ip);
	_ip_header_dump(ip);
	printf("ICMP: type %hhu, code %hhu, size %hu, id 0x%04hx, seq 0x%04hx\n",
	       icmp->type, icmp->code, ip->tot_len, id, seq);
}

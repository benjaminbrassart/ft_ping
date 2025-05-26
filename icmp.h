/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   icmp.h                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bbrassar <bbrassar@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/05/18 12:11:12 by bbrassar          #+#    #+#             */
/*   Updated: 2025/05/26 16:24:39 by bbrassar         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#pragma once

#include <stdint.h>

#include <netinet/ip_icmp.h>

uint16_t compute_icmp_checksum(struct iovec const iov[], size_t iov_len);
char const *icmp_code_tostring(uint8_t code, uint8_t type);

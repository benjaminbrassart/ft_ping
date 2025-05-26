/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   display.h                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bbrassar <bbrassar@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/05/17 17:04:11 by bbrassar          #+#    #+#             */
/*   Updated: 2025/05/26 16:45:09 by bbrassar         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#pragma once

#include <stdio.h> // IWYU pragma: keep

#define ERR(Fmt, ...) (fprintf(stderr, "ft_ping: " Fmt "\n", ##__VA_ARGS__))

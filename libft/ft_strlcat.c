/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strlcat.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bbrassar <bbrassar@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/05/21 16:43:20 by bbrassar          #+#    #+#             */
/*   Updated: 2025/05/21 16:44:05 by bbrassar         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stddef.h>
#include <string.h>

size_t ft_strlcat(char *dst, char const *src, size_t dstsize)
{
	size_t i;
	size_t j;

	i = 0;
	while (dst[i] != '\0' && i <= dstsize)
		i += 1;
	if (i >= dstsize)
		return (strlen(src) + dstsize);
	j = 0;
	while (src[j] != '\0' && i + j < dstsize - 1) {
		dst[i + j] = src[j];
		j += 1;
	}
	dst[i + j] = '\0';
	return (strlen(src) + i);
}

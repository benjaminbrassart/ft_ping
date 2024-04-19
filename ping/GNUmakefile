# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    GNUmakefile                                        :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: bbrassar <bbrassar@student.42.fr>          +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2024/04/14 15:01:33 by bbrassar          #+#    #+#              #
#    Updated: 2024/04/19 13:08:47 by bbrassar         ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

MAKEFILE := $(lastword $(MAKEFILE_LIST))
NAME := ft_ping

SRC := main.c parse_arguments.c resolve_hostname.c create_socket.c \
       dump_header.c icmp_checksum.c
OBJ := $(SRC:.c=.c.o)
DEP := $(OBJ:.o=.d)

$(NAME): $(OBJ)
	$(CC) $^ -o $@ -lm

$(OBJ): .EXTRA_PREREQS = $(MAKEFILE)
$(OBJ): %.c.o: %.c
	$(CC) -Wall -Werror -Wextra -Wconversion -MMD -MP -I. -std=c99 -D_POSIX_C_SOURCE=200112L $(CFLAGS) -c $< -o $@

-include $(DEP)

.PHONY: all clean fclean re

all: $(NAME)

clean:
	$(RM) $(OBJ) $(DEP)

fclean: clean
	$(RM) $(NAME)

re: fclean
	@$(MAKE) -f $(MAKEFILE) all

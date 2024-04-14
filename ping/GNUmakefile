# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    GNUmakefile                                        :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: bbrassar <bbrassar@student.42.fr>          +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2024/04/14 15:01:33 by bbrassar          #+#    #+#              #
#    Updated: 2024/04/14 15:28:29 by bbrassar         ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

MAKEFILE := $(lastword $(MAKEFILE_LIST))
NAME := ft_ping

SRC := main.c parse_arguments.c
OBJ := $(SRC:.c=.c.o)
DEP := $(OBJ:.o=.d)

$(NAME): $(OBJ)
	$(CC) $^ -o $@

$(OBJ): .EXTRA_PREREQS = $(MAKEFILE)
$(OBJ): %.c.o: %.c
	$(CC) -Wall -Werror -Wextra -Wconversion -MMD -MP -I. -std=c99 $(CFLAGS) -c $< -o $@

-include $(DEP)

.PHONY: all clean fclean re

all: $(NAME)

clean:
	$(RM) $(OBJ) $(DEP)

fclean:
	$(RM) $(NAME)

re: fclean
	@$(MAKE) -f $(MAKEFILE) all

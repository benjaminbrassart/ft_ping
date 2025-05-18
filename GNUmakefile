# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    GNUmakefile                                        :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: bbrassar <bbrassar@student.42.fr>          +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2025/05/14 13:29:12 by bbrassar          #+#    #+#              #
#    Updated: 2025/05/18 12:22:21 by bbrassar         ###   ########.fr        #
#                                                                              #
# **************************************************************************** #

override MAKEFILE := $(lastword $(MAKEFILE_LIST))

NAME := ft_ping

override SRC := main.c args.c options.c icmp.c context.c
override OBJ := $(SRC:%.c=%.c.o)
override DEP := $(OBJ:.o=.d)

override CFLAGS += -Wall -Wextra -c
override CPPFLAGS += -MMD -MP
override LDFLAGS ?=
override LDLIBS ?= -lm

$(NAME): $(OBJ)
	$(CC) $^ $(LDFLAGS) $(LDLIBS) -o $@

$(OBJ): .EXTRA_PREREQS = $(MAKEFILE)
$(OBJ): %.c.o: %.c
	$(CC) $< $(CFLAGS) $(CPPFLAGS) -o $@

-include $(DEP)

.PHONY: all clean fclean re

all: $(NAME)

clean:
	$(RM) $(OBJ) $(DEP)

fclean: clean
	$(RM) $(NAME)

re: fclean
	$(MAKE) -f $(MAKEFILE) all

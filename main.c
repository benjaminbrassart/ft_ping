/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bbrassar <bbrassar@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/05/14 13:35:57 by bbrassar          #+#    #+#             */
/*   Updated: 2025/05/15 16:28:39 by bbrassar         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#define ERR(Fmt, ...) (fprintf(stderr, "ft_ping: " Fmt "\n", ##__VA_ARGS__))

struct flags {
	unsigned verbose : 1;
	unsigned help : 1;
};

struct options {
	struct flags flags;
	char const *hostname;
};

struct ping_context {
	struct options const *opts;
	int sock;
	struct sockaddr_in addr;
	char addr_s[INET_ADDRSTRLEN];
};

static struct options const OPTS_DEFAULT = {
	.flags = {
		.help = 0,
		.verbose = 0,
	},
	.hostname = NULL,
};

static int opts_parse(int argc, char *const argv[], struct options *opt_out)
{
	// TODO actually parse the arguments
	*opt_out = OPTS_DEFAULT;
	opt_out->hostname = "1.1.1.1";
	return EXIT_SUCCESS;
}

static int resolve_hostname(char const hostname[], struct sockaddr_in *addr)
{
	struct addrinfo const hint = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_RAW,
		.ai_protocol = IPPROTO_ICMP,
	};
	struct addrinfo *ret;
	int err;

	err = getaddrinfo(hostname, NULL, &hint, &ret);
	if (err != 0) {
		ERR("failed to resolve %s: %s", hostname, gai_strerror(err));
		return EXIT_FAILURE;
	}

	*addr = *(struct sockaddr_in *)ret->ai_addr;
	freeaddrinfo(ret);
	return EXIT_SUCCESS;
}

static int context_create(struct ping_context *ctx, struct options const *opts)
{
	int sock_fd = -1;
	int res = EXIT_FAILURE;

	do {
		sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
		if (sock_fd == -1) {
			ERR("failed to create socket: %m");
			break;
		}

		res = resolve_hostname(opts->hostname, &ctx->addr);
		if (res != EXIT_SUCCESS) {
			break;
		}

		inet_ntop(AF_INET, &ctx->addr.sin_addr.s_addr, ctx->addr_s,
			  INET_ADDRSTRLEN);

		ctx->opts = opts;
		return EXIT_SUCCESS;
	} while (0);

	if (sock_fd != -1) {
		close(sock_fd);
	}

	return res;
}

static void context_free(struct ping_context *ctx)
{
	close(ctx->sock);
}

static void print_init_message(struct ping_context *ctx)
{
	printf("PING %s (%s): %u data bytes\n", ctx->opts->hostname,
	       ctx->addr_s, 56);
}

static void print_summary(struct ping_context *ctx)
{
	printf("--- %s ping statistics ---\n", ctx->opts->hostname);
	printf("%u packets transmitted, %u packets received, %u%% packet loss\n",
	       0, 0, 100);
	printf("round-trip min/avg/max/stddev = %.3f/%.3f/%.3f/%.3f\n", 0.0,
	       0.0, 0.0, 0.0);
}

static int context_execute(struct ping_context *ctx)
{
	print_init_message(ctx);

	// TODO do make the actual loop

	print_summary(ctx);
	return EXIT_SUCCESS;
}

int main(int argc, char *const argv[])
{
	struct options opts;
	int res;

	res = opts_parse(argc, argv, &opts);
	if (res != EXIT_SUCCESS) {
		return res;
	}

	if (opts.flags.help) {
		// TODO print help
		return EXIT_SUCCESS;
	}

	struct ping_context ctx;

	res = context_create(&ctx, &opts);
	if (res != EXIT_SUCCESS) {
		return res;
	}

	res = context_execute(&ctx);

	context_free(&ctx);
	return res;
}

/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bbrassar <bbrassar@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/05/14 13:35:57 by bbrassar          #+#    #+#             */
/*   Updated: 2025/05/15 17:48:53 by bbrassar         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
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
	unsigned running : 1;
	int sock;
	int epoll;
	int sigfd;
	struct sockaddr_in addr;
	char addr_s[INET_ADDRSTRLEN];
	pid_t pid;
	uint16_t seq;
};

struct packet_info {
	char src[INET6_ADDRSTRLEN];
	uint8_t const *raw;
	size_t len;
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
	int epoll_fd = -1;
	int sock_fd = -1;
	int sig_fd = -1;
	int res = EXIT_FAILURE;

	sigset_t handled_signals;

	sigemptyset(&handled_signals);
	sigaddset(&handled_signals, SIGINT);

	do {
		epoll_fd = epoll_create1(EPOLL_CLOEXEC);
		if (epoll_fd == -1) {
			ERR("failed to create epoll: %m");
			break;
		}

		sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
		if (sock_fd == -1) {
			ERR("failed to create socket: %m");
			break;
		}

		struct epoll_event sock_event = {
			.events = EPOLLIN,
			.data = { .fd = sock_fd },
		};

		if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock_fd, &sock_event) ==
		    -1) {
			ERR("failed to poll socket: %m");
			break;
		}

		sig_fd = signalfd(-1, &handled_signals, SFD_CLOEXEC);
		if (sig_fd == -1) {
			ERR("failed to create signal fd: %m");
			break;
		}

		struct epoll_event sig_event = {
			.events = EPOLLIN,
			.data = { .fd = sig_fd },
		};

		if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sig_fd, &sig_event) ==
		    -1) {
			ERR("failed to poll signal fd: %m");
			break;
		}

		if (sigprocmask(SIG_BLOCK, &handled_signals, NULL) == -1) {
			ERR("failed to set signal mask: %m");
			break;
		}

		res = resolve_hostname(opts->hostname, &ctx->addr);
		if (res != EXIT_SUCCESS) {
			break;
		}

		inet_ntop(AF_INET, &ctx->addr.sin_addr.s_addr, ctx->addr_s,
			  INET_ADDRSTRLEN);

		ctx->opts = opts;
		ctx->running = 1;
		ctx->sock = sock_fd;
		ctx->sigfd = sig_fd;
		ctx->epoll = epoll_fd;
		ctx->pid = getpid();
		ctx->seq = 0;
		return EXIT_SUCCESS;
	} while (0);

	if (sock_fd != -1) {
		close(sock_fd);
	}

	if (epoll_fd != -1) {
		close(epoll_fd);
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

static uint8_t *recvfrom_peeked(int fd, size_t *len, struct sockaddr *addr,
				socklen_t *addr_len)
{
	uint8_t *rbuf = NULL;

	do {
		size_t rbuf_len;
		ssize_t rr;

		// MSG_PEEK: read without consuming the socket's queue
		// MSG_TRUNC: return the actual length of the incoming message
		rr = recv(fd, NULL, 0, MSG_PEEK | MSG_TRUNC);
		if (rr == -1) {
			return NULL;
		}

		rbuf_len = (size_t)rr;
		rbuf = malloc(rbuf_len);
		if (rbuf == NULL) {
			break;
		}

		rr = recvfrom(fd, rbuf, rbuf_len, 0, addr, addr_len);
		if (rr == -1) {
			break;
		}

		*len = rbuf_len;
		return rbuf;
	} while (0);

	free(rbuf);
	return NULL;
}

static uint16_t compute_icmp_checksum(struct msghdr const *msg)
{
	// TODO compute checksum
	return 0;
}

static int send_ping(struct ping_context *ctx)
{
	struct icmphdr icmp = {
		.type = ICMP_ECHO,
		.code = 0,
		.checksum = 0,
		.un = {
			.echo = {
				.id = (uint16_t)ctx->pid,
				.sequence = ctx->seq,
			},
		},
	};
	struct iovec iov[] = {
		{ &icmp, sizeof(icmp) },
	};
	struct msghdr msg = {
		.msg_iov = iov,
		.msg_iovlen = sizeof(iov) / sizeof(iov[0]),
		.msg_name = &ctx->addr,
		.msg_namelen = sizeof(ctx->addr),
	};

	icmp.checksum = compute_icmp_checksum(&msg);

	ssize_t sc;

	sc = sendmsg(ctx->sock, &msg, 0);
	if (sc == -1) {
		return EXIT_FAILURE;
	}

	ctx->seq += 1;
	return EXIT_SUCCESS;
}

static int handle_raw_packet(uint8_t const *raw, size_t len,
			     struct sockaddr_storage const *addr)
{
	void const *raw_addr;
	char addr_s[INET6_ADDRSTRLEN];

	switch (addr->ss_family) {
	case AF_INET:
		raw_addr = &((struct sockaddr_in *)&addr)->sin_addr.s_addr;
		break;
	case AF_INET6:
		raw_addr = &((struct sockaddr_in6 *)&addr)->sin6_addr;
		break;
	default: // what the fuck?
		return EXIT_FAILURE;
	}

	inet_ntop(addr->ss_family, raw_addr, addr_s, sizeof(addr_s));

	printf("%zu bytes from %s: icmp_seq=%u ttl=%u time=%.3f ms\n", len,
	       addr_s, 0, 0, 0.0);

	return EXIT_SUCCESS;
}

static int context_handle_socket(struct ping_context *ctx)
{
	size_t buf_len;
	uint8_t *buf;
	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);
	int res = EXIT_FAILURE;

	do {
		buf = recvfrom_peeked(ctx->sock, &buf_len,
				      (struct sockaddr *)&addr, &addr_len);
		if (buf == NULL) {
			break;
		}

		res = handle_raw_packet(buf, buf_len, &addr);
	} while (0);

	free(buf);
	return res;
}

static int context_handle_signal(struct ping_context *ctx)
{
	struct signalfd_siginfo siginfo;
	ssize_t rr;

	rr = read(ctx->sigfd, &siginfo, sizeof(siginfo));
	if (rr == -1) {
		return EXIT_FAILURE;
	}

	ctx->running = 0;
	return EXIT_SUCCESS;
}

static int context_handle_event(struct ping_context *ctx,
				struct epoll_event const *ev)
{
	if (ev->events & EPOLLERR) {
		return EXIT_FAILURE;
	}

	int fd = ev->data.fd;

	if (fd == ctx->sock) {
		return context_handle_socket(ctx);
	} else if (fd == ctx->sigfd) {
		return context_handle_signal(ctx);
	} else {
		ERR("unhandled file descriptor: %d", fd);
		return EXIT_FAILURE;
	}
}

static int context_execute(struct ping_context *ctx)
{
	int epr;
	struct epoll_event ev[2];
	int ec = sizeof(ev) / sizeof(ev[0]);
	int res = EXIT_SUCCESS;

	print_init_message(ctx);

	res = send_ping(ctx);
	if (res != EXIT_SUCCESS) {
		return EXIT_FAILURE;
	}

	while (ctx->running) {
		epr = epoll_wait(ctx->epoll, ev, ec, 0);
		if (epr == -1) {
			ERR("failed to poll: %m");
			return EXIT_FAILURE;
		}

		for (int i = 0; ctx->running && i < epr; i += 1) {
			res = context_handle_event(ctx, &ev[i]);
			if (res != EXIT_SUCCESS) {
				return res;
			}
		}
	}

	print_summary(ctx);
	return res;
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

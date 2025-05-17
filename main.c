/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.c                                             :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bbrassar <bbrassar@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/05/14 13:35:57 by bbrassar          #+#    #+#             */
/*   Updated: 2025/05/17 16:07:31 by bbrassar         ###   ########.fr       */
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
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

#define DBG(Fmt, ...) (fprintf(stderr, "[DEBUG]: " Fmt "\n", ##__VA_ARGS__))
#define ERR(Fmt, ...) (fprintf(stderr, "ft_ping: " Fmt "\n", ##__VA_ARGS__))

struct options {
	unsigned verbose : 1;
	unsigned help : 1;
	unsigned quiet : 1;
	uint8_t ttl;
	size_t payload_size;
	struct timespec interval;
	char const *hostname;
};

struct ping_stats {
	size_t send_count;
	size_t recv_count;
	double time_min;
	double time_max;
	double time_sum;
	double time_sum_squared;
};

struct ping_context {
	struct options const *opts;
	struct ping_stats stats;
	unsigned running : 1;
	int sock_fd;
	int epoll_fd;
	int timer_fd;
	int signal_fd;
	struct sockaddr_in addr;
	char addr_s[INET_ADDRSTRLEN];
	pid_t pid;
	uint16_t seq;
	size_t payload_size;
	uint8_t *payload;
};

struct packet_info {
	char src[INET6_ADDRSTRLEN];
	uint8_t const *raw;
	size_t len;
};

static struct options const OPTS_DEFAULT = {
	.help = 0,
	.verbose = 0,
	.quiet = 0,
	.payload_size = 56,
	.ttl = 0,
	.interval = {
		.tv_sec = 1,
		.tv_nsec = 0,
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
	uint8_t *payload = NULL;
	int epoll_fd = -1;
	int sock_fd = -1;
	int timer_fd = -1;
	int signal_fd = -1;
	int res = EXIT_FAILURE;

	sigset_t handled_signals;

	sigemptyset(&handled_signals);
	sigaddset(&handled_signals, SIGINT);

	do {
		payload = malloc(opts->payload_size);
		if (payload == NULL) {
			break;
		}

		for (size_t i = 0; i < opts->payload_size; i += 1) {
			payload[i] = (uint8_t)i;
		}

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

		if (opts->ttl != 0) {
			if (setsockopt(sock_fd, IPPROTO_IP, IP_TTL, &opts->ttl,
				       sizeof(opts->ttl)) == -1) {
				ERR("failed to set TTL: %m");
				break;
			}
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

		timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
		if (timer_fd == -1) {
			ERR("failed to create timer fd: %m");
			break;
		}

		struct itimerspec timer_spec = {
			.it_interval = opts->interval,
			.it_value = { .tv_sec = 0, .tv_nsec = 1 },
		};

		if (timerfd_settime(timer_fd, 0, &timer_spec, NULL) == -1) {
			ERR("failed to set timer interval: %m");
			break;
		}

		struct epoll_event timer_event = {
			.events = EPOLLIN,
			.data = { .fd = timer_fd },
		};

		if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, timer_fd,
			      &timer_event) == -1) {
			ERR("failed to poll timer fd: %m");
			break;
		}

		signal_fd = signalfd(-1, &handled_signals, SFD_CLOEXEC);
		if (signal_fd == -1) {
			ERR("failed to create signal fd: %m");
			break;
		}

		struct epoll_event sig_event = {
			.events = EPOLLIN,
			.data = { .fd = signal_fd },
		};

		if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, signal_fd, &sig_event) ==
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

		ctx->stats = (struct ping_stats){
			.recv_count = 0,
			.send_count = 0,
			.time_max = 0.0,
			.time_min = 0.0,
			.time_sum = 0.0,
			.time_sum_squared = 0.0,
		};
		ctx->opts = opts;
		ctx->running = 1;
		ctx->epoll_fd = epoll_fd;
		ctx->sock_fd = sock_fd;
		ctx->timer_fd = timer_fd;
		ctx->signal_fd = signal_fd;
		ctx->payload = payload;
		ctx->payload_size = opts->payload_size;
		ctx->pid = getpid();
		ctx->seq = 0;
		return EXIT_SUCCESS;
	} while (0);

	if (signal_fd != -1) {
		close(signal_fd);
	}

	if (timer_fd != -1) {
		close(timer_fd);
	}

	if (sock_fd != -1) {
		close(sock_fd);
	}

	if (epoll_fd != -1) {
		close(epoll_fd);
	}

	free(payload);

	return res;
}

static void context_free(struct ping_context *ctx)
{
	close(ctx->sock_fd);
	close(ctx->signal_fd);
	close(ctx->timer_fd);
	close(ctx->epoll_fd);
	free(ctx->payload);
}

static void print_init_message(struct ping_context *ctx)
{
	printf("PING %s (%s): %u data bytes\n", ctx->opts->hostname,
	       ctx->addr_s, 56);
}

static void print_summary(struct ping_context *ctx)
{
	struct ping_stats const *stats = &ctx->stats;
	unsigned int packet_loss = 0;
	double time_avg = stats->time_sum / (double)stats->recv_count;
	double time_stddev = 0;

	printf("--- %s ping statistics ---\n", ctx->opts->hostname);
	printf("%zu packets transmitted, %zu packets received, %u%% packet loss\n",
	       stats->send_count, stats->recv_count, packet_loss);
	printf("round-trip min/avg/max/stddev = %.3f/%.3f/%.3f/%.3f\n",
	       stats->time_min, time_avg, stats->time_max, time_stddev);
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
	uint32_t sum = 0;

	for (size_t i = 0; i < msg->msg_iovlen; i++) {
		struct iovec const *iov = &msg->msg_iov[i];
		uint8_t const *data = iov->iov_base;
		size_t len = iov->iov_len;

		/* Sum up all 16-bit words */
		while (len > 1) {
			sum += (uint16_t)((data[0] << 8) | data[1]);
			data += 2;
			len -= 2;
		}

		/* If there's a trailing byte, pad with zero */
		if (len == 1) {
			sum += (uint16_t)(data[0] << 8);
		}
	}

	/* Fold 32-bit sum to 16 bits */
	while (sum >> 16) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}

	/* One's complement and return */
	return htons((uint16_t)~sum);
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
		{ ctx->payload, ctx->payload_size },
	};
	struct msghdr msg = {
		.msg_iov = iov,
		.msg_iovlen = sizeof(iov) / sizeof(iov[0]),
		.msg_name = &ctx->addr,
		.msg_namelen = sizeof(ctx->addr),
	};

	icmp.checksum = compute_icmp_checksum(&msg);

	ssize_t sc;

	sc = sendmsg(ctx->sock_fd, &msg, 0);
	if (sc == -1) {
		return EXIT_FAILURE;
	}

	ctx->seq += 1;
	return EXIT_SUCCESS;
}

static char const *icmp_code_tostring(uint8_t code, uint8_t type)
{
	switch (code) {
	case ICMP_DEST_UNREACH:
		switch (type) {
		case ICMP_NET_UNREACH:
			return "Network unreachable";
		case ICMP_HOST_UNREACH:
			return "Host unreachable";
		case ICMP_PROT_UNREACH:
			return "Protocol unreachable";
		case ICMP_PORT_UNREACH:
			return "Port unreachable";
		case ICMP_FRAG_NEEDED:
			return "Fragmentation needed";
		case ICMP_SR_FAILED:
			return "Source Route failed";
		case ICMP_NET_UNKNOWN:
			return "Network unknown";
		case ICMP_HOST_UNKNOWN:
			return "Host unknown";
		case ICMP_HOST_ISOLATED:
			return "Host isolated";
		case ICMP_NET_ANO:
			return "Network anonymous";
		case ICMP_HOST_ANO:
			return "Host anonymous";
		case ICMP_NET_UNR_TOS:
			return "Network unreachable for TOS";
		case ICMP_HOST_UNR_TOS:
			return "Host unreachable for TOS";
		case ICMP_PKT_FILTERED:
			return "Packet filtered";
		case ICMP_PREC_VIOLATION:
			return "Host precedence violation";
		case ICMP_PREC_CUTOFF:
			return "Precedence cutoff in effect";
		default:
			return NULL;
		}

	case ICMP_SOURCE_QUENCH:
		return "Source quench";

	case ICMP_REDIRECT:
		return "Redirected";

	case ICMP_TIME_EXCEEDED:
		return "Time to live exceeded";

	case ICMP_PARAMETERPROB:
		return "Parameter problem";

	default:
		return NULL;
	}
}

static int handle_raw_packet(struct ping_context *ctx, uint8_t const *raw,
			     size_t len, struct sockaddr_in const *addr)
{
	char addr_s[INET6_ADDRSTRLEN];

	inet_ntop(AF_INET, &addr->sin_addr, addr_s, sizeof(addr_s));

	struct iphdr const *ip = (struct iphdr *)raw;
	struct icmphdr const *icmp = (struct icmphdr *)(raw + sizeof(*ip));
	uint8_t const *payload = (raw + sizeof(*ip) + sizeof(*icmp));

	switch (icmp->type) {
	case ICMP_ECHO:
	case ICMP_TIMESTAMP:
	case ICMP_TIMESTAMPREPLY:
	case ICMP_ADDRESS:
	case ICMP_ADDRESSREPLY:
		return EXIT_SUCCESS;

	case ICMP_ECHOREPLY: {
		if (icmp->un.echo.id != (uint16_t)ctx->pid) {
			return EXIT_SUCCESS;
		}

		printf("%zu bytes from %s: icmp_seq=%hu ttl=%hhu time=%.3f ms\n",
		       len - sizeof(*ip), addr_s, icmp->un.echo.sequence,
		       ip->ttl, 0.0);

		break;
	}

	default: {
		struct iphdr const *orig_ip = (struct iphdr *)payload;
		struct icmphdr const *orig_icmp =
			(struct icmphdr *)(payload + sizeof(*orig_ip));

		if (orig_icmp->code != ICMP_ECHO) {
			return EXIT_SUCCESS;
		}

		if (orig_icmp->un.echo.id != (uint16_t)ctx->pid) {
			return EXIT_SUCCESS;
		}

		char const *message =
			icmp_code_tostring(icmp->code, icmp->type);

		if (message == NULL) {
			return EXIT_SUCCESS;
		}

		printf("%zu bytes from %s: %s\n", len - sizeof(*ip), addr_s,
		       message);
		break;
	}
	}

	return EXIT_SUCCESS;
}

static int context_handle_socket(struct ping_context *ctx)
{
	size_t buf_len;
	uint8_t *buf;
	struct sockaddr_in addr;
	socklen_t addr_len = sizeof(addr);
	int res = EXIT_FAILURE;

	do {
		buf = recvfrom_peeked(ctx->sock_fd, &buf_len,
				      (struct sockaddr *)&addr, &addr_len);
		if (buf == NULL) {
			break;
		}

		res = handle_raw_packet(ctx, buf, buf_len, &addr);
	} while (0);

	free(buf);
	return res;
}

static int context_handle_signal(struct ping_context *ctx)
{
	struct signalfd_siginfo siginfo;
	ssize_t rr;

	rr = read(ctx->signal_fd, &siginfo, sizeof(siginfo));
	if (rr == -1) {
		return EXIT_FAILURE;
	}

	ctx->running = 0;
	return EXIT_SUCCESS;
}

static int context_handle_timer(struct ping_context *ctx)
{
	uint64_t buf;
	ssize_t rr;

	rr = read(ctx->timer_fd, &buf, sizeof(buf));
	if (rr == -1) {
		return EXIT_FAILURE;
	}

	int res;

	res = send_ping(ctx);
	if (res != EXIT_SUCCESS) {
		return res;
	}

	return EXIT_SUCCESS;
}

static int context_handle_event(struct ping_context *ctx,
				struct epoll_event const *ev)
{
	if (ev->events & EPOLLERR) {
		return EXIT_FAILURE;
	}

	int fd = ev->data.fd;

	if (fd == ctx->sock_fd) {
		return context_handle_socket(ctx);
	} else if (fd == ctx->timer_fd) {
		return context_handle_timer(ctx);
	} else if (fd == ctx->signal_fd) {
		return context_handle_signal(ctx);
	} else {
		ERR("unhandled file descriptor: %d", fd);
		return EXIT_FAILURE;
	}
}

static int context_execute(struct ping_context *ctx)
{
	int epr;
	struct epoll_event ev[3];
	int ec = sizeof(ev) / sizeof(ev[0]);
	int res = EXIT_SUCCESS;

	print_init_message(ctx);

	while (ctx->running) {
		epr = epoll_wait(ctx->epoll_fd, ev, ec, -1);
		if (epr == -1) {
			ERR("failed to poll: %m");
			return EXIT_FAILURE;
		}

		for (int i = 0; i < epr; i += 1) {
			if (!ctx->running) {
				break;
			}

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

	if (opts.help) {
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

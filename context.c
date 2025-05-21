/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   context.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: bbrassar <bbrassar@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025/05/18 12:16:28 by bbrassar          #+#    #+#             */
/*   Updated: 2025/05/21 15:56:47 by bbrassar         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "context.h"
#include "display.h"
#include "icmp.h"

#include <inttypes.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <tgmath.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

static uint8_t hex_to_nibble(char c)
{
	if (c >= '0' && c <= '9') {
		return c - '0';
	}

	if (c >= 'a' && c <= 'f') {
		return c - 'a' + 0xa;
	}

	if (c >= 'A' && c <= 'F') {
		return c - 'A' + 0xa;
	}

	return 0xff;
}

static void fill_payload(uint8_t *payload, size_t len, char const pattern[])
{
	size_t pattern_len = strlen(pattern);

	if (pattern_len == 0) {
		return;
	}

	size_t j = 0;

	for (size_t i = 0; i < len; i += 1) {
		payload[i] = hex_to_nibble(pattern[j]);
		if (j + 1 < pattern_len) {
			j += 1;
			payload[i] <<= 4;
			payload[i] |= (hex_to_nibble(pattern[j]) & 0x0F);
		}
		j = (j + 1) % pattern_len;
	}
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

int context_create(struct ping_context *ctx, struct options const *opts,
		   char const hostname[])
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
		payload = calloc(opts->size, 1);
		if (payload == NULL) {
			break;
		}

		if (opts->pattern == NULL) {
			for (size_t i = 0; i < opts->size; i += 1) {
				payload[i] = (uint8_t)i;
			}
		} else {
			fill_payload(payload, opts->size, opts->pattern);
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

		res = resolve_hostname(hostname, &ctx->addr);
		if (res != EXIT_SUCCESS) {
			break;
		}

		inet_ntop(AF_INET, &ctx->addr.sin_addr.s_addr, ctx->addr_s,
			  INET_ADDRSTRLEN);

		ctx->stats = (struct ping_stats){
			.send_count = 0,
			.recv_count = 0,
			.dup_count = 0,
			.time_min = 0,
			.time_max = 0,
			.time_sum = 0,
			.time_sum_squared = 0,
		};
		ctx->packets = (struct packet_list){
			.begin = NULL,
			.end = NULL,
			.size = 0,
		};
		ctx->opts = opts;
		ctx->hostname = hostname;
		ctx->running = 1;
		ctx->epoll_fd = epoll_fd;
		ctx->sock_fd = sock_fd;
		ctx->timer_fd = timer_fd;
		ctx->signal_fd = signal_fd;
		ctx->payload = payload;
		ctx->payload_size = opts->size;
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

void context_free(struct ping_context *ctx)
{
	close(ctx->sock_fd);
	close(ctx->signal_fd);
	close(ctx->timer_fd);
	close(ctx->epoll_fd);
	free(ctx->payload);

	struct packet_list_node *it = ctx->packets.begin;

	while (it != NULL) {
		struct packet_list_node *next = it->next;

		free(it);
		it = next;
	}
}

static void print_init_message(struct ping_context *ctx)
{
	printf("PING %s (%s): %zu data bytes\n", ctx->hostname, ctx->addr_s,
	       ctx->opts->size);
}

static void print_summary(struct ping_context *ctx)
{
	struct ping_stats const *stats = &ctx->stats;
	unsigned int packet_loss = 0;
	double time_avg = 0;
	double time_stddev = 0;

	if (stats->recv_count > 0) {
		time_avg = stats->time_sum / (double)stats->recv_count;
	}

	if (stats->recv_count > 1) {
		double time_variance =
			(stats->time_sum_squared / (double)stats->recv_count) -
			(time_avg * time_avg);
		time_stddev = sqrt(time_variance);
	}

	printf("--- %s ping statistics ---\n", ctx->hostname);
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

static int send_ping(struct ping_context *ctx)
{
	struct packet_list_node *node;

	node = malloc(sizeof(*node));
	if (node == NULL) {
		return EXIT_FAILURE;
	}

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
		free(node);
		return EXIT_FAILURE;
	}

	struct packet_list *packets = &ctx->packets;

	if (packets->size == 0) {
		packets->begin = node;
	} else {
		packets->end->next = node;
	}

	node->received = 0;
	node->seq = ctx->seq;
	node->received_at.tv_sec = 0;
	node->received_at.tv_nsec = 0;
	clock_gettime(CLOCK_MONOTONIC, &node->sent_at);

	node->next = NULL;
	node->prev = packets->end;
	packets->end = node;
	packets->size += 1;

	ctx->seq += 1;
	ctx->stats.send_count += 1;
	return EXIT_SUCCESS;
}

static void dump_ip(struct iphdr const *ip)
{
#define FMT_VR " %" PRIx8
	uint8_t const vr = ip->version;

#define FMT_HL " %" PRIx8
	uint8_t const hl = ip->ihl;

#define FMT_TOS " %02" PRIx8
	uint8_t const tos = ip->tos;

#define FMT_LEN "%04" PRIx16
	uint16_t const len = ip->tot_len;

#define FMT_ID "%04" PRIx16
	uint16_t const id = ip->id;

#define FMT_FLG "  %" PRIu8
	uint8_t const flg =
		(uint8_t)((ip->frag_off & ~(uint16_t)IP_OFFMASK) >> 13);

#define FMT_OFF "%04" PRIx16
	uint16_t const off = ip->frag_off & (uint16_t)IP_OFFMASK;

#define FMT_TTL " %02" PRIx8
	uint8_t const ttl = ip->ttl;

#define FMT_PRO " %02" PRIx8
	uint8_t const pro = ip->protocol;

#define FMT_CKS "%04" PRIx16
	uint8_t const cks = ip->check;

#define FMT_SRC "%s"
	char src[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &ip->saddr, src, sizeof(src));

#define FMT_DST " %s"
	char dst[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &ip->daddr, dst, sizeof(src));

	printf("IP Hdr Dump:\n");

	uint8_t const *raw_ip = (uint8_t *)ip;

	// TODO data between ip and icmp is missing
	for (size_t i = 0; i < sizeof(*ip); i += 1) {
		if ((i % 2) == 0) {
			printf(" ");
		}

		printf("%02" PRIx8, raw_ip[i]);
	}

	printf(" \n");

	printf("Vr HL TOS  Len   ID Flg  off TTL Pro  cks      Src\tDst\tData\n");

	printf(FMT_VR " " FMT_HL " " FMT_TOS " " FMT_LEN " " FMT_ID " " FMT_FLG
		      " " FMT_OFF " " FMT_TTL " " FMT_PRO " " FMT_CKS
		      " " FMT_SRC " " FMT_DST " "
		      "\n",
	       vr, hl, tos, len, id, flg, off, ttl, pro, cks, src, dst);

	// TODO dump data

#undef FMT_VR
#undef FMT_HL
#undef FMT_TOS
#undef FMT_LEN
#undef FMT_ID
#undef FMT_FLG
#undef FMT_OFF
#undef FMT_TTL
#undef FMT_PRO
#undef FMT_CKS
#undef FMT_SRC
#undef FMT_DST
}

static void dump_icmp(struct icmphdr const *icmp, uint16_t data_size)
{
#define FMT_TYPE "%" PRIu8
	uint8_t const type = icmp->type;
#define FMT_CODE "%" PRIu8
	uint8_t const code = icmp->code;
#define FMT_SIZE "%" PRIu16
	uint16_t const size = sizeof(*icmp) + data_size;
#define FMT_ID "0x%04" PRIx16
	uint16_t const id = icmp->un.echo.id;
#define FMT_SEQ "0x%04" PRIx16
	uint16_t const seq = icmp->un.echo.sequence;

	printf("ICMP: type " FMT_TYPE ", code " FMT_CODE ", size " FMT_SIZE
	       ", id " FMT_ID ", seq " FMT_SEQ "\n",
	       type, code, size, id, seq);

#undef FMT_TYPE
#undef FMT_CODE
#undef FMT_SIZE
#undef FMT_ID
#undef FMT_SEQ
}

static double timespec_diff(struct timespec const *t1,
			    struct timespec const *t2)
{
	double n1 = (t1->tv_sec * 1e3) + (t1->tv_nsec / 1e6);
	double n2 = (t2->tv_sec * 1e3) + (t2->tv_nsec / 1e6);

	return n1 > n2 ? n1 - n2 : n2 - n1;
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

		struct packet_list_node *node = ctx->packets.end;

		while (node != NULL) {
			if (icmp->un.echo.sequence == node->seq) {
				break;
			}

			node = node->prev;
		}

		if (node == NULL) {
			break;
		}

		clock_gettime(CLOCK_MONOTONIC, &node->received_at);

		double time_diff =
			timespec_diff(&node->sent_at, &node->received_at);

		if (!ctx->opts->quiet) {
			printf("%zu bytes from %s: icmp_seq=%hu ttl=%hhu time=%.3f ms",
			       len - sizeof(*ip), addr_s,
			       icmp->un.echo.sequence, ip->ttl, time_diff);

			if (node->received) {
				printf(" (DUP!)");
			}

			printf("\n");
		}

		if (node->received) {
			ctx->stats.dup_count += 1;
		} else {
			if (ctx->stats.recv_count == 0 ||
			    time_diff < ctx->stats.time_min) {
				ctx->stats.time_min = time_diff;
			}

			if (ctx->stats.recv_count == 0 ||
			    time_diff > ctx->stats.time_max) {
				ctx->stats.time_max = time_diff;
			}

			ctx->stats.recv_count += 1;
			ctx->stats.time_sum += time_diff;
			ctx->stats.time_sum_squared += (time_diff * time_diff);
		}

		node->received = 1;
		break;
	}

	default: {
		struct iphdr const *orig_ip = (struct iphdr *)payload;
		struct icmphdr const *orig_icmp =
			(struct icmphdr *)(payload + sizeof(*orig_ip));

		if (orig_icmp->un.echo.id != (uint16_t)ctx->pid) {
			return EXIT_SUCCESS;
		}

		char const *message =
			icmp_code_tostring(icmp->type, icmp->code);

		if (message == NULL) {
			return EXIT_SUCCESS;
		}

		printf("%zu bytes from %s: %s\n", len - sizeof(*ip), addr_s,
		       message);

		if (ctx->opts->verbose) {
			dump_ip(orig_ip);
			dump_icmp(orig_icmp, 0); // TODO
		}

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

int context_execute(struct ping_context *ctx)
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

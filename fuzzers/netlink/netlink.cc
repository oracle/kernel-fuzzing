/*
 * kernel-fuzzing.git
 * Copyright (c) 2016  Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Universal Permissive License v1.0 as shown at
 * http://oss.oracle.com/licenses/upl.
 */

#include <asm/types.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/netlink.h>

#include "fuzzer.hh"

struct params {
	/* For socket() */
	int type;
	int protocol;

	/* For sendmsg() */
	struct sockaddr_nl name;
	struct msghdr msg;
	int flags;
} __attribute__((packed));

static void write_example(const char *pathname, struct params *p, const char *buf, size_t count)
{
	int fd = open(pathname, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd == -1)
		error(1, errno, "open()");

	if (write(fd, p, sizeof(*p)) != sizeof(*p))
		error(1, errno, "write()");

	ssize_t len = write(fd, buf, count);
	if (len < 0 || (size_t) len != count)
		error(1, errno, "write()");

	close(fd);
}

#define example(_num, _protocol, _buf) \
	do { \
		struct params p; \
		memset(&p, 0, sizeof(p)); \
		p.type = SOCK_RAW; \
		p.protocol = _protocol; \
		p.name.nl_family = AF_NETLINK; \
		p.msg.msg_namelen = sizeof(p.name); \
		\
		const char buf[] = _buf; \
		char filename[PATH_MAX]; \
		snprintf(filename, sizeof(filename), "%s/%u", dir, _num); \
		write_example(filename, &p, buf, sizeof(buf)); \
	} while (0)

static void write_examples(const char *dir)
{
	/* ip link delete eth0 */
	example(0, NETLINK_ROUTE, " \0\0\0\21\0\5\0H\361^V\0\0\0\0\0\0\0\0\2\0\0\0\0\0\0\0\0\0\0\0");

	/* iw wlan0 info */
	example(1, NETLINK_GENERIC, " \0\0\0\20\0\5\0t\364^Vkk\0\0\3\1\0\0\f\0\2\0nl80211\0");
	example(2, NETLINK_GENERIC, "\34\0\0\0\32\0\5\0u\364^Vkk\0\0\5\0\0\0\10\0\3\0\3\0\0\0");

	/* ip route del */
	example(3, NETLINK_ROUTE, "\34\0\0\0\31\0\5\0x\367^V\0\0\0\0\2\0\0\0\376\0\377\0\0\0\0\0");

	/* ip link set eth0 name foobar */
	example(4, NETLINK_ROUTE, ",\0\0\0\20\0\5\0\305\367^V\0\0\0\0\0\0\0\0\2\0\0\0\0\0\0\0\0\0\0\0\v\0\3\0foobar\0\0");

	/* ip rule add */
	example(5, NETLINK_ROUTE, "\34\0\0\0 \0\5\6\3\370^V\0\0\0\0\2\0\0\0\376\3\0\1\0\0\0\0");

	/* ip l2tp */
	example(6, NETLINK_GENERIC, " \0\0\0\20\0\1\0;\370^V\0\0\0\0\3\0\0\0\t\0\2\0l2tp\0\0\0\0");

	/* ip l2tp add tunnel remote 10.10.10.10 local 127.0.0.1 tunnel_id 1 peer_tunnel_id 2 udp_sport 2 udp_dport 3 */
	example(7, NETLINK_GENERIC, "T\0\0\0\33\0\5\0\252\370^V\0\0\0\0\1\1\0\0\10\0\t\0\1\0\0\0\10\0\n\0\2\0\0\0\5\0\7\0\3\0\0\0\6\0\2\0\0\0\0\0\10\0\30\0\177\0\0\1\10\0\31\0\n\n\n\n\6\0\32\0\2\0\0\0\6\0\33\0\3\0\0\0");

	/* ip link add type veth */
	example(8, NETLINK_ROUTE, ",\0\0\0\20\0\5\6\353\370^V\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\f\0\22\0\10\0\1\0veth");
}

class netlink_fuzzer:
	public fuzzer
{
public:
	struct params p;
	char buffer[1024];
	ssize_t len;

	netlink_fuzzer()
	{
		/* XXX: global state */
		//setuid(10023);
	}

	~netlink_fuzzer()
	{
	}

	void generate(const char *path)
	{
		write_examples(path);
	}

	int setup(const char *path)
	{
		int fd = open(path, O_RDONLY);
		if (fd == -1)
			error(1, errno, "open()");

		if (read(fd, &p, sizeof(p)) != sizeof(p)) {
			close(fd);
			return -1;
		}

		len = read(fd, buffer, sizeof(buffer));
		close(fd);
		if (len < 0)
			return -1;

		return 0;
	}

	void cleanup()
	{
	}

	void run()
	{
		int sock = socket(AF_NETLINK, p.type, p.protocol);
		if (sock == -1)
			return;

		p.msg.msg_name = &p.name;

		struct iovec iov = {
			.iov_base = &buffer[0],
			.iov_len = (size_t) len,
		};
		p.msg.msg_iov = &iov;
		p.msg.msg_iovlen = 1;
		p.msg.msg_control = 0;

		sendmsg(sock, &p.msg, p.flags);
		close(sock);
	}
} netlink_fuzzer;

fuzzer *fuzzer = &netlink_fuzzer;

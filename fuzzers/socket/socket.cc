/*
 * kernel-fuzzing.git
 * Copyright (c) 2016  Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Universal Permissive License v1.0 as shown at
 * http://oss.oracle.com/licenses/upl.
 */

#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <error.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include "fuzzer.hh"

struct params {
	/* For socket() */
	int domain;
	int type;
	int protocol;
} __attribute__((packed));

class socket_fuzzer:
	public fuzzer
{
public:
	int epfd;
	int pipefd[2];
	pid_t child;

	int fd;
	struct params p;
	char buffer[1024];
	ssize_t len;

	socket_fuzzer()
	{
		/* We can get SIGPIPE if we try to send/recv on a half open socket;
		 * ignore that. */
		signal(SIGPIPE, SIG_IGN);

		epfd = epoll_create(1);
		if (epfd == -1)
			error(1, errno, "epoll_create()");

		if (pipe(pipefd) == -1)
			error(1, errno, "pipe()");

		/* We want the read end to be O_NONBLOCK so that splice() doesn't
		 * block. */
		if (fcntl(pipefd[0], F_SETFL, O_NONBLOCK) == -1)
			error(1, errno, "fcntl()");

		child = fork();
		if (child == -1)
			error(1, errno, "fork()");
		if (child == 0) {
			/* Continually fill pipe with data; will be consumed by
			 * the main process. */
			static char data[4096];
			memset(data, 0, sizeof(data));
			while (1)
				write(pipefd[1], data, sizeof(data));

			/* XXX */
			exit(1);
		}
	}

	~socket_fuzzer()
	{
		/* XXX: error handling + kill/waitpid */
		close(epfd);
		close(pipefd[0]);
		close(pipefd[1]);
		kill(child, SIGKILL);
	}

	void generate(const char *path)
	{
		int fd = open(path, O_CREAT | O_WRONLY, 0644);
		if (fd == -1)
			error(1, errno, "open(%s)", path);

		struct params p;
		memset(&p, 0, sizeof(p));
		write(fd, &p, sizeof(p));

		char buffer[1024];
		memset(buffer, 0, sizeof(buffer));
		write(fd, buffer, sizeof(buffer));

		close(fd);
	}

	int setup(const char *path)
	{
		fd = open(path, O_RDONLY);
		if (fd == -1)
			error(1, errno, "open(%s)", path);

		if (read(fd, &p, sizeof(p)) != sizeof(p)) {
			close(fd);
			return -1;
		}

		memset(buffer, 0, sizeof(buffer));

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
		/* Create two sockets; try to bind() + listen() on one and
		 * connect() (presumably to the first one) with the other. */
		int sock1 = -1, sock2 = -1, sock3 = -1;
		sock1 = socket(p.domain, p.type | SOCK_NONBLOCK, p.protocol);
		sock2 = socket(p.domain, p.type | SOCK_NONBLOCK, p.protocol);
		if (sock1 == -1 || sock2 == -1) {
			if (sock1 != -1)
				close(sock1);
			if (sock2 != -1)
				close(sock2);
			return;
		}

		/* Try to increase determinism */
		int so_reuseaddr = 1;
		setsockopt(sock1, SOL_SOCKET, SO_REUSEADDR, &so_reuseaddr, sizeof(so_reuseaddr));
		setsockopt(sock2, SOL_SOCKET, SO_REUSEADDR, &so_reuseaddr, sizeof(so_reuseaddr));

		/* Try to avoid getting stuck */
		struct timeval timeout = { 0, 1 };
		setsockopt(sock1, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
		setsockopt(sock1, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
		setsockopt(sock2, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
		setsockopt(sock2, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

		/* Try to make them connect... it's a long shot, but worth a try */
		struct sockaddr_storage addr;
		socklen_t addrlen = sizeof(addr);

		/* Kernel bug? If you bind() a named UNIX socket that uses all the
		 * 108 bytes in the name (not including the final NUL byte), then
		 * the kernel will happily accept the full name and return a name
		 * length that _includes_ the NUL byte (which is past the end of
		 * struct sockaddr_un). */
		if (p.domain == AF_UNIX && len == 111)
			len = 110;

		int err = bind(sock1, (struct sockaddr *) buffer, len);
		if (p.domain == AF_UNIX && err == 0) {
			/* Clean up UNIX sockets in the filesystem immediately */
			struct sockaddr_un *addr_un = (struct sockaddr_un *) buffer;
			if (addr_un->sun_path[0] != '\0')
				unlink(addr_un->sun_path);
		}

		listen(sock1, SOMAXCONN);
		connect(sock2, (struct sockaddr *) buffer, len);
		sock3 = accept4(sock1, (struct sockaddr *) &addr, &addrlen, SOCK_NONBLOCK);

	#if 1
		/* Unlikely to succeed, but we do it for kicks. */
		int sock4 = accept4(sock2, (struct sockaddr *) &addr, &addrlen, SOCK_NONBLOCK);
		if (sock4 != -1)
			close(sock4);

		if (sock3 != -3) {
			int sock5 = accept4(sock3, (struct sockaddr *) &addr, &addrlen, SOCK_NONBLOCK);
			if (sock5 != -1)
				close(sock5);
		}
	#endif

		/* For completeness */
		addrlen = sizeof(addr);
		getsockname(sock1, (struct sockaddr *) &addr, &addrlen);
		addrlen = sizeof(addr);
		getsockname(sock2, (struct sockaddr *) &addr, &addrlen);
		addrlen = sizeof(addr);
		getpeername(sock1, (struct sockaddr *) &addr, &addrlen);
		addrlen = sizeof(addr);
		getpeername(sock2, (struct sockaddr *) &addr, &addrlen);

		struct epoll_event ev;
		memset(&ev, 0, sizeof(ev));
		ev.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLPRI | EPOLLERR | EPOLLHUP | EPOLLET | EPOLLONESHOT;
		if (sock1 != -1)
			epoll_ctl(epfd, EPOLL_CTL_ADD, sock1, &ev);
		if (sock2 != -1)
			epoll_ctl(epfd, EPOLL_CTL_ADD, sock2, &ev);
		if (sock3 != -1)
			epoll_ctl(epfd, EPOLL_CTL_ADD, sock3, &ev);

		/* Communicate? */
		const char str[] = "hello world";
		send(sock1, str, sizeof(str), 0);
		send(sock2, str, sizeof(str), 0);
		if (sock3 != -1)
			send(sock3, str, sizeof(str), 0);
		recv(sock1, buffer, sizeof(buffer), 0);
		recv(sock2, buffer, sizeof(buffer), 0);
		if (sock3 != -1)
			recv(sock3, buffer, sizeof(buffer), 0);

		if (sock1 != -1)
			splice(pipefd[0], NULL, sock1, NULL, 4096 + 2048, SPLICE_F_NONBLOCK | SPLICE_F_MORE);
		if (sock2 != -1)
			splice(pipefd[0], NULL, sock2, NULL, 4096 + 2048, SPLICE_F_NONBLOCK | SPLICE_F_MORE);
		if (sock3 != -1)
			splice(pipefd[0], NULL, sock3, NULL, 4096 + 2048, SPLICE_F_NONBLOCK | SPLICE_F_MORE);

		void *mem1 = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, sock1, 0);
		if (mem1 != MAP_FAILED) {
			++*(char *) mem1;
			munmap(mem1, 4096);
		}

		void *mem2 = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, sock2, 0);
		if (mem2 != MAP_FAILED) {
			++*(char *) mem2;
			munmap(mem2, 4096);
		}

		void *mem3 = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, sock3, 0);
		if (mem3 != MAP_FAILED) {
			++*(char *) mem3;
			munmap(mem3, 4096);
		}

		struct epoll_event evs[10];
		epoll_wait(epfd, evs, 10, 0);

		if (sock1 != -1)
			epoll_ctl(epfd, EPOLL_CTL_DEL, sock1, NULL);
		if (sock2 != -1)
			epoll_ctl(epfd, EPOLL_CTL_DEL, sock2, NULL);
		if (sock3 != -1)
			epoll_ctl(epfd, EPOLL_CTL_DEL, sock3, NULL);

		shutdown(sock1, SHUT_RD);
		shutdown(sock2, SHUT_WR);
		if (sock3 != -1)
			shutdown(sock3, SHUT_WR);
		shutdown(sock1, SHUT_WR);
		shutdown(sock2, SHUT_RD);
		if (sock3 != -1)
			shutdown(sock3, SHUT_RD);

		if (sock1 != -1)
			close(sock1);
		if (sock2 != -1)
			close(sock2);
		if (sock3 != -1)
			close(sock3);
	}
} socket_fuzzer;

fuzzer *fuzzer = &socket_fuzzer;

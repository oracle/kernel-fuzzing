/*
 * kernel-fuzzing.git
 * Copyright (c) 2016  Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Universal Permissive License v1.0 as shown at
 * http://oss.oracle.com/licenses/upl.
 */

#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <assert.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fuzzer.hh"

static const char *ep_names[31] = {
	"/dev/gadget/dummy_udc",
	"/dev/gadget/ep1in-bulk",
	"/dev/gadget/ep2out-bulk",
	"/dev/gadget/ep3in-iso",
	"/dev/gadget/ep4out-iso",
	"/dev/gadget/ep5in-int",
	"/dev/gadget/ep6in-bulk",
	"/dev/gadget/ep7out-bulk",
	"/dev/gadget/ep8in-iso",
	"/dev/gadget/ep9out-iso",
	"/dev/gadget/ep10in-int",
	"/dev/gadget/ep11in-bulk",
	"/dev/gadget/ep12out-bulk",
	"/dev/gadget/ep13in-iso",
	"/dev/gadget/ep14out-iso",
	"/dev/gadget/ep15in-int",
	"/dev/gadget/ep1out-bulk",
	"/dev/gadget/ep2in-bulk",
	"/dev/gadget/ep3out",
	"/dev/gadget/ep4in",
	"/dev/gadget/ep5out",
	"/dev/gadget/ep6out",
	"/dev/gadget/ep7in",
	"/dev/gadget/ep8out",
	"/dev/gadget/ep9in",
	"/dev/gadget/ep10out",
	"/dev/gadget/ep11out",
	"/dev/gadget/ep12in",
	"/dev/gadget/ep13out",
	"/dev/gadget/ep14in",
	"/dev/gadget/ep15out",
};

class usb_fuzzer:
	public fuzzer
{
public:
	int fd;

	usb_fuzzer()
	{
		mkdir("/dev/gadget", 0755);
	}

	int setup(const char *path)
	{
		if (mount("none", "/dev/gadget", "gadgetfs", 0, NULL) != 0)
			error(1, errno, "mount()");

		fd = open(path, O_RDONLY);
		if (fd == -1)
			error(1, errno, "open(%s)", path);

		return 0;
	}

	void cleanup()
	{
		close(fd);

		if (umount2("/dev/gadget", MNT_FORCE | MNT_DETACH) == -1)
			error(1, errno, "umount2()");
	}

	void run()
	{
		int fds[31];
		for (unsigned int i = 0; i < 31; ++i)
			fds[i] = -1;

		while (1) {
			uint8_t ep;
			if (read(fd, &ep, sizeof(ep)) != sizeof(ep))
				goto out_close_fds;

			ep = ep % 31;

			int epfd = fds[ep];
			if (epfd == -1) {
				epfd = open(ep_names[ep], O_RDWR);
				if (epfd == -1)
					continue;

				fds[ep] = epfd;
			}

			uint8_t packet_len;
			if (read(fd, &packet_len, sizeof(packet_len)) != sizeof(packet_len))
				goto out_close_fds;

			if (packet_len == 0) {
				struct pollfd pfd = {};
				pfd.fd = epfd;
				pfd.events = POLLIN;
				if (poll(&pfd, 1, 0) == 1) {
					static char buf[4096];
					if (read(epfd, buf, sizeof(buf)) == -1 && errno == EINTR)
						break;
				}
			} else {
				uint8_t buffer[256];
				int len = read(fd, buffer, packet_len);
				if (len <= 0)
					goto out_close_fds;

				if (write(epfd, buffer, len) == -1 && errno == EINTR)
					break;
			}
		}

	out_close_fds:
		for (unsigned int i = 0; i < 31; ++i) {
			if (fds[i] != -1)
				close(fds[i]);
		}
	}
} usb_fuzzer;

fuzzer *fuzzer = &usb_fuzzer;

/*
 * kernel-fuzzing.git
 * Copyright (c) 2016  Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Universal Permissive License v1.0 as shown at
 * http://oss.oracle.com/licenses/upl.
 */

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <linux/if.h>
#include <linux/if_tun.h>

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fuzzer.hh"

class net_fuzzer:
	public fuzzer
{
public:
	int tunfd;
	struct sockaddr tun_hwaddr;

	ssize_t rlen;
	char buffer[8192];

	net_fuzzer()
	{
		tunfd = open("/dev/net/tun", O_RDWR);
		if (tunfd == -1)
			error(1, errno, "open()");

		{
			struct ifreq ifr;
			memset(&ifr, 0, sizeof(ifr));
			ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
			strncpy(ifr.ifr_name, "afl0", IFNAMSIZ);
			if (ioctl(tunfd, TUNSETIFF, (void *) &ifr) < 0)
				error(1, errno, "ioctl()");
		}

		/* Bring interface up; otherwise out packets will simply
		 * get dropped. */
		int ret = system("ip link set dev afl0 up");
		if (ret != 0)
			error(1, 0, "ip link");

		/* Get device's MAC address so we can insert it into
		 * the packets we send. */
		{
			struct ifreq ifr;
			memset(&ifr, 0, sizeof(ifr));
			if (ioctl(tunfd, SIOCGIFHWADDR, &ifr) < 0)
				error(1, errno, "ioctl(SIOCGIFHWADDR)");

			tun_hwaddr = ifr.ifr_hwaddr;
		}
	}

	int setup(const char *path)
	{
		int infd = open(path, O_RDONLY);
		if (infd == -1)
			error(1, errno, "open()");

		rlen = read(infd, buffer, sizeof(buffer));
		if (rlen < 0)
			error(1, errno, "read()");
		if (rlen == 0)
			return 1;

		close(infd);
		return 0;
	}

	void run()
	{
		/* Overwrite the target MAC so it won't just get dropped
		 * as PACKET_OTHERHOST. */
		memcpy(&buffer[0], &tun_hwaddr.sa_data[0], 6);

		write(tunfd, buffer, rlen);
		/* Ignore errors */
	}
} net_fuzzer;

fuzzer *fuzzer = &net_fuzzer;

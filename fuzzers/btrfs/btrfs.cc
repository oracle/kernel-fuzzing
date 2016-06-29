/*
 * kernel-fuzzing.git
 * Copyright (c) 2016  Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Universal Permissive License v1.0 as shown at
 * http://oss.oracle.com/licenses/upl.
 */

#include "crc32c.h"
#include "fs-fuzzer.hh"

#include "btrfs-extents.hh"

static class btrfs_fuzzer:
	public fs_fuzzer
{
public:
	btrfs_fuzzer():
		fs_fuzzer("btrfs", 0, 0, btrfs_extents)
	{
	}

	void fix_checksums(int fd)
	{
		uint8_t buf[4096];
		pread(fd, buf, sizeof(buf), 1 << 16);

		uint32_t crc = ~crc32c(-1, buf + 32, sizeof(buf) - 32);
		memcpy(buf, &crc, sizeof(crc));

		pwrite(fd, buf, sizeof(buf), 1 << 16);
	}
} btrfs_fuzzer;

fuzzer *fuzzer = &btrfs_fuzzer;

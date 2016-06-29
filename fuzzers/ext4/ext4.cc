/*
 * kernel-fuzzing.git
 * Copyright (c) 2016  Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Universal Permissive License v1.0 as shown at
 * http://oss.oracle.com/licenses/upl.
 */

#include <stdlib.h>
#include <unistd.h>

#include "fs-fuzzer.hh"
#include "ext4-extents.hh"

static class ext4_fuzzer:
	public fs_fuzzer
{
public:
	ext4_fuzzer():
		fs_fuzzer("ext4", 0, "errors=remount-ro", ext4_extents)
	{
	}

	void info()
	{
		char command[1024];
		snprintf(command, sizeof(command), "dumpe2fs -fx %s", filename);
		system(command);
	}

	void fix_checksums(int fd)
	{
		/* disable RO_COMPAT_GDT_CSUM and RO_COMPAT_METADATA_CSUM */
		uint32_t s_feature_ro_compat;
		pread(fd, &s_feature_ro_compat, sizeof(s_feature_ro_compat), 0x400 + 0x64);
		s_feature_ro_compat &= ~0x0410;
		pwrite(fd, &s_feature_ro_compat, sizeof(s_feature_ro_compat), 0x400 + 0x64);
	}
} ext4_fuzzer;

fuzzer *fuzzer = &ext4_fuzzer;

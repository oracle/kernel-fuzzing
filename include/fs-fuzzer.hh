/*
 * kernel-fuzzing.git
 * Copyright (c) 2016  Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Universal Permissive License v1.0 as shown at
 * http://oss.oracle.com/licenses/upl.
 */

#ifndef KERNEL_FUZZING_FS_FUZZER_HH
#define KERNEL_FUZZING_FS_FUZZER_HH

#include <sys/types.h>
#include <sys/uio.h>

#include <assert.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "fuzzer.hh"
#include "mount.hh"

struct fs_extents {
	struct extent {
		off_t offset;
		size_t len;
	};

	unsigned int in_size;
	unsigned int out_size;
	unsigned int nr_extents;
	const extent *extents;
};

class fs_fuzzer:
	public fuzzer
{
public:
	mount_helper helper;
	const fs_extents &extents;
	char filename[PATH_MAX];

	uint8_t *buffer;

	fs_fuzzer(const char *fstype, unsigned long flags, const char *data,
		const fs_extents &extents):
		helper(fstype, flags, data),
		extents(extents),
		buffer(new uint8_t[extents.in_size])
	{
		helper.loop_setup();
		mkdir(helper.mountpoint, 0755);
	}

	~fs_fuzzer()
	{
		delete[] buffer;
	}

	int setup(const char *path)
	{
		helper.unmount();
		helper.loop_detach(1);

		snprintf(filename, sizeof(filename), "%s.full", path);
		if (construct_image(path, filename))
			return 1;

		helper.loop_attach(filename);
		return 0;
	}

	void cleanup()
	{
		helper.unmount();
		helper.loop_detach(0);
		unlink(filename);
	}

	void run()
	{
		if (helper.mount() == 0)
			helper.activity();

		helper.unmount();
	}

	virtual void info()
	{
	}

	virtual void fix_checksums(int fd)
	{
		/* By default, do nothing. */
	}

	/* Construct a proper filesystem image given a compact input image
	 * (typically the testcase afl has mutated). */
	int construct_image(const char *in, const char *out)
	{
		int infd = open(in, O_RDONLY);
		if (infd == -1)
			return -1;

		ssize_t read_len = read(infd, buffer, extents.in_size);
		close(infd);
		if (read_len != extents.in_size)
			return -1;

		int outfd = open(out, O_RDWR | O_CREAT | O_TRUNC, 0700);
		if (outfd == -1)
			return -1;

		const uint8_t *ptr = buffer;
		if (ftruncate(outfd, extents.out_size) == -1)
			goto error_close_outfd;

		for (unsigned int i = 0; i < extents.nr_extents; ++i) {
			if (lseek(outfd, extents.extents[i].offset, SEEK_SET) == -1)
				goto error_close_outfd;

			ssize_t write_len = write(outfd, ptr, extents.extents[i].len);
			if (write_len != (ssize_t) extents.extents[i].len)
				goto error_close_outfd;

			ptr += extents.extents[i].len;
		}

		/* Sanity check to see that we read exactly how much we expected */
		assert(ptr == &buffer[extents.in_size]);

		fix_checksums(outfd);
		close(outfd);
		return 0;

	error_close_outfd:
		close(outfd);
		return -1;
	}
};

#endif

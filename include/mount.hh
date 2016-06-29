/*
 * kernel-fuzzing.git
 * Copyright (c) 2016  Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Universal Permissive License v1.0 as shown at
 * http://oss.oracle.com/licenses/upl.
 */

#ifndef KERNEL_FUZZING_MOUNT_HH
#define KERNEL_FUZZING_MOUNT_HH

#include <sys/types.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/xattr.h>

#include <dirent.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/falloc.h>
#include <linux/loop.h>

class mount_helper {
public:
	const char *loopdev;
	const char *mountpoint;
	const char *fstype;
	unsigned long flags;
	const char *data;

	char *foo_bar_baz;
	char *foo_baz;
	char *xattr;
	char *hln;
	char *sln;

	int loop_fd;

	mount_helper(const char *fstype, unsigned long flags = 0, const char *data = 0):
		loopdev("/dev/loop0"),
		mountpoint("/mnt"),
		fstype(fstype),
		flags(flags),
		data(data),
		foo_bar_baz(0),
		foo_baz(0),
		xattr(0),
		hln(0),
		sln(0)
	{
		asprintf(&foo_bar_baz, "%s/foo/bar/baz", mountpoint);
		asprintf(&foo_baz, "%s/foo/baz", mountpoint);
		asprintf(&xattr, "%s/foo/bar/xattr", mountpoint);
		asprintf(&hln, "%s/foo/bar/hln", mountpoint);
		asprintf(&sln, "%s/foo/bar/sln", mountpoint);
	}

	~mount_helper()
	{
		free(foo_bar_baz);
		free(foo_baz);
		free(xattr);
		free(hln);
		free(sln);
	}

	void loop_setup()
	{
		loop_fd = open(loopdev, O_RDWR);
		if (loop_fd < 0)
			error(1, errno, "open(%s)", loopdev);
	}

	void loop_attach(const char *filename)
	{
		int file_fd = open(filename, O_RDWR);
		if (file_fd < 0)
			error(1, errno, "open(%s)", filename);

		unsigned int max_nr_retry = 150;

		while (1) {
			if (ioctl(loop_fd, LOOP_SET_FD, file_fd) == 0)
				break;

			if (!--max_nr_retry) {
				/* Do the whole setup again */
				ioctl(loop_fd, LOOP_CLR_FD, 0);
				close(loop_fd);
				loop_setup();
				max_nr_retry = 150;
			}
		}

		close(file_fd);
	}

	void loop_detach(bool ignore_errors)
	{
		if (ioctl(loop_fd, LOOP_CLR_FD, 0) < 0 && !ignore_errors)
			error(1, errno, "ioctl(%s, LOOP_CLR_FD)", loopdev);
	}

	void loop_setinfo(const char *filename)
	{
		struct loop_info64 linfo;
		memset(&linfo, 0, sizeof(linfo));

		strncpy((char *) linfo.lo_file_name, filename, sizeof(linfo.lo_file_name));

		if (ioctl(loop_fd, LOOP_SET_STATUS64, &linfo) < 0)
			error(1, errno, "ioctl(%s, LOOP_SET_STATUS64)", loopdev);
	}

	int mount()
	{
		return ::mount(loopdev, mountpoint, fstype, flags, data);
	}

	int unmount()
	{
		int err = umount2(mountpoint, 0);
		if (err)
			err = umount2(mountpoint, MNT_FORCE);
		if (err)
			err = umount2(mountpoint, MNT_DETACH);
		return err;
	}

	void activity()
	{

		DIR *dir = opendir(mountpoint);
		if (dir) {
			readdir(dir);
			closedir(dir);
		}

		static int buf[8192];
		memset(buf, 0, sizeof(buf));

		int fd = open(foo_bar_baz, O_RDONLY);
		if (fd != -1) {
			void *mem = mmap(NULL, 4096, PROT_READ, MAP_SHARED | MAP_POPULATE, fd, 0);
			if (mem != MAP_FAILED) {
				munmap(mem, 4096);
			}

			read(fd, buf, 11);
			read(fd, buf, 11);
			close(fd);
		}

		fd = open(foo_bar_baz, O_RDWR | O_TRUNC | O_DIRECT, 0777);
		if (fd != -1) {
			write(fd, buf, 517);
			write(fd, buf, sizeof(buf));
			lseek(fd, 0, SEEK_SET);
			read(fd, buf, sizeof(buf));
			lseek(fd, 1234, SEEK_SET);
			read(fd, buf, 517);
			close(fd);
		}

		fd = open(foo_bar_baz, O_RDWR | O_TRUNC, 0777);
		if (fd != -1) {
			void *mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd, 0);
			if (mem != MAP_FAILED) {
				//++*((char *) mem);
				munmap(mem, 4096);
			}

			write(fd, buf, sizeof(buf));
			write(fd, buf, sizeof(buf));
			fdatasync(fd);
			fsync(fd);

			lseek(fd, 1024 - 33, SEEK_SET);
			write(fd, buf, sizeof(buf));
			lseek(fd, 1024 * 1024 + 67, SEEK_SET);
			write(fd, buf, sizeof(buf));
			lseek(fd, 1024 * 1024 * 1024 - 113, SEEK_SET);
			write(fd, buf, sizeof(buf));

			lseek(fd, 0, SEEK_SET);
			write(fd, buf, sizeof(buf));

			fallocate(fd, 0, 0, 123871237);
			fallocate(fd, 0, -13123, 123);
			fallocate(fd, 0, 234234, -45897);
			fallocate(fd, FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE, 0, 4243261);
			fallocate(fd, FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE, -95713, 38447);
			fallocate(fd, FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE, 18237, -9173);

			close(fd);
		}

		rename(foo_bar_baz, foo_baz);

		struct stat stbuf;
		memset(&stbuf, 0, sizeof(stbuf));
		stat(foo_baz, &stbuf);

		chmod(foo_baz, 0000);
		chmod(foo_baz, 1777);
		chmod(foo_baz, 3777);
		chmod(foo_baz, 7777);
		chown(foo_baz, 0, 0);
		chown(foo_baz, 1, 1);

		unlink(foo_bar_baz);
		unlink(foo_baz);

		mknod(foo_baz, 0777, makedev(0, 0));

		char buf2[113];
		memset(buf2, 0, sizeof(buf2));
		listxattr(xattr, buf2, sizeof(buf2));
		removexattr(xattr, "user.mime_type");
		setxattr(xattr, "user.md5", buf2, sizeof(buf2), XATTR_CREATE);
		setxattr(xattr, "user.md5", buf2, sizeof(buf2), XATTR_REPLACE);
		readlink(sln, buf2, sizeof(buf2));
	}
};

#endif

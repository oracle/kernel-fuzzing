/*
 * kernel-fuzzing.git
 * Copyright (c) 2016  Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Universal Permissive License v1.0 as shown at
 * http://oss.oracle.com/licenses/upl.
 */

#include "fs-fuzzer.hh"
#include "ntfs-extents.hh"

static class ntfs_fuzzer:
	public fs_fuzzer
{
public:
	ntfs_fuzzer():
		fs_fuzzer("ntfs", 0, 0, ntfs_extents)
	{
	}
} ntfs_fuzzer;

fuzzer *fuzzer = &ntfs_fuzzer;

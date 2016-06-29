/*
 * kernel-fuzzing.git
 * Copyright (c) 2016  Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Universal Permissive License v1.0 as shown at
 * http://oss.oracle.com/licenses/upl.
 */

#include "fs-fuzzer.hh"
#include "reiserfs-extents.hh"

static class reiserfs_fuzzer:
	public fs_fuzzer
{
public:
	reiserfs_fuzzer():
		fs_fuzzer("reiserfs", 0, 0, reiserfs_extents)
	{
	}
} reiserfs_fuzzer;

fuzzer *fuzzer = &reiserfs_fuzzer;

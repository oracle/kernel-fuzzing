/*
 * kernel-fuzzing.git
 * Copyright (c) 2016  Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Universal Permissive License v1.0 as shown at
 * http://oss.oracle.com/licenses/upl.
 */

#include "fs-fuzzer.hh"
#include "hfs-extents.hh"

static class hfs_fuzzer:
	public fs_fuzzer
{
public:
	hfs_fuzzer():
		fs_fuzzer("hfs", 0, 0, hfs_extents)
	{
	}
} hfs_fuzzer;

fuzzer *fuzzer = &hfs_fuzzer;

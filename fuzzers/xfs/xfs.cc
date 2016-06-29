/*
 * kernel-fuzzing.git
 * Copyright (c) 2016  Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Universal Permissive License v1.0 as shown at
 * http://oss.oracle.com/licenses/upl.
 */

#include "fs-fuzzer.hh"
#include "xfs-extents.hh"

static class xfs_fuzzer:
	public fs_fuzzer
{
public:
	xfs_fuzzer():
		fs_fuzzer("xfs", 0, "nobarrier", xfs_extents)
	{
	}
} xfs_fuzzer;

fuzzer *fuzzer = &xfs_fuzzer;

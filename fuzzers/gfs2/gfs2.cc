/*
 * kernel-fuzzing.git
 * Copyright (c) 2016  Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Universal Permissive License v1.0 as shown at
 * http://oss.oracle.com/licenses/upl.
 */

#include "fs-fuzzer.hh"
#include "gfs2-extents.hh"

static class gfs2_fuzzer:
	public fs_fuzzer
{
public:
	gfs2_fuzzer():
		fs_fuzzer("gfs2", 0, 0, gfs2_extents)
	{
	}
} gfs2_fuzzer;

fuzzer *fuzzer = &gfs2_fuzzer;

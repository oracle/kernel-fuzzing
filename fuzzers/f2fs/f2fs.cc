/*
 * kernel-fuzzing.git
 * Copyright (c) 2016  Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Universal Permissive License v1.0 as shown at
 * http://oss.oracle.com/licenses/upl.
 */

#include "fs-fuzzer.hh"
#include "f2fs-extents.hh"

static class f2fs_fuzzer:
	public fs_fuzzer
{
public:
	f2fs_fuzzer():
		fs_fuzzer("f2fs", 0, 0, f2fs_extents)
	{
	}
} f2fs_fuzzer;

fuzzer *fuzzer = &f2fs_fuzzer;

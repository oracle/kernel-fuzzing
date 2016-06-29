/*
 * kernel-fuzzing.git
 * Copyright (c) 2016  Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Universal Permissive License v1.0 as shown at
 * http://oss.oracle.com/licenses/upl.
 */

#include "fs-fuzzer.hh"
#include "vfat-extents.hh"

static class vfat_fuzzer:
	public fs_fuzzer
{
public:
	vfat_fuzzer():
		fs_fuzzer("vfat", 0, 0, vfat_extents)
	{
	}
} vfat_fuzzer;

fuzzer *fuzzer = &vfat_fuzzer;

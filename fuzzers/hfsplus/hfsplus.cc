/*
 * kernel-fuzzing.git
 * Copyright (c) 2016  Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Universal Permissive License v1.0 as shown at
 * http://oss.oracle.com/licenses/upl.
 */

#include "fs-fuzzer.hh"
#include "hfsplus-extents.hh"

static class hfsplus_fuzzer:
	public fs_fuzzer
{
public:
	hfsplus_fuzzer():
		fs_fuzzer("hfsplus", 0, 0, hfsplus_extents)
	{
	}
} hfsplus_fuzzer;

fuzzer *fuzzer = &hfsplus_fuzzer;

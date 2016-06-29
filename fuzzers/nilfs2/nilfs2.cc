/*
 * kernel-fuzzing.git
 * Copyright (c) 2016  Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Universal Permissive License v1.0 as shown at
 * http://oss.oracle.com/licenses/upl.
 */

#include "fs-fuzzer.hh"
#include "nilfs2-extents.hh"

static class nilfs2_fuzzer:
	public fs_fuzzer
{
public:
	nilfs2_fuzzer():
		fs_fuzzer("nilfs2", 0, 0, nilfs2_extents)
	{
	}
} nilfs2_fuzzer;

fuzzer *fuzzer = &nilfs2_fuzzer;

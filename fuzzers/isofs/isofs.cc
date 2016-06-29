/*
 * kernel-fuzzing.git
 * Copyright (c) 2016  Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Universal Permissive License v1.0 as shown at
 * http://oss.oracle.com/licenses/upl.
 */

#include "fs-fuzzer.hh"
#include "isofs-extents.hh"

static class isofs_fuzzer:
	public fs_fuzzer
{
public:
	isofs_fuzzer():
		fs_fuzzer("isofs", MS_RDONLY | MS_SILENT, 0, isofs_extents)
	{
	}
} isofs_fuzzer;

fuzzer *fuzzer = &isofs_fuzzer;

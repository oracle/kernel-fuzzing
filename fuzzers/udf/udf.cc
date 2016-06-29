/*
 * kernel-fuzzing.git
 * Copyright (c) 2016  Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Universal Permissive License v1.0 as shown at
 * http://oss.oracle.com/licenses/upl.
 */

#include "fs-fuzzer.hh"
#include "udf-extents.hh"

static class udf_fuzzer:
	public fs_fuzzer
{
public:
	udf_fuzzer():
		fs_fuzzer("udf", MS_RDONLY | MS_SILENT, 0, udf_extents)
	{
	}
} udf_fuzzer;

fuzzer *fuzzer = &udf_fuzzer;

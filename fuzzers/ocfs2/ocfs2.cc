/*
 * kernel-fuzzing.git
 * Copyright (c) 2016  Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Universal Permissive License v1.0 as shown at
 * http://oss.oracle.com/licenses/upl.
 */

#include "fs-fuzzer.hh"
#include "ocfs2-extents.hh"

static class ocfs2_fuzzer:
	public fs_fuzzer
{
public:
	ocfs2_fuzzer():
		fs_fuzzer("ocfs2", 0, 0, ocfs2_extents)
	{
	}
} ocfs2_fuzzer;

fuzzer *fuzzer = &ocfs2_fuzzer;

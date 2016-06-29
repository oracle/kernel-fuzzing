/*
 * kernel-fuzzing.git
 * Copyright (c) 2016  Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Universal Permissive License v1.0 as shown at
 * http://oss.oracle.com/licenses/upl.
 */

#ifndef KERNEL_FUZZING_FUZZER_HH
#define KERNEL_FUZZING_FUZZER_HH

class fuzzer {
public:
	fuzzer()
	{
	}

	virtual ~fuzzer()
	{
	}

	/* Generate initial set of test cases */
	virtual void generate(const char *path)
	{
	}

	/* Not instrumented */
	virtual int setup(const char *path)
	{
		return 0;
	}

	/* Not instrumented */
	virtual void cleanup()
	{
	}

	/* Instrumented */
	virtual void run() = 0;

	/* Print some human-readable info about the test-case to stdout */
	virtual void info()
	{
	}
};

#endif

/*
 * kernel-fuzzing.git
 * Copyright (c) 2016  Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Universal Permissive License v1.0 as shown at
 * http://oss.oracle.com/licenses/upl.
 */

#include <string.h>

#include "fuzzer.hh"

/*
 * This gets compiled together with a specific fuzzer (from fuzzers/)
 * into a standalone binary that can be used to run a test case without
 * using AFL.
 */

extern class fuzzer *fuzzer;

int main(int argc, char *argv[])
{
	if (!strcmp(argv[1], "--generate")) {
		fuzzer->generate(argv[2]);
	} else if (!strcmp(argv[1], "--info")) {
		if (fuzzer->setup(argv[2]))
			return 1;
		fuzzer->info();
		fuzzer->cleanup();
	} else {
		if (fuzzer->setup(argv[1]))
			return 1;

		fuzzer->run();
		fuzzer->cleanup();
	}

	return 0;
}

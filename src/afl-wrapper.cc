/*
 * kernel-fuzzing.git
 * Copyright (c) 2016  Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Universal Permissive License v1.0 as shown at
 * http://oss.oracle.com/licenses/upl.
 */

#include "fuzzer.hh"

/*
 * This gets compiled together with a specific fuzzer (from fuzzers/)
 * into a shared object that AFL knows how to load and run.
 */

extern class fuzzer *fuzzer;

extern "C" int pre_hook(int argc, char *argv[])
{
	return fuzzer->setup(argv[1]);
}

extern "C" void post_hook(int argc, char *argv[])
{
	fuzzer->cleanup();
}

extern "C" void run(int argc, char *argv[])
{
	fuzzer->run();
}

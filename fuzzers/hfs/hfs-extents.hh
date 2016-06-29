#include "fs-fuzzer.hh"

const fs_extents::extent _hfs_extents[] = {
	{ 1024, 192 },
	{ 1536, 128 },
	{ 7168, 64 },
	{ 7360, 64 },
	{ 7616, 64 },
	{ 530944, 64 },
	{ 531136, 64 },
	{ 531392, 1280 },
	{ 532928, 576 },
	{ 1054720, 64 },
	{ 1060864, 64 },
	{ 67107840, 192 },
	};

const fs_extents hfs_extents = {
	2816,
	67108864,
	12,
	_hfs_extents,
};

#include "fs-fuzzer.hh"

const fs_extents::extent _vfat_extents[] = {
	{ 0, 192 },
	{ 448, 128 },
	{ 66048, 64 },
	{ 131584, 64 },
	{ 150016, 128 },
	{ 152064, 320 },
	{ 154112, 64 },
	{ 156160, 64 },
	};

const fs_extents vfat_extents = {
	1024,
	67108864,
	8,
	_vfat_extents,
};

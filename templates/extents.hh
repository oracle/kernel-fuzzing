#include "fs-fuzzer.hh"

const fs_extents::extent _{{ name }}_extents[] = {
	{% for offset, length in extents -%}
	{ {{ offset }}, {{ length }} },
	{% endfor -%}
};

const fs_extents {{ name }}_extents = {
	{{ in_size }},
	{{ out_size }},
	{{ extents|length }},
	_{{ name }}_extents,
};

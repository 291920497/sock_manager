#include "hash_func.h"

uint32_t cf_hash_func(const char* char_key, int32_t klen) {
	uint32_t hash = 0;
	const unsigned char* key = (const unsigned char*)char_key;
	const unsigned char* p;
	int i;
	if (!key) return hash;

	if (klen == -1) {
		for (p = key; *p; p++) {
			hash = hash * 33 + tolower(*p);
		}
		klen = p - key;
	}
	else {
		for (p = key, i = klen; i; i--, p++) {
			hash = hash * 33 + tolower(*p);
		}
	}

	return hash;
}
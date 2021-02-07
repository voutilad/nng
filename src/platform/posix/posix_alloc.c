//
// Copyright 2016 Garrett D'Amore <garrett@damore.org>
//
// This software is supplied under the terms of the MIT License, a
// copy of which should be located in the distribution where this
// file was obtained (LICENSE.txt).  A copy of the license may also be
// found online at https://opensource.org/licenses/MIT.
//

#include "core/nng_impl.h"

#ifdef NNG_PLATFORM_POSIX

#include <stdlib.h>

nni_atomic_u64 *memtrack_alloc = NULL;
nni_atomic_u64 *memtrack_freed = NULL;

int
nni_memtrack(uint64_t *alloc, uint64_t *freed)
{
	if (memtrack_alloc != NULL && memtrack_freed != NULL) {
		*alloc = nni_atomic_get64(memtrack_alloc);
		*freed = nni_atomic_get64(memtrack_freed);
		return 0;
	}
	return -1;
}

// POSIX memory allocation.  This is pretty much standard C.
void *
nni_alloc(size_t sz)
{
	if (memtrack_alloc == NULL) {
		memtrack_alloc = malloc(sizeof(memtrack_alloc));
		nni_atomic_init64(memtrack_alloc);
	}
	nni_atomic_add(memtrack_alloc, sz);
	return (sz > 0 ? malloc(sz) : NULL);
}

void *
nni_zalloc(size_t sz)
{
	if (memtrack_alloc == NULL) {
		memtrack_alloc = malloc(sizeof(memtrack_alloc));
		nni_atomic_init64(memtrack_alloc);
	}
	nni_atomic_add(memtrack_alloc, sz);
	return (sz > 0 ? calloc(1, sz) : NULL);
}

void
nni_free(void *ptr, size_t size)
{
	NNI_ARG_UNUSED(size);
	if (memtrack_freed == NULL) {
		memtrack_freed = malloc(sizeof(memtrack_freed));
		nni_atomic_init64(memtrack_freed);
	}
	nni_atomic_add(memtrack_freed, size);
	free(ptr);
}

#endif // NNG_PLATFORM_POSIX

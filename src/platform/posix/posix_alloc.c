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

extern nni_atomic_int *memtrack_alloc;
extern nni_atomic_int *memtrack_freed;

// POSIX memory allocation.  This is pretty much standard C.
void *
nni_alloc(size_t sz)
{
	if (memtrack_alloc == NULL) {
		nni_atomic_init(memtrack_alloc);
	}
	nni_atomic_add(memtrack_alloc, sz);
	return (sz > 0 ? malloc(sz) : NULL);
}

void *
nni_zalloc(size_t sz)
{
	if (memtrack_alloc == NULL) {
		nni_atomic_init(memtrack_alloc);
	}
	nni_atomic_add(memtrack_alloc, sz);
	return (sz > 0 ? calloc(1, sz) : NULL);
}

void
nni_free(void *ptr, size_t size)
{
	NNI_ARG_UNUSED(size);
	if (memtrack_freed == NULL) {
		nni_atomic_init(memtrack_freed);
	}
	nni_atomic_add(memtrack_freed, size);
	free(ptr);
}

#endif // NNG_PLATFORM_POSIX

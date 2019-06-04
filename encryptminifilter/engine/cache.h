#ifndef _CACHE_H_
#define _CACHE_H_

#include "common.h"

VOID
Cc_ClearFileCache(
	__in PFILE_OBJECT FileObject,
	__in BOOLEAN bIsFlushCache,
	__in PLARGE_INTEGER FileOffset, 
	__in ULONG Length
	) ;


#endif
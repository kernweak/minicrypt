#include "common.h"

//
//  Memory Pool Tags
//

#define STRING_TAG                        'tSxC'
#define RESOURCE_TAG                      'cRxC'
#define STREAM_CONTEXT_TAG                'cSxC'

#define SC_iLOCK(SC)\
	(ASSERT(KeGetCurrentIrql() <= APC_LEVEL), \
	ASSERT(ExIsResourceAcquiredExclusiveLite(SC) || \
	       !ExIsResourceAcquiredSharedLite(SC)),\
	 KeEnterCriticalRegion(),\
	 ExAcquireResourceExclusiveLite(SC, TRUE))
	 
#define SC_iUNLOCK(SC) \
	(ASSERT(KeGetCurrentIrql() <= APC_LEVEL), \
	 ASSERT(ExIsResourceAcquiredSharedLite(SC) ||\
	         ExIsResourceAcquiredExclusiveLite(SC)),\
	 ExReleaseResourceLite(SC),\
	 KeLeaveCriticalRegion())

VOID 
SC_LOCK(PSTREAM_CONTEXT SC, PKIRQL OldIrql) ;

VOID 
SC_UNLOCK(PSTREAM_CONTEXT SC, KIRQL OldIrql) ;

NTSTATUS
Ctx_FindOrCreateStreamContext (
    __in PFLT_CALLBACK_DATA Cbd,
	__in PFLT_RELATED_OBJECTS FltObjects,
    __in BOOLEAN CreateIfNotFound,
    __deref_out PSTREAM_CONTEXT *StreamContext,
    __out_opt BOOLEAN* ContextCreated
    ) ;

NTSTATUS
Ctx_UpdateNameInStreamContext (
    __in PUNICODE_STRING DirectoryName,
    __inout PSTREAM_CONTEXT StreamContext
    );
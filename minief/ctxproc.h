#pragma once

#define CTX_STRING_TAG                        'tSxC'
#define CTX_RESOURCE_TAG                      'cRxC'
#define CTX_EVENT_TAG						  'cExC'
#define CTX_INSTANCE_CONTEXT_TAG              'cIxC'
#define CTX_FILE_CONTEXT_TAG                  'cFxC'
#define CTX_STREAM_CONTEXT_TAG                'cSxC'
#define CTX_STREAMHANDLE_CONTEXT_TAG          'cHxC'
#define CTX_SIGN_TAG						  'nSxC'
#define CTX_BUFFER_TAG						  'fBxC'

#define MIN_SECTOR_SIZE 0x200

typedef struct _CTX_INSTANCE_CONTEXT {

    PFLT_INSTANCE Instance;

    PFLT_VOLUME Volume;

	//
	//  Volume Name
	//
    UNICODE_STRING VolumeName;

	//
	//  Instance Name
	//
	UNICODE_STRING InstanceName;

	UNICODE_STRING AltitudeName;

	ULONG Altitude;
	
	ULONG SectorSize;

	UNICODE_STRING DosName;

	ULONG DeviceType;

	PERESOURCE Resource;

	//
	//  Cancel safe queue members
	//
    FLT_CALLBACK_DATA_QUEUE Cbdq;
    LIST_ENTRY QueueHead;
    FAST_MUTEX QueueLock;

    volatile LONG WorkerThreadFlag;

    PKEVENT TeardownEvent;

} CTX_INSTANCE_CONTEXT, *PCTX_INSTANCE_CONTEXT;

#define CTX_INSTANCE_CONTEXT_SIZE		sizeof( CTX_INSTANCE_CONTEXT )

typedef struct _CTX_STREAM_CONTEXT {

    UNICODE_STRING FileName;

	PVOID FsContext;

    ULONG CreateCount;

    ULONG CleanupCount;

    ULONG CloseCount;

    ERESOURCE Resource;
	
	KSPIN_LOCK Lock;
	LARGE_INTEGER FileSize;
	LARGE_INTEGER ValidDataLength;

	BOOLEAN EncryptFile;
	BOOLEAN EncryptFolder;
	BOOLEAN DecryptOnRead;

	ULONG SignLength;

} CTX_STREAM_CONTEXT, *PCTX_STREAM_CONTEXT;

#define CTX_STREAM_CONTEXT_SIZE			sizeof( CTX_STREAM_CONTEXT )


typedef struct _CTX_STREAMHANDLE_CONTEXT {

    UNICODE_STRING FileName;

    PERESOURCE Resource;

} CTX_STREAMHANDLE_CONTEXT, *PCTX_STREAMHANDLE_CONTEXT;

#define CTX_STREAMHANDLE_CONTEXT_SIZE	sizeof( CTX_STREAMHANDLE_CONTEXT )


NTSTATUS
CtxInstanceSetup (
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_INSTANCE_SETUP_FLAGS Flags,
    __in DEVICE_TYPE VolumeDeviceType,
    __in FLT_FILESYSTEM_TYPE VolumeFilesystemType
    );

NTSTATUS
CtxInstanceQueryTeardown (
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );

VOID
CtxInstanceTeardownStart (
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

VOID
CtxInstanceTeardownComplete (
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

VOID
CtxContextCleanup (
    __in PFLT_CONTEXT Context,
    __in FLT_CONTEXT_TYPE ContextType
    );

FLT_PREOP_CALLBACK_STATUS
CtxPreOperationCallback (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    );

FLT_POSTOP_CALLBACK_STATUS
CtxPostOperationCallback (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
CtxPreCreate (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    );

FLT_POSTOP_CALLBACK_STATUS
CtxPostCreate (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __inout_opt PVOID CbdContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
CtxPreCleanup (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    );

FLT_PREOP_CALLBACK_STATUS
CtxPreClose (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    );

FLT_PREOP_CALLBACK_STATUS
CtxPreRead (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    );

FLT_POSTOP_CALLBACK_STATUS
CtxPostRead (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __inout_opt PVOID CbdContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    );

FLT_POSTOP_CALLBACK_STATUS
CtxPostReadWhenSafe (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
CtxPreWrite (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    );

FLT_POSTOP_CALLBACK_STATUS
CtxPostWrite (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __inout_opt PVOID CbdContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
CtxPreQueryInfo (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    );

FLT_POSTOP_CALLBACK_STATUS
CtxPostQueryInfo (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __inout_opt PVOID CbdContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
CtxPreSetInfo (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    );

FLT_POSTOP_CALLBACK_STATUS
CtxPostSetInfoWhenSafe (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    );

FLT_POSTOP_CALLBACK_STATUS
CtxPostSetInfo (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __inout_opt PVOID CbdContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
CtxPreDirCtrl (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    );

FLT_POSTOP_CALLBACK_STATUS
CtxPostDirCtrl (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __inout_opt PVOID CbdContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    );

FLT_POSTOP_CALLBACK_STATUS
CtxPostDirCtrlWhenSafe (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    );

NTSTATUS
CtxProcessDirCtrl (
	__inout PFLT_CALLBACK_DATA Cbd,
	__in PCTX_STREAM_CONTEXT StreamContext,
	__inout PVOID Buffer
	);


NTSTATUS
CtxFindOrCreateStreamContext (
    __in PFLT_CALLBACK_DATA Cbd,
    __in BOOLEAN CreateIfNotFound,
    __deref_out PCTX_STREAM_CONTEXT *StreamContext,
    __out_opt PBOOLEAN ContextCreated
    );

NTSTATUS
CtxCreateStreamContext (
    __deref_out PCTX_STREAM_CONTEXT *StreamContext
    );


NTSTATUS
CtxUpdateNameInStreamContext (
    __in PUNICODE_STRING DirectoryName,
    __inout PCTX_STREAM_CONTEXT StreamContext
    );

NTSTATUS
CtxCreateOrReplaceStreamHandleContext (
    __in PFLT_CALLBACK_DATA Cbd,
    __in BOOLEAN ReplaceIfExists,
    __deref_out PCTX_STREAMHANDLE_CONTEXT *StreamHandleContext,
    __out_opt PBOOLEAN ContextReplaced
    );

NTSTATUS
CtxCreateStreamHandleContext (
    __deref_out PCTX_STREAMHANDLE_CONTEXT *StreamHandleContext
    );

NTSTATUS
CtxUpdateNameInStreamHandleContext (
    __in PUNICODE_STRING DirectoryName,
    __inout PCTX_STREAMHANDLE_CONTEXT StreamHandleContext
    );


NTSTATUS
CtxAllocateUnicodeString (
    __inout PUNICODE_STRING String
    );

VOID
CtxFreeUnicodeString (
    __inout PUNICODE_STRING String
    );

FORCEINLINE
PERESOURCE
CtxAllocateResource (
    VOID
    )
{
    return ExAllocatePoolWithTag( NonPagedPool,
                                  sizeof( ERESOURCE ),
                                  CTX_RESOURCE_TAG );
}

FORCEINLINE
VOID
CtxFreeResource (
    __inout PERESOURCE Resource
    )
{
    ExFreePoolWithTag( Resource,
                       CTX_RESOURCE_TAG );
}

static PCHAR GlobalIrqlString[] = {
	"PASSIVE",
	"APC",
	"DISPATCH",
	"UNKNOWN"
};

FORCEINLINE
VOID
CtxAcquireResourceExclusive (
    __inout PERESOURCE Resource
    )
{
	KIRQL Irql, NewIrql;
	
    ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
    ASSERT(ExIsResourceAcquiredExclusiveLite(Resource) ||
           !ExIsResourceAcquiredSharedLite(Resource));

	Irql = KeGetCurrentIrql();

    KeEnterCriticalRegion();
    (VOID)ExAcquireResourceExclusiveLite( Resource, TRUE );

	NewIrql = KeGetCurrentIrql();

	DebugTrace(DEBUG_TRACE_INFO, ("[Ctx]: Irql -> %s, NewIrql -> %s\n", GlobalIrqlString[(int)Irql], GlobalIrqlString[(int)NewIrql]));
}

FORCEINLINE
VOID
CtxAcquireResourceShared (
    __inout PERESOURCE Resource
    )
{
	KIRQL Irql, NewIrql;

    ASSERT(KeGetCurrentIrql() <= APC_LEVEL);

	Irql = KeGetCurrentIrql();

    KeEnterCriticalRegion();
    (VOID)ExAcquireResourceSharedLite( Resource, TRUE );

	NewIrql = KeGetCurrentIrql();

	DebugTrace(DEBUG_TRACE_INFO, ("[Ctx]: Irql -> %s, NewIrql -> %s\n", GlobalIrqlString[(int)Irql], GlobalIrqlString[(int)NewIrql]));
}

FORCEINLINE
VOID
CtxReleaseResource (
    __inout PERESOURCE Resource
    )
{
    ASSERT(KeGetCurrentIrql() <= APC_LEVEL);
    ASSERT(ExIsResourceAcquiredExclusiveLite(Resource) ||
           ExIsResourceAcquiredSharedLite(Resource));

    ExReleaseResourceLite(Resource);
    KeLeaveCriticalRegion();
}


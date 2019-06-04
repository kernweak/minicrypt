#include "mefkern.h"

MINIEF_DATA	MiniEfData;

NTSTATUS
DriverEntry (
    __in PDRIVER_OBJECT DriverObject,
    __in PUNICODE_STRING RegistryPath
    );

VOID
MiniReadDriverParameters (
    __in PUNICODE_STRING RegistryPath
    );

NTSTATUS
MiniMessage (
    __in PVOID ConnectionCookie,
    __in_bcount_opt(InputBufferSize) PVOID InputBuffer,
    __in ULONG InputBufferSize,
    __out_bcount_part_opt(OutputBufferSize,*ReturnOutputBufferLength) PVOID OutputBuffer,
    __in ULONG OutputBufferSize,
    __out PULONG ReturnOutputBufferLength
    );

NTSTATUS
MiniConnect(
    __in PFLT_PORT ClientPort,
    __in PVOID ServerPortCookie,
    __in_bcount(SizeOfContext) PVOID ConnectionContext,
    __in ULONG SizeOfContext,
    __deref_out_opt PVOID *ConnectionCookie
    );

VOID
MiniDisconnect(
    __in_opt PVOID ConnectionCookie
    );

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, MiniReadDriverParameters)
#pragma alloc_text(PAGE, MiniFilterUnload)
#pragma alloc_text(PAGE, MiniConnect)
#pragma alloc_text(PAGE, MiniDisconnect)
#pragma alloc_text(PAGE, MiniMessage)
#pragma alloc_text(PAGE, MiniPreOperationCallback)
#endif

#define SetFlagInterlocked(_ptrFlags,_flagToSet) \
    ((VOID)InterlockedOr(((volatile LONG *)(_ptrFlags)),_flagToSet))

NTSTATUS
DriverEntry (
    __in PDRIVER_OBJECT DriverObject,
    __in PUNICODE_STRING RegistryPath
    )
{
    PSECURITY_DESCRIPTOR Sd;
    OBJECT_ATTRIBUTES Oa;
    UNICODE_STRING UniString;
    NTSTATUS Status;

	PAGED_CODE();

    try {

        MiniEfData.LogSequenceNumber = 0;
        MiniEfData.MaxRecordsToAllocate = DEFAULT_MAX_RECORDS_TO_ALLOCATE;
        MiniEfData.RecordsAllocated = 0;
        MiniEfData.NameQueryMethod = DEFAULT_NAME_QUERY_METHOD;
	
        MiniEfData.DriverObject = DriverObject;

		MiniEfData.DebugLevels = DEBUG_TRACE_ERROR|DEBUG_TRACE_LOAD_UNLOAD|DEBUG_TRACE_INSTANCE_CONTEXT_OPERATIONS;

		MiniEfData.DebugFlags = 0xFFFFFFFF;

		DebugTrace (DEBUG_TRACE_LOAD_UNLOAD, ("[Mini] Start!\n"));

        InitializeListHead( &MiniEfData.OutputBufferList );
        KeInitializeSpinLock( &MiniEfData.OutputBufferLock );

        ExInitializeNPagedLookasideList( &MiniEfData.FreeBufferList,
                                         NULL,
                                         NULL,
                                         0,
                                         RECORD_SIZE,
                                         MINI_TAG,
                                         0 );

        ExInitializeNPagedLookasideList( &MiniEfData.CompletionContextList,
                                         NULL,
                                         NULL,
                                         0,
                                         COMPLETION_CONTEXT_SIZE,
                                         MINI_TAG,
                                         0 );

		MiniReadDriverParameters(RegistryPath);

        Status = FltRegisterFilter( DriverObject,
                                    &FilterRegistration,
                                    &MiniEfData.Filter );

        if (!NT_SUCCESS( Status )) {

			DebugTrace( DEBUG_TRACE_ERROR, 
						("[Mini] Failed To FltRegisterFilter Status = %x\n", Status) );

			leave;
        }

        Status  = FltBuildDefaultSecurityDescriptor( &Sd,
                                                     FLT_PORT_ALL_ACCESS );

        if (!NT_SUCCESS( Status )) {

			DebugTrace( DEBUG_TRACE_ERROR, 
						("[Mini] Failed To FltBuildDefaultSecurityDescriptor Status = %x\n", Status) );

            leave;
        }

        RtlInitUnicodeString( &UniString, MINIEF_PORT_NAME );

        InitializeObjectAttributes( &Oa,
                                    &UniString,
                                    OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                                    NULL,
                                    Sd );

        Status = FltCreateCommunicationPort( MiniEfData.Filter,
                                             &MiniEfData.ServerPort,
                                             &Oa,
                                             NULL,
                                             MiniConnect,
                                             MiniDisconnect,
                                             MiniMessage,
                                             1 );

        FltFreeSecurityDescriptor( Sd );

        if (!NT_SUCCESS( Status )) {

			DebugTrace( DEBUG_TRACE_ERROR, 
						("[Mini] Failed To FltCreateCommunicationPort Status = %x\n", Status) );

            leave;
        }

        Status = FltStartFiltering( MiniEfData.Filter );

        if (!NT_SUCCESS( Status )) {

			DebugTrace( DEBUG_TRACE_ERROR, 
						("[Mini] Failed To FltStartFiltering Status = %x\n", Status) );

        }

    } finally {

        if (!NT_SUCCESS( Status ) ) {

             if (NULL != MiniEfData.ServerPort) {
                 FltCloseCommunicationPort( MiniEfData.ServerPort );
             }

             if (NULL != MiniEfData.Filter) {
                 FltUnregisterFilter( MiniEfData.Filter );
             }

			 ExDeleteNPagedLookasideList( &MiniEfData.FreeBufferList );

			 ExDeleteNPagedLookasideList( &MiniEfData.CompletionContextList );
        }
    }

	if (!NT_SUCCESS (Status)) {

		DebugTrace (DEBUG_TRACE_LOAD_UNLOAD, ("[Mini] Start Failed %x\n", Status));

	} else {

		DebugTrace (DEBUG_TRACE_LOAD_UNLOAD, ("[Mini] Start Success\n"));
	}

    return Status;
}

VOID
MiniReadDriverParameters (
    __in PUNICODE_STRING RegistryPath
    )
{
    OBJECT_ATTRIBUTES Oa;
    HANDLE DriverRegKey;
    NTSTATUS Status;
    ULONG ResultLength;
    UNICODE_STRING ValueName;
    PKEY_VALUE_PARTIAL_INFORMATION ValuePartialInfo;
    UCHAR Buffer[sizeof( KEY_VALUE_PARTIAL_INFORMATION ) + sizeof( LONG )];

	PAGED_CODE();

    InitializeObjectAttributes( &Oa,
                                RegistryPath,
                                OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                NULL,
                                NULL );

    Status = ZwOpenKey( &DriverRegKey,
                        KEY_READ,
                        &Oa );

    if (!NT_SUCCESS( Status )) {

        return;
    }

    RtlInitUnicodeString( &ValueName, MAX_RECORDS_TO_ALLOCATE );

    Status = ZwQueryValueKey( DriverRegKey,
                              &ValueName,
                              KeyValuePartialInformation,
                              Buffer,
                              sizeof(Buffer),
                              &ResultLength );

    if (NT_SUCCESS( Status )) {

        ValuePartialInfo = (PKEY_VALUE_PARTIAL_INFORMATION) Buffer;
        ASSERT( ValuePartialInfo->Type == REG_DWORD );
        MiniEfData.MaxRecordsToAllocate = *((PLONG)&(ValuePartialInfo->Data));
    }

    RtlInitUnicodeString( &ValueName, NAME_QUERY_METHOD );

    Status = ZwQueryValueKey( DriverRegKey,
                              &ValueName,
                              KeyValuePartialInformation,
                              Buffer,
                              sizeof(Buffer),
                              &ResultLength );

    if (NT_SUCCESS( Status )) {

        ValuePartialInfo = (PKEY_VALUE_PARTIAL_INFORMATION) Buffer;
        ASSERT( ValuePartialInfo->Type == REG_DWORD );
        MiniEfData.NameQueryMethod = *((PLONG)&(ValuePartialInfo->Data));
    }

    ZwClose(DriverRegKey);
}

NTSTATUS
MiniConnect(
    __in PFLT_PORT ClientPort,
    __in PVOID ServerPortCookie,
    __in_bcount(SizeOfContext) PVOID ConnectionContext,
    __in ULONG SizeOfContext,
    __deref_out_opt PVOID *ConnectionCookie
    )
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER( ServerPortCookie );
    UNREFERENCED_PARAMETER( ConnectionContext );
    UNREFERENCED_PARAMETER( SizeOfContext);
    UNREFERENCED_PARAMETER( ConnectionCookie );

    ASSERT( MiniEfData.ClientPort == NULL );
    MiniEfData.ClientPort = ClientPort;

    return STATUS_SUCCESS;
}

VOID
MiniDisconnect(
    __in_opt PVOID ConnectionCookie
   )
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER( ConnectionCookie );

    FltCloseClientPort( MiniEfData.Filter, &MiniEfData.ClientPort );
}

NTSTATUS
MiniFilterUnload (
    __in FLT_FILTER_UNLOAD_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    FltCloseCommunicationPort( MiniEfData.ServerPort );

    FltUnregisterFilter( MiniEfData.Filter );

    SpyEmptyOutputBufferList();
    ExDeleteNPagedLookasideList( &MiniEfData.FreeBufferList );
	ExDeleteNPagedLookasideList( &MiniEfData.CompletionContextList );

	DebugTrace (DEBUG_TRACE_LOAD_UNLOAD, ("[Mini] Unload\n"));

    return STATUS_SUCCESS;
}

NTSTATUS
MiniMessage (
    __in PVOID ConnectionCookie,
    __in_bcount_opt(InputBufferSize) PVOID InputBuffer,
    __in ULONG InputBufferSize,
    __out_bcount_part_opt(OutputBufferSize,*ReturnOutputBufferLength) PVOID OutputBuffer,
    __in ULONG OutputBufferSize,
    __out PULONG ReturnOutputBufferLength
    )
{
    MINIEF_COMMAND Command;
    NTSTATUS Status;

    PAGED_CODE();

    UNREFERENCED_PARAMETER( ConnectionCookie );

    if ((InputBuffer != NULL) &&
        (InputBufferSize >= (FIELD_OFFSET(COMMAND_MESSAGE,Command) +
                             sizeof(MINIEF_COMMAND)))) {

        try  {

            Command = ((PCOMMAND_MESSAGE) InputBuffer)->Command;

        } except( EXCEPTION_EXECUTE_HANDLER ) {

            return GetExceptionCode();
        }

        switch (Command) {

            case GetMiniEfLog:

                if ((OutputBuffer == NULL) || (OutputBufferSize == 0)) {

                    Status = STATUS_INVALID_PARAMETER;
                    break;
                }

#if defined(_WIN64)
                if (IoIs32bitProcess( NULL )) {

                    if (!IS_ALIGNED(OutputBuffer,sizeof(ULONG))) {

                        Status = STATUS_DATATYPE_MISALIGNMENT;
                        break;
                    }

                } else {
#endif

                    if (!IS_ALIGNED(OutputBuffer,sizeof(PVOID))) {

                        Status = STATUS_DATATYPE_MISALIGNMENT;
                        break;
                    }

#if defined(_WIN64)
                }
#endif

                Status = SpyGetLog( OutputBuffer,
                                    OutputBufferSize,
                                    ReturnOutputBufferLength );
                break;


            case GetMiniEfVersion:

                if ((OutputBufferSize < sizeof( MINIEFVER )) ||
                    (OutputBuffer == NULL)) {

                    Status = STATUS_INVALID_PARAMETER;
                    break;
                }

                if (!IS_ALIGNED(OutputBuffer,sizeof(ULONG))) {

                    Status = STATUS_DATATYPE_MISALIGNMENT;
                    break;
                }

                try {

                    ((PMINIEFVER)OutputBuffer)->Major = MINIEF_MAJ_VERSION;
                    ((PMINIEFVER)OutputBuffer)->Minor = MINIEF_MIN_VERSION;

                } except( EXCEPTION_EXECUTE_HANDLER ) {

                      return GetExceptionCode();
                }

                *ReturnOutputBufferLength = sizeof( MINIEFVER );
                Status = STATUS_SUCCESS;
                break;

            default:
                Status = STATUS_INVALID_PARAMETER;
                break;
        }

    } else {

        Status = STATUS_INVALID_PARAMETER;
    }

    return Status;
}

PCOMPLETION_CONTEXT
MiniAllocateContext (
	VOID
    )
{
	PCOMPLETION_CONTEXT CompCtx;

	CompCtx = ExAllocateFromNPagedLookasideList( &MiniEfData.CompletionContextList );

	RtlZeroMemory (CompCtx, sizeof(COMPLETION_CONTEXT));

	return CompCtx;
}

VOID
MiniFreeContext (
    __in PVOID Buffer
    )
{
	PCOMPLETION_CONTEXT CompCtx = (PCOMPLETION_CONTEXT)Buffer;

	if (CompCtx->Instance) {

		FltReleaseContext( CompCtx->Instance );
	}

	if (CompCtx->Stream) {

		FltReleaseContext( CompCtx->Stream );
	}

    ExFreeToNPagedLookasideList( &MiniEfData.CompletionContextList, Buffer );
}

VOID
MiniPreInfo (
	__inout PFLT_CALLBACK_DATA Cbd
	)
{
	BOOLEAN FastIo = FALSE, FsFilter = FALSE;
	PUCHAR FlagString = "None";
	PUCHAR MajorString = "None";

	PAGED_CODE();

	//FastIo = FLT_IS_FASTIO_OPERATION(Cbd);
	//FsFilter = FLT_IS_FS_FILTER_OPERATION(Cbd);

	if ( BooleanFlagOn( Cbd->Flags, FLTFL_CALLBACK_DATA_FAST_IO_OPERATION ) ) {

		FastIo = TRUE;
		FlagString = "FAST_IO   -> ";

	} else if( BooleanFlagOn( Cbd->Flags, FLTFL_CALLBACK_DATA_FS_FILTER_OPERATION ) ) {

		FsFilter = TRUE;
		FlagString = "FS_FILTER -> ";
		
	} else if( BooleanFlagOn( Cbd->Flags, FLTFL_CALLBACK_DATA_IRP_OPERATION ) ) {

		FlagString = "IRP       -> ";
	}

	switch ( Cbd->Iopb->MajorFunction ) {

		case IRP_MJ_CREATE:
			MajorString = "IRP_MJ_CREATE";
			break;

		case IRP_MJ_CREATE_NAMED_PIPE:
			MajorString = "IRP_MJ_CREATE_NAMED_PIPE";
			break;
		
		case IRP_MJ_CLOSE:
			MajorString = "IRP_MJ_CLOSE";
			break;

		case IRP_MJ_READ:
			if( FastIo )
				MajorString = "FastIoRead";
			else
				MajorString = "IRP_MJ_READ";
			break;

		case IRP_MJ_WRITE:
			if( FastIo )
				MajorString = "FastIoWrite";
			else
				MajorString = "IRP_MJ_WRITE";
			break;
		
		case IRP_MJ_QUERY_INFORMATION:
			if( FastIo ) {
				FILE_INFORMATION_CLASS FileInfoClass = Cbd->Iopb->Parameters.QueryFileInformation.FileInformationClass;
				switch( FileInfoClass ) {
					case FileStandardInformation:
						MajorString = "FastIoQueryStandardInfo";
						break;
					case FileBasicInformation:
						MajorString = "FastIoQueryBasicInfo";
						break;
					case FileNetworkOpenInformation:
						MajorString = "FastIoQueryNetworkOpenInfo";
						break;
					default:
						ASSERT( FALSE );
				}
			} else {
				MajorString = "IRP_MJ_QUERY_INFORMATION";
			}
			break;

		case IRP_MJ_SET_INFORMATION:
			MajorString = "IRP_MJ_SET_INFORMATION";
			break;

		case IRP_MJ_QUERY_EA:
			MajorString = "IRP_MJ_QUERY_EA";
			break;
		
		case IRP_MJ_SET_EA:
			MajorString = "IRP_MJ_SET_EA";
			break;

		case IRP_MJ_FLUSH_BUFFERS:
			MajorString = "IRP_MJ_FLUSH_BUFFERS";
			break;

		case IRP_MJ_QUERY_VOLUME_INFORMATION:
			MajorString = "IRP_MJ_QUERY_VOLUME_INFORMATION";
			break;
		
		case IRP_MJ_SET_VOLUME_INFORMATION:
			MajorString = "IRP_MJ_SET_VOLUME_INFORMATION";
			break;

		case IRP_MJ_DIRECTORY_CONTROL:
			MajorString = "IRP_MJ_DIRECTORY_CONTROL";
			break;

		case IRP_MJ_FILE_SYSTEM_CONTROL:
			MajorString = "IRP_MJ_FILE_SYSTEM_CONTROL";
			break;
		
		case IRP_MJ_DEVICE_CONTROL:
			if( FastIo )
				MajorString = "FastIoDeviceControl";
			else
				MajorString = "IRP_MJ_DEVICE_CONTROL";
			break;

		case IRP_MJ_INTERNAL_DEVICE_CONTROL:
			if( FastIo )
				MajorString = "FastIoDeviceControl";
			else
				MajorString = "IRP_MJ_INTERNAL_DEVICE_CONTROL";
			break;

		case IRP_MJ_SHUTDOWN:
			MajorString = "IRP_MJ_SHUTDOWN";
			break;
		
		case IRP_MJ_LOCK_CONTROL:
			if( FastIo ) {
				switch( Cbd->Iopb->MinorFunction ) {
					case IRP_MN_LOCK:
						MajorString = "FastIoLock";
						break;
					case IRP_MN_UNLOCK_SINGLE:
						MajorString = "FastIoUnlockSingle";
						break;
					case IRP_MN_UNLOCK_ALL:
						MajorString = "FastIoUnlockAll";
						break;
					case IRP_MN_UNLOCK_ALL_BY_KEY:
						MajorString = "FastIoUnlockAllByKey";
						break;
					default:
						ASSERT( FALSE );
						break;
				}

			} else {
				MajorString = "IRP_MJ_LOCK_CONTROL";
			}
			break;

		case IRP_MJ_CLEANUP:
			MajorString = "IRP_MJ_CLEANUP";
			break;

		case IRP_MJ_CREATE_MAILSLOT:
			MajorString = "IRP_MJ_CREATE_MAILSLOT";
			break;
		
		case IRP_MJ_QUERY_SECURITY:
			MajorString = "IRP_MJ_QUERY_SECURITY";
			break;

		case IRP_MJ_SET_SECURITY:
			MajorString = "IRP_MJ_SET_SECURITY";
			break;

		case IRP_MJ_QUERY_QUOTA:
			MajorString = "IRP_MJ_QUERY_QUOTA";
			break;
		
		case IRP_MJ_SET_QUOTA:
			MajorString = "IRP_MJ_SET_QUOTA";
			break;

		case IRP_MJ_PNP:
			MajorString = "IRP_MJ_PNP";
			break;

		//
		//  在文件过滤驱动中看不到以下几个FastIo调用, 只能通过SF_FILTER才能看到
		//

		case IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION:
			ASSERT( FsFilter );
			if( FastIo )
				MajorString = "AcquireFileForNtCreateSection";
			else
				MajorString = "AcquireForSectionSynchronization";
			break;
		
		case IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION:
			ASSERT( FsFilter );
			if( FastIo )
				MajorString = "ReleaseFileForNtCreateSection";
			else
				MajorString = "ReleaseForSectionSynchronization";
			break;

		case IRP_MJ_ACQUIRE_FOR_MOD_WRITE:
			ASSERT( FsFilter );
			if( FastIo )
				MajorString = "AcquireForModWrite";
			else
				MajorString = "AcquireForModifiedPageWriter";
			break;

		case IRP_MJ_RELEASE_FOR_MOD_WRITE:
			ASSERT( FsFilter );
			if( FastIo )
				MajorString = "ReleaseForModWrite";
			else
				MajorString = "ReleaseForModifiedPageWriter";
			break;
		
		case IRP_MJ_ACQUIRE_FOR_CC_FLUSH:
			ASSERT( FsFilter );
			if( FastIo )
				MajorString = "AcquireForCcFlush";
			else
				MajorString = "AcquireForCcFlush";
			break;

		case IRP_MJ_RELEASE_FOR_CC_FLUSH:
			ASSERT( FsFilter );
			if( FastIo )
				MajorString = "ReleaseForCcFlush";
			else
				MajorString = "ReleaseForCcFlush";
			break;


		case IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE:
			ASSERT( FastIo );
			MajorString = "FastIoCheckIfPossible";
			break;
		
		case IRP_MJ_NETWORK_QUERY_OPEN:
			ASSERT( FastIo );
			MajorString = "FastIoQueryOpen";
			break;

		case IRP_MJ_MDL_READ:
			ASSERT( FastIo );
			MajorString = "MdlRead";
			break;

		case IRP_MJ_MDL_READ_COMPLETE:
			ASSERT( FastIo );
			MajorString = "MdlReadComplete";
			break;
		
		case IRP_MJ_PREPARE_MDL_WRITE:
			ASSERT( FastIo );
			MajorString = "PrepareMdlWrite";
			break;

		case IRP_MJ_MDL_WRITE_COMPLETE:
			ASSERT( FastIo );
			MajorString = "MdlWriteComplete";
			break;

		case IRP_MJ_VOLUME_MOUNT:
			ASSERT( FastIo );
			MajorString = "VolumeMount";
			break;
		
		case IRP_MJ_VOLUME_DISMOUNT:
			ASSERT( FastIo );
			MajorString = "VolumeDismount";
			break;
	}

	if( Cbd->Iopb->MajorFunction > 128 ) {

		DebugTrace(DEBUG_TRACE_INFO, ("[Mini] %s %s[-%d]\n", FlagString, MajorString, 256 - Cbd->Iopb->MajorFunction));
	 
	} else {

		DebugTrace(DEBUG_TRACE_INFO, ("[Mini] %s %s[%d]\n", FlagString, MajorString, Cbd->Iopb->MajorFunction));
	}

	if( !Cbd->Iopb->TargetInstance ) {
		
		if( !Cbd->Iopb->TargetFileObject ) {
			DebugTrace(DEBUG_TRACE_INFO, ("[Mini] TargetInstance And FileObject Is NULL\n"));
		} else {
			DebugTrace(DEBUG_TRACE_INFO, ("[Mini] TargetInstance Is NULL %wZ\n", Cbd->Iopb->TargetFileObject->FileName));
		}
	}
}

FLT_PREOP_CALLBACK_STATUS
MiniPreOperationCallback (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
	FLT_PREOP_CALLBACK_STATUS ReturnStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
	NTSTATUS Status;
	ULONG Altitude;
	PCOMPLETION_CONTEXT CompCtx;
	PCTX_INSTANCE_CONTEXT InstanceContext = NULL;

	PAGED_CODE();

	MiniPreInfo( Cbd );

	if( !Cbd->Iopb->TargetInstance ) {

		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	CompCtx = MiniAllocateContext();
	if( !CompCtx ) {

        DebugTrace( DEBUG_TRACE_INSTANCE_CONTEXT_OPERATIONS | DEBUG_TRACE_ERROR,
                    ("[Mini]: MiniPreOperationCallback -> Failed to allocation completion context (Cbd = %p, FileObject = %p)\n",
                     Cbd,
                     FltObjects->FileObject) );
    
        return ReturnStatus;
	}

    Status = FltGetInstanceContext( Cbd->Iopb->TargetInstance,
                                    &InstanceContext );

	if( !NT_SUCCESS( Status ) ) {

        DebugTrace( DEBUG_TRACE_INSTANCE_CONTEXT_OPERATIONS | DEBUG_TRACE_ERROR,
                    ("[Mini]: MiniPreOperationCallback -> Failed to get instance context (Cbd = %p, FileObject = %p)\n",
                     Cbd,
                     FltObjects->FileObject) );
    
		MiniFreeContext(CompCtx);

        return ReturnStatus;
	}

	Altitude = InstanceContext->Altitude;

	CompCtx->Instance = InstanceContext;
	*CompletionContext = CompCtx;

	switch( Altitude ) {

		case INSTANCE_TOP_MONITOR:
		case INSTANCE_BOTTOM_MONITOR:

			//ReturnStatus = SpyPreOperationCallback( Altitude,
			//										  Cbd,
			//										  FltObjects,
			//										  CompletionContext );
			break;

		case INSTANCE_ENCRYPT_FOLDER:

			ReturnStatus = CtxPreOperationCallback( Cbd,
													FltObjects,
													CompletionContext );
			break;

		default:

			ASSERT (FALSE);
			break;
	}

	if( ReturnStatus != FLT_PREOP_SUCCESS_WITH_CALLBACK &&
		ReturnStatus != FLT_PREOP_SYNCHRONIZE ) {

		MiniFreeContext( CompCtx );
		*CompletionContext = NULL;
	}

	return ReturnStatus;
}

FLT_POSTOP_CALLBACK_STATUS
MiniPostOperationCallback (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    )
{
	FLT_POSTOP_CALLBACK_STATUS ReturnStatus = FLT_POSTOP_FINISHED_PROCESSING;
	PCOMPLETION_CONTEXT CompCtx = (PCOMPLETION_CONTEXT)CompletionContext;
	ULONG Altitude = CompCtx->Instance->Altitude;

	switch (Altitude) {

		case INSTANCE_TOP_MONITOR:
		case INSTANCE_BOTTOM_MONITOR:

			ReturnStatus = SpyPostOperationCallback( Cbd,
											FltObjects,
											CompCtx->Record.RecordList,
											Flags );
			break;

		case INSTANCE_ENCRYPT_FOLDER:

			ReturnStatus = CtxPostOperationCallback( Cbd,
											FltObjects,
											CompCtx,
											Flags );
			break;

		default:

			ASSERT (FALSE);
			break;
	}
	
	if (ReturnStatus < FLT_POSTOP_WITHOUT_FREE_CONTEXT) {
		
		MiniFreeContext( CompCtx );

	} else {

		ReturnStatus -= FLT_POSTOP_WITHOUT_FREE_CONTEXT;
	}

	return ReturnStatus;
}
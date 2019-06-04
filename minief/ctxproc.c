#include "mefkern.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, CtxAllocateUnicodeString)
#pragma alloc_text(PAGE, CtxFreeUnicodeString)
#pragma alloc_text(PAGE, CtxInstanceSetup)
#pragma alloc_text(PAGE, CtxInstanceQueryTeardown)
#pragma alloc_text(PAGE, CtxInstanceTeardownStart)
#pragma alloc_text(PAGE, CtxInstanceTeardownComplete)
#pragma alloc_text(PAGE, CtxContextCleanup)
#pragma alloc_text(PAGE, CtxFindOrCreateStreamContext)
#pragma alloc_text(PAGE, CtxCreateStreamContext)
#pragma alloc_text(PAGE, CtxUpdateNameInStreamContext)
#pragma alloc_text(PAGE, CtxCreateOrReplaceStreamHandleContext)
#pragma alloc_text(PAGE, CtxCreateStreamHandleContext)
#pragma alloc_text(PAGE, CtxUpdateNameInStreamHandleContext)
#endif

NTSTATUS
CtxAllocateUnicodeString (
    __inout PUNICODE_STRING String
    )
{
    PAGED_CODE();

    String->Buffer = ExAllocatePoolWithTag( NonPagedPool,
                                            String->MaximumLength,
                                            CTX_STRING_TAG );

    if (String->Buffer == NULL) {

        DebugTrace( DEBUG_TRACE_ERROR,
                    ("[Ctx]: CtxAllocateUnicodeString -> Failed to allocate unicode string of size 0x%x\n",
                    String->MaximumLength) );

        return STATUS_INSUFFICIENT_RESOURCES;
    }

    String->Length = 0;

    return STATUS_SUCCESS;
}

VOID
CtxFreeUnicodeString (
    __inout PUNICODE_STRING String
    )
{
    PAGED_CODE();

    ExFreePoolWithTag( String->Buffer,
                       CTX_STRING_TAG );

    String->Length = String->MaximumLength = 0;
    String->Buffer = NULL;
}

NTSTATUS
CtxInstanceSetup (
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_INSTANCE_SETUP_FLAGS Flags,
    __in DEVICE_TYPE VolumeDeviceType,
    __in FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
{
    PCTX_INSTANCE_CONTEXT InstanceContext = NULL;
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG VolumeNameLength;
	PINSTANCE_PARTIAL_INFORMATION InstPartInf;
	CHAR InstPartInfBuffer[128];
	ULONG InstPartInfLength = 128;
	ULONG RetLength;
	UNICODE_STRING TopMonitorName;
	UNICODE_STRING BottomMonitorName;
	UNICODE_STRING EncCompName;
	PDEVICE_OBJECT DeviceObject = NULL;
	PDEVICE_OBJECT RealDevice = NULL;
	PVOID VolPropBuffer = NULL;
	PFLT_VOLUME_PROPERTIES VolProp;

    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( VolumeDeviceType );
    UNREFERENCED_PARAMETER( VolumeFilesystemType );

    PAGED_CODE();

    Status = FltAllocateContext( FltObjects->Filter,
                                 FLT_INSTANCE_CONTEXT,
                                 CTX_INSTANCE_CONTEXT_SIZE,
                                 NonPagedPool,
                                 &InstanceContext );

    if (!NT_SUCCESS( Status )) {

        DebugTrace( DEBUG_TRACE_INSTANCE_CONTEXT_OPERATIONS | DEBUG_TRACE_ERROR,
                    ("[Ctx]: CtxInstanceSetup -> Failed to allocate instance context (Volume = %p, Instance = %p, Status = 0x%x)\n",
                     FltObjects->Volume,
                     FltObjects->Instance,
                     Status) );

        return Status;
    }

	RtlZeroMemory( InstanceContext, CTX_INSTANCE_CONTEXT_SIZE );

    InstanceContext->Resource = CtxAllocateResource();
    if( InstanceContext->Resource == NULL ) {

        FltReleaseContext( InstanceContext );
        return STATUS_INSUFFICIENT_RESOURCES;
    }
	ExInitializeResourceLite( InstanceContext->Resource );

    Status = FltGetVolumeName( FltObjects->Volume, NULL, &VolumeNameLength );

    if( !NT_SUCCESS( Status ) &&
        (Status != STATUS_BUFFER_TOO_SMALL) ) {

        DebugTrace( DEBUG_TRACE_INSTANCE_CONTEXT_OPERATIONS | DEBUG_TRACE_ERROR,
                    ("[Ctx]: CtxInstanceSetup -> Unexpected failure in FltGetVolumeName. (Volume = %p, Instance = %p, Status = 0x%x)\n",
                     FltObjects->Volume,
                     FltObjects->Instance,
                     Status) );

        goto CtxInstanceSetupCleanup;
    }

    InstanceContext->VolumeName.MaximumLength = (USHORT) VolumeNameLength;
    Status = CtxAllocateUnicodeString( &InstanceContext->VolumeName );

    if( !NT_SUCCESS( Status )) {

        DebugTrace( DEBUG_TRACE_INSTANCE_CONTEXT_OPERATIONS | DEBUG_TRACE_ERROR,
                    ("[Ctx]: CtxInstanceSetup -> Failed to allocate volume name string. (Volume = %p, Instance = %p, Status = 0x%x)\n",
                     FltObjects->Volume,
                     FltObjects->Instance,
                     Status) );

        goto CtxInstanceSetupCleanup;
    }

    Status = FltGetVolumeName( FltObjects->Volume, &InstanceContext->VolumeName, &VolumeNameLength );

    if( !NT_SUCCESS( Status ) ) {

        DebugTrace( DEBUG_TRACE_INSTANCE_CONTEXT_OPERATIONS | DEBUG_TRACE_ERROR,
                    ("[Ctx]: CtxInstanceSetup -> Unexpected failure in FltGetVolumeName. (Volume = %p, Instance = %p, Status = 0x%x)\n",
                     FltObjects->Volume,
                     FltObjects->Instance,
                     Status) );

        goto CtxInstanceSetupCleanup;
    }

	VolPropBuffer = ExAllocatePoolWithTag( NonPagedPool, 
										   sizeof(FLT_VOLUME_PROPERTIES)+512, 
										   CTX_BUFFER_TAG );
	if (!VolPropBuffer) {

        DebugTrace( DEBUG_TRACE_INSTANCE_CONTEXT_OPERATIONS | DEBUG_TRACE_ERROR,
                    ("[Ctx]: CtxInstanceSetup -> Failed to allocate buffer. (Volume = %p, Instance = %p)\n",
                     FltObjects->Volume,
                     FltObjects->Instance ) );

		Status = STATUS_INSUFFICIENT_RESOURCES;
        goto CtxInstanceSetupCleanup;
	}

	VolProp = (PFLT_VOLUME_PROPERTIES)VolPropBuffer;

	//
	//  Get Volume Properties
	//
	Status = FltGetVolumeProperties( FltObjects->Volume,
                                     VolProp,
									 (sizeof(FLT_VOLUME_PROPERTIES)+512),
									 &RetLength );

    if( !NT_SUCCESS( Status ) ) {

        DebugTrace( DEBUG_TRACE_INSTANCE_CONTEXT_OPERATIONS | DEBUG_TRACE_ERROR,
                    ("[Ctx]: CtxInstanceSetup -> Unexpected failure in FltGetVolumeProperties. (Volume = %p, Instance = %p, Status = 0x%x)\n",
                     FltObjects->Volume,
                     FltObjects->Instance,
                     Status) );

        goto CtxInstanceSetupCleanup;
    }

	ASSERT((VolProp->SectorSize == 0) || (VolProp->SectorSize >= MIN_SECTOR_SIZE));

	InstanceContext->SectorSize = max(VolProp->SectorSize,MIN_SECTOR_SIZE);
	
	Status = FltGetDeviceObject( FltObjects->Volume, &DeviceObject );

	if( !NT_SUCCESS( Status ) ) {

        DebugTrace( DEBUG_TRACE_INSTANCE_CONTEXT_OPERATIONS | DEBUG_TRACE_ERROR,
                    ("[Ctx]: CtxInstanceSetup -> Unexpected failure in FltGetDeviceObject. (Volume = %p, Instance = %p, Status = 0x%x)\n",
                     FltObjects->Volume,
                     FltObjects->Instance,
                     Status) );

        goto CtxInstanceSetupCleanup;

	} else {

		ObDereferenceObject(DeviceObject);
	}

	InstanceContext->DeviceType = DeviceObject->DeviceType;
	
	InstanceContext->DosName.Buffer = NULL;
	
    Status = FltGetDiskDeviceObject( FltObjects->Volume, &RealDevice );

	if (NT_SUCCESS(Status)) {
		
		RtlVolumeDeviceToDosName( RealDevice, &InstanceContext->DosName );

		ObDereferenceObject(RealDevice);
	}

	Status = FltGetInstanceInformation( FltObjects->Instance, 
										InstancePartialInformation,
										InstPartInfBuffer,
										InstPartInfLength,
										&RetLength );
	if( !NT_SUCCESS( Status ) ) {

        DebugTrace( DEBUG_TRACE_INSTANCE_CONTEXT_OPERATIONS | DEBUG_TRACE_ERROR,
                    ("[Ctx]: CtxInstanceSetup -> Unexpected failure in FltGetInstanceInformation. (Volume = %p, Instance = %p, Status = 0x%x)\n",
                     FltObjects->Volume,
                     FltObjects->Instance,
                     Status) );

        goto CtxInstanceSetupCleanup;
	}

	InstPartInf = (PINSTANCE_PARTIAL_INFORMATION)InstPartInfBuffer;

	InstanceContext->InstanceName.MaximumLength = (USHORT)InstPartInf->InstanceNameLength + sizeof(WCHAR);
	Status = CtxAllocateUnicodeString( &InstanceContext->InstanceName );
	InstanceContext->InstanceName.Length = (USHORT)InstPartInf->InstanceNameLength;

	if( !NT_SUCCESS( Status ) ) {

		DebugTrace( DEBUG_TRACE_INSTANCE_CONTEXT_OPERATIONS | DEBUG_TRACE_ERROR,
					("[Ctx]: CtxInstanceSetup -> Failed to allocate instance name string. (Volume = %p, Instance = %p, Status = 0x%x)\n",
					 FltObjects->Volume,
					 FltObjects->Instance,
					 Status) );

		goto CtxInstanceSetupCleanup;
	}

	RtlCopyMemory( InstanceContext->InstanceName.Buffer, 
				   &InstPartInfBuffer[InstPartInf->InstanceNameBufferOffset],
				   InstPartInf->InstanceNameLength );
	InstanceContext->InstanceName.Buffer[InstPartInf->InstanceNameLength/sizeof(WCHAR)] = 0;

	InstanceContext->AltitudeName.MaximumLength = (USHORT)InstPartInf->AltitudeLength + sizeof(WCHAR);
	Status = CtxAllocateUnicodeString( &InstanceContext->AltitudeName );
	InstanceContext->AltitudeName.Length = (USHORT)InstPartInf->AltitudeLength;

	if( !NT_SUCCESS( Status ) ) {

		DebugTrace( DEBUG_TRACE_INSTANCE_CONTEXT_OPERATIONS | DEBUG_TRACE_ERROR,
					("[Ctx]: CtxInstanceSetup -> Failed to allocate altitude string. (Volume = %p, Instance = %p, Status = 0x%x)\n",
					 FltObjects->Volume,
					 FltObjects->Instance,
					 Status) );

		goto CtxInstanceSetupCleanup;
	}

	RtlCopyMemory( InstanceContext->AltitudeName.Buffer, 
				   &InstPartInfBuffer[InstPartInf->AltitudeBufferOffset],
				   InstPartInf->AltitudeLength );
	InstanceContext->AltitudeName.Buffer[InstPartInf->AltitudeLength/sizeof(WCHAR)] = 0;

	RtlInitUnicodeString( &TopMonitorName, INSTANCE_TOP_MONITOR_STR );
	RtlInitUnicodeString( &BottomMonitorName, INSTANCE_BOTTOM_MONITOR_STR );
	RtlInitUnicodeString( &EncCompName, INSTANCE_ENCRYPT_FOLDER_STR );
	
	if( !RtlCompareUnicodeString( &TopMonitorName, &InstanceContext->AltitudeName, TRUE ) ) {
		
		InstanceContext->Altitude = INSTANCE_TOP_MONITOR;

	} else if( !RtlCompareUnicodeString( &BottomMonitorName, &InstanceContext->AltitudeName, TRUE ) ) {

		InstanceContext->Altitude = INSTANCE_BOTTOM_MONITOR;

	} else if( !RtlCompareUnicodeString( &EncCompName, &InstanceContext->AltitudeName, TRUE ) ) {

		InstanceContext->Altitude = INSTANCE_ENCRYPT_FOLDER;

	} else{

		InstanceContext->Altitude = 0;
	}

	//
	//  init cbdq
	//
    Status = FltCbdqInitialize( FltObjects->Instance,
                                &InstanceContext->Cbdq,
                                CsqInsertIo,
                                CsqRemoveIo,
                                CsqPeekNextIo,
                                CsqAcquire,
                                CsqRelease,
                                CsqCompleteCanceledIo );

    if (!NT_SUCCESS( Status )) {

		DebugTrace( DEBUG_TRACE_INSTANCE_CONTEXT_OPERATIONS | DEBUG_TRACE_ERROR,
					("[Csq]: CtxInstanceSetup -> Failed to initialize callback data queue. (Volume = %p, Instance = %p, Status = 0x%x)\n",
					 FltObjects->Volume,
					 FltObjects->Instance,
					 Status) );

		goto CtxInstanceSetupCleanup;
    }

    InstanceContext->TeardownEvent = ExAllocatePoolWithTag( NonPagedPool,
															sizeof( KEVENT ),
															CTX_EVENT_TAG );
	KeInitializeEvent( InstanceContext->TeardownEvent, NotificationEvent, FALSE );

    //
    //  Initialize the internal queue head and lock of the cancel safe queue.
    //
    InitializeListHead( &InstanceContext->QueueHead );
    ExInitializeFastMutex( &InstanceContext->QueueLock );

    InstanceContext->Instance = FltObjects->Instance;
    InstanceContext->Volume = FltObjects->Volume;

    DebugTrace( DEBUG_TRACE_INSTANCE_CONTEXT_OPERATIONS,
		("[Ctx]: CtxInstanceSetup -> Setting instance context %p for \n\t\tvolume:   %wZ\n\t\tdosname:  %wZ (DeviceType = %d, SectionSize = %d) \n\t\tinstance: %wZ \n\t\taltitude: %wZ(%d) \n\t\t(Volume = %p, Instance = %p, Flags = 0x%x)\n",
                 InstanceContext,
                 &InstanceContext->VolumeName,
				 &InstanceContext->DosName,
				 InstanceContext->DeviceType,
				 InstanceContext->SectorSize, 
				 &InstanceContext->InstanceName,
				 &InstanceContext->AltitudeName,
				 InstanceContext->Altitude,
                 FltObjects->Volume,
                 FltObjects->Instance,
				 Flags) );

    Status = FltSetInstanceContext( FltObjects->Instance,
                                    FLT_SET_CONTEXT_KEEP_IF_EXISTS,
                                    InstanceContext,
                                    NULL );

    if( !NT_SUCCESS( Status )) {

        DebugTrace( DEBUG_TRACE_INSTANCE_CONTEXT_OPERATIONS | DEBUG_TRACE_ERROR,
                    ("[Ctx]: CtxInstanceSetup -> Failed to set instance context for volume %wZ (Volume = %p, Instance = %p, Status = 0x%08X)\n",
                     &InstanceContext->VolumeName,
                     FltObjects->Volume,
                     FltObjects->Instance,
                     Status) );
        goto CtxInstanceSetupCleanup;
    }

CtxInstanceSetupCleanup:

	if ( VolPropBuffer ) {
	
		ExFreePoolWithTag (VolPropBuffer, CTX_BUFFER_TAG);
	}

    if ( InstanceContext != NULL ) {

        FltReleaseContext( InstanceContext );
    }

    if (NT_SUCCESS( Status )) {

        DebugTrace( DEBUG_TRACE_INSTANCE_CONTEXT_OPERATIONS,
                    ("[Ctx]: Instance setup complete (Volume = %p, Instance = %p). Filter will attach to the volume.\n",
                     FltObjects->Volume,
                     FltObjects->Instance) );
    } else {

        DebugTrace( DEBUG_TRACE_INSTANCE_CONTEXT_OPERATIONS,
                    ("[Ctx]: Instance setup complete (Volume = %p, Instance = %p). Filter will not attach to the volume.\n",
                     FltObjects->Volume,
                     FltObjects->Instance) );
    }

    return Status;
}

NTSTATUS
CtxInstanceQueryTeardown (
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    DebugTrace( DEBUG_TRACE_INSTANCES,
                ("[Ctx]: CtxInstanceQueryTeardown -> (Instance = %p)\n",
                 FltObjects->Instance) );

    return STATUS_SUCCESS;
}

VOID
CtxInstanceTeardownStart (
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
{
	NTSTATUS Status;
	PCTX_INSTANCE_CONTEXT InstanceContext = NULL;

    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    DebugTrace( DEBUG_TRACE_INSTANCES,
                ("[Ctx]: CtxInstanceTeardownStart -> (Instance = %p)\n",
                 FltObjects->Instance) );

    Status = FltGetInstanceContext( FltObjects->Instance,
                                    &InstanceContext );

	if( !NT_SUCCESS( Status ) ) {

        DebugTrace( DEBUG_TRACE_INSTANCE_CONTEXT_OPERATIONS | DEBUG_TRACE_ERROR,
                    ("[Ctx]: CtxInstanceTeardownStart -> Failed to get instance context (FileObject = %p)\n",
                     FltObjects->FileObject) );
    
		ASSERT( !"Instance Context is missing" );
		return;
	}

    if (!NT_SUCCESS(Status))
    {
        ASSERT( !"Instance Context is missing" );
        return;
    }

    //
    //  Disable the insert to the cancel safe queue.
    //
    FltCbdqDisable( &InstanceContext->Cbdq );

    //
    //  Remove all callback data from the queue and complete them.
    //

    CqsEmptyQueueAndComplete( InstanceContext );

    //
    //  Signal the worker thread if it is pended.
    //
    KeSetEvent( InstanceContext->TeardownEvent, 0, FALSE );

    FltReleaseContext( InstanceContext );
}

VOID
CtxInstanceTeardownComplete (
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
{
    PCTX_INSTANCE_CONTEXT InstanceContext;
    NTSTATUS Status;

    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    DebugTrace( DEBUG_TRACE_INSTANCE_CONTEXT_OPERATIONS,
                ("[Ctx]: CtxInstanceTeardownComplete -> (Volume = %p, Instance = %p)\n",
                 FltObjects->Volume,
                 FltObjects->Instance) );

    Status = FltGetInstanceContext( FltObjects->Instance,
                                    &InstanceContext );

    if (NT_SUCCESS( Status )) {

        DebugTrace( DEBUG_TRACE_INSTANCE_CONTEXT_OPERATIONS,
                    ("[Ctx]: CtxInstanceTeardownComplete -> Instance teardown for volume %wZ (Volume = %p, Instance = %p, InstanceContext = %p)\n",
                     &InstanceContext->VolumeName,
                     FltObjects->Volume,
                     FltObjects->Instance,
                     InstanceContext) );

        FltReleaseContext( InstanceContext );

    }
}

VOID
CtxContextCleanup (
    __in PFLT_CONTEXT Context,
    __in FLT_CONTEXT_TYPE ContextType
    )
{
    PCTX_INSTANCE_CONTEXT InstanceContext;
    PCTX_STREAM_CONTEXT StreamContext;
    PCTX_STREAMHANDLE_CONTEXT StreamHandleContext;

    PAGED_CODE();

    switch(ContextType) {

    case FLT_INSTANCE_CONTEXT:

        InstanceContext = (PCTX_INSTANCE_CONTEXT) Context;

        DebugTrace( DEBUG_TRACE_INSTANCE_CONTEXT_OPERATIONS,
                    ("[Ctx]: CtxContextCleanup -> Cleaning up instance context for volume %wZ (Context = %p)\n",
                     &InstanceContext->VolumeName,
                     Context) );
		
		if( InstanceContext->Resource != NULL ) {

            ExDeleteResourceLite( InstanceContext->Resource );
            CtxFreeResource( InstanceContext->Resource );
		}

        //
        //  Here the filter should free memory or synchronization objects allocated to
        //  objects within the instance context. The instance context itself should NOT
        //  be freed. It will be freed by Filter Manager when the ref count on the
        //  context falls to zero.
        //

        CtxFreeUnicodeString( &InstanceContext->VolumeName );
		
		CtxFreeUnicodeString( &InstanceContext->InstanceName );

		CtxFreeUnicodeString( &InstanceContext->AltitudeName );

		if( InstanceContext->DosName.Buffer ) {

			ExFreePool(InstanceContext->DosName.Buffer);
			InstanceContext->DosName.Buffer = NULL;
		}
		
		ExFreePoolWithTag (InstanceContext->TeardownEvent, CTX_EVENT_TAG);

        break;

    case FLT_STREAM_CONTEXT:
		{
			LONG Dbg = 0;

			StreamContext = (PCTX_STREAM_CONTEXT) Context;
			
			if (StreamContext->EncryptFile) {

				Dbg |= DEBUG_TRACE_ENCRYPT;
			}

			DebugTrace( DEBUG_TRACE_STREAM_CONTEXT_OPERATIONS | Dbg,
						("[Ctx]: CtxContextCleanup -> Cleaning up stream context for file %wZ (Fcb = %p, StreamContext = %p) \n\tCreateCount = %x \n\tCleanupCount = %x, \n\tCloseCount = %x\n",
						 &StreamContext->FileName,
						 StreamContext->FsContext,
						 StreamContext,
						 StreamContext->CreateCount,
						 StreamContext->CleanupCount,
						 StreamContext->CloseCount) );

			ExDeleteResourceLite( &StreamContext->Resource );

			if (StreamContext->FileName.Buffer != NULL) {

				CtxFreeUnicodeString(&StreamContext->FileName);
			}
		}

        break;

    case FLT_STREAMHANDLE_CONTEXT:

        StreamHandleContext = (PCTX_STREAMHANDLE_CONTEXT) Context;

        DebugTrace( DEBUG_TRACE_STREAMHANDLE_CONTEXT_OPERATIONS,
                    ("[Ctx]: CtxContextCleanup -> Cleaning up stream handle context for file %wZ (StreamContext = %p)\n",
                     &StreamHandleContext->FileName,
                     StreamHandleContext) );

        if (StreamHandleContext->Resource != NULL) {

            ExDeleteResourceLite( StreamHandleContext->Resource );
            CtxFreeResource( StreamHandleContext->Resource );
        }

        if (StreamHandleContext->FileName.Buffer != NULL) {

            CtxFreeUnicodeString(&StreamHandleContext->FileName);
        }

        break;
    }
}

NTSTATUS
CtxFindOrCreateStreamContext (
    __in PFLT_CALLBACK_DATA Cbd,
    __in BOOLEAN CreateIfNotFound,
    __deref_out PCTX_STREAM_CONTEXT *OutStreamContext,
    __out_opt PBOOLEAN ContextCreated
    )
{
    NTSTATUS Status;
    PCTX_STREAM_CONTEXT StreamContext;
    PCTX_STREAM_CONTEXT OldStreamContext;

    PAGED_CODE();

    *OutStreamContext = NULL;
    if (ContextCreated != NULL) *ContextCreated = FALSE;

    Status = FltGetStreamContext( Cbd->Iopb->TargetInstance,
                                  Cbd->Iopb->TargetFileObject,
                                  &StreamContext );

    if (!NT_SUCCESS( Status ) &&
        (Status == STATUS_NOT_FOUND) &&
        CreateIfNotFound) {

        DebugTrace( DEBUG_TRACE_STREAM_CONTEXT_OPERATIONS,
                    ("[Ctx]: Creating stream context (FileObject = %p, Instance = %p)\n",
                     Cbd->Iopb->TargetFileObject,
                     Cbd->Iopb->TargetInstance) );

        Status = CtxCreateStreamContext( &StreamContext );

        if (!NT_SUCCESS( Status )) {

            DebugTrace( DEBUG_TRACE_ERROR | DEBUG_TRACE_STREAM_CONTEXT_OPERATIONS,
                        ("[Ctx]: Failed to create stream context with Status 0x%x. (FileObject = %p, Instance = %p)\n",
                        Status,
                        Cbd->Iopb->TargetFileObject,
                        Cbd->Iopb->TargetInstance) );

            return Status;
        }

        Status = FltSetStreamContext( Cbd->Iopb->TargetInstance,
                                      Cbd->Iopb->TargetFileObject,
                                      FLT_SET_CONTEXT_KEEP_IF_EXISTS,
                                      StreamContext,
                                      &OldStreamContext );

        if (!NT_SUCCESS( Status )) {

            DebugTrace( DEBUG_TRACE_STREAM_CONTEXT_OPERATIONS,
                        ("[Ctx]: Failed to set stream context with Status 0x%x. (FileObject = %p, Instance = %p)\n",
                        Status,
                        Cbd->Iopb->TargetFileObject,
                        Cbd->Iopb->TargetInstance) );

            FltReleaseContext( StreamContext );

            if (Status != STATUS_FLT_CONTEXT_ALREADY_DEFINED) {

                return Status;
            }

            DebugTrace( DEBUG_TRACE_STREAM_CONTEXT_OPERATIONS,
                        ("[Ctx]: Stream context already defined. Retaining old stream context %p (FileObject = %p, Instance = %p)\n",
                         OldStreamContext,
                         Cbd->Iopb->TargetFileObject,
                         Cbd->Iopb->TargetInstance) );

            StreamContext = OldStreamContext;
            Status = STATUS_SUCCESS;

        } else {

            if (ContextCreated != NULL) *ContextCreated = TRUE;
        }
    }

    *OutStreamContext = StreamContext;

    return Status;
}

NTSTATUS
CtxCreateStreamContext (
    __deref_out PCTX_STREAM_CONTEXT *OutStreamContext
    )
{
    NTSTATUS Status;
    PCTX_STREAM_CONTEXT StreamContext;

    PAGED_CODE();

    Status = FltAllocateContext( MiniEfData.Filter,
                                 FLT_STREAM_CONTEXT,
                                 CTX_STREAM_CONTEXT_SIZE,
                                 NonPagedPool,
                                 &StreamContext );

    if (!NT_SUCCESS( Status )) {

        DebugTrace( DEBUG_TRACE_STREAM_CONTEXT_OPERATIONS | DEBUG_TRACE_ERROR,
                    ("[Ctx]: Failed to allocate stream context with Status 0x%x \n",
                     Status) );
        return Status;
    }

    RtlZeroMemory( StreamContext, CTX_STREAM_CONTEXT_SIZE );

	KeInitializeSpinLock( &StreamContext->Lock );

    ExInitializeResourceLite( &StreamContext->Resource );

    *OutStreamContext = StreamContext;

    return STATUS_SUCCESS;
}

NTSTATUS
CtxUpdateNameInStreamContext (
    __in PUNICODE_STRING DirectoryName,
    __inout PCTX_STREAM_CONTEXT StreamContext
    )
{
    NTSTATUS Status;

    PAGED_CODE();

    if (StreamContext->FileName.Buffer != NULL) {

        CtxFreeUnicodeString(&StreamContext->FileName);
    }

    StreamContext->FileName.MaximumLength = DirectoryName->Length;
    Status = CtxAllocateUnicodeString(&StreamContext->FileName);
    if (NT_SUCCESS(Status)) {

        RtlCopyUnicodeString(&StreamContext->FileName, DirectoryName);
    }

    return Status;
}

NTSTATUS
CtxCreateOrReplaceStreamHandleContext (
    __in PFLT_CALLBACK_DATA Cbd,
    __in BOOLEAN ReplaceIfExists,
    __deref_out PCTX_STREAMHANDLE_CONTEXT *OutStreamHandleContext,
    __out_opt PBOOLEAN ContextReplaced
    )
{
    NTSTATUS Status;
    PCTX_STREAMHANDLE_CONTEXT StreamHandleContext;
    PCTX_STREAMHANDLE_CONTEXT OldStreamHandleContext;

    PAGED_CODE();

    *OutStreamHandleContext = NULL;
    if (ContextReplaced != NULL) *ContextReplaced = FALSE;

    Status = CtxCreateStreamHandleContext( &StreamHandleContext );

    if (!NT_SUCCESS( Status )) {

        DebugTrace( DEBUG_TRACE_ERROR | DEBUG_TRACE_STREAMHANDLE_CONTEXT_OPERATIONS,
                    ("[Ctx]: Failed to create stream context with Status 0x%x. (FileObject = %p, Instance = %p)\n",
                    Status,
                    Cbd->Iopb->TargetFileObject,
                    Cbd->Iopb->TargetInstance) );

        return Status;
    }

    Status = FltSetStreamHandleContext( Cbd->Iopb->TargetInstance,
                                        Cbd->Iopb->TargetFileObject,
                                        ReplaceIfExists ? FLT_SET_CONTEXT_REPLACE_IF_EXISTS : FLT_SET_CONTEXT_KEEP_IF_EXISTS,
                                        StreamHandleContext,
                                        &OldStreamHandleContext );

    if (!NT_SUCCESS( Status )) {

        DebugTrace( DEBUG_TRACE_STREAMHANDLE_CONTEXT_OPERATIONS,
                    ("[Ctx]: Failed to set stream handle context with Status 0x%x. (FileObject = %p, Instance = %p)\n",
                    Status,
                    Cbd->Iopb->TargetFileObject,
                    Cbd->Iopb->TargetInstance) );

        FltReleaseContext( StreamHandleContext );

        if (Status != STATUS_FLT_CONTEXT_ALREADY_DEFINED) {

            return Status;
        }

        ASSERT( ReplaceIfExists  == FALSE );

        DebugTrace( DEBUG_TRACE_STREAMHANDLE_CONTEXT_OPERATIONS,
                    ("[Ctx]: Stream context already defined. Retaining old stream context %p (FileObject = %p, Instance = %p)\n",
                     OldStreamHandleContext,
                     Cbd->Iopb->TargetFileObject,
                     Cbd->Iopb->TargetInstance) );

        StreamHandleContext = OldStreamHandleContext;
        Status = STATUS_SUCCESS;

    } else {

        if ( ReplaceIfExists &&
             OldStreamHandleContext != NULL) {

            DebugTrace( DEBUG_TRACE_STREAMHANDLE_CONTEXT_OPERATIONS,
                        ("[Ctx]: Releasing old stream handle context %p (FileObject = %p, Instance = %p)\n",
                         OldStreamHandleContext,
                         Cbd->Iopb->TargetFileObject,
                         Cbd->Iopb->TargetInstance) );

            FltReleaseContext( OldStreamHandleContext );
            if (ContextReplaced != NULL) *ContextReplaced = TRUE;
        }
    }

    *OutStreamHandleContext = StreamHandleContext;

    return Status;
}

NTSTATUS
CtxCreateStreamHandleContext (
    __deref_out PCTX_STREAMHANDLE_CONTEXT *OutStreamHandleContext
    )
{
    NTSTATUS Status;
    PCTX_STREAMHANDLE_CONTEXT StreamHandleContext;

    PAGED_CODE();

    Status = FltAllocateContext( MiniEfData.Filter,
                                 FLT_STREAMHANDLE_CONTEXT,
                                 CTX_STREAMHANDLE_CONTEXT_SIZE,
                                 PagedPool,
                                 &StreamHandleContext );

    if (!NT_SUCCESS( Status )) {

        DebugTrace( DEBUG_TRACE_STREAMHANDLE_CONTEXT_OPERATIONS | DEBUG_TRACE_ERROR,
                    ("[Ctx]: Failed to allocate stream handle context with Status 0x%x \n",
                     Status) );

        return Status;
    }

    RtlZeroMemory( StreamHandleContext, CTX_STREAMHANDLE_CONTEXT_SIZE );

    StreamHandleContext->Resource = CtxAllocateResource();
    if(StreamHandleContext->Resource == NULL) {

        FltReleaseContext( StreamHandleContext );
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    ExInitializeResourceLite( StreamHandleContext->Resource );

    *OutStreamHandleContext = StreamHandleContext;

    return STATUS_SUCCESS;
}

NTSTATUS
CtxUpdateNameInStreamHandleContext (
    __in PUNICODE_STRING DirectoryName,
    __inout PCTX_STREAMHANDLE_CONTEXT StreamHandleContext
    )
{
    NTSTATUS Status;

    PAGED_CODE();

    if (StreamHandleContext->FileName.Buffer != NULL) {

        CtxFreeUnicodeString(&StreamHandleContext->FileName);
    }

    StreamHandleContext->FileName.MaximumLength = DirectoryName->Length;
    Status = CtxAllocateUnicodeString(&StreamHandleContext->FileName);
    if (NT_SUCCESS(Status)) {

        RtlCopyUnicodeString(&StreamHandleContext->FileName, DirectoryName);
    }

    return Status;
}
#include "mefkern.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, CtxPreOperationCallback)
#pragma alloc_text(PAGE, CtxPreCreate)
#pragma alloc_text(PAGE, CtxPostCreate)
#pragma alloc_text(PAGE, CtxPreCleanup)
#pragma alloc_text(PAGE, CtxPreClose)
#endif

FLT_PREOP_CALLBACK_STATUS
CtxPreOperationCallback (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
	NTSTATUS ReturnStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
    NTSTATUS Status;
    PCTX_STREAM_CONTEXT StreamContext;
	UCHAR MajorFunction = Cbd->Iopb->MajorFunction;
	PCOMPLETION_CONTEXT CompCtx = (PCOMPLETION_CONTEXT)(*CompletionContext);

    PAGED_CODE();

	if( MajorFunction == IRP_MJ_CLEANUP ||
		MajorFunction == IRP_MJ_CLOSE ||
		MajorFunction == IRP_MJ_READ ||
		MajorFunction == IRP_MJ_WRITE ||
		MajorFunction == IRP_MJ_QUERY_INFORMATION ||
		MajorFunction == IRP_MJ_SET_INFORMATION ||
		MajorFunction == IRP_MJ_DIRECTORY_CONTROL ) {

		Status = FltGetStreamContext( Cbd->Iopb->TargetInstance,
									  Cbd->Iopb->TargetFileObject,
									  &StreamContext );
		if (!NT_SUCCESS( Status )) {

			return ReturnStatus;
		}

		CompCtx->Stream = StreamContext;
	}

	switch( Cbd->Iopb->MajorFunction ) {

	case IRP_MJ_CREATE:

		return CtxPreCreate( Cbd,
							 FltObjects,
							 CompletionContext );

	case IRP_MJ_CLEANUP:

		return CtxPreCleanup( Cbd,
							  FltObjects,
							  CompletionContext );

	case IRP_MJ_CLOSE:

		return CtxPreClose( Cbd,
							FltObjects,
							CompletionContext );

	case IRP_MJ_READ:

		return CtxPreRead( Cbd, 
						   FltObjects,
						   CompletionContext );


	case IRP_MJ_WRITE:

		return CtxPreWrite( Cbd, 
							FltObjects,
							CompletionContext );

	case IRP_MJ_QUERY_INFORMATION:

		return CtxPreQueryInfo( Cbd, 
								FltObjects,
								CompletionContext );

	case IRP_MJ_SET_INFORMATION:

		return CtxPreSetInfo( Cbd,
							  FltObjects,
							  CompletionContext ); 

	case IRP_MJ_DIRECTORY_CONTROL:

		return CtxPreDirCtrl( Cbd,
							  FltObjects,
							  CompletionContext );

	default:
		break;
	}

	return ReturnStatus;
}

FLT_POSTOP_CALLBACK_STATUS
CtxPostOperationCallback (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    )
{
	NTSTATUS ReturnStatus = FLT_POSTOP_FINISHED_PROCESSING;

	switch( Cbd->Iopb->MajorFunction ) {

	case IRP_MJ_CREATE:

		return CtxPostCreate( Cbd,
							 FltObjects,
							 CompletionContext,
							 Flags );

	case IRP_MJ_READ:

		return CtxPostRead( Cbd, 
						    FltObjects,
						    CompletionContext,
							Flags );

	case IRP_MJ_WRITE:

		return CtxPostWrite( Cbd, 
							 FltObjects,
							 CompletionContext,
							 Flags );

	case IRP_MJ_QUERY_INFORMATION:

		return CtxPostQueryInfo( Cbd, 
								 FltObjects,
								 CompletionContext,
								 Flags );

	case IRP_MJ_SET_INFORMATION:

		return CtxPostSetInfo( Cbd,
							   FltObjects,
							   CompletionContext,
							   Flags );

	case IRP_MJ_DIRECTORY_CONTROL:

		return CtxPostDirCtrl( Cbd,
							   FltObjects,
							   CompletionContext,
							   Flags );

	default:
		break;
	}

	return ReturnStatus;
}

FLT_PREOP_CALLBACK_STATUS
CtxPreCreate (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{     
	NTSTATUS Status;
	PCOMPLETION_CONTEXT CompCtx = (PCOMPLETION_CONTEXT)(*CompletionContext);

    UNREFERENCED_PARAMETER( Cbd );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    PAGED_CODE();
	
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}


FLT_POSTOP_CALLBACK_STATUS
CtxPostCreate (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __inout_opt PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    )
{
    PCTX_STREAM_CONTEXT StreamContext = NULL;    
    PCTX_STREAMHANDLE_CONTEXT StreamHandleContext = NULL;    
    PFLT_FILE_NAME_INFORMATION NameInfo = NULL;
    UNICODE_STRING FileName;

    NTSTATUS Status = STATUS_SUCCESS;
    BOOLEAN StreamContextCreated, StreamHandleContextReplaced;

	PCOMPLETION_CONTEXT CompCtx = (PCOMPLETION_CONTEXT)(CompletionContext);
	BOOLEAN InstanceAcquired = FALSE;

	BOOLEAN EncryptFile;
	
	LONG Dbg = 0;

    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    if (!NT_SUCCESS( Cbd->IoStatus.Status )) {
        
        goto CtxPostCreateCleanup;        
    }

    Status = FltGetFileNameInformation( Cbd,
                                        FLT_FILE_NAME_NORMALIZED |
                                        FLT_FILE_NAME_QUERY_DEFAULT,
                                        &NameInfo );    

    if (!NT_SUCCESS( Status )) {

        DebugTrace( DEBUG_TRACE_ERROR | DEBUG_TRACE_CREATE | DEBUG_TRACE_STREAM_CONTEXT_OPERATIONS | DEBUG_TRACE_STREAMHANDLE_CONTEXT_OPERATIONS,
                    ("[Ctx]: CtxPostCreate -> Failed to get name information %wZ(Cbd = %p, FileObject = %p)\n",
                     Cbd,
                     FltObjects->FileObject,
					 FltObjects->FileObject->FileName) );

        goto CtxPostCreateCleanup;
    }

    Status = CtxFindOrCreateStreamContext(Cbd, 
                                          TRUE,
                                          &StreamContext,
                                          &StreamContextCreated);
    if (!NT_SUCCESS( Status )) {
  
        DebugTrace( DEBUG_TRACE_ERROR | DEBUG_TRACE_CREATE | DEBUG_TRACE_STREAM_CONTEXT_OPERATIONS,
                    ("[Ctx]: CtxPostCreate -> Failed to find or create stream context for file %wZ (Cbd = %p, FileObject = %p)\n",
                     &NameInfo->Name,
					 Cbd,
                     FltObjects->FileObject) );
    
        goto CtxPostCreateCleanup;
    }        

    CtxAcquireResourceExclusive(&StreamContext->Resource);

    StreamContext->CreateCount++;

    Status = CtxUpdateNameInStreamContext( &NameInfo->Name, 
                                            StreamContext);

	StreamContext->FsContext = FltObjects->FileObject->FsContext;

	CtxReleaseResource(&StreamContext->Resource);

    if (!NT_SUCCESS( Status )) {
    
        DebugTrace( DEBUG_TRACE_ERROR | DEBUG_TRACE_STREAM_CONTEXT_OPERATIONS,
                    ("[Ctx]: CtxPostCreate -> Failed to update name in stream context for file %wZ (Cbd = %p, FileObject = %p)\n",
                     &NameInfo->Name,
                     Cbd,
                     FltObjects->FileObject) );

        goto CtxPostCreateCleanup;
    }

	CtxAcquireResourceExclusive(&StreamContext->Resource);

	Status = EncPostCreate(Cbd, FltObjects, StreamContext, StreamContextCreated, &EncryptFile);

	CtxReleaseResource(&StreamContext->Resource);

	if (!NT_SUCCESS( Status )) {

        DebugTrace( DEBUG_TRACE_ERROR | DEBUG_TRACE_STREAM_CONTEXT_OPERATIONS,
                    ("[Ctx]: CtxPostCreate -> Failed to EncPostCreate for file %wZ (Cbd = %p, FileObject = %p)\n",
                     &NameInfo->Name,
                     Cbd,
                     FltObjects->FileObject) );

        goto CtxPostCreateCleanup;
	}

	if (StreamContext->EncryptFile) {

		Dbg |= DEBUG_TRACE_ENCRYPT;
	}

	DebugTrace( DEBUG_TRACE_CREATE | DEBUG_TRACE_STREAM_CONTEXT_OPERATIONS | Dbg,
				("[Ctx]: CtxPostCreate -> Stream context info for file %wZ (Cbd = %p, FileObject = %p, Fcb = %p, StreamContext = %p) \n\t\tName = %wZ \n\t\tCreateCount = %x \n\t\tCleanupCount = %x, \n\t\tCloseCount = %x\n",
				 &NameInfo->Name,
				 Cbd,
				 FltObjects->FileObject,
				 FltObjects->FileObject->FsContext,
				 StreamContext,
				 &StreamContext->FileName,
				 StreamContext->CreateCount,
				 StreamContext->CleanupCount,
				 StreamContext->CloseCount) );

    Status = CtxCreateOrReplaceStreamHandleContext(Cbd, 
                                                   TRUE,
                                                   &StreamHandleContext,
                                                   &StreamHandleContextReplaced);
    if (!NT_SUCCESS( Status )) {
 
        DebugTrace( DEBUG_TRACE_ERROR | DEBUG_TRACE_STREAMHANDLE_CONTEXT_OPERATIONS,
                    ("[Ctx]: CtxPostCreate -> Failed to find or create stream handle context %wZ (Cbd = %p, FileObject = %p)\n",
                     &NameInfo->Name, 
					 Cbd,
                     FltObjects->FileObject) );

        goto CtxPostCreateCleanup;
    }        

    CtxAcquireResourceExclusive( StreamHandleContext->Resource );

    Status = CtxUpdateNameInStreamHandleContext( &NameInfo->Name, 
                                                 StreamHandleContext);

    DebugTrace( DEBUG_TRACE_CREATE | DEBUG_TRACE_STREAMHANDLE_CONTEXT_OPERATIONS | Dbg,
                ("[Ctx]: CtxPostCreate -> Stream handle context info for file %wZ (Cbd = %p, FileObject = %p, StreamHandleContext = %p) \n\t\tName = %wZ\n",
                 &NameInfo->Name,
                 Cbd,
                 FltObjects->FileObject,
                 StreamHandleContext,
                 &StreamHandleContext->FileName) );

    CtxReleaseResource(StreamHandleContext->Resource);

    if (!NT_SUCCESS( Status )) {

        DebugTrace( DEBUG_TRACE_ERROR | DEBUG_TRACE_STREAMHANDLE_CONTEXT_OPERATIONS,
                    ("[Ctx]: CtxPostCreate -> Failed to update name in stream handle context for file %wZ (Cbd = %p, FileObject = %p)\n",
                     &NameInfo->Name,
                     Cbd,
                     FltObjects->FileObject) );

        goto CtxPostCreateCleanup;
    }

CtxPostCreateCleanup:

    if (!NT_SUCCESS( Status ) && EncryptFile) {
    
        DebugTrace( DEBUG_TRACE_ERROR,
                    ("[Ctx]: CtxPostCreate -> Failed with %wZ Status 0x%x \n",
                    &NameInfo->Name, Status) );

		Cbd->IoStatus.Status = Status;
		Cbd->IoStatus.Information = 0;

		//ASSERT (FALSE);

		FltCancelFileOpen( Cbd->Iopb->TargetInstance, 
		   				   Cbd->Iopb->TargetFileObject );
    }

    if (NameInfo != NULL) {

        FltReleaseFileNameInformation( NameInfo );
    }
    
    if (StreamContext != NULL) {

        FltReleaseContext( StreamContext );            
    }

    if (StreamHandleContext != NULL) {

        FltReleaseContext( StreamHandleContext );            
    }
    
    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS
CtxPreCleanup (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
	PCOMPLETION_CONTEXT CompCtx = (PCOMPLETION_CONTEXT)(*CompletionContext);
    PCTX_STREAM_CONTEXT StreamContext = CompCtx->Stream;    
    NTSTATUS Status;
	LONG Dbg = 0;

    UNREFERENCED_PARAMETER( FltObjects );

    PAGED_CODE();

    CtxAcquireResourceExclusive(&StreamContext->Resource);

    StreamContext->CleanupCount++;

    CtxReleaseResource(&StreamContext->Resource);

	if (StreamContext->EncryptFile) {

		Dbg |= DEBUG_TRACE_ENCRYPT;
	}

	DebugTrace( DEBUG_TRACE_CLEANUP | DEBUG_TRACE_STREAM_CONTEXT_OPERATIONS | Dbg,
				("[Ctx]: CtxPreCleanup -> New info in stream context for file (Cbd = %p, FileObject = %p, Fcb = %p, StreamContext = %p) \n\tName = %wZ \n\tCreateCount = %x \n\tCleanupCount = %x, \n\tCloseCount = %x\n",
				 Cbd,
				 FltObjects->FileObject,
				 FltObjects->FileObject->FsContext,
				 StreamContext,
				 &StreamContext->FileName,
				 StreamContext->CreateCount,
				 StreamContext->CleanupCount,
				 StreamContext->CloseCount) );

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
CtxPreClose (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
	PCOMPLETION_CONTEXT CompCtx = (PCOMPLETION_CONTEXT)(*CompletionContext);
    PCTX_STREAM_CONTEXT StreamContext = CompCtx->Stream;  
    NTSTATUS Status;
	LONG Dbg = 0;

    UNREFERENCED_PARAMETER( FltObjects );

    PAGED_CODE();

    CtxAcquireResourceExclusive(&StreamContext->Resource);

    StreamContext->CloseCount++;

    CtxReleaseResource(&StreamContext->Resource);

	if (StreamContext->EncryptFile) {

		Dbg |= DEBUG_TRACE_ENCRYPT;
	}

	DebugTrace( DEBUG_TRACE_CLOSE | DEBUG_TRACE_STREAM_CONTEXT_OPERATIONS | Dbg,
				("[Ctx]: CtxPreClose -> New info in stream context for file (Cbd = %p, FileObject = %p, Fcb = %p, StreamContext = %p) \n\tName = %wZ \n\tCreateCount = %x \n\tCleanupCount = %x, \n\tCloseCount = %x\n",
				 Cbd,
				 FltObjects->FileObject,
				 FltObjects->FileObject->FsContext,
				 StreamContext,
				 &StreamContext->FileName,
				 StreamContext->CreateCount,
				 StreamContext->CleanupCount,
				 StreamContext->CloseCount) );

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
CtxPreRead (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
	FLT_PREOP_CALLBACK_STATUS ReturnStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
	PCOMPLETION_CONTEXT CompCtx = (PCOMPLETION_CONTEXT)(*CompletionContext);
    PCTX_STREAM_CONTEXT StreamContext = CompCtx->Stream;   
    NTSTATUS Status;
	PFLT_IO_PARAMETER_BLOCK Iopb = Cbd->Iopb;
    PVOID NewBuffer = NULL;
    PMDL NewMdl = NULL;
	ULONG Length = Iopb->Parameters.Read.Length;
	ULONG SectorSize = CompCtx->Instance->SectorSize;

    UNREFERENCED_PARAMETER( FltObjects );

	if( Length == 0 ) {

		goto CtxPreReadCleanup;
	}

	if( !StreamContext->EncryptFile) {

		goto CtxPreReadCleanup;
	}

	if( FlagOn(IRP_NOCACHE | IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO, Iopb->IrpFlags) ) {

		if( FlagOn(IRP_NOCACHE, Iopb->IrpFlags )) {

			Length = (ULONG)ROUND_TO_SIZE(Length, SectorSize);
		}

		NewBuffer = ExAllocatePoolWithTag( NonPagedPool,
										   Length,
										   CTX_BUFFER_TAG );
		if( NewBuffer == NULL ) {

			DebugTrace( DEBUG_TRACE_ERROR | DEBUG_TRACE_READ,
						("[Ctx]: CtxPreRead -> %wZ Failed to allocate buffer. \n",
						&StreamContext->FileName) );

			Cbd->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
			ReturnStatus = FLT_PREOP_COMPLETE;
			goto CtxPreReadCleanup;
		}
		
		RtlZeroMemory (NewBuffer, Length);

		if( FLT_IS_IRP_OPERATION( Cbd ) ) {

			NewMdl = IoAllocateMdl( NewBuffer,
									Length,
									FALSE,
									FALSE,
									NULL );

			if (NewMdl == NULL) {

				DebugTrace( DEBUG_TRACE_ERROR | DEBUG_TRACE_READ,
							("[Ctx]: CtxPreRead -> %wZ Failed to allocate mdl. \n",
							&StreamContext->FileName) );

				Cbd->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
				ReturnStatus = FLT_PREOP_COMPLETE;

				goto CtxPreReadCleanup;
			}

			MmBuildMdlForNonPagedPool( NewMdl );
		}

		Iopb->Parameters.Read.ByteOffset.QuadPart += StreamContext->SignLength;
		Iopb->Parameters.Read.ReadBuffer = NewBuffer;
		Iopb->Parameters.Read.MdlAddress = NewMdl;
		FltSetCallbackDataDirty( Cbd );

		CompCtx->Read.SwappedBuffer = NewBuffer;
		CompCtx->Read.Length = Length;

		ReturnStatus = FLT_PREOP_SUCCESS_WITH_CALLBACK;

	} else {

		LARGE_INTEGER FileSize;
		KIRQL irql;

		KeAcquireSpinLock( &StreamContext->Lock, &irql );
		
		FileSize = StreamContext->FileSize;

		if (FileSize.QuadPart == 0 || 
			Iopb->Parameters.Read.ByteOffset.QuadPart >= FileSize.QuadPart) {

			Cbd->IoStatus.Status = STATUS_END_OF_FILE;
			ReturnStatus = FLT_PREOP_COMPLETE;

		} else {

			ReturnStatus = FLT_PREOP_SUCCESS_WITH_CALLBACK;
		}

		KeReleaseSpinLock( &StreamContext->Lock, irql );
	}

CtxPreReadCleanup:

	if( ReturnStatus != FLT_PREOP_SUCCESS_WITH_CALLBACK ) {

		if( NewBuffer != NULL ) {

			ExFreePoolWithTag( NewBuffer, CTX_BUFFER_TAG );
		}

		if( NewMdl != NULL ) {

			IoFreeMdl( NewMdl );
		}
	}

	return ReturnStatus;
}

FLT_POSTOP_CALLBACK_STATUS
CtxPostRead (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __inout_opt PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    )
{
	FLT_POSTOP_CALLBACK_STATUS ReturnStatus = FLT_POSTOP_FINISHED_PROCESSING;
	PCOMPLETION_CONTEXT CompCtx = (PCOMPLETION_CONTEXT)(CompletionContext);
	PCTX_STREAM_CONTEXT StreamContext = CompCtx->Stream;   
	ULONG SectorSize = CompCtx->Instance->SectorSize;

	PFLT_IO_PARAMETER_BLOCK Iopb = Cbd->Iopb;
	ULONG Length = Iopb->Parameters.Read.Length;
	PVOID OldBuffer;
	BOOLEAN CleanupAllocatedBuffer = TRUE;

	BOOLEAN NonCached = FlagOn(IRP_NOCACHE | IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO, Iopb->IrpFlags);
	BOOLEAN PagingIo = FlagOn(IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO, Iopb->IrpFlags);
	BOOLEAN SynchronousIo = FlagOn(Iopb->TargetFileObject->Flags, FO_SYNCHRONOUS_IO);
	BOOLEAN ChangeRet;

    //
    //  This system won't draining an operation with swapped buffers, verify
    //  the draining flag is not set.
    //

    ASSERT(!FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING));

	if( !NonCached ) {

		LARGE_INTEGER FileSize;
		KIRQL irql;

		if (!NT_SUCCESS(Cbd->IoStatus.Status) ||
			Cbd->IoStatus.Information == 0) {

			return ReturnStatus;
		}

		KeAcquireSpinLock( &StreamContext->Lock, &irql );
		
		FileSize = StreamContext->FileSize;

		if (Iopb->Parameters.Read.ByteOffset.QuadPart > FileSize.QuadPart) {
		
			Cbd->IoStatus.Information = 0;
			ChangeRet = TRUE;

		} else if (Iopb->Parameters.Read.ByteOffset.QuadPart + Cbd->IoStatus.Information > FileSize.QuadPart) {

			Cbd->IoStatus.Information = (ULONG_PTR)(FileSize.QuadPart - Iopb->Parameters.Read.ByteOffset.QuadPart);
			ChangeRet = TRUE;
		}

		KeReleaseSpinLock( &StreamContext->Lock, irql );

		if (ChangeRet && SynchronousIo) {

			Iopb->TargetFileObject->CurrentByteOffset.QuadPart =
					Iopb->Parameters.Read.ByteOffset.QuadPart + Cbd->IoStatus.Information;
		}

		return ReturnStatus;

	}  else if( NT_SUCCESS(Cbd->IoStatus.Status) && 
			   SynchronousIo && !PagingIo ) {

		Iopb->TargetFileObject->CurrentByteOffset.QuadPart =
				Iopb->Parameters.Read.ByteOffset.QuadPart + Cbd->IoStatus.Information;
	}

    try {

		if (NT_SUCCESS(Cbd->IoStatus.Status) && Cbd->IoStatus.Information > 0) {

			if (Iopb->Parameters.Read.MdlAddress != NULL) {
				
				OldBuffer = MmGetSystemAddressForMdlSafe( Iopb->Parameters.Read.MdlAddress,
														NormalPagePriority );
				if (!OldBuffer) {

					DebugTrace( DEBUG_TRACE_ERROR,
							   ("CtxPostRead -> %wZ Failed to get system address for MDL: %p\n",
								&StreamContext->FileName, Iopb->Parameters.Read.MdlAddress) );

					Cbd->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
					Cbd->IoStatus.Information = 0;
					leave;
				}

			} else if (FlagOn(Cbd->Flags, FLTFL_CALLBACK_DATA_SYSTEM_BUFFER) ||
					   FlagOn(Cbd->Flags, FLTFL_CALLBACK_DATA_FAST_IO_OPERATION)) {

				OldBuffer = Iopb->Parameters.Read.ReadBuffer;

			} else {

				ASSERT (CompCtx->Read.SwappedBuffer);

				if (FltDoCompletionProcessingWhenSafe( Cbd,
													   FltObjects,
													   CompletionContext,
													   Flags,
													   CtxPostReadWhenSafe,
													   &ReturnStatus )) {

					//
					//  This operation has been moved to a safe IRQL, the called
					//  routine will do (or has done) the freeing so don't do it
					//  in our routine.
					//

					CleanupAllocatedBuffer = FALSE;

					//
					//  release ctx in CtxPostReadWhenSafe
					//
					ReturnStatus += FLT_POSTOP_WITHOUT_FREE_CONTEXT;

				} else {

					DebugTrace( DEBUG_TRACE_ERROR,
							   ("CtxPostRead -> %wZ Unable to post to a safe IRQL\n",
								&StreamContext->FileName) );

					Cbd->IoStatus.Status = STATUS_UNSUCCESSFUL;
					Cbd->IoStatus.Information = 0;
				}

				leave;
			}

			try {
				
				LARGE_INTEGER FileSize;
				KIRQL irql;
				ULONG Length = Cbd->IoStatus.Information;
				ULONG ZeroOffset;

				ASSERT (Length <= Iopb->Parameters.Read.Length);
				ASSERT (Iopb->Parameters.Read.Length % 16 == 0);
				
				Length = ROUND_TO_SIZE(Length, 16);

				KeAcquireSpinLock( &StreamContext->Lock, &irql );

				if (Iopb->Parameters.Read.ByteOffset.QuadPart + Length > StreamContext->ValidDataLength.QuadPart) {
				
					if (Iopb->Parameters.Read.ByteOffset.QuadPart < StreamContext->ValidDataLength.QuadPart) {
					
						ZeroOffset = (ULONG)ROUND_TO_SIZE(StreamContext->ValidDataLength.QuadPart - Iopb->Parameters.Read.ByteOffset.QuadPart, SectorSize);

						if (ZeroOffset > Length) {

							ZeroOffset = Length;
						}
					
					} else {

						ZeroOffset = 0;
					}

				} else {

					ZeroOffset = Length;
				}

				KeReleaseSpinLock( &StreamContext->Lock, irql );

				if (StreamContext->DecryptOnRead && ZeroOffset > 0) {

					EncDecryptBuffer( CompCtx->Read.SwappedBuffer, ZeroOffset, CompCtx->Read.SwappedBuffer);
				} 

				RtlCopyMemory( OldBuffer,
							   CompCtx->Read.SwappedBuffer,
							   Cbd->IoStatus.Information );

				if (Iopb->Parameters.Read.Length - Cbd->IoStatus.Information > 0) {
					
					PCHAR p = OldBuffer;
					RtlZeroMemory( &p[Cbd->IoStatus.Information], 
									Iopb->Parameters.Read.Length - Cbd->IoStatus.Information);
				}

			} except (EXCEPTION_EXECUTE_HANDLER) {

				Cbd->IoStatus.Status = GetExceptionCode();
				Cbd->IoStatus.Information = 0;

				DebugTrace( DEBUG_TRACE_ERROR,
						   ("CtxPostRead -> %wZ Invalid user buffer, Status=%x\n",
							&StreamContext->FileName, Cbd->IoStatus.Status) );
			}
		}

		//
		//  修正返回长度
		//

		if (PagingIo && 
			(NT_SUCCESS (Cbd->IoStatus.Status) || Cbd->IoStatus.Status == STATUS_END_OF_FILE)) {

			KIRQL irql;
			LARGE_INTEGER FileSize;
			PLARGE_INTEGER ByteOffset = &(Iopb->Parameters.Read.ByteOffset);

			KeAcquireSpinLock( &StreamContext->Lock, &irql );
			
			FileSize = StreamContext->FileSize;

			KeReleaseSpinLock( &StreamContext->Lock, irql );

			if (Cbd->IoStatus.Information + ByteOffset->QuadPart == FileSize.QuadPart) {

				Cbd->IoStatus.Status = STATUS_SUCCESS;
				Cbd->IoStatus.Information = min(Cbd->IoStatus.Information + StreamContext->SignLength, Iopb->Parameters.Read.Length);

			} else if (ByteOffset->QuadPart > FileSize.QuadPart) {

				if (ByteOffset->QuadPart < FileSize.QuadPart + StreamContext->SignLength) {

					Cbd->IoStatus.Status = STATUS_SUCCESS;
					Cbd->IoStatus.Information = (ULONG_PTR)(min(FileSize.QuadPart + StreamContext->SignLength - ByteOffset->QuadPart, Iopb->Parameters.Read.Length));
				}
			}
		}

    } finally {

        if (CleanupAllocatedBuffer) {

			ExFreePoolWithTag( CompCtx->Read.SwappedBuffer, CTX_BUFFER_TAG );
        }
    }

	return ReturnStatus;
}

FLT_POSTOP_CALLBACK_STATUS
CtxPostReadWhenSafe (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    )
{
	FLT_POSTOP_CALLBACK_STATUS ReturnStatus = FLT_POSTOP_FINISHED_PROCESSING;
	PCOMPLETION_CONTEXT CompCtx = (PCOMPLETION_CONTEXT)(CompletionContext);
	PCTX_STREAM_CONTEXT StreamContext = CompCtx->Stream;   
	ULONG SectorSize = CompCtx->Instance->SectorSize;
	PFLT_IO_PARAMETER_BLOCK Iopb = Cbd->Iopb;
	PVOID OldBuffer;
    NTSTATUS Status;

    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    ASSERT(Cbd->IoStatus.Information != 0);

    Status = FltLockUserBuffer( Cbd );

    if (!NT_SUCCESS(Status)) {

		DebugTrace( DEBUG_TRACE_ERROR, 
					("CtxPostReadWhenSafe -> %wZ Count not lock user buffer, Status = %x\n", 
					&StreamContext->FileName, Status) );

        Cbd->IoStatus.Status = Status;
        Cbd->IoStatus.Information = 0;

    } else {

        OldBuffer = MmGetSystemAddressForMdlSafe( Iopb->Parameters.Read.MdlAddress,
												  NormalPagePriority );

        if (OldBuffer == NULL) {

            DebugTrace( DEBUG_TRACE_ERROR,
                       ("CtxPostReadWhenSafe -> %wZ Failed to get system address for MDL: %p\n",
                        &StreamContext->FileName, Iopb->Parameters.Read.MdlAddress) );

            Cbd->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
            Cbd->IoStatus.Information = 0;

        } else {

			LARGE_INTEGER FileSize;
			KIRQL irql;
			ULONG Length = Cbd->IoStatus.Information;
			ULONG ZeroOffset;

			ASSERT (Length <= Iopb->Parameters.Read.Length);
			ASSERT (Iopb->Parameters.Read.Length % 16 == 0);
			
			Length = ROUND_TO_SIZE(Length, 16);

			KeAcquireSpinLock( &StreamContext->Lock, &irql );

			if (Iopb->Parameters.Read.ByteOffset.QuadPart + Length > StreamContext->ValidDataLength.QuadPart) {
			
				if (Iopb->Parameters.Read.ByteOffset.QuadPart < StreamContext->ValidDataLength.QuadPart) {
				
					ZeroOffset = (ULONG)ROUND_TO_SIZE(StreamContext->ValidDataLength.QuadPart - Iopb->Parameters.Read.ByteOffset.QuadPart, SectorSize);

					if (ZeroOffset > Length) {

						ZeroOffset = Length;
					}
				
				} else {

					ZeroOffset = 0;
				}

			} else {

				ZeroOffset = Length;
			}

			KeReleaseSpinLock( &StreamContext->Lock, irql );

			if (StreamContext->DecryptOnRead && ZeroOffset > 0) {

				EncDecryptBuffer( CompCtx->Read.SwappedBuffer, ZeroOffset, CompCtx->Read.SwappedBuffer);
			} 

			RtlCopyMemory( OldBuffer,
						   CompCtx->Read.SwappedBuffer,
						   Cbd->IoStatus.Information );

			if (Iopb->Parameters.Read.Length - Cbd->IoStatus.Information > 0) {
				
				PCHAR p = OldBuffer;
				RtlZeroMemory( &p[Cbd->IoStatus.Information], 
							   Iopb->Parameters.Read.Length - Cbd->IoStatus.Information);
			}
        }
    }

    ExFreePoolWithTag( CompCtx->Read.SwappedBuffer, CTX_BUFFER_TAG );

	MiniFreeContext( CompCtx );

    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS
CtxPreWrite (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
	NTSTATUS Status;
	FLT_PREOP_CALLBACK_STATUS ReturnStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
	PFLT_IO_PARAMETER_BLOCK Iopb = Cbd->Iopb;
	PCOMPLETION_CONTEXT CompCtx = (PCOMPLETION_CONTEXT)(*CompletionContext);
    PCTX_STREAM_CONTEXT StreamContext = CompCtx->Stream;   
	ULONG SectorSize = CompCtx->Instance->SectorSize;

	PVOID OldBuffer = NULL;
    PVOID NewBuffer = NULL;
    PMDL NewMdl = NULL;
	
	ULONG Length = Iopb->Parameters.Write.Length;
	LARGE_INTEGER ByteOffset;
	LARGE_INTEGER NewFileSize;
	ULONG PreAddLength = 0;	
	BOOLEAN ExtendFileSize = FALSE;

	BOOLEAN NonCached = FlagOn(IRP_NOCACHE | IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO, Iopb->IrpFlags);
	BOOLEAN PagingIo = FlagOn(IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO, Iopb->IrpFlags);

	BOOLEAN WriteToEof;
	KIRQL irql;
	PFSRTL_COMMON_FCB_HEADER FcbHeader;

	PVOID TopIrp = IoGetTopLevelIrp();

    UNREFERENCED_PARAMETER( FltObjects );

	if( Length == 0 ) {

		goto CtxPreWriteCleanup;
	}

	if (!StreamContext->EncryptFile) {

		goto CtxPreWriteCleanup;
	}

	FcbHeader = (PFSRTL_COMMON_FCB_HEADER)Iopb->TargetFileObject->FsContext;

	ASSERT (StreamContext->ValidDataLength.QuadPart <= StreamContext->FileSize.QuadPart);
	
	//ASSERT (StreamContext->FileSize.QuadPart + StreamContext->SignLength == FcbHeader->FileSize.QuadPart);
	if (StreamContext->FileSize.QuadPart + StreamContext->SignLength != FcbHeader->FileSize.QuadPart) {
		
		DebugTrace (DEBUG_TRACE_WARN, ("[Ctx]: CtxPreWrite -> %wZ FileSize = %x%x, Fcb.FileSize = %x%x %s\n", 
										&StreamContext->FileName, 
										StreamContext->FileSize.HighPart, StreamContext->FileSize.LowPart, 
										FcbHeader->FileSize.HighPart, FcbHeader->FileSize.LowPart,
										PagingIo ? "PagingIo" : ""));
	}

	//ASSERT (StreamContext->ValidDataLength.QuadPart + StreamContext->SignLength == FcbHeader->ValidDataLength.QuadPart);
	if (StreamContext->ValidDataLength.QuadPart != FcbHeader->ValidDataLength.QuadPart && 
		StreamContext->ValidDataLength.QuadPart + StreamContext->SignLength != FcbHeader->ValidDataLength.QuadPart) {
		
		DebugTrace (DEBUG_TRACE_WARN, ("[Ctx]: CtxPreWrite -> %wZ ValidDataLength = %x%x, Fcb.ValidDataLength = %x%x\n", 
										&StreamContext->FileName, 
										StreamContext->ValidDataLength.HighPart, StreamContext->ValidDataLength.LowPart, 
										FcbHeader->ValidDataLength.HighPart, FcbHeader->ValidDataLength.LowPart));
	}

	WriteToEof = ( (Iopb->Parameters.Write.ByteOffset.LowPart == FILE_WRITE_TO_END_OF_FILE) &&
					(Iopb->Parameters.Write.ByteOffset.HighPart == -1) );

	KeAcquireSpinLock( &StreamContext->Lock, &irql );

	if (WriteToEof && !PagingIo) {
		
		ByteOffset = StreamContext->FileSize;

	} else {

		ByteOffset = Iopb->Parameters.Write.ByteOffset;
	}

	CompCtx->Write.OldByteOffset = ByteOffset;

	NewFileSize.QuadPart = ByteOffset.QuadPart + Length;

	//
	//  防止重入, fastfat cleanup中调用CcZeroData, 可能又引起write中CcZeroData
	//

	if (PagingIo && (ByteOffset.QuadPart > ROUND_TO_SIZE(StreamContext->ValidDataLength.QuadPart, SectorSize))) {
		
		PreAddLength = (ULONG)(ByteOffset.QuadPart - ROUND_TO_SIZE(StreamContext->ValidDataLength.QuadPart, SectorSize));
		CompCtx->Write.PreAddLength = PreAddLength;
		ByteOffset.QuadPart = ROUND_TO_SIZE(StreamContext->ValidDataLength.QuadPart, SectorSize);
	}

	CompCtx->Write.OldLength = Length;

	if (!PagingIo) {
		
		CompCtx->Write.OldFileSize = StreamContext->FileSize;
		if (NewFileSize.QuadPart > StreamContext->FileSize.QuadPart) {
			
			StreamContext->FileSize.QuadPart = NewFileSize.QuadPart;
			ExtendFileSize = TRUE;
		}
	}

	if (NewFileSize.QuadPart > StreamContext->ValidDataLength.QuadPart) {
	
		CompCtx->Write.ExtendValidDataLength = TRUE;

		//
		//  扩大写入长度, 保证fsd validdatalength = validdatlength+END_HEADER_SIZE,
		//  如果同时存在映射写文件, 可能重置mapview写入的数据为0
		//

		if (!NonCached) {
			Length += StreamContext->SignLength;
		}
	}

	KeReleaseSpinLock( &StreamContext->Lock, irql );
	
	Length += PreAddLength;
	
	if( FlagOn(IRP_NOCACHE, Iopb->IrpFlags )) {

		Length = (ULONG)ROUND_TO_SIZE(Length, SectorSize);
	}

	CompCtx->Write.Length = Length;

	NewBuffer = ExAllocatePoolWithTag( NonPagedPool,
									   Length,
									   CTX_BUFFER_TAG );
	if( NewBuffer == NULL ) {

		DebugTrace( DEBUG_TRACE_ERROR | DEBUG_TRACE_WRITE,
					("[Ctx]: CtxPreWrite -> %wZ Failed to allocate buffer. \n",
					StreamContext->FileName) );

		Cbd->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		ReturnStatus = FLT_PREOP_COMPLETE;
		goto CtxPreWriteCleanup;
	}

	CompCtx->Write.SwappedBuffer = NewBuffer;

	RtlZeroMemory(NewBuffer, Length);

	if( FLT_IS_IRP_OPERATION( Cbd ) ) {

		NewMdl = IoAllocateMdl( NewBuffer,
								Length,
								FALSE,
								FALSE,
								NULL );

		if (NewMdl == NULL) {

			DebugTrace( DEBUG_TRACE_ERROR | DEBUG_TRACE_READ,
						("[Ctx]: CtxPreWrite -> %wZ Failed to allocate mdl. \n",
						StreamContext->FileName) );

			Cbd->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
			ReturnStatus = FLT_PREOP_COMPLETE;

			goto CtxPreWriteCleanup;
		}

		MmBuildMdlForNonPagedPool( NewMdl );
	}

	if (Iopb->Parameters.Write.MdlAddress != NULL) {

		OldBuffer = MmGetSystemAddressForMdlSafe( Iopb->Parameters.Write.MdlAddress,
												  NormalPagePriority );
		if (!OldBuffer) {

			DebugTrace( DEBUG_TRACE_ERROR, 
						("[Ctx]: CtxPreWrite -> %wZ Failed to allocate mdl. \n",
						StreamContext->FileName) );
			
			Cbd->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
			Cbd->IoStatus.Information = 0;
			ReturnStatus = FLT_PREOP_COMPLETE;
			
			goto CtxPreWriteCleanup;
		}

	} else {

		OldBuffer = Iopb->Parameters.Write.WriteBuffer;
	}

	try {

		RtlCopyMemory( &(((PUCHAR)NewBuffer)[PreAddLength]),
					   OldBuffer,
					   CompCtx->Write.OldLength );

	} except (EXCEPTION_EXECUTE_HANDLER) {

		Cbd->IoStatus.Status = GetExceptionCode();
		Cbd->IoStatus.Information = 0;
		ReturnStatus = FLT_PREOP_COMPLETE;

		DebugTrace( DEBUG_TRACE_ERROR, 
					("[Ctx]: CtxPreWrite -> %wZ Invalid user buffer status=%x\n",
					&StreamContext->FileName, Cbd->IoStatus.Status) );

		goto CtxPreWriteCleanup;
	}

	Iopb->Parameters.Write.ByteOffset = ByteOffset;
	Iopb->Parameters.Write.Length = Length;

	if (NonCached) {

		Iopb->Parameters.Write.ByteOffset.QuadPart += StreamContext->SignLength;

		if (PagingIo) {
			
			LARGE_INTEGER FileSize;
			LARGE_INTEGER ValidDataLength;
			KIRQL irql;

			KeAcquireSpinLock( &StreamContext->Lock, &irql );

			FileSize = StreamContext->FileSize;
			ValidDataLength = StreamContext->ValidDataLength;

			KeReleaseSpinLock( &StreamContext->Lock, irql );

			FileSize.QuadPart += StreamContext->SignLength;
			FileSize.QuadPart = ROUND_TO_SIZE(FileSize.QuadPart, SectorSize);

			ValidDataLength.QuadPart += StreamContext->SignLength;
			ValidDataLength.QuadPart = ROUND_TO_SIZE(ValidDataLength.QuadPart, SectorSize);

			if( Iopb->Parameters.Write.ByteOffset.QuadPart >= FileSize.QuadPart ) {
			
				Cbd->IoStatus.Status = STATUS_SUCCESS;
				Cbd->IoStatus.Information = 0;
				ReturnStatus = FLT_PREOP_COMPLETE;

				goto CtxPreWriteCleanup;

			} else if( (Iopb->Parameters.Write.ByteOffset.QuadPart + 
						Iopb->Parameters.Write.Length) > FileSize.QuadPart ) {

				Iopb->Parameters.Write.Length = (ULONG)(FileSize.QuadPart - Iopb->Parameters.Write.ByteOffset.QuadPart);
			}

			//
			//  lazywrite? 不能确定FSRTL_CACHE_TOP_LEVEL_IRP一定是lazywrite发起的
			//  lazywrite下可能ByteOffset+Length > ValidDataLength, 返回STATUS_FILE_LOCK_CONFLICT
			//

			if (TopIrp == (PVOID)FSRTL_CACHE_TOP_LEVEL_IRP) {

				if (Iopb->Parameters.Write.ByteOffset.QuadPart >= ValidDataLength.QuadPart) {
				
					Cbd->IoStatus.Status = STATUS_SUCCESS;
					Cbd->IoStatus.Information = 0;
					ReturnStatus = FLT_PREOP_COMPLETE;

					goto CtxPreWriteCleanup;

				} else if( (Iopb->Parameters.Write.ByteOffset.QuadPart + 
							Iopb->Parameters.Write.Length) > ValidDataLength.QuadPart ) {

					Iopb->Parameters.Write.Length = (ULONG)(ValidDataLength.QuadPart - Iopb->Parameters.Write.ByteOffset.QuadPart);
				}
			}
		}

		ASSERT (Length % 16 == 0);
		EncEncryptBuffer( NewBuffer, Length, NewBuffer);
	}

	Iopb->Parameters.Write.WriteBuffer = NewBuffer;
	Iopb->Parameters.Write.MdlAddress = NewMdl;
	FltSetCallbackDataDirty( Cbd );

	ReturnStatus = FLT_PREOP_SUCCESS_WITH_CALLBACK;

CtxPreWriteCleanup:

	if( ReturnStatus != FLT_PREOP_SUCCESS_WITH_CALLBACK ) {

		if( NewBuffer != NULL ) {

			ExFreePoolWithTag( NewBuffer, CTX_BUFFER_TAG );
		}

		if( NewMdl != NULL ) {

			IoFreeMdl( NewMdl );
		}

		if (!PagingIo && ExtendFileSize) {

			KeAcquireSpinLock( &StreamContext->Lock, &irql );

			StreamContext->FileSize = CompCtx->Write.OldFileSize;

			KeReleaseSpinLock( &StreamContext->Lock, irql );
		}
	}

	return ReturnStatus;
}

FLT_POSTOP_CALLBACK_STATUS
CtxPostWrite (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __inout_opt PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    )
{
	FLT_POSTOP_CALLBACK_STATUS ReturnStatus = FLT_POSTOP_FINISHED_PROCESSING;
	PCOMPLETION_CONTEXT CompCtx = (PCOMPLETION_CONTEXT)(CompletionContext);
	PCTX_STREAM_CONTEXT StreamContext = CompCtx->Stream;
	PFLT_IO_PARAMETER_BLOCK Iopb = Cbd->Iopb;
	BOOLEAN NonCached = FlagOn(IRP_NOCACHE | IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO, Iopb->IrpFlags);
	BOOLEAN PagingIo = FlagOn(IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO, Iopb->IrpFlags);
	BOOLEAN SynchronousIo = FlagOn(Iopb->TargetFileObject->Flags, FO_SYNCHRONOUS_IO);
	LARGE_INTEGER ValidDataLength;
	BOOLEAN ChangeValid = FALSE;
	
	KIRQL irql;

    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

	KeAcquireSpinLock( &StreamContext->Lock, &irql );

	if (!NT_SUCCESS (Cbd->IoStatus.Status) && !PagingIo) {
	
		StreamContext->FileSize = CompCtx->Write.OldFileSize;
	}

	if (NT_SUCCESS (Cbd->IoStatus.Status)) {

		Cbd->IoStatus.Information -= CompCtx->Write.PreAddLength;

		if (Cbd->IoStatus.Information > CompCtx->Write.OldLength) {

			Cbd->IoStatus.Information = CompCtx->Write.OldLength;
		}

		if (!PagingIo) {

			ASSERT (Cbd->IoStatus.Information == CompCtx->Write.OldLength);
		}

		if (CompCtx->Write.ExtendValidDataLength) {

			if (CompCtx->Write.OldByteOffset.QuadPart + Cbd->IoStatus.Information > StreamContext->ValidDataLength.QuadPart) {

				StreamContext->ValidDataLength.QuadPart = CompCtx->Write.OldByteOffset.QuadPart + Cbd->IoStatus.Information;

				if (StreamContext->ValidDataLength.QuadPart > StreamContext->FileSize.QuadPart) {
					
					StreamContext->ValidDataLength = StreamContext->FileSize;
				}

				ChangeValid = TRUE;
				ValidDataLength = StreamContext->ValidDataLength;
			}
		}

		if (!PagingIo && SynchronousIo) {

			Iopb->TargetFileObject->CurrentByteOffset.QuadPart = 
					CompCtx->Write.OldByteOffset.QuadPart + Cbd->IoStatus.Information;
		}
	}

	KeReleaseSpinLock( &StreamContext->Lock, irql );

	//
	//  扩大文件系统和Cache有效文件长度
	//

	//if (!NonCached && ChangeValid) {
	//
	//	PFSRTL_COMMON_FCB_HEADER FcbHeader;
	//	FcbHeader = (PFSRTL_COMMON_FCB_HEADER)Iopb->TargetFileObject->FsContext;

	//	EncLockFcb(Iopb->TargetFileObject);
	//
	//	ASSERT (FcbHeader->ValidDataLength.QuadPart <= ValidDataLength.QuadPart + StreamContext->SignLength);

	//	if (FcbHeader->ValidDataLength.QuadPart < ValidDataLength.QuadPart + StreamContext->SignLength) {
	//	
	//		FcbHeader->ValidDataLength.QuadPart = ValidDataLength.QuadPart + StreamContext->SignLength;

	//		ASSERT (CcIsFileCached( Iopb->TargetFileObject ));

	//		CcSetFileSizes( Iopb->TargetFileObject, (PCC_FILE_SIZES)&FcbHeader->AllocationSize );
	//	}

	//	EncUnlockFcb(Iopb->TargetFileObject);
	//}

	if (!NT_SUCCESS (Cbd->IoStatus.Status) && NonCached) {
	
		DebugTrace( DEBUG_TRACE_ERROR | DEBUG_TRACE_WRITE, ("CtxPostWrite -> failed %x\n", 
					Cbd->IoStatus.Status) );

		if (Cbd->IoStatus.Status == STATUS_FILE_LOCK_CONFLICT) {

			ASSERT (FALSE);
		}
	}

	if (CompCtx->Read.SwappedBuffer) {

		ExFreePoolWithTag( CompCtx->Read.SwappedBuffer, CTX_BUFFER_TAG );
		CompCtx->Read.SwappedBuffer = NULL;
	}

	return ReturnStatus;
}

FLT_PREOP_CALLBACK_STATUS
CtxPreQueryInfo (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
	FLT_PREOP_CALLBACK_STATUS ReturnStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
	PCOMPLETION_CONTEXT CompCtx = (PCOMPLETION_CONTEXT)(*CompletionContext);
    PCTX_STREAM_CONTEXT StreamContext = CompCtx->Stream;   
	PFLT_IO_PARAMETER_BLOCK Iopb = Cbd->Iopb;
	FILE_INFORMATION_CLASS FileInfoClass = Iopb->Parameters.QueryFileInformation.FileInformationClass;

    UNREFERENCED_PARAMETER( FltObjects );
	
	if (StreamContext->EncryptFile && 
		(FileInfoClass == FileStandardInformation ||
		FileInfoClass == FileAllInformation ||
		FileInfoClass == FileNetworkOpenInformation)) {

		ReturnStatus = FLT_PREOP_SUCCESS_WITH_CALLBACK;
	}

	return ReturnStatus;
}

FLT_POSTOP_CALLBACK_STATUS
CtxPostQueryInfo (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __inout_opt PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
	)
{
	FLT_POSTOP_CALLBACK_STATUS ReturnStatus = FLT_POSTOP_FINISHED_PROCESSING;
	PCOMPLETION_CONTEXT CompCtx = (PCOMPLETION_CONTEXT)(CompletionContext);
	PCTX_STREAM_CONTEXT StreamContext = CompCtx->Stream;   
	PFLT_IO_PARAMETER_BLOCK Iopb = Cbd->Iopb;
	FILE_INFORMATION_CLASS FileInfoClass = Iopb->Parameters.QueryFileInformation.FileInformationClass;
	PVOID Buffer;
	LARGE_INTEGER FileSize;
	KIRQL irql;

	if (FlagOn(Cbd->Flags, FLTFL_CALLBACK_DATA_SYSTEM_BUFFER) ||
		FlagOn(Cbd->Flags, FLTFL_CALLBACK_DATA_FAST_IO_OPERATION)) {

        Buffer = Iopb->Parameters.QueryFileInformation.InfoBuffer;
	} else {

		ASSERT (FALSE);
	}
	
	KeAcquireSpinLock( &StreamContext->Lock, &irql );
	
	FileSize = StreamContext->FileSize;

	KeReleaseSpinLock( &StreamContext->Lock, irql );

	if (NT_SUCCESS(Cbd->IoStatus.Status) || 
		(Cbd->IoStatus.Status == STATUS_BUFFER_OVERFLOW && FileInfoClass == FileAllInformation)) {

		switch (FileInfoClass) {

		case FileStandardInformation:
			{
				PFILE_STANDARD_INFORMATION FileStdInfo = (PFILE_STANDARD_INFORMATION)Buffer;
				FileStdInfo->EndOfFile.QuadPart -= StreamContext->SignLength;
				FileStdInfo->AllocationSize.QuadPart -= StreamContext->SignLength;

				ASSERT (FileSize.QuadPart == FileStdInfo->EndOfFile.QuadPart);
			}
			break;

		case FileAllInformation:
			{
				PFILE_ALL_INFORMATION FileAllInfo = (PFILE_ALL_INFORMATION)Buffer;
				FileAllInfo->StandardInformation.EndOfFile.QuadPart -= StreamContext->SignLength;
				FileAllInfo->StandardInformation.AllocationSize.QuadPart -= StreamContext->SignLength;

				ASSERT (FileSize.QuadPart == FileAllInfo->StandardInformation.EndOfFile.QuadPart);
			}
			break;

		case FileNetworkOpenInformation:
			{ 
				PFILE_NETWORK_OPEN_INFORMATION FileNetOpenInfo = (PFILE_NETWORK_OPEN_INFORMATION)Buffer;
				FileNetOpenInfo->EndOfFile.QuadPart -= StreamContext->SignLength;
				FileNetOpenInfo->AllocationSize.QuadPart -= StreamContext->SignLength;

				ASSERT (FileSize.QuadPart == FileNetOpenInfo->EndOfFile.QuadPart);
			}
			break;
		}
	}

	return ReturnStatus;
}

FLT_PREOP_CALLBACK_STATUS
CtxPreSetInfo (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
	FLT_PREOP_CALLBACK_STATUS ReturnStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
	PCOMPLETION_CONTEXT CompCtx = (PCOMPLETION_CONTEXT)(*CompletionContext);
    PCTX_STREAM_CONTEXT StreamContext = CompCtx->Stream;   
	PFLT_IO_PARAMETER_BLOCK Iopb = Cbd->Iopb;
	FILE_INFORMATION_CLASS FileInfoClass = Iopb->Parameters.SetFileInformation.FileInformationClass;
	ULONG Length = Iopb->Parameters.SetFileInformation.Length;
	PVOID NewBuffer = NULL;
	PVOID OldBuffer = NULL;

    UNREFERENCED_PARAMETER( FltObjects );

	if (!StreamContext->EncryptFile) {

		goto CtxPreSetInfoCleanup;
	}

	if (FileInfoClass == FileRenameInformation ||
		FileInfoClass == FileDispositionInformation ||
		FileInfoClass == FileEndOfFileInformation ||
		FileInfoClass == FileAllocationInformation) {

		ReturnStatus = FLT_PREOP_SUCCESS_WITH_CALLBACK;
	}

	if (FileInfoClass == FileEndOfFileInformation ||
		FileInfoClass == FileAllocationInformation) {

		NewBuffer = ExAllocatePoolWithTag( NonPagedPool,
										   Length,
										   CTX_BUFFER_TAG );
		if( NewBuffer == NULL ) {

			DebugTrace( DEBUG_TRACE_ERROR | DEBUG_TRACE_READ,
						("[Ctx]: CtxPreSetInfo -> %wZ Failed to allocate buffer. \n",
						&StreamContext->FileName) );

			Cbd->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
			ReturnStatus = FLT_PREOP_COMPLETE;
			goto CtxPreSetInfoCleanup;
		}

		OldBuffer = Iopb->Parameters.SetFileInformation.InfoBuffer;

		try {

			RtlCopyMemory( NewBuffer,
						   OldBuffer,
						   Length );

		} except (EXCEPTION_EXECUTE_HANDLER) {

			Cbd->IoStatus.Status = GetExceptionCode();
			Cbd->IoStatus.Information = 0;
			ReturnStatus = FLT_PREOP_COMPLETE;

			DebugTrace( DEBUG_TRACE_ERROR, 
						("[Ctx]: CtxPreSetInfo -> %wZ Invalid user buffer status=%x\n",
						&StreamContext->FileName, Cbd->IoStatus.Status) );

			goto CtxPreSetInfoCleanup;
		}

		if (FileInfoClass == FileEndOfFileInformation) {

			PFILE_END_OF_FILE_INFORMATION EndOfFileInfo = (PFILE_END_OF_FILE_INFORMATION)NewBuffer;

			//
			//  不处理cache发起的设置长度
			//

			if (!Iopb->Parameters.SetFileInformation.AdvanceOnly) {

				LARGE_INTEGER FileSize;
				KIRQL irql;

				KeAcquireSpinLock( &StreamContext->Lock, &irql );
		
				CompCtx->SetFile.OldFileSize = StreamContext->FileSize;
				StreamContext->FileSize = EndOfFileInfo->EndOfFile;

				CompCtx->SetFile.OldValidDataLength = StreamContext->ValidDataLength;
				if (StreamContext->FileSize.QuadPart < StreamContext->ValidDataLength.QuadPart) {
					
					StreamContext->ValidDataLength = StreamContext->FileSize;
					CompCtx->SetFile.ReduceSize = TRUE;
				}

				KeReleaseSpinLock( &StreamContext->Lock, irql );

				EndOfFileInfo->EndOfFile.QuadPart += StreamContext->SignLength;
			}
		}
		else if (FileInfoClass == FileAllocationInformation) {

			PFILE_ALLOCATION_INFORMATION AllocationInfo = (PFILE_ALLOCATION_INFORMATION)NewBuffer;
			AllocationInfo->AllocationSize.QuadPart += StreamContext->SignLength;
		}

		Iopb->Parameters.SetFileInformation.InfoBuffer = NewBuffer;
		FltSetCallbackDataDirty( Cbd );

		CompCtx->SetFile.SwappedBuffer = NewBuffer;
	}

CtxPreSetInfoCleanup:
	
	if (ReturnStatus != FLT_PREOP_SUCCESS_WITH_CALLBACK) {

		if (NewBuffer) {

			ExFreePoolWithTag( NewBuffer, CTX_BUFFER_TAG );
		}
	}

    return ReturnStatus;
}

FLT_POSTOP_CALLBACK_STATUS
CtxPostSetInfo (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __inout_opt PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    )
{
	FLT_POSTOP_CALLBACK_STATUS ReturnStatus = FLT_POSTOP_FINISHED_PROCESSING;
	PCOMPLETION_CONTEXT CompCtx = (PCOMPLETION_CONTEXT)(CompletionContext);
	PCTX_STREAM_CONTEXT StreamContext = CompCtx->Stream;  
	FILE_INFORMATION_CLASS FileInfoClass = Cbd->Iopb->Parameters.SetFileInformation.FileInformationClass;
	BOOLEAN CleanupAllocatedBuffer = TRUE;
	
    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( FltObjects );

    if (!NT_SUCCESS( Cbd->IoStatus.Status )) {
        
		if (FileInfoClass == FileEndOfFileInformation) {

			KIRQL irql;

			KeAcquireSpinLock( &StreamContext->Lock, &irql );
			
			StreamContext->FileSize = CompCtx->SetFile.OldFileSize;
			StreamContext->ValidDataLength = CompCtx->SetFile.OldValidDataLength;

			KeReleaseSpinLock( &StreamContext->Lock, irql );
		}

        goto CtxPostSetInfoCleanup;        
    }
	
	if ((KeGetCurrentIrql() > APC_LEVEL) && FLT_IS_IRP_OPERATION(Cbd)) {

		if (FltDoCompletionProcessingWhenSafe( Cbd,
											   FltObjects,
											   CompletionContext,
											   Flags,
											   CtxPostSetInfoWhenSafe,
											   &ReturnStatus )) {

			CleanupAllocatedBuffer = FALSE;
			ReturnStatus += FLT_POSTOP_WITHOUT_FREE_CONTEXT;

		} else {

			DebugTrace( DEBUG_TRACE_ERROR,
						("CtxPostSetInfo -> %wZ Unable to post to a safe IRQL\n",
						&StreamContext->FileName) );

			Cbd->IoStatus.Status = STATUS_UNSUCCESSFUL;
			Cbd->IoStatus.Information = 0;
		}

	} else {

		ReturnStatus = CtxPostSetInfoWhenSafe( Cbd,
								FltObjects,
								CompletionContext,
								Flags );

		CleanupAllocatedBuffer = FALSE;
		ReturnStatus += FLT_POSTOP_WITHOUT_FREE_CONTEXT;
	}

CtxPostSetInfoCleanup:

    if (CleanupAllocatedBuffer && CompCtx->SetFile.SwappedBuffer) {

		ExFreePoolWithTag( CompCtx->SetFile.SwappedBuffer, CTX_BUFFER_TAG );
		CompCtx->SetFile.SwappedBuffer = NULL;
    }

	return ReturnStatus;
}

FLT_POSTOP_CALLBACK_STATUS
CtxPostSetInfoWhenSafe (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    )
{
	PCOMPLETION_CONTEXT CompCtx = (PCOMPLETION_CONTEXT)(CompletionContext);
	PCTX_STREAM_CONTEXT StreamContext = CompCtx->Stream;  
    PCTX_STREAMHANDLE_CONTEXT StreamHandleContext = NULL;
    PFLT_FILE_NAME_INFORMATION NameInfo = NULL;
	PFLT_IO_PARAMETER_BLOCK Iopb = Cbd->Iopb;
	FILE_INFORMATION_CLASS FileInfoClass = Iopb->Parameters.SetFileInformation.FileInformationClass;
	PVOID Buffer;
	NTSTATUS Status;
	BOOLEAN StreamHandleContextReplaced;
	
	if (FlagOn(Cbd->Flags, FLTFL_CALLBACK_DATA_SYSTEM_BUFFER) ||
		FlagOn(Cbd->Flags, FLTFL_CALLBACK_DATA_FAST_IO_OPERATION)) {

        Buffer = Iopb->Parameters.SetFileInformation.InfoBuffer;
	} else {

		ASSERT (FALSE);
	}

    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( FltObjects );

	switch (FileInfoClass) {
		
	case FileEndOfFileInformation:
		{
			//
			//  置Cache中最后ENC_HEADER_SIZE大小数据为0
			//

			if (CompCtx->SetFile.ReduceSize) {
			
				NTSTATUS Status;
				PVOID EncBuffer;
				PFILE_END_OF_FILE_INFORMATION EndOfFileInfo = (PFILE_END_OF_FILE_INFORMATION)Iopb->Parameters.SetFileInformation.InfoBuffer;

				DebugTrace (DEBUG_TRACE_SETFILE|DEBUG_TRACE_WARN, ("[Enc] CtxPostSetInfoWhenSafe -> To Write %wZ. \n", 
																	&StreamContext->FileName ));

				EncBuffer = ExAllocatePoolWithTag( NonPagedPool, StreamContext->SignLength, CTX_BUFFER_TAG );
				
				if (EncBuffer) {

					RtlZeroMemory (EncBuffer, StreamContext->SignLength);

					Status = FltWriteFile( Cbd->Iopb->TargetInstance,
										   Cbd->Iopb->TargetFileObject,
										   &EndOfFileInfo->EndOfFile,
										   StreamContext->SignLength,
										   EncBuffer,
										   FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
										   NULL,
										   NULL,
										   NULL );

					ExFreePoolWithTag (EncBuffer, CTX_BUFFER_TAG);
				}
			}
		}
		break;

	case FileAllocationInformation:
		{
			PFILE_ALLOCATION_INFORMATION AllocationInfo = (PFILE_ALLOCATION_INFORMATION)Iopb->Parameters.SetFileInformation.InfoBuffer;
			LARGE_INTEGER FileSize;
			KIRQL irql;

			KeAcquireSpinLock( &StreamContext->Lock, &irql );
		
			if (StreamContext->FileSize.QuadPart > AllocationInfo->AllocationSize.QuadPart) {
			
				DebugTrace (DEBUG_TRACE_SETFILE|DEBUG_TRACE_WARN, ("[Enc] CtxPostSetInfoWhenSafe -> Reset FileSize %wZ. \n", 
																	&StreamContext->FileName ));

				StreamContext->FileSize = AllocationInfo->AllocationSize;

				if (StreamContext->FileSize.QuadPart < StreamContext->ValidDataLength.QuadPart) {
					
					StreamContext->ValidDataLength = StreamContext->FileSize;
				}
			}

			KeReleaseSpinLock( &StreamContext->Lock, irql );
		}
		break;

	case FileRenameInformation:
		{
			Status = FltGetFileNameInformation( Cbd,
												FLT_FILE_NAME_NORMALIZED |
												FLT_FILE_NAME_QUERY_DEFAULT,
												&NameInfo );
		    
			if (!NT_SUCCESS( Status )) {
		    
				DebugTrace( DEBUG_TRACE_ERROR | DEBUG_TRACE_STREAM_CONTEXT_OPERATIONS | DEBUG_TRACE_STREAMHANDLE_CONTEXT_OPERATIONS | DEBUG_TRACE_SETFILE,
							("[Ctx]: CtxPostSetInfo -> Failed to get file name information (Cbd = %p, FileObject = %p)\n",
							 Cbd,
							 FltObjects->FileObject) );
		    
				goto CtxPostSetInfoWhenSafeCleanup;
			}

			CtxAcquireResourceExclusive(&StreamContext->Resource);

			Status = CtxUpdateNameInStreamContext( &NameInfo->Name, 
													StreamContext);

			DebugTrace( DEBUG_TRACE_SETFILE | DEBUG_TRACE_STREAM_CONTEXT_OPERATIONS,
						("[Ctx]: CtxPostSetInfo -> New info in stream context for file %wZ (Cbd = %p, FileObject = %p, StreamContext = %p) \n\t\tName = %wZ \n\t\tCreateCount = %x \n\t\tCleanupCount = %x, \n\t\tCloseCount = %x\n",
						 &NameInfo->Name,
						 Cbd,
						 FltObjects->FileObject,
						 StreamContext,
						 &StreamContext->FileName,
						 StreamContext->CreateCount,
						 StreamContext->CleanupCount,
						 StreamContext->CloseCount) );

			CtxReleaseResource(&StreamContext->Resource);

			if (!NT_SUCCESS( Status )) {
		    
				DebugTrace( DEBUG_TRACE_ERROR | DEBUG_TRACE_STREAM_CONTEXT_OPERATIONS | DEBUG_TRACE_SETFILE,
							("[Ctx]: CtxPostSetInfo -> Failed to update name in stream context for file %wZ (Cbd = %p, FileObject = %p)\n",
							 &NameInfo->Name,
							 Cbd,
							 FltObjects->FileObject) );

				goto CtxPostSetInfoWhenSafeCleanup;
			}

			Status = CtxCreateOrReplaceStreamHandleContext(Cbd, 
														   TRUE,
														   &StreamHandleContext,
														   &StreamHandleContextReplaced);
			if (!NT_SUCCESS( Status )) {

				goto CtxPostSetInfoWhenSafeCleanup;
			}        

			CtxAcquireResourceExclusive(StreamHandleContext->Resource);

			Status = CtxUpdateNameInStreamHandleContext( &NameInfo->Name, 
														 StreamHandleContext);

			DebugTrace( DEBUG_TRACE_STREAMHANDLE_CONTEXT_OPERATIONS | DEBUG_TRACE_SETFILE,
						("[Ctx]: CtxPostSetInfo -> Stream handle context info for file %wZ (Cbd = %p, FileObject = %p, StreamHandleContext = %p) \n\t\tName = %wZ\n",
						 &NameInfo->Name,
						 Cbd,
						 FltObjects->FileObject,
						 StreamHandleContext,
						 &StreamHandleContext->FileName) );

			CtxReleaseResource( StreamHandleContext->Resource );

			if (!NT_SUCCESS( Status )) {

				DebugTrace( DEBUG_TRACE_ERROR | DEBUG_TRACE_STREAMHANDLE_CONTEXT_OPERATIONS | DEBUG_TRACE_SETFILE,
							("[Ctx]: CtxPostSetInfo -> Failed to update name in stream handle context for file %wZ (Cbd = %p, FileObject = %p)\n",
							 &NameInfo->Name,
							 Cbd,
							 FltObjects->FileObject) );

				goto CtxPostSetInfoWhenSafeCleanup;
			}
		}
		break;
	}

CtxPostSetInfoWhenSafeCleanup:

    if (StreamHandleContext != NULL) {

        FltReleaseContext( StreamHandleContext );            
    }

    if (NameInfo != NULL) {

        FltReleaseFileNameInformation( NameInfo );
    }

    if (CompCtx->SetFile.SwappedBuffer) {

		ExFreePoolWithTag( CompCtx->SetFile.SwappedBuffer, CTX_BUFFER_TAG );
		CompCtx->SetFile.SwappedBuffer = NULL;
    }

	MiniFreeContext( CompCtx );

    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS
CtxPreDirCtrl (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
	FLT_PREOP_CALLBACK_STATUS ReturnStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
	PCOMPLETION_CONTEXT CompCtx = (PCOMPLETION_CONTEXT)(*CompletionContext);
    PCTX_STREAM_CONTEXT StreamContext = CompCtx->Stream;   
    NTSTATUS Status;
	PFLT_IO_PARAMETER_BLOCK Iopb = Cbd->Iopb;
    PVOID NewBuffer = NULL;
    PMDL NewMdl = NULL;
	ULONG Length = Iopb->Parameters.DirectoryControl.QueryDirectory.Length;

    UNREFERENCED_PARAMETER( FltObjects );

	if( Cbd->Iopb->MinorFunction != IRP_MN_QUERY_DIRECTORY) {
		
		goto CtxPreDirCtrlCleanup;
	}

	if( Length == 0 ) {

		goto CtxPreDirCtrlCleanup;
	}
	
	if( !StreamContext->EncryptFolder ) {

		goto CtxPreDirCtrlCleanup;
	}

	NewBuffer = ExAllocatePoolWithTag( NonPagedPool,
                                       Length,
                                       CTX_BUFFER_TAG );
	if( NewBuffer == NULL ) {

        DebugTrace( DEBUG_TRACE_ERROR | DEBUG_TRACE_DIRCTRL,
                    ("[Ctx]: CtxPreDirCtrl -> %wZ Failed to allocate buffer. \n",
					&StreamContext->FileName) );

		Cbd->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		ReturnStatus = FLT_PREOP_COMPLETE;

		goto CtxPreDirCtrlCleanup;
	}

	if( FLT_IS_IRP_OPERATION( Cbd ) ) {

        NewMdl = IoAllocateMdl( NewBuffer,
                                Length,
                                FALSE,
                                FALSE,
                                NULL );

		if (NewMdl == NULL) {

			DebugTrace( DEBUG_TRACE_ERROR | DEBUG_TRACE_DIRCTRL,
						("[Ctx]: CtxPreDirCtrl -> %wZ Failed to allocate mdl. \n",
						&StreamContext->FileName) );

			Cbd->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
			ReturnStatus = FLT_PREOP_COMPLETE;

			goto CtxPreDirCtrlCleanup;
		}

		MmBuildMdlForNonPagedPool( NewMdl );
	}

    Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer = NewBuffer;
    Iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress = NewMdl;
	FltSetCallbackDataDirty( Cbd );

	CompCtx->QueryDir.SwappedBuffer = NewBuffer;
	CompCtx->QueryDir.Length = Length;

	ReturnStatus = FLT_PREOP_SUCCESS_WITH_CALLBACK;

CtxPreDirCtrlCleanup:

	if( ReturnStatus != FLT_PREOP_SUCCESS_WITH_CALLBACK ) {

		if( NewBuffer != NULL ) {

			ExFreePoolWithTag( NewBuffer, CTX_BUFFER_TAG );
		}

		if( NewMdl != NULL ) {

			IoFreeMdl( NewMdl );
		}
	}

	return ReturnStatus;
}

FLT_POSTOP_CALLBACK_STATUS
CtxPostDirCtrl (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __inout_opt PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    )
{
	FLT_POSTOP_CALLBACK_STATUS ReturnStatus = FLT_POSTOP_FINISHED_PROCESSING;
	PCOMPLETION_CONTEXT CompCtx = (PCOMPLETION_CONTEXT)(CompletionContext);
	PCTX_STREAM_CONTEXT StreamContext = CompCtx->Stream;   
	PFLT_IO_PARAMETER_BLOCK Iopb = Cbd->Iopb;
	PVOID OldBuffer;
	BOOLEAN CleanupAllocatedBuffer = TRUE;

    ASSERT(!FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING));

    try {

		if ((!NT_SUCCESS(Cbd->IoStatus.Status) && Cbd->IoStatus.Status != STATUS_NO_MORE_FILES) ||
			Cbd->IoStatus.Information == 0) {

			leave;
		}
	
		if (Iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress != NULL) {
			
			OldBuffer = MmGetSystemAddressForMdlSafe( Iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress,
                                                    NormalPagePriority );
			if (!OldBuffer) {

                DebugTrace( DEBUG_TRACE_ERROR,
                           ("CtxPostDirCtrl -> %wZ Failed to get system address for MDL: %p\n",
                            &StreamContext->FileName, 
							Iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress) );

                Cbd->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                Cbd->IoStatus.Information = 0;
                leave;
            }

        } else if (FlagOn(Cbd->Flags, FLTFL_CALLBACK_DATA_SYSTEM_BUFFER) ||
                   FlagOn(Cbd->Flags, FLTFL_CALLBACK_DATA_FAST_IO_OPERATION)) {

            OldBuffer = Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;

        } else {

            if (FltDoCompletionProcessingWhenSafe( Cbd,
                                                   FltObjects,
                                                   CompletionContext,
                                                   Flags,
                                                   CtxPostDirCtrlWhenSafe,
                                                   &ReturnStatus )) {

                //
                //  This operation has been moved to a safe IRQL, the called
                //  routine will do (or has done) the freeing so don't do it
                //  in our routine.
                //

                CleanupAllocatedBuffer = FALSE;
				ReturnStatus += FLT_POSTOP_WITHOUT_FREE_CONTEXT;

            } else {

                DebugTrace( DEBUG_TRACE_ERROR,
                           ("CtxPostDirCtrl -> %wZ Unable to post to a safe IRQL\n",
                            &StreamContext->FileName) );

                Cbd->IoStatus.Status = STATUS_UNSUCCESSFUL;
                Cbd->IoStatus.Information = 0;
            }

            leave;
        }

        try {

			CtxProcessDirCtrl( Cbd,
							   StreamContext,
							   CompCtx->QueryDir.SwappedBuffer );

            RtlCopyMemory( OldBuffer,
                           CompCtx->QueryDir.SwappedBuffer,
                           Iopb->Parameters.DirectoryControl.QueryDirectory.Length );//Cbd->IoStatus.Information );

        } except (EXCEPTION_EXECUTE_HANDLER) {

            Cbd->IoStatus.Status = GetExceptionCode();
            Cbd->IoStatus.Information = 0;

            DebugTrace( DEBUG_TRACE_ERROR,
                       ("CtxPostDirCtrl -> %wZ Invalid user buffer, Status=%x\n",
                        &StreamContext->FileName, Cbd->IoStatus.Status) );
        }

    } finally {

        if (CleanupAllocatedBuffer) {

			ExFreePoolWithTag( CompCtx->QueryDir.SwappedBuffer, CTX_BUFFER_TAG );
        }
    }

	return ReturnStatus;
}

FLT_POSTOP_CALLBACK_STATUS
CtxPostDirCtrlWhenSafe (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    )
{
	FLT_POSTOP_CALLBACK_STATUS ReturnStatus = FLT_POSTOP_FINISHED_PROCESSING;
	PCOMPLETION_CONTEXT CompCtx = (PCOMPLETION_CONTEXT)(CompletionContext);
	PCTX_STREAM_CONTEXT StreamContext = CompCtx->Stream;   
	PFLT_IO_PARAMETER_BLOCK Iopb = Cbd->Iopb;
	PVOID OldBuffer;
    NTSTATUS Status;

    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    ASSERT(Cbd->IoStatus.Information != 0);

    Status = FltLockUserBuffer( Cbd );

    if (!NT_SUCCESS(Status)) {

		DebugTrace( DEBUG_TRACE_ERROR, 
					("CtxPostDirCtrlWhenSafe -> %wZ Count not lock user buffer, Status = %x\n", 
					&StreamContext->FileName, Status) );

        Cbd->IoStatus.Status = Status;
        Cbd->IoStatus.Information = 0;

    } else {

        OldBuffer = MmGetSystemAddressForMdlSafe( Iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress,
												  NormalPagePriority );

        if (OldBuffer == NULL) {

            DebugTrace( DEBUG_TRACE_ERROR,
                       ("CtxPostDirCtrlWhenSafe -> %wZ Failed to get system address for MDL: %p\n",
                        &StreamContext->FileName, Iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress) );

            Cbd->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
            Cbd->IoStatus.Information = 0;

        } else {

			CtxProcessDirCtrl( Cbd,
							   StreamContext,
							   CompCtx->QueryDir.SwappedBuffer );

            RtlCopyMemory( OldBuffer,
						   CompCtx->QueryDir.SwappedBuffer,
                           Iopb->Parameters.DirectoryControl.QueryDirectory.Length );//Cbd->IoStatus.Information );
        }
    }

    ExFreePoolWithTag( CompCtx->QueryDir.SwappedBuffer, CTX_BUFFER_TAG );

	MiniFreeContext( CompCtx );

    return FLT_POSTOP_FINISHED_PROCESSING;
}

NTSTATUS
CtxProcessDirCtrl (
	__inout PFLT_CALLBACK_DATA Cbd,
	__in PCTX_STREAM_CONTEXT StreamContext,
	__inout PVOID Buffer
	)
{
	NTSTATUS Status;
	PFLT_IO_PARAMETER_BLOCK Iopb = Cbd->Iopb;
	FILE_INFORMATION_CLASS FileInformationClass = Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass;

	switch (FileInformationClass)
	{
	case FileBothDirectoryInformation: 
		{
			PFILE_BOTH_DIR_INFORMATION Info = (PFILE_BOTH_DIR_INFORMATION)Buffer;	
			while (Info) {
				
				if (Info->EndOfFile.QuadPart >= ENC_HEADER_SIZE) {

					Info->EndOfFile.QuadPart -= ENC_HEADER_SIZE;
					Info->AllocationSize.QuadPart -= ENC_HEADER_SIZE;
				}

				if (!Info->NextEntryOffset)
					break;

				Info = (PFILE_BOTH_DIR_INFORMATION)((PUCHAR)Info + Info->NextEntryOffset);
			}
		}
		break;
	
	case FileDirectoryInformation:
		{
			PFILE_DIRECTORY_INFORMATION Info = (PFILE_DIRECTORY_INFORMATION)Buffer;	
			while (Info) {	

				if (Info->EndOfFile.QuadPart >= ENC_HEADER_SIZE) {

					Info->EndOfFile.QuadPart -= ENC_HEADER_SIZE;
					Info->AllocationSize.QuadPart -= ENC_HEADER_SIZE;
				}

				if (!Info->NextEntryOffset)
					break;

				Info = (PFILE_DIRECTORY_INFORMATION)((PUCHAR)Info + Info->NextEntryOffset);
			}
		}
		break;

	case FileFullDirectoryInformation:
		{
			PFILE_FULL_DIR_INFORMATION Info = (PFILE_FULL_DIR_INFORMATION)Buffer;	
			while (Info) {	

				if (Info->EndOfFile.QuadPart >= ENC_HEADER_SIZE) {

					Info->EndOfFile.QuadPart -= ENC_HEADER_SIZE;
					Info->AllocationSize.QuadPart -= ENC_HEADER_SIZE;
				}

				if (!Info->NextEntryOffset)
					break;

				Info = (PFILE_FULL_DIR_INFORMATION)((PUCHAR)Info + Info->NextEntryOffset);
			}
		}
		break;

	case FileIdFullDirectoryInformation:
		{
			PFILE_ID_FULL_DIR_INFORMATION Info = (PFILE_ID_FULL_DIR_INFORMATION)Buffer;	
			while (Info) {	

				if (Info->EndOfFile.QuadPart >= ENC_HEADER_SIZE) {

					Info->EndOfFile.QuadPart -= ENC_HEADER_SIZE;
					Info->AllocationSize.QuadPart -= ENC_HEADER_SIZE;
				}

				if (!Info->NextEntryOffset)
					break;

				Info = (PFILE_ID_FULL_DIR_INFORMATION)((PUCHAR)Info + Info->NextEntryOffset);
			}
		}
		break;

	case FileIdBothDirectoryInformation:
		{
			PFILE_ID_BOTH_DIR_INFORMATION Info = (PFILE_ID_BOTH_DIR_INFORMATION)Buffer;	
			while (Info) {		

				if (Info->EndOfFile.QuadPart >= ENC_HEADER_SIZE) {

					Info->EndOfFile.QuadPart -= ENC_HEADER_SIZE;
					Info->AllocationSize.QuadPart -= ENC_HEADER_SIZE;
				}

				if (!Info->NextEntryOffset)
					break;

				Info = (PFILE_ID_BOTH_DIR_INFORMATION)((PUCHAR)Info + Info->NextEntryOffset);
			}
		}
		break;
	}

	return STATUS_SUCCESS;
}
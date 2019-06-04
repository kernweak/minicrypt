#include "mefkern.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, CsqPreRead)
#pragma alloc_text(PAGE, CsqPreReadInternal)
#endif

FLT_PREOP_CALLBACK_STATUS
CsqPreRead (
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
	ULONG Length = Iopb->Parameters.Read.Length;

    UNREFERENCED_PARAMETER( FltObjects );

    PAGED_CODE();

	DebugTrace( DEBUG_TRACE_CBDQ_CALLBACK | DEBUG_TRACE_INFO | DEBUG_TRACE_READ, 
				("[Csq]: CsqPreRead ->\n") );

	if( Length == 0 ) {

		goto CsqPreReadCleanup;
	}

	if ((Iopb->IrpFlags & IRP_PAGING_IO) ||
		(Iopb->IrpFlags & IRP_SYNCHRONOUS_PAGING_IO) ||
		IoGetTopLevelIrp() ||
		!FLT_IS_IRP_OPERATION (Cbd)) {

		ReturnStatus = CsqPreReadInternal( Cbd,
										   CompCtx );
	} else {

		DebugTrace( DEBUG_TRACE_CBDQ_CALLBACK | DEBUG_TRACE_INFO | DEBUG_TRACE_READ, 
					("[Csq]: CsqPreRead -> File %wZ QueueItem \n", 
					&StreamContext->FileName) );

		Cbd->QueueContext[0] = (PVOID) CompCtx;
		Cbd->QueueContext[1] = NULL;

		Status = FltCbdqInsertIo( &CompCtx->Instance->Cbdq,
								  Cbd,
								  NULL,
								  NULL );

		if (Status == STATUS_SUCCESS) {

			//
			//  In general, we can create a worker thread here as long as we can
			//  correctly handle the insert/remove race conditions b/w multi threads.
			//  In this sample, the worker thread creation is done in CsqInsertIo.
			//  This is a simpler solution because CsqInsertIo is atomic with 
			//  respect to other CsqXxxIo callback routines.
			//

			ReturnStatus = FLT_PREOP_PENDING;

		} else {

			DebugTrace( DEBUG_TRACE_CBDQ_CALLBACK | DEBUG_TRACE_ERROR | DEBUG_TRACE_CBDQIO,
						("[Csq]: CsqPreRead -> Failed to insert into cbdq (Status = 0x%x)\n",
						Status) );
		}

		if (ReturnStatus == FLT_PREOP_PENDING) {
		
			*CompletionContext = NULL;
		}
	}

CsqPreReadCleanup:

	return ReturnStatus;
}

FLT_PREOP_CALLBACK_STATUS
CsqPreReadInternal (
    __inout PFLT_CALLBACK_DATA Cbd,
	__inout PVOID Context
	)
{
	FLT_PREOP_CALLBACK_STATUS ReturnStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
	PCOMPLETION_CONTEXT CompCtx = (PCOMPLETION_CONTEXT)Context;
    PCTX_STREAM_CONTEXT StreamContext = CompCtx->Stream;   
    NTSTATUS Status;
	PFLT_IO_PARAMETER_BLOCK Iopb = Cbd->Iopb;
    PVOID NewBuffer = NULL;
    PMDL NewMdl = NULL;
	ULONG Length = Iopb->Parameters.Read.Length;
	BOOLEAN AcquiredStreamContext = FALSE;
	BOOLEAN PagingIo = (Iopb->IrpFlags & IRP_PAGING_IO) || (Iopb->IrpFlags & IRP_SYNCHRONOUS_PAGING_IO);
	BOOLEAN TopLevel = !IoGetTopLevelIrp();
	BOOLEAN SynchronousIo = BooleanFlagOn(Iopb->TargetFileObject->Flags, FO_SYNCHRONOUS_IO);

	PAGED_CODE();

	if (TopLevel && !PagingIo) {
		
		CtxAcquireResourceShared(&StreamContext->Resource);

		AcquiredStreamContext = TRUE;
	}

	try {

		ReturnStatus = FLT_PREOP_SUCCESS_WITH_CALLBACK;
		
	} finally {

		if (ReturnStatus != FLT_PREOP_SUCCESS_WITH_CALLBACK) {

			if (AcquiredStreamContext) {

				CtxReleaseResource(&StreamContext->Resource);
			}
		}
	}

	return ReturnStatus;
}

FLT_POSTOP_CALLBACK_STATUS
CsqPostRead (
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
	ULONG Length = Iopb->Parameters.Read.Length;
	PVOID OldBuffer;
	BOOLEAN CleanupAllocatedBuffer = TRUE;
	BOOLEAN PagingIo = (Iopb->IrpFlags & IRP_PAGING_IO) || (Iopb->IrpFlags & IRP_SYNCHRONOUS_PAGING_IO);
	BOOLEAN TopLevel = !IoGetTopLevelIrp();

    ASSERT(!FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING));

    try {

		if (!NT_SUCCESS(Cbd->IoStatus.Status) ||
			Cbd->IoStatus.Information == 0) {

			leave;
		}
	
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

			ASSERT (FALSE);
		}

    } finally {

		if (TopLevel && !PagingIo) {
			
			CtxReleaseResource(&StreamContext->Resource);
		}
    }

	return ReturnStatus;
}
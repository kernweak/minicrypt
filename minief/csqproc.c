#include "mefkern.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, CsqAcquire)
#pragma alloc_text(PAGE, CsqRelease)
#pragma alloc_text(PAGE, CsqInsertIo)
#pragma alloc_text(PAGE, CsqRemoveIo)
#pragma alloc_text(PAGE, CsqPeekNextIo)
#pragma alloc_text(PAGE, CsqCompleteCanceledIo)
#pragma alloc_text(PAGE, CsqPreIoWorkItemRoutine)
#pragma alloc_text(PAGE, CqsEmptyQueueAndComplete)
#endif

VOID
CsqAcquire(
    __in PFLT_CALLBACK_DATA_QUEUE DataQueue,
    __out PKIRQL Irql
    )
{
    PCTX_INSTANCE_CONTEXT InstanceContext;

	PAGED_CODE();

    UNREFERENCED_PARAMETER( Irql );

	DebugTrace( DEBUG_TRACE_CBDQ_CALLBACK | DEBUG_TRACE_INFO, ("[Csq]: CsqAcquire ->\n") );

    InstanceContext = CONTAINING_RECORD( DataQueue, CTX_INSTANCE_CONTEXT, Cbdq );

    ExAcquireFastMutex( &InstanceContext->QueueLock );
}

VOID
CsqRelease(
    __in PFLT_CALLBACK_DATA_QUEUE DataQueue,
    __in KIRQL Irql
    )
{
    PCTX_INSTANCE_CONTEXT InstanceContext;

	PAGED_CODE();

    UNREFERENCED_PARAMETER( Irql );

	DebugTrace( DEBUG_TRACE_CBDQ_CALLBACK | DEBUG_TRACE_INFO, ("[Csq]: CsqRelease ->\n") );

    InstanceContext = CONTAINING_RECORD( DataQueue, CTX_INSTANCE_CONTEXT, Cbdq );

    ExReleaseFastMutex( &InstanceContext->QueueLock );
}

NTSTATUS
CsqInsertIo(
    __in PFLT_CALLBACK_DATA_QUEUE DataQueue,
    __in PFLT_CALLBACK_DATA Cbd,
    __in_opt PVOID Context
    )
{
    PCTX_INSTANCE_CONTEXT InstanceContext;
    PFLT_GENERIC_WORKITEM WorkItem = NULL;
    NTSTATUS Status = STATUS_SUCCESS;
    BOOLEAN WasQueueEmpty;

	PAGED_CODE();

    UNREFERENCED_PARAMETER( Context );

    DebugTrace( DEBUG_TRACE_CBDQ_CALLBACK | DEBUG_TRACE_INFO, ("[Csq]: CsqInsertIo ->\n") );

    InstanceContext = CONTAINING_RECORD( DataQueue, CTX_INSTANCE_CONTEXT, Cbdq );

    WasQueueEmpty = IsListEmpty( &InstanceContext->QueueHead );

    InsertTailList( &InstanceContext->QueueHead,
                    &Cbd->QueueLinks );

    //
    //  Queue a work item if no worker thread present.
    //
    if (WasQueueEmpty &&
        InterlockedIncrement( &InstanceContext->WorkerThreadFlag ) == 1) {

        WorkItem = FltAllocateGenericWorkItem();

        if (WorkItem) {

			FltReferenceContext(InstanceContext);

            Status = FltQueueGenericWorkItem( WorkItem,
                                              InstanceContext->Instance,
                                              CsqPreIoWorkItemRoutine,
                                              DelayedWorkQueue,
                                              InstanceContext );

            if (!NT_SUCCESS(Status)) {

                DebugTrace( DEBUG_TRACE_CBDQ_CALLBACK | DEBUG_TRACE_ERROR, 
                            ("[Csq]: CsqInsertIo -> Failed to queue the work item (Status = 0x%x)\n", Status) );

				FltReleaseContext(InstanceContext);
                FltFreeGenericWorkItem( WorkItem );
            }

        } else {

            DebugTrace( DEBUG_TRACE_CBDQ_CALLBACK | DEBUG_TRACE_ERROR, 
                        ("[Csq]: CsqInsertIo -> Failed to allocate work item\n") );

            Status = STATUS_INSUFFICIENT_RESOURCES;
        }

        if ( !NT_SUCCESS( Status )) {

            RemoveTailList( &InstanceContext->QueueHead );
        }
    }

    return Status;
}

VOID
CsqRemoveIo(
    __in PFLT_CALLBACK_DATA_QUEUE DataQueue,
    __in PFLT_CALLBACK_DATA Cbd
    )
{
	PAGED_CODE();

    UNREFERENCED_PARAMETER( DataQueue );

	DebugTrace( DEBUG_TRACE_CBDQ_CALLBACK | DEBUG_TRACE_INFO, ("[Csq]: CsqRemoveIo ->\n") );

    RemoveEntryList( &Cbd->QueueLinks );
}

PFLT_CALLBACK_DATA
CsqPeekNextIo(
    __in PFLT_CALLBACK_DATA_QUEUE DataQueue,
    __in_opt PFLT_CALLBACK_DATA Cbd,
    __in_opt PVOID PeekContext
    )
{
    PCTX_INSTANCE_CONTEXT InstanceContext;
    PLIST_ENTRY NextEntry;
    PFLT_CALLBACK_DATA NextCbd;

	PAGED_CODE();

    UNREFERENCED_PARAMETER( PeekContext );

	DebugTrace( DEBUG_TRACE_CBDQ_CALLBACK | DEBUG_TRACE_INFO, ("[Csq]: CsqPeekNextIo ->\n") );

    InstanceContext = CONTAINING_RECORD( DataQueue, CTX_INSTANCE_CONTEXT, Cbdq );

    if (Cbd == NULL) {

        NextEntry = InstanceContext->QueueHead.Flink;

    } else {

        NextEntry =  Cbd->QueueLinks.Flink;
    }

    if (NextEntry == &InstanceContext->QueueHead) {

        return NULL;
    }

    NextCbd = CONTAINING_RECORD( NextEntry, FLT_CALLBACK_DATA, QueueLinks );

    return NextCbd;
}

VOID
CsqCompleteCanceledIo(
    __in PFLT_CALLBACK_DATA_QUEUE DataQueue,
    __inout PFLT_CALLBACK_DATA Cbd
    )
{
	PCOMPLETION_CONTEXT CompCtx;

	PAGED_CODE();

    UNREFERENCED_PARAMETER( DataQueue );

	DebugTrace( DEBUG_TRACE_CBDQ_CALLBACK | DEBUG_TRACE_INFO, ("[Csq]: CsqCompleteCanceledIo ->\n") );

    CompCtx = (PCOMPLETION_CONTEXT) Cbd->QueueContext[0];

    Cbd->IoStatus.Status = STATUS_CANCELLED;
    Cbd->IoStatus.Information = 0;

    FltCompletePendedPreOperation( Cbd,
                                   FLT_PREOP_COMPLETE,
                                   0 );

	MiniFreeContext (CompCtx);
}

VOID
CsqPreIoWorkItemRoutine (
    __in PFLT_GENERIC_WORKITEM WorkItem,
    __in PFLT_FILTER Filter,
    __in PVOID Context
    )
{
	FLT_PREOP_CALLBACK_STATUS ReturnStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
	PCTX_INSTANCE_CONTEXT InstanceContext = (PCTX_INSTANCE_CONTEXT)Context;
	PCOMPLETION_CONTEXT CompCtx;
    PCTX_STREAM_CONTEXT StreamContext;
    PFLT_CALLBACK_DATA Cbd;
    NTSTATUS Status = STATUS_SUCCESS;

	PAGED_CODE();

    UNREFERENCED_PARAMETER( WorkItem );
    UNREFERENCED_PARAMETER( Filter );

	DebugTrace( DEBUG_TRACE_CBDQ_CALLBACK | DEBUG_TRACE_INFO | DEBUG_TRACE_CBDQIO, ("[Csq]: CsqPreIoWorkItemRoutine ->\n") );

    for (;;) {

		Status = KeWaitForSingleObject( InstanceContext->TeardownEvent,
										Executive,
										KernelMode,
										FALSE,
										NULL );
		if (NT_SUCCESS (Status)) {
			break;
		}

        //
        //  WorkerThreadFlag >= 1;
        //  Here we reduce it to 1.
        //

        InterlockedExchange( &InstanceContext->WorkerThreadFlag, 1 );

        //
        //  Remove an I/O from the cancel safe queue.
        //

        Cbd = FltCbdqRemoveNextIo( &InstanceContext->Cbdq,
                                    NULL);

        if (Cbd) {

            CompCtx = (PCOMPLETION_CONTEXT) Cbd->QueueContext[0];
			StreamContext = CompCtx->Stream;

            if ( Cbd->Iopb->Parameters.Read.MdlAddress == NULL &&
                 !FlagOn(Cbd->Flags, FLTFL_CALLBACK_DATA_SYSTEM_BUFFER) ) {

                Status = FltLockUserBuffer( Cbd );

                if (!NT_SUCCESS(Status)) {

                    DebugTrace( DEBUG_TRACE_CBDQ_CALLBACK | DEBUG_TRACE_CBDQIO | DEBUG_TRACE_ERROR,
                                ("[Csq]: CsqPreIoWorkItemRoutine -> Failed to lock user buffer (Status = 0x%x)\n",
                                Status) );

					Cbd->IoStatus.Status = Status;
					ReturnStatus = FLT_PREOP_COMPLETE;
                }
            }

			if (NT_SUCCESS (Status)) {

				switch (Cbd->Iopb->MajorFunction) {

				case IRP_MJ_READ:

					ReturnStatus = CsqPreReadInternal (Cbd, CompCtx);
					break;
				}
			}
			
			if (ReturnStatus == FLT_PREOP_SUCCESS_WITH_CALLBACK) {

				ReturnStatus = FLT_PREOP_SYNCHRONIZE;
			}

            //
            //  Complete the I/O
            //
            FltCompletePendedPreOperation( Cbd,
                                           ReturnStatus,
										   ReturnStatus == FLT_PREOP_SYNCHRONIZE ? CompCtx : NULL );
			
			MiniFreeContext (CompCtx);
			CompCtx = NULL;

        } else {

            if (InterlockedDecrement( &InstanceContext->WorkerThreadFlag ) == 0)
                break;
        }
    }

	FltReleaseContext(InstanceContext);

    FltFreeGenericWorkItem(WorkItem);
}

VOID
CqsEmptyQueueAndComplete (
    __in PCTX_INSTANCE_CONTEXT InstanceContext
    )
{
    PFLT_CALLBACK_DATA Cbd;
	PCOMPLETION_CONTEXT CompCtx;

	PAGED_CODE();

    do {

        Cbd = FltCbdqRemoveNextIo( &InstanceContext->Cbdq,
                                    NULL );

        if (Cbd) {

            CompCtx = (PCOMPLETION_CONTEXT) Cbd->QueueContext[0];

            if ( Cbd->Iopb->Parameters.Read.MdlAddress == NULL &&
                !FlagOn(Cbd->Flags, FLTFL_CALLBACK_DATA_SYSTEM_BUFFER) ) {

                (VOID) FltLockUserBuffer( Cbd );
            }

            FltCompletePendedPreOperation( Cbd,
                                           FLT_PREOP_SUCCESS_NO_CALLBACK,
                                           NULL );
			
			MiniFreeContext (CompCtx);
        }

    } while (Cbd);
}
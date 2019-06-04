#pragma once

VOID
CsqAcquire(
    __in PFLT_CALLBACK_DATA_QUEUE DataQueue,
    __out PKIRQL Irql
    );

VOID
CsqRelease(
    __in PFLT_CALLBACK_DATA_QUEUE DataQueue,
    __in KIRQL Irql
    );

NTSTATUS
CsqInsertIo(
    __in PFLT_CALLBACK_DATA_QUEUE DataQueue,
    __in PFLT_CALLBACK_DATA Cbd,
    __in_opt PVOID Context
    );

VOID
CsqRemoveIo(
    __in PFLT_CALLBACK_DATA_QUEUE DataQueue,
    __in PFLT_CALLBACK_DATA Cbd
    );

PFLT_CALLBACK_DATA
CsqPeekNextIo(
    __in PFLT_CALLBACK_DATA_QUEUE DataQueue,
    __in_opt PFLT_CALLBACK_DATA Cbd,
    __in_opt PVOID PeekContext
    );

VOID
CsqCompleteCanceledIo(
    __in PFLT_CALLBACK_DATA_QUEUE DataQueue,
    __inout PFLT_CALLBACK_DATA Cbd
    );

VOID
CsqPreIoWorkItemRoutine (
    __in PFLT_GENERIC_WORKITEM WorkItem,
    __in PFLT_FILTER Filter,
    __in PVOID Context
    );

VOID
CqsEmptyQueueAndComplete (
    __in PCTX_INSTANCE_CONTEXT InstanceContext
    );

FLT_PREOP_CALLBACK_STATUS
CsqPreRead (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    );

FLT_PREOP_CALLBACK_STATUS
CsqPreReadInternal (
    __inout PFLT_CALLBACK_DATA Cbd,
	__inout PVOID Context
	);

FLT_POSTOP_CALLBACK_STATUS
CsqPostRead (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __inout_opt PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    );
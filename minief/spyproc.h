#pragma once

PRECORD_LIST
SpyAllocateBuffer (
    __out PULONG RecordType
    );

VOID
SpyFreeBuffer (
    __in PVOID Buffer
    );

PRECORD_LIST
SpyNewRecord (
    VOID
    );

VOID
SpyFreeRecord (
    __in PRECORD_LIST Record
    );

VOID
SpySetRecordName (
    __inout PLOG_RECORD LogRecord,
    __in PUNICODE_STRING Name
    );

VOID
SpyLogPreOperationData (
	__in ULONG Altitude,
    __in PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __inout PRECORD_LIST RecordList
    );

VOID
SpyLogPostOperationData (
    __in PFLT_CALLBACK_DATA Cbd,
    __inout PRECORD_LIST RecordList
    );

VOID
SpyLog (
    __in PRECORD_LIST RecordList
    );

NTSTATUS
SpyGetLog (
    __out_bcount_part(OutputBufferLength,*ReturnOutputBufferLength) PUCHAR OutputBuffer,
    __in ULONG OutputBufferLength,
    __out PULONG ReturnOutputBufferLength
    );

VOID
SpyEmptyOutputBufferList (
    VOID
    );


FLT_PREOP_CALLBACK_STATUS
SpyPreOperationCallback (
	__in ULONG Altitude,
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    );

FLT_POSTOP_CALLBACK_STATUS
SpyPostOperationCallback (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    );
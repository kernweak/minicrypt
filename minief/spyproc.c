#include "mefkern.h"
#include <stdio.h>

NTSTATUS StatusToBreakOn = 0;

PRECORD_LIST
SpyAllocateBuffer (
    __out PULONG RecordType
    )
{
    PVOID NewBuffer;
    ULONG NewRecordType = RECORD_TYPE_NORMAL;

    if (MiniEfData.RecordsAllocated < MiniEfData.MaxRecordsToAllocate) {

        InterlockedIncrement( &MiniEfData.RecordsAllocated );

        NewBuffer = ExAllocateFromNPagedLookasideList( &MiniEfData.FreeBufferList );

        if (NewBuffer == NULL) {

            InterlockedDecrement( &MiniEfData.RecordsAllocated );

            NewRecordType = RECORD_TYPE_FLAG_OUT_OF_MEMORY;
        }

    } else {

        NewRecordType = RECORD_TYPE_FLAG_EXCEED_MEMORY_ALLOWANCE;
        NewBuffer = NULL;
    }

    *RecordType = NewRecordType;
    return NewBuffer;
}

VOID
SpyFreeBuffer (
    __in PVOID Buffer
    )
{
    InterlockedDecrement( &MiniEfData.RecordsAllocated );
    ExFreeToNPagedLookasideList( &MiniEfData.FreeBufferList, Buffer );
}

PRECORD_LIST
SpyNewRecord (
    VOID
    )
{
    PRECORD_LIST NewRecord;
    ULONG InitialRecordType;

    NewRecord = SpyAllocateBuffer( &InitialRecordType );

    if (NewRecord == NULL) {

        if (!InterlockedExchange( &MiniEfData.StaticBufferInUse, TRUE )) {

            NewRecord = (PRECORD_LIST)MiniEfData.OutOfMemoryBuffer;
            InitialRecordType |= RECORD_TYPE_FLAG_STATIC;
        }
    }

    if (NewRecord != NULL) {

        NewRecord->LogRecord.RecordType = InitialRecordType;
        NewRecord->LogRecord.Length = sizeof(LOG_RECORD);
        NewRecord->LogRecord.SequenceNumber = InterlockedIncrement( &MiniEfData.LogSequenceNumber );
        RtlZeroMemory( &NewRecord->LogRecord.Data, sizeof( RECORD_DATA ) );
    }

    return( NewRecord );
}

VOID
SpyFreeRecord (
    __in PRECORD_LIST Record
    )
{
    if (FlagOn(Record->LogRecord.RecordType,RECORD_TYPE_FLAG_STATIC)) {

        ASSERT(MiniEfData.StaticBufferInUse);
        MiniEfData.StaticBufferInUse = FALSE;

    } else {

        SpyFreeBuffer( Record );
    }
}

VOID
SpySetRecordName (
    __inout PLOG_RECORD LogRecord,
    __in PUNICODE_STRING Name
    )
{
    ULONG NameCopyLength;
    PCHAR CopyPointer = (PCHAR)LogRecord->Name;

    if (NULL != Name) {

        if (Name->Length > (MAX_NAME_SPACE - sizeof( UNICODE_NULL ))) {

            NameCopyLength = MAX_NAME_SPACE - sizeof( UNICODE_NULL );

        } else {

            NameCopyLength = (ULONG)Name->Length;
        }

        //
        //  We will always round up log-record length to sizeof(PVOID) so that
        //  the next log record starts on the right PVOID boundary to prevent
        //  IA64 alignment faults.  The length of the record of course
        //  includes the additional NULL at the end.
        //

        LogRecord->Length = ROUND_TO_SIZE( (LogRecord->Length +
                                            NameCopyLength +
                                            sizeof( UNICODE_NULL )),
                                            sizeof( PVOID ) );

        RtlCopyMemory( CopyPointer, Name->Buffer, NameCopyLength );

        CopyPointer += NameCopyLength;

        *((PWCHAR) CopyPointer) = UNICODE_NULL;

        ASSERT(LogRecord->Length <= MAX_LOG_RECORD_LENGTH);
    }
}

VOID
SpyLogPreOperationData (
	__in ULONG Altitude,
    __in PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __inout PRECORD_LIST RecordList
    )
{
    PRECORD_DATA RecordData = &RecordList->LogRecord.Data;
    PDEVICE_OBJECT DevObj;
    NTSTATUS Status;

    Status = FltGetDeviceObject(FltObjects->Volume,&DevObj);
    if (NT_SUCCESS(Status)) {

        ObDereferenceObject(DevObj);

    } else {

        DevObj = NULL;
    }

	RecordData->Altitude		= Altitude;
    RecordData->CallbackMajorId = Cbd->Iopb->MajorFunction;
    RecordData->CallbackMinorId = Cbd->Iopb->MinorFunction;
    RecordData->IrpFlags        = Cbd->Iopb->IrpFlags;
    RecordData->Flags           = Cbd->Flags;

    RecordData->DeviceObject    = (FILE_ID)DevObj;
    RecordData->FileObject      = (FILE_ID)FltObjects->FileObject;
    RecordData->Transaction     = (FILE_ID)FltObjects->Transaction;
    RecordData->ProcessId       = (FILE_ID)PsGetCurrentProcessId();
    RecordData->ThreadId        = (FILE_ID)PsGetCurrentThreadId();

    RecordData->Arg1 = Cbd->Iopb->Parameters.Others.Argument1;
    RecordData->Arg2 = Cbd->Iopb->Parameters.Others.Argument2;
    RecordData->Arg3 = Cbd->Iopb->Parameters.Others.Argument3;
    RecordData->Arg4 = Cbd->Iopb->Parameters.Others.Argument4;
    RecordData->Arg5 = Cbd->Iopb->Parameters.Others.Argument5;
    RecordData->Arg6.QuadPart = Cbd->Iopb->Parameters.Others.Argument6.QuadPart;

    KeQuerySystemTime( &RecordData->OriginatingTime );
}

VOID
SpyLogPostOperationData (
    __in PFLT_CALLBACK_DATA Cbd,
    __inout PRECORD_LIST RecordList
    )
{
    PRECORD_DATA RecordData = &RecordList->LogRecord.Data;

    RecordData->Status = Cbd->IoStatus.Status;
    RecordData->Information = Cbd->IoStatus.Information;
    KeQuerySystemTime( &RecordData->CompletionTime );
}

VOID
SpyLog (
    __in PRECORD_LIST RecordList
    )
{
    KIRQL OldIrql;

    KeAcquireSpinLock(&MiniEfData.OutputBufferLock, &OldIrql);
    InsertTailList(&MiniEfData.OutputBufferList, &RecordList->List);
    KeReleaseSpinLock(&MiniEfData.OutputBufferLock, OldIrql);
}

NTSTATUS
SpyGetLog (
    __out_bcount_part(OutputBufferLength,*ReturnOutputBufferLength) PUCHAR OutputBuffer,
    __in ULONG OutputBufferLength,
    __out PULONG ReturnOutputBufferLength
    )
{
    PLIST_ENTRY ListPtr;
    ULONG BytesWritten = 0;
    PLOG_RECORD LogRecordPtr;
    NTSTATUS Status = STATUS_NO_MORE_ENTRIES;
    PRECORD_LIST RecordListPtr;
    KIRQL OldIrql;
    BOOLEAN RecordsAvailable = FALSE;

    KeAcquireSpinLock( &MiniEfData.OutputBufferLock, &OldIrql );

    while (!IsListEmpty( &MiniEfData.OutputBufferList ) && (OutputBufferLength > 0)) {

        RecordsAvailable = TRUE;

        ListPtr = RemoveHeadList( &MiniEfData.OutputBufferList );

        RecordListPtr = CONTAINING_RECORD( ListPtr, RECORD_LIST, List );

        LogRecordPtr = &RecordListPtr->LogRecord;

        //
        //  If no filename was set then make it into a NULL file name.
        //

        if (REMAINING_NAME_SPACE( LogRecordPtr ) == MAX_NAME_SPACE) {

            LogRecordPtr->Length += ROUND_TO_SIZE( sizeof( UNICODE_NULL ), sizeof( PVOID ) );
            LogRecordPtr->Name[0] = UNICODE_NULL;
        }

        if (OutputBufferLength < LogRecordPtr->Length) {

            InsertHeadList( &MiniEfData.OutputBufferList, ListPtr );
            break;
        }

        KeReleaseSpinLock( &MiniEfData.OutputBufferLock, OldIrql );

        try {
            RtlCopyMemory( OutputBuffer, LogRecordPtr, LogRecordPtr->Length );
        } except( EXCEPTION_EXECUTE_HANDLER ) {

            KeAcquireSpinLock( &MiniEfData.OutputBufferLock, &OldIrql );
            InsertHeadList( &MiniEfData.OutputBufferList, ListPtr );
            KeReleaseSpinLock( &MiniEfData.OutputBufferLock, OldIrql );

            return GetExceptionCode();
        }

        BytesWritten += LogRecordPtr->Length;

        OutputBufferLength -= LogRecordPtr->Length;

        OutputBuffer += LogRecordPtr->Length;

        SpyFreeRecord( RecordListPtr );

        KeAcquireSpinLock( &MiniEfData.OutputBufferLock, &OldIrql );
    }

    KeReleaseSpinLock( &MiniEfData.OutputBufferLock, OldIrql );

    if ((BytesWritten == 0) && RecordsAvailable) {

        Status = STATUS_BUFFER_TOO_SMALL;

    } else if (BytesWritten > 0) {

        Status = STATUS_SUCCESS;
    }

    *ReturnOutputBufferLength = BytesWritten;

    return Status;
}

VOID
SpyEmptyOutputBufferList (
    VOID
    )
{
    PLIST_ENTRY ListPtr;
    PRECORD_LIST RecordListPtr;
    KIRQL OldIrql;

    KeAcquireSpinLock( &MiniEfData.OutputBufferLock, &OldIrql );

    while (!IsListEmpty( &MiniEfData.OutputBufferList )) {

        ListPtr = RemoveHeadList( &MiniEfData.OutputBufferList );
        KeReleaseSpinLock( &MiniEfData.OutputBufferLock, OldIrql );

        RecordListPtr = CONTAINING_RECORD( ListPtr, RECORD_LIST, List );

        SpyFreeRecord( RecordListPtr );

        KeAcquireSpinLock( &MiniEfData.OutputBufferLock, &OldIrql );
    }

    KeReleaseSpinLock( &MiniEfData.OutputBufferLock, OldIrql );
}


FLT_PREOP_CALLBACK_STATUS
SpyPreOperationCallback (
	__in ULONG Altitude,
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
    FLT_PREOP_CALLBACK_STATUS ReturnStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
	PCOMPLETION_CONTEXT CompCtx = (PCOMPLETION_CONTEXT)*CompletionContext;
    PRECORD_LIST RecordList;
    PFLT_FILE_NAME_INFORMATION NameInfo = NULL;
    UNICODE_STRING DefaultName;
    PUNICODE_STRING NameToUse;
    NTSTATUS Status;
#if MINIEF_NOT_W2K
    WCHAR name[MAX_NAME_SPACE/sizeof(WCHAR)];
#endif

	ASSERT (CompCtx);
    RecordList = SpyNewRecord();
	
    if (RecordList) {

		CompCtx->Record.RecordList = RecordList;

        //
        //  We got a log record, if there is a file object, get its name.
        //
        //  NOTE: By default, we use the query method
        //  FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP
        //  because MiniSpy would like to get the name as much as possible, but
        //  can cope if we can't retrieve a name.  For a debugging type filter,
        //  like Minispy, this is reasonable, but for most production filters
        //  who need names reliably, they should query the name at times when it
        //  is known to be safe and use the query method
        //  FLT_FILE_NAME_QUERY_DEFAULT.
        //

        if (FltObjects->FileObject != NULL) {

            Status = FltGetFileNameInformation( Cbd,
                                                FLT_FILE_NAME_NORMALIZED |
                                                    MiniEfData.NameQueryMethod,
                                                &NameInfo );

        } else {

            Status = STATUS_UNSUCCESSFUL;
        }

        if (NT_SUCCESS( Status )) {

            NameToUse = &NameInfo->Name;

            //
            //  Parse the name if requested
            //

            if (FlagOn( MiniEfData.DebugFlags, DEBUG_PARSE_NAMES )) {

                Status = FltParseFileNameInformation( NameInfo );
                ASSERT(NT_SUCCESS(Status));
            }

        } else {

#if MINIEF_NOT_W2K
            NTSTATUS lStatus;
            PFLT_FILE_NAME_INFORMATION lNameInfo;

            //
            //  If we couldn't get the "normalized" name try and get the
            //  "opened" name
            //

            if (FltObjects->FileObject != NULL) {

                //
                //  Get the opened name
                //

                lStatus = FltGetFileNameInformation( Cbd,
                                                     FLT_FILE_NAME_OPENED |
                                                            FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
                                                     &lNameInfo );


                if (NT_SUCCESS(lStatus)) {

#pragma prefast(suppress:__WARNING_BANNED_API_USAGE, "reviewed and safe usage")
                    (VOID)_snwprintf( name,
                                      sizeof(name)/sizeof(WCHAR),
                                      L"<%08x> %wZ",
                                      Status,
                                      &lNameInfo->Name );

                    FltReleaseFileNameInformation( lNameInfo );

                } else {

                    //
                    //  If that failed report both NORMALIZED Status and
                    //  OPENED Status
                    //

#pragma prefast(suppress:__WARNING_BANNED_API_USAGE, "reviewed and safe usage")
                    (VOID)_snwprintf( name,
                                      sizeof(name)/sizeof(WCHAR),
                                      L"<NO NAME: NormalizeStatus=%08x OpenedStatus=%08x>",
                                      Status,
                                      lStatus );
                }

            } else {

#pragma prefast(suppress:__WARNING_BANNED_API_USAGE, "reviewed and safe usage")
                (VOID)_snwprintf( name,
                                  sizeof(name)/sizeof(WCHAR),
                                  L"<NO NAME>" );

            }

            RtlInitUnicodeString( &DefaultName, name );
            NameToUse = &DefaultName;
#else
            //
            //  We were unable to get the String safe routine to work on W2K
            //  Do it the old safe way
            //

            RtlInitUnicodeString( &DefaultName, L"<NO NAME>" );
            NameToUse = &DefaultName;
#endif

#if DBG
            //
            //  Debug support to break on certain errors.
            //

            if (FltObjects->FileObject != NULL) {
                NTSTATUS retryStatus;

                if ((StatusToBreakOn != 0) && (Status == StatusToBreakOn)) {

                    DbgBreakPoint();
                }

                retryStatus = FltGetFileNameInformation( Cbd,
                                                         FLT_FILE_NAME_NORMALIZED |
                                                             MiniEfData.NameQueryMethod,
                                                         &NameInfo );
            }
#endif

        }

        //
        //  Store the name
        //

        SpySetRecordName( &(RecordList->LogRecord), NameToUse );

        //
        //  Release the name information structure (if defined)
        //

        if (NULL != NameInfo) {

            FltReleaseFileNameInformation( NameInfo );
        }

        SpyLogPreOperationData( Altitude, Cbd, FltObjects, RecordList );

        //
        //  Pass the record to our completions routine and return that
        //  we want our completion routine called.
        //

        if( Cbd->Iopb->MajorFunction == IRP_MJ_SHUTDOWN ) {

            //
            //  Since completion callbacks are not supported for
            //  this operation, do the completion processing now
            //

            SpyPostOperationCallback( Cbd,
                                      FltObjects,
                                      RecordList,
                                      0 );

            ReturnStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;

        } else {

            ReturnStatus = FLT_PREOP_SUCCESS_WITH_CALLBACK;
        }
    }

    return ReturnStatus;
}

FLT_POSTOP_CALLBACK_STATUS
SpyPostOperationCallback (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    )
{
    PRECORD_LIST RecordList;
    PRECORD_LIST ReparseRecordList = NULL;
    PLOG_RECORD ReparseLogRecord;
    PFLT_TAG_DATA_BUFFER TagData;
    ULONG CopyLength;

    UNREFERENCED_PARAMETER( FltObjects );

    RecordList = (PRECORD_LIST)CompletionContext;

    //
    //  If our instance is in the process of being torn down don't bother to
    //  log this record, free it now.
    //

    if (FlagOn(Flags,FLTFL_POST_OPERATION_DRAINING)) {

        SpyFreeRecord( RecordList );
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    SpyLogPostOperationData( Cbd, RecordList );

    //
    //  Log reparse tag information if specified.
    //

    if (TagData = Cbd->TagData) {

        ReparseRecordList = SpyNewRecord();

        if (ReparseRecordList) {

            //
            //  only copy the DATA portion of the information
            //

            RtlCopyMemory( &ReparseRecordList->LogRecord.Data,
                           &RecordList->LogRecord.Data,
                           sizeof(RECORD_DATA) );

            ReparseLogRecord = &ReparseRecordList->LogRecord;

            CopyLength = FLT_TAG_DATA_BUFFER_HEADER_SIZE + TagData->TagDataLength;

            if(CopyLength > MAX_NAME_SPACE) {

                CopyLength = MAX_NAME_SPACE;
            }

            //
            //  Copy reparse data
            //

            RtlCopyMemory(
                &ReparseRecordList->LogRecord.Name[0],
                TagData,
                CopyLength
                );

            ReparseLogRecord->RecordType |= RECORD_TYPE_FILETAG;
            ReparseLogRecord->Length += (ULONG) ROUND_TO_SIZE( CopyLength, sizeof( PVOID ) );
        }
    }

    SpyLog( RecordList );

    if (ReparseRecordList) {

        SpyLog( ReparseRecordList );
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}
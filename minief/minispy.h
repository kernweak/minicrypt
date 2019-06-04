#pragma once

#define IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION  ((UCHAR)-1)
#define IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION  ((UCHAR)-2)
#define IRP_MJ_ACQUIRE_FOR_MOD_WRITE                ((UCHAR)-3)
#define IRP_MJ_RELEASE_FOR_MOD_WRITE                ((UCHAR)-4)
#define IRP_MJ_ACQUIRE_FOR_CC_FLUSH                 ((UCHAR)-5)
#define IRP_MJ_RELEASE_FOR_CC_FLUSH                 ((UCHAR)-6)
#define IRP_MJ_NOTIFY_STREAM_FO_CREATION            ((UCHAR)-7)

#define IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE            ((UCHAR)-13)
#define IRP_MJ_NETWORK_QUERY_OPEN                   ((UCHAR)-14)
#define IRP_MJ_MDL_READ                             ((UCHAR)-15)
#define IRP_MJ_MDL_READ_COMPLETE                    ((UCHAR)-16)
#define IRP_MJ_PREPARE_MDL_WRITE                    ((UCHAR)-17)
#define IRP_MJ_MDL_WRITE_COMPLETE                   ((UCHAR)-18)
#define IRP_MJ_VOLUME_MOUNT                         ((UCHAR)-19)
#define IRP_MJ_VOLUME_DISMOUNT                      ((UCHAR)-20)


typedef ULONG_PTR FILE_ID;
typedef LONG NTSTATUS;

//
//  The maximum size of a record that can be passed from the filter
//

#define RECORD_SIZE     512

//
//  This defines the type of record buffer this is along with certain flags.
//

#define RECORD_TYPE_NORMAL                       0x00000000
#define RECORD_TYPE_FILETAG                      0x00000004

#define RECORD_TYPE_FLAG_STATIC                  0x80000000
#define RECORD_TYPE_FLAG_EXCEED_MEMORY_ALLOWANCE 0x20000000
#define RECORD_TYPE_FLAG_OUT_OF_MEMORY           0x10000000
#define RECORD_TYPE_FLAG_MASK                    0xffff0000


typedef struct _RECORD_DATA {

    LARGE_INTEGER OriginatingTime;
    LARGE_INTEGER CompletionTime;

	ULONG Altitude;
	ULONG Reserved2;

    FILE_ID DeviceObject;
    FILE_ID FileObject;
    FILE_ID Transaction;

    FILE_ID ProcessId;
    FILE_ID ThreadId;

    ULONG_PTR Information;

    NTSTATUS Status;

    ULONG IrpFlags;
    ULONG Flags;

    UCHAR CallbackMajorId;
    UCHAR CallbackMinorId;
    UCHAR Reserved[2];      // Alignment on IA64

    PVOID Arg1;
    PVOID Arg2;
    PVOID Arg3;
    PVOID Arg4;
    PVOID Arg5;
    LARGE_INTEGER Arg6;

} RECORD_DATA, *PRECORD_DATA;

//
//  What information we actually log.
//

typedef struct _LOG_RECORD {

    ULONG Length;           // Length of log record.  This Does not include
    ULONG SequenceNumber;   // space used by other members of RECORD_LIST

    ULONG RecordType;       // The type of log record this is.
    ULONG Reserved;         // For alignment on IA64

    RECORD_DATA Data;
    WCHAR Name[];           //  This is a null terminated string

} LOG_RECORD, *PLOG_RECORD;

//
//  How the mini-filter manages the log records.
//

typedef struct _RECORD_LIST {

    LIST_ENTRY List;

    //
    // Must always be last item.  See MAX_LOG_RECORD_LENGTH macro below.
    // Must be aligned on PVOID boundary in this structure. This is because the
    // log records are going to be packed one after another & accessed directly
    // Size of log record must also be multiple of PVOID size to avoid alignment
    // faults while accessing the log records on IA64
    //

    LOG_RECORD LogRecord;

} RECORD_LIST, *PRECORD_LIST;


//
//  The maximum number of BYTES that can be used to store the file name in the
//  RECORD_LIST structure
//

#define MAX_NAME_SPACE ROUND_TO_SIZE( (RECORD_SIZE - sizeof(RECORD_LIST)), sizeof( PVOID ))

//
//  Returns the number of BYTES unused in the RECORD_LIST structure.  Note that
//  LogRecord->Length already contains the size of LOG_RECORD which is why we
//  have to remove it.
//

#define REMAINING_NAME_SPACE(LogRecord) \
    (ASSERT((LogRecord)->Length >= sizeof(LOG_RECORD)), \
     (USHORT)(MAX_NAME_SPACE - ((LogRecord)->Length - sizeof(LOG_RECORD))))

#define MAX_LOG_RECORD_LENGTH  (RECORD_SIZE - FIELD_OFFSET( RECORD_LIST, LogRecord ))
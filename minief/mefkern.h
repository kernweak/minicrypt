#pragma once

#include <fltKernel.h>
#include <suppress.h>
#include "minief.h"
#include "minispy.h"

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

#define MINI_TAG 'sfVM'

#define FLT_POSTOP_WITHOUT_FREE_CONTEXT			0xed


#define MINIEF_VISTA    (NTDDI_VERSION >= NTDDI_VISTA)
#define MINIEF_NOT_W2K  (OSVER(NTDDI_VERSION) > NTDDI_WIN2K)

typedef struct _MINIEF_DATA {

    PDRIVER_OBJECT DriverObject;

    //
    //  The filter that results from a call to
    //  FltRegisterFilter.
    //

    PFLT_FILTER Filter;

    //
    //  Server port: user mode connects to this port
    //

    PFLT_PORT ServerPort;

    //
    //  Client connection port: only one connection is allowed at a time.,
    //

    PFLT_PORT ClientPort;

	NPAGED_LOOKASIDE_LIST CompletionContextList;

    //
    //  List of buffers with data to send to user mode.
    //

    KSPIN_LOCK OutputBufferLock;
    LIST_ENTRY OutputBufferList;

    //
    //  Lookaside list used for allocating buffers.
    //

    NPAGED_LOOKASIDE_LIST FreeBufferList;

    //
    //  Variables used to throttle how many records buffer we can use
    //

    LONG MaxRecordsToAllocate;
    __volatile LONG RecordsAllocated;

    //
    //  static buffer used for sending an "out-of-memory" message
    //  to user mode.
    //

    __volatile ULONG StaticBufferInUse;

    //
    //  We need to make sure this buffer aligns on a PVOID boundary because
    //  minispy casts this buffer to a RECORD_LIST structure.
    //  That can cause alignment faults unless the structure starts on the
    //  proper PVOID boundary
    //

    PVOID OutOfMemoryBuffer[RECORD_SIZE/sizeof( PVOID )];

    //
    //  Variable and lock for maintaining LogRecord sequence numbers.
    //

    __volatile ULONG LogSequenceNumber;

    //
    //  The name query method to use.  By default, it is set to
    //  FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, but it can be overridden
    //  by a setting in the registery.
    //

    ULONG NameQueryMethod;

    //
    //  Global debug flags
    //

    ULONG DebugFlags;

	ULONG DebugLevels;

} MINIEF_DATA, *PMINIEF_DATA;

//
//  Minispy's global variables
//

extern MINIEF_DATA							MiniEfData;

#define DEFAULT_MAX_RECORDS_TO_ALLOCATE     500
#define MAX_RECORDS_TO_ALLOCATE             L"MaxRecords"

#define DEFAULT_NAME_QUERY_METHOD           FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP
#define NAME_QUERY_METHOD                   L"NameQueryMethod"


extern const FLT_REGISTRATION FilterRegistration;

#define INSTANCE_TOP_MONITOR			385000
#define INSTANCE_TOP_MONITOR_STR		L"385000"
#define INSTANCE_BOTTOM_MONITOR			48500
#define INSTANCE_BOTTOM_MONITOR_STR		L"48500"
#define INSTANCE_ENCRYPT_FOLDER			143000
#define INSTANCE_ENCRYPT_FOLDER_STR		L"143000"


#if DBG

#define DEBUG_TRACE_ERROR                               0x00000001  // Errors - whenever we return a failure code
#define DEBUG_TRACE_INFO								0x00000002	// Info
#define DEBUG_TRACE_WARN								0x00000004

#define DEBUG_TRACE_ENCRYPT								0x00000008

#define DEBUG_TRACE_LOAD_UNLOAD                         0x00000010  // Loading/unloading of the filter

#define DEBUG_TRACE_INSTANCES                           0x00000100  // Attach / detatch of instances
#define DEBUG_TRACE_INSTANCE_CONTEXT_OPERATIONS         0x00000200  // Operation on instance context
#define DEBUG_TRACE_STREAM_CONTEXT_OPERATIONS           0x00000400  // Operation on stream context
#define DEBUG_TRACE_STREAMHANDLE_CONTEXT_OPERATIONS     0x00000800  // Operation on stream handle context

#define DEBUG_TRACE_CREATE								0x00010000
#define DEBUG_TRACE_CLEANUP								0x00020000
#define DEBUG_TRACE_CLOSE								0x00040000
#define DEBUG_TRACE_READ								0x00080000
#define DEBUG_TRACE_WRITE								0x00100000
#define DEBUG_TRACE_SETFILE								0x00200000
#define DEBUG_TRACE_QUERYFILE							0x00400000
#define DEBUG_TRACE_DIRCTRL								0x00800000

#define DEBUG_TRACE_CBDQ_CALLBACK						0x10000000
#define DEBUG_TRACE_CBDQIO								0x20000000

#define DEBUG_TRACE_ALL                                 0xFFFFFFFF  // All flags

#define DebugTrace(Level, Data)					\
    if ((Level) & MiniEfData.DebugLevels) {	\
        DbgPrint Data;							\
    }

#else

#define DebugTrace(Level, Data)             {NOTHING;}

#endif

#define DEBUG_PARSE_NAMES   0x00000001


#include "ctxproc.h"
#include "csqproc.h"
#include "spyproc.h"
#include "encrypt.h"

typedef struct _COMPLETION_CONTEXT {

	PCTX_INSTANCE_CONTEXT Instance;
	PCTX_STREAM_CONTEXT Stream;
	
	union {
		struct {
			PRECORD_LIST RecordList;
		} Record;

		struct {
			PVOID SwappedBuffer;
			ULONG Length;
		} Read;
		
		struct {
			PVOID SwappedBuffer;
			ULONG Length;
			LARGE_INTEGER OldFileSize;
			LARGE_INTEGER OldByteOffset;
			ULONG OldLength;
			ULONG PreAddLength;
			BOOLEAN ExtendValidDataLength;
			UCHAR Flags;
		} Write;

		struct {
			PVOID SwappedBuffer;
			ULONG Length;
			LARGE_INTEGER OldFileSize;
			LARGE_INTEGER OldValidDataLength;
			BOOLEAN ReduceSize;
		} SetFile;

		struct {
			PVOID SwappedBuffer;
			ULONG Length;
		} QueryDir;
	};

} COMPLETION_CONTEXT, *PCOMPLETION_CONTEXT;

#define COMPLETION_CONTEXT_SIZE (sizeof(COMPLETION_CONTEXT))

NTSTATUS
MiniFilterUnload (
    __in FLT_FILTER_UNLOAD_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
MiniPreOperationCallback (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    );

FLT_POSTOP_CALLBACK_STATUS
MiniPostOperationCallback (
    __inout PFLT_CALLBACK_DATA Cbd,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    );

PCOMPLETION_CONTEXT
MiniAllocateContext (
	VOID
    );

VOID
MiniFreeContext (
    __in PVOID Buffer
    );

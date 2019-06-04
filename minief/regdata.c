#include "mefkern.h"

#ifdef ALLOC_DATA_PRAGMA
#pragma data_seg("INIT")
#pragma const_seg("INIT")
#endif

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE,
      0,	//FLTFL_OPERATION_REGISTRATION_SKIP_CACHED_IO|FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO
      MiniPreOperationCallback,
      MiniPostOperationCallback },

    { IRP_MJ_CREATE_NAMED_PIPE,
      0,
      MiniPreOperationCallback,
      MiniPostOperationCallback },

    { IRP_MJ_CLOSE,
      0,
      MiniPreOperationCallback,
      MiniPostOperationCallback },

    { IRP_MJ_READ,
      0,
      MiniPreOperationCallback,
      MiniPostOperationCallback },

    { IRP_MJ_WRITE,
      0,
      MiniPreOperationCallback,
      MiniPostOperationCallback },

    { IRP_MJ_QUERY_INFORMATION,
      0,
      MiniPreOperationCallback,
      MiniPostOperationCallback },

    { IRP_MJ_SET_INFORMATION,
      0,
      MiniPreOperationCallback,
      MiniPostOperationCallback },

    { IRP_MJ_QUERY_EA,
      0,
      MiniPreOperationCallback,
      MiniPostOperationCallback },

    { IRP_MJ_SET_EA,
      0,
      MiniPreOperationCallback,
      MiniPostOperationCallback },

    { IRP_MJ_FLUSH_BUFFERS,
      0,
      MiniPreOperationCallback,
      MiniPostOperationCallback },

    { IRP_MJ_QUERY_VOLUME_INFORMATION,
      0,
      MiniPreOperationCallback,
      MiniPostOperationCallback },

    { IRP_MJ_SET_VOLUME_INFORMATION,
      0,
      MiniPreOperationCallback,
      MiniPostOperationCallback },

    { IRP_MJ_DIRECTORY_CONTROL,
      0,
      MiniPreOperationCallback,
      MiniPostOperationCallback },

    { IRP_MJ_FILE_SYSTEM_CONTROL,
      0,
      MiniPreOperationCallback,
      MiniPostOperationCallback },

    { IRP_MJ_DEVICE_CONTROL,
      0,
      MiniPreOperationCallback,
      MiniPostOperationCallback },

    { IRP_MJ_INTERNAL_DEVICE_CONTROL,
      0,
      MiniPreOperationCallback,
      MiniPostOperationCallback },

    { IRP_MJ_SHUTDOWN,
      0,
      MiniPreOperationCallback,
      NULL },                           //post operation callback not supported

    { IRP_MJ_LOCK_CONTROL,
      0,
      MiniPreOperationCallback,
      MiniPostOperationCallback },

    { IRP_MJ_CLEANUP,
      0,
      MiniPreOperationCallback,
      MiniPostOperationCallback },

    { IRP_MJ_CREATE_MAILSLOT,
      0,
      MiniPreOperationCallback,
      MiniPostOperationCallback },

    { IRP_MJ_QUERY_SECURITY,
      0,
      MiniPreOperationCallback,
      MiniPostOperationCallback },

    { IRP_MJ_SET_SECURITY,
      0,
      MiniPreOperationCallback,
      MiniPostOperationCallback },

    { IRP_MJ_QUERY_QUOTA,
      0,
      MiniPreOperationCallback,
      MiniPostOperationCallback },

    { IRP_MJ_SET_QUOTA,
      0,
      MiniPreOperationCallback,
      MiniPostOperationCallback },

    { IRP_MJ_PNP,
      0,
      MiniPreOperationCallback,
      MiniPostOperationCallback },

    { IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
      0,
      MiniPreOperationCallback,
      MiniPostOperationCallback },

    { IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION,
      0,
      MiniPreOperationCallback,
      MiniPostOperationCallback },

    { IRP_MJ_ACQUIRE_FOR_MOD_WRITE,
      0,
      MiniPreOperationCallback,
      MiniPostOperationCallback },

    { IRP_MJ_RELEASE_FOR_MOD_WRITE,
      0,
      MiniPreOperationCallback,
      MiniPostOperationCallback },

    { IRP_MJ_ACQUIRE_FOR_CC_FLUSH,
      0,
      MiniPreOperationCallback,
      MiniPostOperationCallback },

    { IRP_MJ_RELEASE_FOR_CC_FLUSH,
      0,
      MiniPreOperationCallback,
      MiniPostOperationCallback },

    { IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE,
      0,
      MiniPreOperationCallback,
      MiniPostOperationCallback },

    { IRP_MJ_NETWORK_QUERY_OPEN,
      0,
      MiniPreOperationCallback,
      MiniPostOperationCallback },

    { IRP_MJ_MDL_READ,
      0,
      MiniPreOperationCallback,
      MiniPostOperationCallback },

    { IRP_MJ_MDL_READ_COMPLETE,
      0,
      MiniPreOperationCallback,
      MiniPostOperationCallback },

    { IRP_MJ_PREPARE_MDL_WRITE,
      0,
      MiniPreOperationCallback,
      MiniPostOperationCallback },

    { IRP_MJ_MDL_WRITE_COMPLETE,
      0,
      MiniPreOperationCallback,
      MiniPostOperationCallback },

    { IRP_MJ_VOLUME_MOUNT,
      0,
      MiniPreOperationCallback,
      MiniPostOperationCallback },

    { IRP_MJ_VOLUME_DISMOUNT,
      0,
      MiniPreOperationCallback,
      MiniPostOperationCallback },

    { IRP_MJ_OPERATION_END }
};

/*
FLT_OPERATION_REGISTRATION Callbacks[] = {

    { IRP_MJ_CREATE,
      FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
      CtxPreCreate,
      CtxPostCreate },

    { IRP_MJ_CLEANUP,
      FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
      CtxPreCleanup,
      NULL },

    { IRP_MJ_CLOSE,
      FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
      CtxPreClose,
      NULL },

    { IRP_MJ_SET_INFORMATION,
      FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
      CtxPreSetInfo,
      CtxPostSetInfo },

    { IRP_MJ_OPERATION_END }
};
*/

const FLT_CONTEXT_REGISTRATION Contexts[] = {

    { FLT_INSTANCE_CONTEXT,
      0,	// LTFL_CONTEXT_REGISTRATION_NO_EXACT_SIZE_MATCH
      CtxContextCleanup,
      CTX_INSTANCE_CONTEXT_SIZE,
      CTX_INSTANCE_CONTEXT_TAG },

    { FLT_STREAM_CONTEXT,
      0,
      CtxContextCleanup,
      CTX_STREAM_CONTEXT_SIZE,
      CTX_STREAM_CONTEXT_TAG },

    { FLT_STREAMHANDLE_CONTEXT,
      0,
      CtxContextCleanup,
      CTX_STREAMHANDLE_CONTEXT_SIZE,
      CTX_STREAMHANDLE_CONTEXT_TAG },

    { FLT_CONTEXT_END }
};

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof(FLT_REGISTRATION),               //  Size
    FLT_REGISTRATION_VERSION,               //  Version
    0,                                      //  Flags  FLTFL_REGISTRATION_DO_NOT_SUPPORT_SERVICE_STOP

    Contexts,                               //  Context
    Callbacks,                              //  Operation callbacks

    MiniFilterUnload,						//  FilterUnload

	CtxInstanceSetup,						//  InstanceSetup
	CtxInstanceQueryTeardown,				//  InstanceQueryTeardown
	CtxInstanceTeardownStart,				//  InstanceTeardownStart
	CtxInstanceTeardownComplete,			//  InstanceTeardownComplete

    //NULL,									//  InstanceSetup
    //SfQueryTeardown,						//  InstanceQueryTeardown
    //NULL,									//  InstanceTeardownStart
    //NULL,									//  InstanceTeardownComplete

    NULL,                                   //  GenerateFileName
    NULL,                                   //  GenerateDestinationFileName
    NULL                                    //  NormalizeNameComponent
};

#ifdef ALLOC_DATA_PRAGMA
#pragma data_seg()
#pragma const_seg()
#endif
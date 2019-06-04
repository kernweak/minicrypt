/*++

Copyright (c) 1999 - 2002  Microsoft Corporation

Module Name:

    main.c

Abstract:

    This is a sample filter which demonstrates proper access of data buffer
    and a general guideline of how to swap buffers.
    For now it only swaps buffers for:

    IRP_MJ_READ
    IRP_MJ_WRITE
    IRP_MJ_DIRECTORY_CONTROL

    By default this filter attaches to all volumes it is notified about.  It
    does support having multiple instances on a given volume.

Environment:

    Kernel mode

--*/

#include "main.h"
#include "process.h"
#include "file.h"
#include "message.h"
#include "cache.h"
#include "key.h"
#include "..\include\interface.h"

/*************************************************************************
    Initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry (
    __in PDRIVER_OBJECT DriverObject,
    __in PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    This is the initialization routine.  This registers with FltMgr and
    initializes all global data structures.

Arguments:

    DriverObject - Pointer to driver object created by the system to
        represent this driver.

    RegistryPath - Unicode string identifying where the parameters for this
        driver are located in the registry.

Return Value:

    Status of the operation

--*/
{
    NTSTATUS status;

    //
    //  Get debug trace flags
    //
    ReadDriverParameters( RegistryPath );

    //
    //  Init lookaside list used to allocate our context structure used to
    //  pass information from out preOperation callback to our postOperation
    //  callback.
    //
    ExInitializeNPagedLookasideList( &Pre2PostContextList, NULL, NULL, 0, sizeof(PRE_2_POST_CONTEXT), PRE_2_POST_TAG, 0 );

	//
	//  Set Process monitor routine
	//	(must removed when unloading minifilter driver, otherwise OS will down)
	//
	//status = PsSetCreateProcessNotifyRoutine(Ps_ProcessCallBack, FALSE) ;
	//if (!NT_SUCCESS(status))
	//{
	//	ExDeleteNPagedLookasideList( &Pre2PostContextList );
	//	return status ;
	//}                                                                                                                                                                                                                                                                                                                                                              

	//
	// get process name offset from PEB
	//
	g_nProcessNameOffset = Ps_GetProcessNameOffset() ;

	//
	// init process list entry to hold all of user processes which may be supervised.
	// init spin lock to synchronize process list operations.
	//
	InitializeListHead(&g_ProcessListHead) ;
	KeInitializeSpinLock(&g_ProcessListLock) ;

	// init global file flag structure
	status = File_InitFileFlag() ;
	if (!NT_SUCCESS(status))
	{
		return status ;
	}
	
	// init file key
	RtlZeroMemory(g_szCurFileKey, MAX_KEY_LENGTH) ;

    //
    //  Register engine with FltMgr
    //
    status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
	if (NT_SUCCESS(status)) 
	{
		//Create serve port for communication between user application and minifilter driver
		status = Msg_CreateCommunicationPort(gFilterHandle) ;
		if (NT_SUCCESS(status))
		{
			status = FltStartFiltering(gFilterHandle); //start filter io
			if (!NT_SUCCESS(status)) 
				FltUnregisterFilter(gFilterHandle);
		}
    }

    return status;
}


NTSTATUS
DriverExit (
    __in FLT_FILTER_UNLOAD_FLAGS Flags
    )
/*++

Routine Description:

    Called when this mini-filter is about to be unloaded.  We unregister
    from the FltMgr and then return it is OK to unload

Arguments:

    Flags - Indicating if this is a mandatory unload.

Return Value:

    Returns the final status of this operation.

--*/
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER( Flags );

	//Close server port, must before filter is unregistered, otherwise filter will be halted.
	Msg_CloseCommunicationPort(g_pServerPort) ;

    //Unregister from FLT mgr
    FltUnregisterFilter( gFilterHandle );

    //Delete lookaside list
    ExDeleteNPagedLookasideList( &Pre2PostContextList );

	//uninit file flag structure
	if (g_psFileFlag)
	{
		File_UninitFileFlag() ;
	}

	//uninit file key list
	if (g_psKeyListInfo)
	{
		Key_DestroyKeyList() ;
	}

    return STATUS_SUCCESS;
}


NTSTATUS
SetupInstance(
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in FLT_INSTANCE_SETUP_FLAGS Flags,
    __in DEVICE_TYPE VolumeDeviceType,
    __in FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
/*++

Routine Description:

    This routine is called whenever a new instance is created on a volume.

    By default we want to attach to all volumes.  This routine will try and
    get a "DOS" name for the given volume.  If it can't, it will try and
    get the "NT" name for the volume (which is what happens on network
    volumes).  If a name is retrieved a volume context will be created with
    that name.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Flags describing the reason for this attach request.

Return Value:

    STATUS_SUCCESS - attach
    STATUS_FLT_DO_NOT_ATTACH - do not attach

--*/
{
    PDEVICE_OBJECT devObj = NULL;
    PVOLUME_CONTEXT ctx = NULL;
    NTSTATUS status;
    ULONG retLen;
    PUNICODE_STRING workingName;
    USHORT size;
    UCHAR volPropBuffer[sizeof(FLT_VOLUME_PROPERTIES)+512];
    PFLT_VOLUME_PROPERTIES volProp = (PFLT_VOLUME_PROPERTIES)volPropBuffer;

	UCHAR szIV[16] = {1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6} ;
	UCHAR szKey[MAX_KEY_LENGTH] = {0} ;
	UCHAR szKeyDigest[HASH_SIZE] = {0} ;
	UCHAR uKeyLen = 32 ;

	///SHA1_CTX shactx ;

    PAGED_CODE();

    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( VolumeDeviceType );
    UNREFERENCED_PARAMETER( VolumeFilesystemType );

    try {

        //Allocate a volume context structure.
        status = FltAllocateContext( FltObjects->Filter, FLT_VOLUME_CONTEXT, sizeof(VOLUME_CONTEXT), NonPagedPool, &ctx );
        if (!NT_SUCCESS(status)) 
            leave;

        //Always get the volume properties, so I can get a sector size
        status = FltGetVolumeProperties( FltObjects->Volume, volProp, sizeof(volPropBuffer), &retLen );
        if (!NT_SUCCESS(status))
            leave;

		ASSERT((volProp->SectorSize == 0) || (volProp->SectorSize >= MIN_SECTOR_SIZE));
        ctx->SectorSize = max(volProp->SectorSize,MIN_SECTOR_SIZE);
        ctx->Name.Buffer = NULL;
		ctx->FsName.Buffer = NULL ;
		///ctx->aes_ctr_ctx = NULL ;

        //Get the storage device object we want a name for.
        status = FltGetDiskDeviceObject( FltObjects->Volume, &devObj );
        if (NT_SUCCESS(status))
            status = RtlVolumeDeviceToDosName( devObj, &ctx->Name ); //Try and get the DOS name.

        //If we could not get a DOS name, get the NT name.
        if (!NT_SUCCESS(status)) 
		{
            ASSERT(ctx->Name.Buffer == NULL);

            //Figure out which name to use from the properties
            if (volProp->RealDeviceName.Length > 0) 
			{
                workingName = &volProp->RealDeviceName;
            }
			else if (volProp->FileSystemDeviceName.Length > 0) 
			{
                workingName = &volProp->FileSystemDeviceName;
            } 
			else 
			{
                status = STATUS_FLT_DO_NOT_ATTACH;  //No name, don't save the context
                leave;
            }

            size = workingName->Length + sizeof(WCHAR); //length plus a trailing colon
            ctx->Name.Buffer = ExAllocatePoolWithTag( NonPagedPool, size, NAME_TAG );
            if (ctx->Name.Buffer == NULL) 
			{
                status = STATUS_INSUFFICIENT_RESOURCES;
                leave;
            }
            ctx->Name.Length = 0;
            ctx->Name.MaximumLength = size;
            RtlCopyUnicodeString( &ctx->Name, workingName );
            RtlAppendUnicodeToString( &ctx->Name, L":" );
        }

		//init aes ctr context
		KeInitializeSpinLock(&ctx->FsCryptSpinLock) ;
		///ctx->aes_ctr_ctx = counter_mode_ctx_init(szIV, g_szCurFileKey, uKeyLen) ;
		///if (NULL == ctx->aes_ctr_ctx)
		///{
		///	leave  ;
		///}


		//init per-volume mutex
		ExInitializeFastMutex(&ctx->FsCtxTableMutex) ;

        //Set the context
        status = FltSetVolumeContext(FltObjects->Volume, FLT_SET_CONTEXT_KEEP_IF_EXISTS, ctx, NULL );
        if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED) //It is OK for the context to already be defined.
            status = STATUS_SUCCESS;

    } finally {

		if (ctx) 
		{
			FltReleaseContext( ctx ); // system will hang if not call this routine
#if DBG			
			if ((ctx->Name.Buffer[0] == L'C') || (ctx->Name.Buffer[0] == L'c'))
			{
				FltDeleteContext(ctx) ;
				status = STATUS_FLT_DO_NOT_ATTACH ;
			}
#endif
        }

        if (devObj) 
            ObDereferenceObject(devObj);//Remove the reference added by FltGetDiskDeviceObject.
    }

    return status;
}


VOID
CleanupContext(
    __in PFLT_CONTEXT Context,
    __in FLT_CONTEXT_TYPE ContextType
    )
/*++

Routine Description:

    The given context is being freed.
    Free the allocated name buffer if there one.

Arguments:

    Context - The context being freed

    ContextType - The type of context this is

Return Value:

    None

--*/
{
    PVOLUME_CONTEXT ctx = NULL ;
	PSTREAM_CONTEXT streamCtx = NULL ;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(ContextType);

    //ASSERT(ContextType == FLT_VOLUME_CONTEXT);

	switch(ContextType)
	{
	case FLT_VOLUME_CONTEXT:
		{
			ctx = (PVOLUME_CONTEXT)Context ;

			if (ctx->Name.Buffer != NULL) 
			{
				ExFreePool(ctx->Name.Buffer);
				ctx->Name.Buffer = NULL;
			}

			///if (NULL != ctx->aes_ctr_ctx)
			///{
			///	counter_mode_ctx_destroy(ctx->aes_ctr_ctx) ;
			///	ctx->aes_ctr_ctx = NULL ;
			///}
		}
	    break ;
	case FLT_STREAM_CONTEXT:
		{
			KIRQL OldIrql ;

			streamCtx = (PSTREAM_CONTEXT)Context ;

			if (streamCtx == NULL)
				break ;

			if (streamCtx->FileName.Buffer != NULL) 
			{
				ExFreePoolWithTag( streamCtx->FileName.Buffer,STRING_TAG );

				streamCtx->FileName.Length = streamCtx->FileName.MaximumLength = 0;
				streamCtx->FileName.Buffer = NULL;
			}

			///if (NULL != streamCtx->aes_ctr_ctx)
			///{
			///	counter_mode_ctx_destroy(streamCtx->aes_ctr_ctx) ;
			///	streamCtx->aes_ctr_ctx = NULL ;
			///}

			if (NULL != streamCtx->Resource)
			{
				ExDeleteResourceLite(streamCtx->Resource) ;
				ExFreePoolWithTag(streamCtx->Resource, RESOURCE_TAG) ;
			}
		}
		break ;	
	}
}


/*************************************************************************
    dispatch callback routines.
*************************************************************************/
FLT_PREOP_CALLBACK_STATUS
PreCreate (
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{   
	FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_SUCCESS_WITH_CALLBACK ;

    UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(FltObjects) ;
	UNREFERENCED_PARAMETER(Data) ;
        
    PAGED_CODE();
	
    return FltStatus ;//FLT_PREOP_SUCCESS_WITH_CALLBACK;
}


FLT_POSTOP_CALLBACK_STATUS
PostCreate (
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __inout_opt PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    )
{
	NTSTATUS status = STATUS_SUCCESS ;

	ULONG uDesiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess ; //get desired access mode

	PVOLUME_CONTEXT pVolCtx = NULL ;
	PFLT_FILE_NAME_INFORMATION pfNameInfo = NULL ;

	PSTREAM_CONTEXT pStreamCtx = NULL ;
	BOOLEAN bNewCreatedOrNot = FALSE ;

	LARGE_INTEGER FileSize = {0} ;

	LARGE_INTEGER ByteOffset = {0} ;
	LARGE_INTEGER OrigByteOffset = {0} ;
	ULONG      uReadLength = 0 ;
	PFILE_FLAG psFileFlag = NULL ;

	KIRQL CurrentIrql ;
	KIRQL OldIrql ;

	UCHAR szIV[HASH_SIZE] = {1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6} ;
	UCHAR szKey[MAX_KEY_LENGTH] = {0} ;

	BOOLEAN bDirectory = FALSE ;
	BOOLEAN bIsSystemProcess = FALSE ;

    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( CompletionContext );

	PAGED_CODE();

	try{

		//  If the Create has failed, do nothing
		if (!NT_SUCCESS( Data->IoStatus.Status ))
			__leave ;   

		//get volume context£¬ remember to release volume context before return
		status = FltGetVolumeContext(FltObjects->Filter, FltObjects->Volume, &pVolCtx) ;
		if (!NT_SUCCESS(status) || (NULL == pVolCtx))
		{
			__leave ;
		}
		///if ((pVolCtx->aes_ctr_ctx == NULL) && g_bInitCurKey)
		///{// set key and key digest in volume context
		///	pVolCtx->aes_ctr_ctx = counter_mode_ctx_init(szIV, g_szCurFileKey, MAX_KEY_LENGTH) ; 
		///	RtlCopyMemory(pVolCtx->szKeyHash, g_szCurFileKeyDigest, MAX_KEY_LENGTH) ;
		///}

		//get file full path(such as \Device\HarddiskVolumeX\test\1.txt)
		status = FltGetFileNameInformation(Data, 
						FLT_FILE_NAME_NORMALIZED|FLT_FILE_NAME_QUERY_DEFAULT, 
						&pfNameInfo) ;
		if (!NT_SUCCESS(status))
		{
			__leave ;
		}
		if (0 == pfNameInfo->Name.Length)
		{// file name length is zero
			__leave ;
		}

		if (0 == RtlCompareUnicodeString(&pfNameInfo->Name, &pfNameInfo->Volume, TRUE))
		{// if volume name, filter it
			__leave ;
		}

		//verify if a directory
		File_GetFileStandardInfo(Data, FltObjects, NULL, NULL, &bDirectory) ;
		if (bDirectory)
		{// open/create a directory, just pass
			__leave ;
		}

		//current process monitored or not
		if (!Ps_IsCurrentProcessMonitored(pfNameInfo->Name.Buffer, 
									pfNameInfo->Name.Length/sizeof(WCHAR), &bIsSystemProcess, NULL))
		{// not monitored, exit
			__leave ;
		}

		//create or get stream context of the file
		status = Ctx_FindOrCreateStreamContext(Data,FltObjects,TRUE,
									&pStreamCtx,&bNewCreatedOrNot);
		if (!NT_SUCCESS(status))
		{
			__leave ;
		}

		//update file path name in stream context
		Ctx_UpdateNameInStreamContext(&pfNameInfo->Name,pStreamCtx) ;

		//verify if the stream context is new created or already exists. 
		if (!bNewCreatedOrNot)
		{
			SC_LOCK(pStreamCtx, &OldIrql) ;
			pStreamCtx->RefCount ++ ;
			pStreamCtx->uAccess = uDesiredAccess ;
			SC_UNLOCK(pStreamCtx, OldIrql) ;
			__leave ;
		}

		//init new created stream context
		SC_LOCK(pStreamCtx, &OldIrql) ;
		RtlCopyMemory(pStreamCtx->wszVolumeName, pfNameInfo->Volume.Buffer, pfNameInfo->Volume.Length) ;
		pStreamCtx->bIsFileCrypt = FALSE ;
		pStreamCtx->bDecryptOnRead = FALSE ;
		pStreamCtx->bEncryptOnWrite= TRUE ;
		pStreamCtx->bHasWriteData = FALSE ; //judge whether data is written into file or not during the life cycle of this stream context
		pStreamCtx->bHasPPTWriteData = FALSE ; //this field is ppt related only
		pStreamCtx->RefCount ++ ;
		pStreamCtx->uAccess = uDesiredAccess ;
		pStreamCtx->uTrailLength = FILE_FLAG_LENGTH ;
		///pStreamCtx->aes_ctr_ctx = NULL ;
		SC_UNLOCK(pStreamCtx, OldIrql) ;
			
		//get file size(this size including real file size, padding length, and file flag data)
		status = File_GetFileStandardInfo(Data, FltObjects, NULL, &FileSize, NULL) ;
		if (!NT_SUCCESS(status))
		{
			__leave ;
		}
		
		//fill some fields in stream context
		SC_LOCK(pStreamCtx, &OldIrql) ;
		pStreamCtx->FileSize = FileSize ;
		RtlCopyMemory(pStreamCtx->szKeyHash, pVolCtx->szKeyHash, HASH_SIZE) ;
		SC_UNLOCK(pStreamCtx, OldIrql) ;

		//empty file or new created file, just pass
		if ((0 == FileSize.QuadPart) && (uDesiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA)))
		{//new created file with write or append access
			__leave ;
		}
		if ((0 == FileSize.QuadPart) && !(uDesiredAccess & (FILE_WRITE_DATA|FILE_APPEND_DATA)))
		{// file size is zero, but without write or append access
			__leave ;
		}

		//if file size is less than file flag length, the file is not encrypted yet but need to be encrypted
		if (FileSize.QuadPart < FILE_FLAG_LENGTH)
		{
			__leave ;
		}

		//holds original byte offset
		File_GetFileOffset(Data,FltObjects,&OrigByteOffset) ;

		// if file size is more than file flag length, read file flag and compare		
		psFileFlag = (PFILE_FLAG)ExAllocatePoolWithTag(NonPagedPool, sizeof(FILE_FLAG), FILEFLAG_POOL_TAG) ;
		ByteOffset.QuadPart = FileSize.QuadPart - FILE_FLAG_LENGTH ; 
		status = File_ReadWriteFile(IRP_MJ_READ, FltObjects->Instance, FltObjects->FileObject, &ByteOffset, FILE_FLAG_LENGTH, psFileFlag, &uReadLength,FLTFL_IO_OPERATION_NON_CACHED|FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET) ;
		if (!NT_SUCCESS(status))
		{
			__leave ;
		}

		//restore original byte offset
		File_SetFileOffset(Data, FltObjects, &OrigByteOffset) ;

		//compare guid in file flag data with global file flag guid
		if (FILE_GUID_LENGTH != RtlCompareMemory(g_psFileFlag, psFileFlag, FILE_GUID_LENGTH))
		{//not equal, so the file has not been encrypted yet.
			SC_LOCK(pStreamCtx, &OldIrql) ;
			pStreamCtx->FileValidLength = FileSize ; //file is existing and has no tail, so filevalidlength equals filesize.
			SC_UNLOCK(pStreamCtx, OldIrql) ;
			__leave ;
		}	
		
		//file has been encrypted, reset some fields
		SC_LOCK(pStreamCtx, &OldIrql) ;
		pStreamCtx->FileValidLength.QuadPart = psFileFlag->FileValidLength;
		pStreamCtx->bIsFileCrypt = TRUE ;
		pStreamCtx->bEncryptOnWrite= TRUE ;
		pStreamCtx->bDecryptOnRead = TRUE ;
		pStreamCtx->uTrailLength = FILE_FLAG_LENGTH ;
		
		//search for encryption/decryption key of the file
		memcpy(pStreamCtx->szKeyHash, psFileFlag->FileKeyHash, HASH_SIZE) ;
		if (memcmp(pStreamCtx->szKeyHash, pVolCtx->szKeyHash, HASH_SIZE))
		{
			if (Key_GetKeyByDigest(psFileFlag->FileKeyHash, HASH_SIZE, szKey, MAX_KEY_LENGTH)) ;
		///		pStreamCtx->aes_ctr_ctx = counter_mode_ctx_init(szIV, szKey, MAX_KEY_LENGTH) ;
		}
		SC_UNLOCK(pStreamCtx, OldIrql) ;
		
	}
	finally{

		if (NULL != pVolCtx)
			FltReleaseContext(pVolCtx) ;

		if (NULL != pfNameInfo)
			FltReleaseFileNameInformation(pfNameInfo) ;

		if (NULL != pStreamCtx)
			FltReleaseContext(pStreamCtx) ;

		if (NULL != psFileFlag)
			ExFreePoolWithTag(psFileFlag, FILEFLAG_POOL_TAG) ;
	}

    return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
PreCleanup (
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{  
    NTSTATUS status = STATUS_SUCCESS ;

	PFLT_FILE_NAME_INFORMATION pfNameInfo = NULL ;
	PSTREAM_CONTEXT pStreamCtx = NULL ;
	LARGE_INTEGER FileOffset = {0} ;

	BOOLEAN bIsSystemProcess = FALSE ;
	BOOLEAN bFileNameLengthNotZero = FALSE ;
	KIRQL OldIrql ;

	PVOLUME_CONTEXT pVolCtx = NULL ;

	BOOLEAN bDirectory = FALSE ;

    UNREFERENCED_PARAMETER( CompletionContext );

    PAGED_CODE();

	try{  
		//get volume context£¬ remember to release volume context before return
		status = FltGetVolumeContext(FltObjects->Filter, FltObjects->Volume, &pVolCtx) ;
		if (!NT_SUCCESS(status) || (NULL == pVolCtx))
		{
			__leave ;
		}
		
		//get file full path(such as \Device\HarddiskVolumeX\test\1.txt)
		status = FltGetFileNameInformation(Data, 
						FLT_FILE_NAME_NORMALIZED|FLT_FILE_NAME_QUERY_DEFAULT, 
						&pfNameInfo) ;
		if (!NT_SUCCESS(status))
		{
			__leave ;
		}
		if (0 != pfNameInfo->Name.Length)
		{// file name length is zero

			// verify file attribute. If directory, pass down directly
			File_GetFileStandardInfo(Data, FltObjects, NULL, NULL, &bDirectory) ;
			if (bDirectory)
			{// pass
				__leave ;
			}

			//current process monitored or not
			if (!Ps_IsCurrentProcessMonitored(pfNameInfo->Name.Buffer, \
										pfNameInfo->Name.Length/sizeof(WCHAR), &bIsSystemProcess, NULL))
			{// non-monitored process data also need to be flushed and purged
				Cc_ClearFileCache(FltObjects->FileObject, TRUE, NULL, 0) ; // flush and purge cache	
			}
		}

		// if excel process, do not operate on cache. Otherwise some write disk operations will be triggered 
		// and lead to partial data of excel document be encrypted, in the end the document will be 
		// destroyed and can not be re-opened.
		if (bIsSystemProcess != EXCEL_PROCESS)
		{// flush and purge cache if not excel process
			Cc_ClearFileCache(FltObjects->FileObject, TRUE, NULL, 0) ; 
		}
	}
	finally{

		if (NULL != pVolCtx)
			FltReleaseContext(pVolCtx) ;

		if (NULL != pStreamCtx)
			FltReleaseContext(pStreamCtx) ;

		if (NULL != pfNameInfo)
			FltReleaseFileNameInformation(pfNameInfo);
	}

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
PreClose (
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{   
    NTSTATUS status = STATUS_SUCCESS ;
	FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK ;

	PSTREAM_CONTEXT pStreamCtx = NULL ;
	PVOLUME_CONTEXT pVolCtx = NULL ;

	BOOLEAN bDeleteStreamCtx = FALSE ;	

	OBJECT_ATTRIBUTES ob ;
	IO_STATUS_BLOCK IoStatus ;
	HANDLE hFile = NULL ;
	PFILE_OBJECT FileObject = NULL ;
	UNICODE_STRING sFileDosFullPath ;
	WCHAR  wszFileDosFullPath[MAX_PATH] = {0};
	PWCHAR pszRelativePathPtr = NULL ;	
	WCHAR  wszFilePathName[260] = {0} ;
	WCHAR  wszVolumePathName[64] = {0} ;	

	KIRQL OldIrql ;
	BOOLEAN bDirectory = FALSE ;

	BOOLEAN bIsSystemProcess = FALSE ;

    UNREFERENCED_PARAMETER( CompletionContext );

    //PAGED_CODE(); //comment this line to avoid IRQL_NOT_LESS_OR_EQUAL error when accessing stream context

	try{

		// verify file attribute, if directory, pass down directly
		File_GetFileStandardInfo(Data, FltObjects, NULL, NULL, &bDirectory) ;
		if (bDirectory)
		{
			__leave ;
		}

		// retireve volume context
		status = FltGetVolumeContext(FltObjects->Filter,FltObjects->Volume,&pVolCtx) ;
		if (!NT_SUCCESS(status))
		{
			__leave ;
		}		
		
		// retrieve stream context
		status = Ctx_FindOrCreateStreamContext(Data, FltObjects,FALSE, &pStreamCtx, NULL) ;
		if (!NT_SUCCESS(status))
		{
			__leave ;
		}

		//current process monitored or not
		if (!Ps_IsCurrentProcessMonitored(pStreamCtx->FileName.Buffer, 
									pStreamCtx->FileName.Length/sizeof(WCHAR), &bIsSystemProcess, NULL))
		{// not monitored, pass
			__leave ;
		}		

		SC_LOCK(pStreamCtx, &OldIrql) ;
		// if it is a stream file object, we don't care about it and don't decrement on reference count
		// since this object is opened by other kernel component
		if ((FltObjects->FileObject->Flags & FO_STREAM_FILE) != FO_STREAM_FILE)
			pStreamCtx->RefCount -- ; // decrement reference count
		if (0 == pStreamCtx->RefCount)
		{//if reference decreases to 0, write file flag, flush|purge cache, and delete file context
			
			bDeleteStreamCtx = TRUE ; //set flag to delete stream context before returning from pre-close routine

			if ((pStreamCtx->bHasWriteData || pStreamCtx->bIsFileCrypt) || \
				(!pStreamCtx->bHasWriteData && !pStreamCtx->bIsFileCrypt && pStreamCtx->bHasPPTWriteData) 
				)
			{
				SC_UNLOCK(pStreamCtx, OldIrql) ;
			
				//get file dos full path
				RtlCopyMemory(wszFilePathName, pStreamCtx->FileName.Buffer, pStreamCtx->FileName.Length) ;
				RtlCopyMemory(wszVolumePathName, pStreamCtx->wszVolumeName, wcslen(pStreamCtx->wszVolumeName)*sizeof(WCHAR)) ;
				pszRelativePathPtr = wcsstr(wszFilePathName, wszVolumePathName) ;
				if (!pszRelativePathPtr)
				{
					__leave ;
				}
				pszRelativePathPtr = pszRelativePathPtr + wcslen(pStreamCtx->wszVolumeName);
				wcscpy(wszFileDosFullPath, L"\\??\\") ;
				RtlCopyMemory(wszFileDosFullPath+4, pVolCtx->Name.Buffer, pVolCtx->Name.Length) ;
				RtlCopyMemory(wszFileDosFullPath+4+pVolCtx->Name.Length/sizeof(WCHAR), pszRelativePathPtr, pStreamCtx->FileName.Length-wcslen(pStreamCtx->wszVolumeName)*sizeof(WCHAR)) ;
				RtlInitUnicodeString(&sFileDosFullPath, wszFileDosFullPath) ;

				// init object attribute
				InitializeObjectAttributes(&ob, &sFileDosFullPath, OBJ_KERNEL_HANDLE|OBJ_CASE_INSENSITIVE, NULL,NULL) ;

				// open file manually
				status = FltCreateFile(FltObjects->Filter,
									   FltObjects->Instance,
									   &hFile,
									   FILE_READ_DATA|FILE_WRITE_DATA,
			                           &ob,
			                           &IoStatus,
			                           NULL,
			                           FILE_ATTRIBUTE_NORMAL,
			                           FILE_SHARE_READ,
			                           FILE_OPEN,
			                           FILE_NON_DIRECTORY_FILE,
									   NULL,
			                           0,
			                           IO_IGNORE_SHARE_ACCESS_CHECK
			                           ) ;
				if (!NT_SUCCESS(status))
				{// open failed, pass
					__leave ;
				}

				// get fileobject
				status = ObReferenceObjectByHandle(hFile,
										STANDARD_RIGHTS_ALL,
										*IoFileObjectType,
										KernelMode,
										&FileObject,
										NULL
										) ;
				if (!NT_SUCCESS(status))
				{
					__leave ;
				}
				
				if (pStreamCtx->bHasWriteData || pStreamCtx->bIsFileCrypt)
				{//write flag into end of file
					File_WriteFileFlag(Data,FltObjects, FileObject, pStreamCtx) ;
				}
				else //if (!pStreamCtx->bHasWriteData && !pStreamCtx->bIsFileCrypt && pStreamCtx->bHasPPTWriteData)
				{//only ppt related, encrypted entire file and add file flag in the end of file
					File_UpdateEntireFileByFileObject(Data, FltObjects, FileObject, pStreamCtx, pVolCtx) ;
				}

				// set flag in stream context
				SC_LOCK(pStreamCtx, &OldIrql) ;
				pStreamCtx->bIsFileCrypt = TRUE ; //set file encrypted
				pStreamCtx->bDecryptOnRead = TRUE ; //set flag in order to decrypt data during read
				SC_UNLOCK(pStreamCtx, OldIrql) ;
				
				//flush cache and purge data in cache	
				Cc_ClearFileCache(FileObject, TRUE, NULL, 0) ; 
			}	
			else
			{
				SC_UNLOCK(pStreamCtx, OldIrql) ;
			}
		}
		else
		{
			SC_UNLOCK(pStreamCtx, OldIrql) ;
		}
	}
	finally{

		if (NULL != pStreamCtx)
			FltReleaseContext(pStreamCtx) ;

		// do not delete stream context manually if process is excel
		if (bDeleteStreamCtx && (bIsSystemProcess != EXCEL_PROCESS))
			FltDeleteContext(pStreamCtx) ;

		if (NULL != pVolCtx)
			FltReleaseContext(pVolCtx) ;

		if (NULL != hFile)
			FltClose(hFile) ;

		if (NULL != FileObject)
			ObDereferenceObject(FileObject) ;
	}	

    return FltStatus;
}


FLT_PREOP_CALLBACK_STATUS
PreRead(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
/*++

Routine Description:

    This routine demonstrates how to swap buffers for the READ operation.

    Note that it handles all errors by simply not doing the buffer swap.

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - Receives the context that will be passed to the
        post-operation callback.

Return Value:

    FLT_PREOP_SUCCESS_WITH_CALLBACK - we want a postOpeation callback
    FLT_PREOP_SUCCESS_NO_CALLBACK - we don't want a postOperation callback

--*/
{
    NTSTATUS status;
	FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
	
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
	ULONG readLen = iopb->Parameters.Read.Length;
	
    PVOID newBuf = NULL;
    PMDL newMdl  = NULL;
	PPRE_2_POST_CONTEXT p2pCtx;

	PVOLUME_CONTEXT volCtx = NULL;
	PSTREAM_CONTEXT pStreamCtx = NULL ;

    try {
		//get volume context
		status = FltGetVolumeContext( FltObjects->Filter, FltObjects->Volume, &volCtx );
        if (!NT_SUCCESS(status)) 
            return FltStatus ;

        //get per-stream context, not used presently
		status = Ctx_FindOrCreateStreamContext(Data,FltObjects,FALSE,&pStreamCtx,NULL) ;
		if (!NT_SUCCESS(status))
			__leave ;

		if (!Ps_IsCurrentProcessMonitored(pStreamCtx->FileName.Buffer,pStreamCtx->FileName.Length/sizeof(WCHAR), NULL, NULL))
			__leave ;

        //fast io path, disallow it, this will lead to an equivalent irp request coming in
		if (FLT_IS_FASTIO_OPERATION(Data))
		{// disallow fast io path
			FltStatus = FLT_PREOP_DISALLOW_FASTIO ;
			__leave ;
		} 

        //cached io irp path
		if (!(Data->Iopb->IrpFlags & (IRP_NOCACHE | IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO)))
		{	
			__leave ;
		}

		// if read offset exceeds file real size, return EOF and complete the irp
		if (iopb->Parameters.Read.ByteOffset.QuadPart >= pStreamCtx->FileValidLength.QuadPart)
		{
			Data->IoStatus.Status =  STATUS_END_OF_FILE;
			Data->IoStatus.Information = 0 ;
			FltStatus = FLT_PREOP_COMPLETE ;
			__leave ;
		}

		// read length is zero, pass
        if (readLen == 0) 
			__leave;

		// nocache read length must sector size aligned
        if (FlagOn(IRP_NOCACHE,iopb->IrpFlags)) 
		{// aligned read length
            readLen = (ULONG)ROUND_TO_SIZE(readLen,volCtx->SectorSize);
        }

        newBuf = ExAllocatePoolWithTag( NonPagedPool, readLen,BUFFER_SWAP_TAG );
        if (newBuf == NULL) 
            __leave;

        //
        //  We only need to build a MDL for IRP operations.  We don't need to
        //  do this for a FASTIO operation since the FASTIO interface has no
        //  parameter for passing the MDL to the file system.
        //
        if (FlagOn(Data->Flags,FLTFL_CALLBACK_DATA_IRP_OPERATION)) 
		{
            newMdl = IoAllocateMdl( newBuf,readLen, FALSE,FALSE, NULL );
            if (newMdl == NULL)
                __leave;
            MmBuildMdlForNonPagedPool( newMdl );
        }

        //
        //  We are ready to swap buffers, get a pre2Post context structure.
        //  We need it to pass the volume context and the allocate memory
        //  buffer to the post operation callback.
        //
        p2pCtx = ExAllocateFromNPagedLookasideList( &Pre2PostContextList );
        if (p2pCtx == NULL)
            __leave;

        // Update the buffer pointers and MDL address, mark we have changed something.
        iopb->Parameters.Read.ReadBuffer = newBuf;
        iopb->Parameters.Read.MdlAddress = newMdl;
        FltSetCallbackDataDirty( Data );

        //  Pass state to our post-read operation callback.
        p2pCtx->SwappedBuffer = newBuf;
        p2pCtx->VolCtx = volCtx;
		p2pCtx->pStreamCtx = pStreamCtx ;
        *CompletionContext = p2pCtx;

        FltStatus = FLT_PREOP_SUCCESS_WITH_CALLBACK;

    } finally {

        if (FltStatus != FLT_PREOP_SUCCESS_WITH_CALLBACK) 
		{
            if (newBuf != NULL)
			{
                ExFreePool( newBuf );
            }

            if (newMdl != NULL) 
			{
                IoFreeMdl( newMdl );
            }

            if (volCtx != NULL) 
			{
                FltReleaseContext( volCtx );
            }

			if (NULL != pStreamCtx)
			{
				FltReleaseContext(pStreamCtx) ;
			}
        }
    }
    return FltStatus;
}


FLT_POSTOP_CALLBACK_STATUS
PostRead(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    )
/*++

Routine Description:

    This routine does postRead buffer swap handling

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The completion context set in the pre-operation routine.

    Flags - Denotes whether the completion is successful or is being drained.

Return Value:

    FLT_POSTOP_FINISHED_PROCESSING
    FLT_POSTOP_MORE_PROCESSING_REQUIRED

--*/
{
	NTSTATUS status = STATUS_SUCCESS ;
	FLT_POSTOP_CALLBACK_STATUS FltStatus = FLT_POSTOP_FINISHED_PROCESSING;
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;

	PVOID origBuf;  
    PPRE_2_POST_CONTEXT p2pCtx = CompletionContext;
    BOOLEAN cleanupAllocatedBuffer = TRUE;

	KIRQL OldIrql ;

    //
    //  This system won't draining an operation with swapped buffers, verify
    //  the draining flag is not set.
    //
    ASSERT(!FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING));

    try {		
        //
        //  If the operation failed or the count is zero, there is no data to
        //  copy so just return now.
        //
        if (!NT_SUCCESS(Data->IoStatus.Status) ||  (Data->IoStatus.Information == 0))
            leave;

        //
        //  We need to copy the read data back into the users buffer.  Note
        //  that the parameters passed in are for the users original buffers
        //  not our swapped buffers.
        //

        if (iopb->Parameters.Read.MdlAddress != NULL) 
		{
            origBuf = MmGetSystemAddressForMdlSafe( iopb->Parameters.Read.MdlAddress, NormalPagePriority );
            if (origBuf == NULL) 
			{
                Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                Data->IoStatus.Information = 0;
                leave;
            }

        }
		else if (FlagOn(Data->Flags,FLTFL_CALLBACK_DATA_SYSTEM_BUFFER) ||FlagOn(Data->Flags,FLTFL_CALLBACK_DATA_FAST_IO_OPERATION)) 
		{
			origBuf = iopb->Parameters.Read.ReadBuffer;
        } 
		else 
		{
            //
            //  They don't have a MDL and this is not a system buffer
            //  or a fastio so this is probably some arbitrary user
            //  buffer.  We can not do the processing at DPC level so
            //  try and get to a safe IRQL so we can do the processing.
            //
            if (FltDoCompletionProcessingWhenSafe( Data,
                                                   FltObjects,
                                                   CompletionContext,
                                                   Flags,
                                                   PostReadWhenSafe,
                                                   &FltStatus )) 
			{
                //
                //  This operation has been moved to a safe IRQL, the called
                //  routine will do (or has done) the freeing so don't do it
                //  in our routine.
                //
                cleanupAllocatedBuffer = FALSE;
            } 
			else 
			{
                //
                //  We are in a state where we can not get to a safe IRQL and
                //  we do not have a MDL.  There is nothing we can do to safely
                //  copy the data back to the users buffer, fail the operation
                //  and return.  This shouldn't ever happen because in those
                //  situations where it is not safe to post, we should have
                //  a MDL.
                Data->IoStatus.Status = STATUS_UNSUCCESSFUL;
                Data->IoStatus.Information = 0;
            }
            leave;
        }

        //
        //  We either have a system buffer or this is a fastio operation
        //  so we are in the proper context.  Copy the data handling an
        //  exception.
        //
        try {
			do{
				
				// decrypt file data only if the file has been encrypted before 
				// or has been set decrypted on read
				if (p2pCtx->pStreamCtx->bIsFileCrypt || p2pCtx->pStreamCtx->bDecryptOnRead)
				{
					// if read data length exceeds file real size, modify returned data length to fit file real size
				    if (p2pCtx->pStreamCtx->FileValidLength.QuadPart < (Data->Iopb->Parameters.Read.ByteOffset.QuadPart + Data->IoStatus.Information))
				    {// last nocache read io
				        Data->IoStatus.Information = (ULONG)(p2pCtx->pStreamCtx->FileValidLength.QuadPart -  Data->Iopb->Parameters.Read.ByteOffset.QuadPart) ;
						FltSetCallbackDataDirty(Data) ;
				    }

					KeEnterCriticalRegion() ;
					///if (NULL == p2pCtx->pStreamCtx->aes_ctr_ctx)
					///{// use current key to decrypt file data
						///if (data_crypt(p2pCtx->VolCtx->aes_ctr_ctx, p2pCtx->SwappedBuffer, Data->Iopb->Parameters.Read.ByteOffset.QuadPart, Data->IoStatus.Information))
						///{
						///	KeLeaveCriticalRegion() ;
						///	break ;
						///}
					///}
					///else
					///{// use file specified key to decrypt file data(this must be history key)
						///if (data_crypt(p2pCtx->pStreamCtx->aes_ctr_ctx, p2pCtx->SwappedBuffer, Data->Iopb->Parameters.Read.ByteOffset.QuadPart, Data->IoStatus.Information))
						///{
						///	KeLeaveCriticalRegion() ;
						///	break ;
						///}
					///}
					KeLeaveCriticalRegion() ;
				}
				
			}while(FALSE) ;	

			RtlCopyMemory( origBuf,
					p2pCtx->SwappedBuffer, // data need to be decrypted
					Data->IoStatus.Information );

        } except (EXCEPTION_EXECUTE_HANDLER) {

            //
            //  The copy failed, return an error, failing the operation.
            //

            Data->IoStatus.Status = GetExceptionCode();
            Data->IoStatus.Information = 0;
        }

    } finally {

        //
        //  If we are supposed to, cleanup the allocated memory and release
        //  the volume context.  The freeing of the MDL (if there is one) is
        //  handled by FltMgr.
        //

        if (cleanupAllocatedBuffer) 
		{
            ExFreePool( p2pCtx->SwappedBuffer );
            FltReleaseContext( p2pCtx->VolCtx );
			FltReleaseContext( p2pCtx->pStreamCtx) ;
            ExFreeToNPagedLookasideList( &Pre2PostContextList, p2pCtx );
        }
    }

    return FltStatus;
}


FLT_POSTOP_CALLBACK_STATUS
PostReadWhenSafe (
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    )
/*++

Routine Description:

    We had an arbitrary users buffer without a MDL so we needed to get
    to a safe IRQL so we could lock it and then copy the data.

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - Contains state from our PreOperation callback

    Flags - Denotes whether the completion is successful or is being drained.

Return Value:

    FLT_POSTOP_FINISHED_PROCESSING - This is always returned.

--*/
{
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
    PPRE_2_POST_CONTEXT p2pCtx = CompletionContext;
    PVOID origBuf;
    NTSTATUS status;

	KIRQL OldIrql ;

    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    ASSERT(Data->IoStatus.Information != 0);

    //  This is some sort of user buffer without a MDL, lock the user buffer
    //  so we can access it.  This will create a MDL for it.
	status = FltLockUserBuffer( Data );

    if (!NT_SUCCESS(status)) 
	{
        Data->IoStatus.Status = status;
        Data->IoStatus.Information = 0;

    } 
	else 
	{
        //  Get a system address for this buffer.
        origBuf = MmGetSystemAddressForMdlSafe( iopb->Parameters.Read.MdlAddress,
                                                NormalPagePriority );
        if (origBuf == NULL) 
		{
            Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
            Data->IoStatus.Information = 0;
        } 
		else 
		{
			do{

				// decrypt file data only if the file has been encrypted before 
				// or has been set decrypted on read
				if (p2pCtx->pStreamCtx->bIsFileCrypt || p2pCtx->pStreamCtx->bDecryptOnRead)
				{
					// if read data length exceeds file real size, modify returned data length to fit file real size
				    if (p2pCtx->pStreamCtx->FileValidLength.QuadPart < (Data->Iopb->Parameters.Read.ByteOffset.QuadPart + Data->IoStatus.Information))
				    {// last nocache read io
				        Data->IoStatus.Information = (ULONG)(p2pCtx->pStreamCtx->FileValidLength.QuadPart -  Data->Iopb->Parameters.Read.ByteOffset.QuadPart) ;
						FltSetCallbackDataDirty(Data) ;
				    }

					KeEnterCriticalRegion() ;
					///if (NULL == p2pCtx->pStreamCtx->aes_ctr_ctx)
					///{// use current key to decrypt file data
						///if (data_crypt(p2pCtx->VolCtx->aes_ctr_ctx, p2pCtx->SwappedBuffer, Data->Iopb->Parameters.Read.ByteOffset.QuadPart, Data->IoStatus.Information))
						///{
						///	KeLeaveCriticalRegion() ;
						///	break ;
						///}
					///}
					///else
					///{// use file specified key to decrypt file data(this must be history key)
						///if (data_crypt(p2pCtx->pStreamCtx->aes_ctr_ctx, p2pCtx->SwappedBuffer, Data->Iopb->Parameters.Read.ByteOffset.QuadPart, Data->IoStatus.Information))
						///{
						///	KeLeaveCriticalRegion() ;
						///	break ;
						///}
					///}
					KeLeaveCriticalRegion() ;
				}


			}while(FALSE) ;	

            //  Copy the data back to the original buffer.  Note that we
            //  don't need a try/except because we will always have a system
            //  buffer address.
            RtlCopyMemory( origBuf,p2pCtx->SwappedBuffer,Data->IoStatus.Information );
        }
    }

    ExFreePool( p2pCtx->SwappedBuffer );
	///ExReleaseFastMutex(&p2pCtx->VolCtx->FsCtxTableMutex) ;
    FltReleaseContext( p2pCtx->VolCtx );
	FltReleaseContext(p2pCtx->pStreamCtx) ;

    ExFreeToNPagedLookasideList( &Pre2PostContextList,
                                 p2pCtx );

    return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
PreWrite(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
/*++

Routine Description:

    This routine demonstrates how to swap buffers for the WRITE operation.

    Note that it handles all errors by simply not doing the buffer swap.

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - Receives the context that will be passed to the
        post-operation callback.

Return Value:

    FLT_PREOP_SUCCESS_WITH_CALLBACK - we want a postOpeation callback
    FLT_PREOP_SUCCESS_NO_CALLBACK - we don't want a postOperation callback
    FLT_PREOP_COMPLETE -
--*/
{
    NTSTATUS status;
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
    FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;

	PVOID newBuf = NULL;
    PMDL newMdl = NULL;
    PPRE_2_POST_CONTEXT p2pCtx;

	PVOID origBuf;
	ULONG writeLen = iopb->Parameters.Write.Length;
	LARGE_INTEGER writeOffset = iopb->Parameters.Write.ByteOffset ;
    
	PVOLUME_CONTEXT volCtx = NULL;
	PSTREAM_CONTEXT pStreamCtx = NULL ;

	BOOLEAN bIsSystemProcess = FALSE ;
	BOOLEAN bIsPPTFile = FALSE ;

	KIRQL OldIrql ;

    try {
			
		status = FltGetVolumeContext( FltObjects->Filter,FltObjects->Volume,&volCtx );
        if (!NT_SUCCESS(status)) 
            __leave;

		status = Ctx_FindOrCreateStreamContext(Data,FltObjects,FALSE,&pStreamCtx,NULL) ;
		if (!NT_SUCCESS(status))
			__leave ;

		if (!Ps_IsCurrentProcessMonitored(pStreamCtx->FileName.Buffer,pStreamCtx->FileName.Length/sizeof(WCHAR), &bIsSystemProcess, &bIsPPTFile))
			__leave ;

		// if fast io, disallow it and pass
		if (FLT_IS_FASTIO_OPERATION(Data))
		{// disallow fast io path
			FltStatus = FLT_PREOP_DISALLOW_FASTIO ;
			__leave ;
		}  

		// update file real size in stream context timely
		// since file size can be extended in cached io path, so we record file size here
		if (!(Data->Iopb->IrpFlags & (IRP_NOCACHE | IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO)))
		{
			SC_LOCK(pStreamCtx, &OldIrql) ;
			if ((writeLen + writeOffset.QuadPart) > pStreamCtx->FileValidLength.QuadPart)
			{//extend file size
				pStreamCtx->FileValidLength.QuadPart = writeLen + writeOffset.QuadPart ;
			}
			SC_UNLOCK(pStreamCtx, OldIrql) ;
			__leave ;
		}

		// if write length is zero, pass
        if (writeLen == 0)
            leave;

		SC_LOCK(pStreamCtx, &OldIrql) ;
		// sometimes paging/nocached write request is lauched by read-only file object and only 
		// write parital data of the file, under this condition, if the file has not been encrypted, 
		// encryption will lead to corrupt of file(since partial data in file is plaintext and partial
		// is ciphertext), so we verify here, if file has not been encrypted and fileobject has no 
		// write access, just pass. But for powerpnt process, we set "has been write" flag for the file
		// and encrypted in pre-close routine
		if (!pStreamCtx->bIsFileCrypt && !FltObjects->FileObject->WriteAccess)
		{
			if (bIsSystemProcess == POWERPNT_PROCESS)
			{// for exception of powerpnt process, we just set write flag for the file
				pStreamCtx->bHasPPTWriteData = TRUE ;
			}
			SC_UNLOCK(pStreamCtx, OldIrql) ;		
			__leave ;
		}

		// This judgement is only for powerpnt process. If it's a temporary file of powerpnt document,
		// going on encrypting. Otherwise, set "has been write" flag for the file and encrypted in 
		// pre-close routine
		// If user modify ppt document and click "close" button in powerpnt, tmp file is generated.
		// If user click "save" button in powerpnt, no tmp file generated and partial data of the file
		// is flush back to disk.
		// This judgement can distinguish such two situations.
		if (bIsPPTFile && !pStreamCtx->bIsFileCrypt && (bIsSystemProcess == POWERPNT_PROCESS))
		{// powerpnt document(not tmp file)
			pStreamCtx->bHasPPTWriteData = TRUE ;
			SC_UNLOCK(pStreamCtx, OldIrql) ;		
			__leave ;
		}//if a ppt tmp file, encrypting directly
		SC_UNLOCK(pStreamCtx, OldIrql) ;

		// nocache write length must sector size aligned
        if (FlagOn(IRP_NOCACHE,iopb->IrpFlags))
            writeLen = (ULONG)ROUND_TO_SIZE(writeLen,volCtx->SectorSize);

        newBuf = ExAllocatePoolWithTag( NonPagedPool, writeLen,BUFFER_SWAP_TAG );
        if (newBuf == NULL) 
            leave;

        //  We only need to build a MDL for IRP operations.  We don't need to
        //  do this for a FASTIO operation because it is a waste of time since
        //  the FASTIO interface has no parameter for passing the MDL to the
        //  file system.
        if (FlagOn(Data->Flags,FLTFL_CALLBACK_DATA_IRP_OPERATION)) 
		{
            newMdl = IoAllocateMdl( newBuf, writeLen, FALSE,FALSE, NULL );
            if (newMdl == NULL) 
                leave;
            MmBuildMdlForNonPagedPool( newMdl );
        }

        //  If the users original buffer had a MDL, get a system address.
        if (iopb->Parameters.Write.MdlAddress != NULL)
		{
            origBuf = MmGetSystemAddressForMdlSafe( iopb->Parameters.Write.MdlAddress,  NormalPagePriority );
            if (origBuf == NULL)
			{
                Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                Data->IoStatus.Information = 0;
                FltStatus = FLT_PREOP_COMPLETE;
                leave;
            }
        } 
		else
		{
            //  There was no MDL defined, use the given buffer address.
            origBuf = iopb->Parameters.Write.WriteBuffer;
        }

        //  Copy the memory, we must do this inside the try/except because we
        //  may be using a users buffer address
        try {
			
			RtlCopyMemory( newBuf,origBuf,writeLen );

			do {

				// This judgement is useless in fact.
				if ((pStreamCtx->bEncryptOnWrite|| pStreamCtx->bIsFileCrypt) && \
					(Data->Iopb->IrpFlags & ( \
					 IRP_NOCACHE|IRP_PAGING_IO|IRP_SYNCHRONOUS_PAGING_IO)))
				{
					KeEnterCriticalRegion() ;
					///if (NULL == pStreamCtx->aes_ctr_ctx)
					///{// use current key to decrypt file data
						///if (data_crypt(volCtx->aes_ctr_ctx, newBuf, Data->Iopb->Parameters.Write.ByteOffset.QuadPart, writeLen))
						///{
						///	KeLeaveCriticalRegion() ;
						///	break ;
						///}
					///}
					///else
					///{// use file specified key to encrypt file data(this must be history key)
						///if (data_crypt(pStreamCtx->aes_ctr_ctx, newBuf, Data->Iopb->Parameters.Write.ByteOffset.QuadPart, writeLen))
						///{
						///	KeLeaveCriticalRegion() ;
						///	break ;
						///}
					///}
					KeLeaveCriticalRegion() ;
				}
			}while(FALSE) ;

        } except (EXCEPTION_EXECUTE_HANDLER) {

            //
            //  The copy failed, return an error, failing the operation.
            //
            Data->IoStatus.Status = GetExceptionCode();
            Data->IoStatus.Information = 0;
            FltStatus = FLT_PREOP_COMPLETE;
            leave;
        }

        p2pCtx = ExAllocateFromNPagedLookasideList( &Pre2PostContextList );
        if (p2pCtx == NULL)
            leave;

		// Set new buffer and Pass state to our post-operation callback.
        iopb->Parameters.Write.WriteBuffer = newBuf;
        iopb->Parameters.Write.MdlAddress = newMdl;
        FltSetCallbackDataDirty( Data );

        p2pCtx->SwappedBuffer = newBuf;
        p2pCtx->VolCtx = volCtx;
		p2pCtx->pStreamCtx = pStreamCtx ;
        *CompletionContext = p2pCtx;

        //  Return we want a post-operation callback
        FltStatus = FLT_PREOP_SUCCESS_WITH_CALLBACK;

    } finally {
		
		if (FltStatus != FLT_PREOP_SUCCESS_WITH_CALLBACK)
		{
			if (newBuf != NULL) 
			{
				ExFreePool( newBuf );
			}

			if (newMdl != NULL)
			{
				IoFreeMdl( newMdl );
			}

			if (volCtx != NULL) 
			{
				FltReleaseContext(volCtx);
			}

			if (NULL != pStreamCtx)
			{
				FltReleaseContext(pStreamCtx) ;
			}
		}
	}
    return FltStatus;
}


FLT_POSTOP_CALLBACK_STATUS
PostWrite(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    )
{
	PPRE_2_POST_CONTEXT p2pCtx = CompletionContext;
	LARGE_INTEGER ByteOffset = Data->Iopb->Parameters.Write.ByteOffset ;
	ULONG uWrittenBytes = Data->IoStatus.Information ;

	KIRQL OldIrql ;

	UNREFERENCED_PARAMETER( FltObjects );
	UNREFERENCED_PARAMETER( Flags );

	//update file valid size if neccesary
	SC_LOCK(p2pCtx->pStreamCtx, &OldIrql) ;
	if ((ByteOffset.QuadPart + (LONGLONG)uWrittenBytes) > \
		p2pCtx->pStreamCtx->FileValidLength.QuadPart)
	{
		p2pCtx->pStreamCtx->FileValidLength.QuadPart = \
			ByteOffset.QuadPart + (LONGLONG)uWrittenBytes ;
	}
	//set "decrypt on read" flag
	if (!p2pCtx->pStreamCtx->bDecryptOnRead)
	{
		p2pCtx->pStreamCtx->bDecryptOnRead = TRUE ;
	}
	// set "has write data" flag, this flag will be used
	// in pre-close to judge whether file flag should be updated
	if (!p2pCtx->pStreamCtx->bHasWriteData)
	{
		p2pCtx->pStreamCtx->bHasWriteData = TRUE ;
	}
	SC_UNLOCK(p2pCtx->pStreamCtx, OldIrql) ;

	ExFreePool( p2pCtx->SwappedBuffer );
	FltReleaseContext( p2pCtx->VolCtx );
	FltReleaseContext(p2pCtx->pStreamCtx) ;
	ExFreeToNPagedLookasideList( &Pre2PostContextList,
		p2pCtx );

    return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
PreDirCtrl(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
/*++

Routine Description:

    This routine demonstrates how to swap buffers for the Directory Control
    operations.  The reason this routine is here is because directory change
    notifications are long lived and this allows you to see how FltMgr
    handles long lived IRP operations that have swapped buffers when the
    mini-filter is unloaded.  It does this by canceling the IRP.

    Note that it handles all errors by simply not doing the
    buffer swap.

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - Receives the context that will be passed to the
        post-operation callback.

Return Value:

    FLT_PREOP_SUCCESS_WITH_CALLBACK - we want a postOpeation callback
    FLT_PREOP_SUCCESS_NO_CALLBACK - we don't want a postOperation callback

--*/
{
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
    FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
    PVOID newBuf = NULL;
    PMDL newMdl = NULL;
    PVOLUME_CONTEXT volCtx = NULL;
    PPRE_2_POST_CONTEXT p2pCtx;
    NTSTATUS status;

    try {

		//if fast io, forbid it
		if (FLT_IS_FASTIO_OPERATION(Data))
		{
			FltStatus = FLT_PREOP_DISALLOW_FASTIO ;
			__leave ;
		}

		//if not dir query, skip it
		if ((iopb->MinorFunction != IRP_MN_QUERY_DIRECTORY) ||
			(iopb->Parameters.DirectoryControl.QueryDirectory.Length == 0))
			__leave ;

		//get volume context
        status = FltGetVolumeContext( FltObjects->Filter,FltObjects->Volume,&volCtx );
        if (!NT_SUCCESS(status))
            leave;

        newBuf = ExAllocatePoolWithTag( NonPagedPool,iopb->Parameters.DirectoryControl.QueryDirectory.Length,BUFFER_SWAP_TAG );
        if (newBuf == NULL) 
            leave;

        if (FlagOn(Data->Flags,FLTFL_CALLBACK_DATA_IRP_OPERATION)) 
		{
			newMdl = IoAllocateMdl(newBuf, iopb->Parameters.DirectoryControl.QueryDirectory.Length,FALSE,FALSE,NULL );
			if (newMdl == NULL) 
				leave;
			MmBuildMdlForNonPagedPool( newMdl );
		}

        p2pCtx = ExAllocateFromNPagedLookasideList( &Pre2PostContextList );
        if (p2pCtx == NULL) 
            leave;

        //Update the buffer pointers and MDL address
        iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer = newBuf;
        iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress = newMdl;
        FltSetCallbackDataDirty( Data );

        //Pass state to our post-operation callback.
        p2pCtx->SwappedBuffer = newBuf;
        p2pCtx->VolCtx = volCtx;
        *CompletionContext = p2pCtx;

        FltStatus = FLT_PREOP_SUCCESS_WITH_CALLBACK;
    } finally {

        if (FltStatus != FLT_PREOP_SUCCESS_WITH_CALLBACK) 
		{
            if (newBuf != NULL) 
			{
                ExFreePool( newBuf );
            }

            if (newMdl != NULL) 
			{
                IoFreeMdl( newMdl );
            }

            if (volCtx != NULL)
			{
                FltReleaseContext( volCtx );
            }
        }
    }
    return FltStatus ;
}


FLT_POSTOP_CALLBACK_STATUS
PostDirCtrl(
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    )
/*++

Routine Description:

    This routine does the post Directory Control buffer swap handling.

Arguments:

    This routine does postRead buffer swap handling
    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The completion context set in the pre-operation routine.

    Flags - Denotes whether the completion is successful or is being drained.

Return Value:

    FLT_POSTOP_FINISHED_PROCESSING
    FLT_POSTOP_MORE_PROCESSING_REQUIRED

--*/
{
    NTSTATUS status = STATUS_SUCCESS ;
    PVOID origBuf;
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
    FLT_POSTOP_CALLBACK_STATUS FltStatus = FLT_POSTOP_FINISHED_PROCESSING;
    PPRE_2_POST_CONTEXT p2pCtx = CompletionContext;
    BOOLEAN cleanupAllocatedBuffer = TRUE;

	FILE_INFORMATION_CLASS FileInfoClass = iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass ;
	PSTREAM_CONTEXT pStreamCtx = NULL ;

    ASSERT(!FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING));

    try {

        if (!NT_SUCCESS(Data->IoStatus.Status) || (Data->IoStatus.Information == 0)) 
            leave;

        //  We need to copy the read data back into the users buffer.  Note
        //  that the parameters passed in are for the users original buffers
        //  not our swapped buffers
        if (iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress != NULL)
		{
            origBuf = MmGetSystemAddressForMdlSafe( iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress,
                                                    NormalPagePriority );
            if (origBuf == NULL)
			{
                Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
                Data->IoStatus.Information = 0;
                leave;
            }
        }
		else if (FlagOn(Data->Flags,FLTFL_CALLBACK_DATA_SYSTEM_BUFFER) || FlagOn(Data->Flags,FLTFL_CALLBACK_DATA_FAST_IO_OPERATION))
		{
            origBuf = iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
        } 
		else 
		{
            if (FltDoCompletionProcessingWhenSafe( Data, FltObjects,CompletionContext,Flags,PostDirCtrlWhenSafe,&FltStatus )) 
			{
                cleanupAllocatedBuffer = FALSE;
            } 
			else 
			{
                Data->IoStatus.Status = STATUS_UNSUCCESSFUL;
                Data->IoStatus.Information = 0;
            }
            leave;
        }

        //
        //  We either have a system buffer or this is a fastio operation
        //  so we are in the proper context.  Copy the data handling an
		//  exception.
		//
		//  NOTE:  Due to a bug in FASTFAT where it is returning the wrong
		//         length in the information field (it is sort) we are always
		//         going to copy the original buffer length.
		//
		try {
		
            RtlCopyMemory( origBuf,
                           p2pCtx->SwappedBuffer,
                           /*Data->IoStatus.Information*/
                           iopb->Parameters.DirectoryControl.QueryDirectory.Length );

        } except (EXCEPTION_EXECUTE_HANDLER) {

            Data->IoStatus.Status = GetExceptionCode();
            Data->IoStatus.Information = 0;
        }

    } finally {

        //
        //  If we are supposed to, cleanup the allocate memory and release
        //  the volume context.  The freeing of the MDL (if there is one) is
        //  handled by FltMgr.
        //
        if (cleanupAllocatedBuffer) 
		{
            ExFreePool( p2pCtx->SwappedBuffer );
            FltReleaseContext( p2pCtx->VolCtx );
            ExFreeToNPagedLookasideList( &Pre2PostContextList,p2pCtx );

			if (NULL != pStreamCtx)
			{
				FltReleaseContext(pStreamCtx) ;
			}
        }
    }
    return FltStatus;
}


FLT_POSTOP_CALLBACK_STATUS
PostDirCtrlWhenSafe (
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __in PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    )
/*++

Routine Description:

    We had an arbitrary users buffer without a MDL so we needed to get
    to a safe IRQL so we could lock it and then copy the data.

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The buffer we allocated and swapped to

    Flags - Denotes whether the completion is successful or is being drained.

Return Value:

    FLT_POSTOP_FINISHED_PROCESSING - This is always returned.

--*/
{
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
    PPRE_2_POST_CONTEXT p2pCtx = CompletionContext;
    PVOID origBuf;
    NTSTATUS status;

	FILE_INFORMATION_CLASS  FileInfoClass = iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass ;
	PSTREAM_CONTEXT pStreamCtx = NULL ;

    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    ASSERT(Data->IoStatus.Information != 0);

    //This is some sort of user buffer without a MDL, lock the user buffer so we can access it
    status = FltLockUserBuffer( Data );

    if (!NT_SUCCESS(status)) 
	{
        Data->IoStatus.Status = status;
        Data->IoStatus.Information = 0;
    } 
	else 
	{
        //Get a system address for this buffer.
        origBuf = MmGetSystemAddressForMdlSafe( iopb->Parameters.DirectoryControl.QueryDirectory.MdlAddress,
                                                NormalPagePriority );
        if (origBuf == NULL) 
		{
			//If we couldn't get a SYSTEM buffer address, fail the operation
            Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
            Data->IoStatus.Information = 0;
        }
		else 
		{
            //Copy the data back to the original buffer
            RtlCopyMemory( origBuf,
                           p2pCtx->SwappedBuffer,
                           /*Data->IoStatus.Information*/
                           iopb->Parameters.DirectoryControl.QueryDirectory.Length );
        }
    }

    //  Free the memory we allocated and return
    ExFreePool( p2pCtx->SwappedBuffer );
    FltReleaseContext( p2pCtx->VolCtx );
    ExFreeToNPagedLookasideList( &Pre2PostContextList,
                                 p2pCtx );
	if (NULL != pStreamCtx)
	{
		FltReleaseContext(pStreamCtx) ;
	}
    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS
PreQueryInfo (
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
	NTSTATUS status = STATUS_SUCCESS ;
	FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_SYNCHRONIZE ;
	FILE_INFORMATION_CLASS FileInfoClass = Data->Iopb->Parameters.QueryFileInformation.FileInformationClass ;

	PSTREAM_CONTEXT pStreamCtx = NULL ;

	try{
		if (!FltIsOperationSynchronous(Data))
		{
			FltStatus = FLT_PREOP_SUCCESS_WITH_CALLBACK ;
		}

		if (FLT_IS_FASTIO_OPERATION(Data))
		{
			FltStatus = FLT_PREOP_DISALLOW_FASTIO ;
			__leave ;
		}

		//get per-stream context
		status = Ctx_FindOrCreateStreamContext(Data,FltObjects,FALSE,&pStreamCtx,NULL) ;
		if (!NT_SUCCESS(status))
		{
			FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK ;
			__leave ;
		}

		// if file has been encrypted, if not, Pass down directly, 
		// otherwise, go on to post-query routine
		if (!pStreamCtx->bIsFileCrypt)
		{
			FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK ;
			__leave ;
		}

		if (FileInfoClass == FileBasicInformation ||
			FileInfoClass == FileAllInformation || 
			FileInfoClass == FileAllocationInformation ||
			FileInfoClass == FileEndOfFileInformation ||
			FileInfoClass == FileStandardInformation ||
			FileInfoClass == FilePositionInformation ||
			FileInfoClass == FileValidDataLengthInformation)
		{
			FltStatus = FLT_PREOP_SUCCESS_WITH_CALLBACK ;
		}
		else
			FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK ;
	}
	finally{
		if (NULL != pStreamCtx)
			FltReleaseContext(pStreamCtx) ;
	}

	return FltStatus ;
}

FLT_POSTOP_CALLBACK_STATUS
PostQueryInfo (
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __inout_opt PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    )
{
	NTSTATUS status = STATUS_SUCCESS ;
	FLT_POSTOP_CALLBACK_STATUS FltStatus = FLT_POSTOP_FINISHED_PROCESSING ;
	FILE_INFORMATION_CLASS FileInfoClass = Data->Iopb->Parameters.QueryFileInformation.FileInformationClass ;
	PVOID FileInfoBuffer = Data->Iopb->Parameters.QueryFileInformation.InfoBuffer ;
	ULONG FileInfoLength = Data->IoStatus.Information ;
	PSTREAM_CONTEXT pStreamCtx = NULL ;

	status = Ctx_FindOrCreateStreamContext(Data, FltObjects,FALSE, &pStreamCtx, NULL) ;
	if (!NT_SUCCESS(status))
	{
		return FltStatus ;
	}

	//current process monitored or not
	if (!Ps_IsCurrentProcessMonitored(pStreamCtx->FileName.Buffer, 
								pStreamCtx->FileName.Length/sizeof(WCHAR), NULL, NULL))
	{// not monitored, exit
		FltReleaseContext(pStreamCtx) ;
		return FltStatus ;
	}	

	switch (FileInfoClass)
	{
		case FileAllInformation:
		{
			PFILE_ALL_INFORMATION psFileAllInfo = (PFILE_ALL_INFORMATION)FileInfoBuffer ;
			if (FileInfoLength >= (sizeof(FILE_BASIC_INFORMATION) + sizeof(FILE_STANDARD_INFORMATION)))
			{
				psFileAllInfo->StandardInformation.EndOfFile = pStreamCtx->FileValidLength;
				psFileAllInfo->StandardInformation.AllocationSize.QuadPart = pStreamCtx->FileValidLength.QuadPart + (PAGE_SIZE - (pStreamCtx->FileValidLength.QuadPart%PAGE_SIZE)) ;
			}
			break ;
		}
		
		case FileAllocationInformation:
		{
			PFILE_ALLOCATION_INFORMATION psFileAllocInfo = (PFILE_ALLOCATION_INFORMATION)FileInfoBuffer;
			psFileAllocInfo->AllocationSize = pStreamCtx->FileValidLength ;
			break ;
		}
		case FileValidDataLengthInformation:
		{
			PFILE_VALID_DATA_LENGTH_INFORMATION psFileValidLengthInfo = (PFILE_VALID_DATA_LENGTH_INFORMATION)FileInfoBuffer ;
			break ;
		}
		case FileStandardInformation:
		{
			PFILE_STANDARD_INFORMATION psFileStandardInfo = (PFILE_STANDARD_INFORMATION)FileInfoBuffer ;
			psFileStandardInfo->AllocationSize.QuadPart = pStreamCtx->FileValidLength.QuadPart + (PAGE_SIZE - (pStreamCtx->FileValidLength.QuadPart%PAGE_SIZE));
			psFileStandardInfo->EndOfFile = pStreamCtx->FileValidLength ;
			break ;
		}
		case FileEndOfFileInformation:
		{
			PFILE_END_OF_FILE_INFORMATION psFileEndInfo = (PFILE_END_OF_FILE_INFORMATION)FileInfoBuffer ;
			psFileEndInfo->EndOfFile = pStreamCtx->FileValidLength ;
			break ;
		}
		case FilePositionInformation:
		{
			PFILE_POSITION_INFORMATION psFilePosInfo = (PFILE_POSITION_INFORMATION)FileInfoBuffer ;
			break ;
		}
		case FileBasicInformation:
		{
			PFILE_BASIC_INFORMATION psFileBasicInfo = (PFILE_BASIC_INFORMATION)FileInfoBuffer ;
			break ;
		}
		default:
			ASSERT(FALSE) ;
	};

	FltReleaseContext(pStreamCtx) ;

	return  FltStatus ;
}


FLT_PREOP_CALLBACK_STATUS
PreSetInfo (
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __deref_out_opt PVOID *CompletionContext
    )
{
	NTSTATUS status = STATUS_SUCCESS ;
    FLT_PREOP_CALLBACK_STATUS callbackStatus = FLT_PREOP_SYNCHRONIZE ;
    FILE_INFORMATION_CLASS FileInfoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
	PVOID FileInfoBuffer = Data->Iopb->Parameters.SetFileInformation.InfoBuffer ;

	PSTREAM_CONTEXT pStreamCtx = NULL ;
	KIRQL OldIrql ;

    UNREFERENCED_PARAMETER( CompletionContext );

    PAGED_CODE();

	try{

		if (FLT_IS_FASTIO_OPERATION(Data))
		{
			callbackStatus = FLT_PREOP_DISALLOW_FASTIO ;
			__leave ;
		}

		status = Ctx_FindOrCreateStreamContext(Data,FltObjects,FALSE,&pStreamCtx,NULL) ;
		if (!NT_SUCCESS(status))
		{
			callbackStatus = FLT_PREOP_SUCCESS_NO_CALLBACK ;
			__leave ;
		}

		//current process monitored or not
		if (!Ps_IsCurrentProcessMonitored(pStreamCtx->FileName.Buffer, 
									pStreamCtx->FileName.Length/sizeof(WCHAR), NULL, NULL))
		{// not monitored, exit
			callbackStatus = FLT_PREOP_SUCCESS_NO_CALLBACK ;
			__leave ;
		}		
		
		// if file has been encrypted, if not, Pass down directly, 
		// otherwise, go on to post-query routine
		if (!pStreamCtx->bEncryptOnWrite && ((FileInfoClass != FileDispositionInformation) &&
			(FileInfoClass != FileRenameInformation)))
		{
			callbackStatus = FLT_PREOP_SUCCESS_NO_CALLBACK ;
			__leave ;
		}

		if (FileInfoClass == FileAllInformation || 
			FileInfoClass == FileAllocationInformation ||
			FileInfoClass == FileEndOfFileInformation ||
			FileInfoClass == FileStandardInformation ||
			FileInfoClass == FilePositionInformation ||
			FileInfoClass == FileValidDataLengthInformation ||
			FileInfoClass == FileDispositionInformation ||
			FileInfoClass == FileRenameInformation)
		{
			callbackStatus = FLT_PREOP_SYNCHRONIZE ;
		}
		else
		{
			callbackStatus = FLT_PREOP_SUCCESS_NO_CALLBACK ;
			__leave ;
		}

		switch(FileInfoClass)
		{
		case FileAllInformation:
			{
				PFILE_ALL_INFORMATION psFileAllInfo = (PFILE_ALL_INFORMATION)FileInfoBuffer ;
				break ;
			}
		case FileAllocationInformation:
			{
				PFILE_ALLOCATION_INFORMATION psFileAllocInfo = (PFILE_ALLOCATION_INFORMATION)FileInfoBuffer ;
				break ;
			}
		case FileEndOfFileInformation:
			{// update file size on disk
				PFILE_END_OF_FILE_INFORMATION psFileEndInfo = (PFILE_END_OF_FILE_INFORMATION)FileInfoBuffer ;
				SC_LOCK(pStreamCtx, &OldIrql) ;
				pStreamCtx->FileValidLength = psFileEndInfo->EndOfFile ;
				SC_UNLOCK(pStreamCtx, OldIrql) ;
				break ;
			}
		case FileStandardInformation:
			{
				PFILE_STANDARD_INFORMATION psStandardInfo = (PFILE_STANDARD_INFORMATION)FileInfoBuffer ;
				break ;
			}
		case FilePositionInformation:
			{
				PFILE_POSITION_INFORMATION psFilePosInfo = (PFILE_POSITION_INFORMATION)FileInfoBuffer ;
				break ;
			}
		case FileValidDataLengthInformation:
			{
				PFILE_VALID_DATA_LENGTH_INFORMATION psFileValidInfo = (PFILE_VALID_DATA_LENGTH_INFORMATION)FileInfoBuffer ;
				break ;
			}
		case FileRenameInformation:
			{
				PFILE_RENAME_INFORMATION psFileRenameInfo = (PFILE_RENAME_INFORMATION)FileInfoBuffer ;
				break ;
			}
		case FileDispositionInformation:
			{
				PFILE_DISPOSITION_INFORMATION psFileDispInfo = (PFILE_DISPOSITION_INFORMATION)FileInfoBuffer; 
				break ;
			}
		default:
			ASSERT(FALSE) ;
		};
	}
	finally{
		if (NULL != pStreamCtx)
		{
			FltReleaseContext(pStreamCtx) ;
		}
	}

    return callbackStatus;
}


FLT_POSTOP_CALLBACK_STATUS
PostSetInfo (
    __inout PFLT_CALLBACK_DATA Data,
    __in PCFLT_RELATED_OBJECTS FltObjects,
    __inout_opt PVOID CompletionContext,
    __in FLT_POST_OPERATION_FLAGS Flags
    )
{
    NTSTATUS status = STATUS_SUCCESS;
	PFLT_FILE_NAME_INFORMATION pfNameInfo = NULL ;
	PSTREAM_CONTEXT pStreamCtx = NULL ;
    
    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    PAGED_CODE();

	try{
		//get file full path(such as \Device\HarddiskVolumeX\test\1.txt)
		status = FltGetFileNameInformation(Data, 
			FLT_FILE_NAME_NORMALIZED|FLT_FILE_NAME_QUERY_DEFAULT, 
			&pfNameInfo) ;
		if (!NT_SUCCESS(status))
		{
			__leave ;
		}
		if (0 == pfNameInfo->Name.Length)
		{// file name length is zero
			__leave ;
		}

		if (0 == RtlCompareUnicodeString(&pfNameInfo->Name, &pfNameInfo->Volume, TRUE))
		{// if volume name, filter it
			__leave ;
		}	

		status = Ctx_FindOrCreateStreamContext(Data,FltObjects,FALSE,&pStreamCtx,NULL) ;
		if (!NT_SUCCESS(status))
		{
			__leave ;
		}

		// update file path name in stream context
		status = Ctx_UpdateNameInStreamContext(&pfNameInfo->Name,pStreamCtx) ;
		if (!NT_SUCCESS(status))
		{
			__leave ;
		}
	}
	finally{

		if (NULL != pStreamCtx)
		{
			FltReleaseContext(pStreamCtx) ;
		}
		if (NULL != pfNameInfo)
		{
			FltReleaseFileNameInformation(pfNameInfo) ;
		}
	}
    return FLT_POSTOP_FINISHED_PROCESSING;
}

VOID
ReadDriverParameters (
    __in PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    This routine tries to read the driver-specific parameters from
    the registry.  These values will be found in the registry location
    indicated by the RegistryPath passed in.

Arguments:

    RegistryPath - the path key passed to the driver during driver entry.

Return Value:

    None.

--*/
{
    OBJECT_ATTRIBUTES attributes;
    HANDLE driverRegKey;
    NTSTATUS status;
    ULONG resultLength;
    UNICODE_STRING valueName;
    UCHAR buffer[sizeof( KEY_VALUE_PARTIAL_INFORMATION ) + sizeof( LONG )];

    //  If this value is not zero then somebody has already explicitly set it so don't override those settings.
    if (0 == LoggingFlags) 
	{
        //  Open the desired registry key
        InitializeObjectAttributes( &attributes,
                                    RegistryPath,
                                    OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                    NULL,
                                    NULL );
        status = ZwOpenKey( &driverRegKey,
                            KEY_READ,
                            &attributes );
        if (!NT_SUCCESS( status )) 
            return;

        // Read the given value from the registry.
        RtlInitUnicodeString( &valueName, L"DebugFlags" );
        status = ZwQueryValueKey( driverRegKey,
                                  &valueName,
                                  KeyValuePartialInformation,
                                  buffer,
                                  sizeof(buffer),
                                  &resultLength );
        if (NT_SUCCESS( status )) 
            LoggingFlags = *((PULONG) &(((PKEY_VALUE_PARTIAL_INFORMATION)buffer)->Data));
        ZwClose(driverRegKey);
    }
}

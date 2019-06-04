#include "mefkern.h"

UCHAR GlobalKey[] = { 0x45, 0x67, 0x12, 0x39, 0x82, 0xa9, 0x6e, 0x1f, 0xd3, 0x3b,
					  0x4c, 0x3a, 0x93, 0x75, 0x48, 0x1b };

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, EncFlushCache)
#pragma alloc_text(PAGE, EncIsEncryptFolderInternal)
#pragma alloc_text(PAGE, EncIsEncryptFolder)
#pragma alloc_text(PAGE, EncIsDirectory)
#pragma alloc_text(PAGE, EncPostCreate)
#endif

NTSTATUS
EncEncryptBuffer (
	__in PVOID Buffer,
	__in ULONG Length,
	__out PVOID OutBuffer
	)
{
	ULONG i, k;
	PUCHAR InBuf = (PUCHAR)Buffer;
	PUCHAR OutBuf = (PUCHAR)OutBuffer;

	ASSERT (Length % 16 == 0);

	for (i = 0; i < Length/16; i++)
	{
		for (k = 0; k < 16; k++)
		{
			(*OutBuf) = (*InBuf) ^ GlobalKey[k];
			InBuf++;
			OutBuf++;
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS
EncDecryptBuffer (
	__in PVOID Buffer,
	__in ULONG Length,
	__out PVOID OutBuffer
	)
{
	return EncEncryptBuffer ( Buffer,
							  Length,
							  OutBuffer );
}

VOID 
EncLockFcb (
	__in PFILE_OBJECT FileObject
	)
{
	PFSRTL_COMMON_FCB_HEADER FcbHeader;
	LARGE_INTEGER Wait;
	BOOLEAN ResourceAcquired = FALSE;
	BOOLEAN PagingIoAcquired = FALSE;

	PAGED_CODE();

	FcbHeader = (PFSRTL_COMMON_FCB_HEADER)FileObject->FsContext;
	ASSERT (FcbHeader);

	Wait.QuadPart = -1 * (LONGLONG)100;
	
	if (!FcbHeader->Resource) {
	
		return;
	}

	KeEnterCriticalRegion();

	while (TRUE) {

		BOOLEAN IsPagingIoResouceLock = FALSE;

		if (FcbHeader->PagingIoResource) {

			IsPagingIoResouceLock = ExIsResourceAcquiredExclusiveLite(FcbHeader->PagingIoResource);
		}

		if (FcbHeader->Resource) {

			if (!ExIsResourceAcquiredExclusiveLite (FcbHeader->Resource)) {

				if (IsPagingIoResouceLock) {

					if (ExAcquireResourceExclusiveLite(FcbHeader->Resource, FALSE)) {

						ResourceAcquired = TRUE;
					}
				} else {

					ExAcquireResourceExclusiveLite(FcbHeader->Resource, TRUE);
					ResourceAcquired = TRUE;
				}
			}
		}
		
		if (!FcbHeader->PagingIoResource && ResourceAcquired) {

			break;
		}

		if (ResourceAcquired && !IsPagingIoResouceLock) {

			if (ExAcquireResourceExclusiveLite(FcbHeader->PagingIoResource, FALSE)) {

				PagingIoAcquired = TRUE;
				break;
			}
		}

		if (PagingIoAcquired) {

			ExReleaseResourceLite(FcbHeader->PagingIoResource);
			PagingIoAcquired = FALSE;
		}

		if (ResourceAcquired) {

			ExReleaseResourceLite(FcbHeader->Resource);
			ResourceAcquired = FALSE;
		}
	
		if (KeGetCurrentIrql() == PASSIVE_LEVEL) {

			KeDelayExecutionThread(KernelMode, FALSE, &Wait);

		} else {

			KEVENT WaitEvent;
			KeInitializeEvent(&WaitEvent, NotificationEvent, FALSE);
			KeWaitForSingleObject(&WaitEvent, Executive, KernelMode, FALSE, &Wait);
		}
	}
}

VOID
EncUnlockFcb (
	__in PFILE_OBJECT FileObject
	)
{
	PFSRTL_COMMON_FCB_HEADER FcbHeader;

	PAGED_CODE();

	FcbHeader = (PFSRTL_COMMON_FCB_HEADER)FileObject->FsContext;
	ASSERT (FcbHeader);

	if (FcbHeader->PagingIoResource) {

		ExReleaseResourceLite(FcbHeader->PagingIoResource);
	}

	if (FcbHeader->Resource) {

		ExReleaseResourceLite(FcbHeader->Resource);
	}

	KeLeaveCriticalRegion();
}

VOID 
EncFlushCache (
	__in PFILE_OBJECT FileObject,
	__in_opt PLARGE_INTEGER ByteOffset,
	__in ULONG Length,
	__in BOOLEAN UninitializeCacheMaps
	)
{
	PFSRTL_COMMON_FCB_HEADER FcbHeader;
	PVOID TopIrp;

	PAGED_CODE();

	FcbHeader = (PFSRTL_COMMON_FCB_HEADER)FileObject->FsContext;
	ASSERT (FcbHeader);

	EncLockFcb(FileObject);

	TopIrp = IoGetTopLevelIrp();
	ASSERT (!TopIrp);

	IoSetTopLevelIrp((PIRP)FSRTL_FSP_TOP_LEVEL_IRP);

	if (FileObject->SectionObjectPointer) {
		
		IO_STATUS_BLOCK IoStatus;
		BOOLEAN Ret;

		CcFlushCache(FileObject->SectionObjectPointer, ByteOffset, Length, &IoStatus);
		ASSERT (NT_SUCCESS(IoStatus.Status));

		if (ByteOffset && IoStatus.Information < Length) {

			DebugTrace( DEBUG_TRACE_ERROR|DEBUG_TRACE_ENCRYPT, 
						("[Enc]: EncFlushCache -> CcFlushCache incompletion, Request Length = %x, Flush Length = %x\n", 
						Length, IoStatus.Information) );
		}

		if (FileObject->SectionObjectPointer->ImageSectionObject) {

			MmFlushImageSection(FileObject->SectionObjectPointer->ImageSectionObject, MmFlushForWrite); 
		}

		Ret = CcPurgeCacheSection(FileObject->SectionObjectPointer, ByteOffset, Length, UninitializeCacheMaps);
		ASSERT (Ret);
	}

	IoSetTopLevelIrp(TopIrp);

	EncUnlockFcb(FileObject);
}

/*
VOID 
EncFlushCache (
	__in PFILE_OBJECT FileObject,
	__in_opt PLARGE_INTEGER ByteOffset,
	__in ULONG Length,
	__in BOOLEAN UninitializeCacheMaps
	)
{
	PFSRTL_COMMON_FCB_HEADER FcbHeader;
	IO_STATUS_BLOCK IoStatus;
	BOOLEAN Ret;

	PAGED_CODE();

	FcbHeader = (PFSRTL_COMMON_FCB_HEADER)FileObject->FsContext;

	ExAcquireResourceExclusiveLite( FcbHeader->Resource, TRUE);

	if (FileObject->SectionObjectPointer) {

		CcFlushCache (FileObject->SectionObjectPointer, ByteOffset, Length, &IoStatus);
		
		ASSERT (NT_SUCCESS(IoStatus.Status));

		if (FcbHeader->PagingIoResource) {

			//
			//  Grab and release PagingIo to serialize ourselves with the lazy writer.
			//  This will work to ensure that all IO has completed on the cached
			//  data and we will succesfully tear away the cache section.
			//

			ExAcquireResourceExclusiveLite( FcbHeader->PagingIoResource, TRUE);
			ExReleaseResourceLite( FcbHeader->PagingIoResource );
		}

		Ret = CcPurgeCacheSection( FileObject->SectionObjectPointer,
									ByteOffset,
									Length,
									UninitializeCacheMaps );

		ASSERT (Ret);
	}

	ExReleaseResourceLite( FcbHeader->Resource );
}
*/

#define ENC_FOLDER	L"\\Device\\HarddiskVolume2\\MiniFolder\\"
#define ENC_FOLDER2 L"\\Device\\HarddiskVolume3\\MiniFolder\\"

NTSTATUS
EncIsEncryptFolderInternal (
	__in PUNICODE_STRING FileName,
	__in PWCHAR FolderName,
	__out PBOOLEAN EncryptFolder,
	__out PBOOLEAN RootFolder
	)
{
	SIZE_T FolderLength;
	SIZE_T FileNameLength;

	PAGED_CODE();

	FileNameLength = FileName->Length/sizeof(WCHAR);
	FolderLength = wcslen(FolderName);

	if (FileNameLength == FolderLength - 1 ||
		FileNameLength == FolderLength) {
		
		if (!_wcsnicmp( FolderName, FileName->Buffer, FileNameLength )) {

			*EncryptFolder = TRUE;
			*RootFolder = TRUE;
			return STATUS_SUCCESS;
		}

	} else if (FileNameLength <= FolderLength) {
		
		return STATUS_SUCCESS;
	}

	if (_wcsnicmp( FolderName, FileName->Buffer, FolderLength )) {
		
		return STATUS_SUCCESS;
	}

	*EncryptFolder = TRUE;

	return STATUS_SUCCESS;
}

NTSTATUS
EncIsEncryptFolder (
	__in PUNICODE_STRING FileName,
	__out PBOOLEAN EncryptFolder,
	__out PBOOLEAN RootFolder
	)
{
	NTSTATUS Status;

	PAGED_CODE();

	*EncryptFolder = FALSE;
	*RootFolder = FALSE;

	Status = EncIsEncryptFolderInternal( FileName, ENC_FOLDER, EncryptFolder, RootFolder);
	if (!NT_SUCCESS (Status) || *EncryptFolder) {

		return Status;
	}
	
	Status = EncIsEncryptFolderInternal( FileName, ENC_FOLDER2, EncryptFolder, RootFolder);

	return Status;
}

NTSTATUS
EncIsDirectory (
	__in PFLT_CALLBACK_DATA Cbd,
	__in PCTX_STREAM_CONTEXT StreamContext,
	__out PBOOLEAN DirectoryFile
	)
{
	NTSTATUS Status;
	PFLT_IO_PARAMETER_BLOCK Iopb = Cbd->Iopb;

	PAGED_CODE();

	*DirectoryFile = TRUE;

	if (BooleanFlagOn(Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE)) {

		return STATUS_SUCCESS;
	}

	if (BooleanFlagOn(Iopb->OperationFlags, SL_OPEN_TARGET_DIRECTORY)) {
	
		return STATUS_SUCCESS;
	}

	if (!BooleanFlagOn(Iopb->Parameters.Create.Options, FILE_NON_DIRECTORY_FILE)) {

		FILE_STANDARD_INFORMATION FileStdInfo;

		Status = FltQueryInformationFile( Cbd->Iopb->TargetInstance,
										  Cbd->Iopb->TargetFileObject,
										  &FileStdInfo,
										  sizeof(FileStdInfo),
										  FileStandardInformation,
										  NULL );
		if (!NT_SUCCESS(Status)) {

			DebugTrace (DEBUG_TRACE_ENCRYPT|DEBUG_TRACE_ERROR, ("[Enc] EncIsDirectory -> %wZ Failed to FltQueryInformationFile %x\n", 
											   &StreamContext->FileName, 
											   Status ));

			return Status;
		}

		if (FileStdInfo.Directory) {

			return STATUS_SUCCESS;
		}
	}

	*DirectoryFile = FALSE;

	return STATUS_SUCCESS;
}

NTSTATUS
EncWriteSig (
    __in PFLT_CALLBACK_DATA Cbd,
	__in PCTX_STREAM_CONTEXT StreamContext
	)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PENC_HEADER EncHeader;
	PVOID EncBuffer;
	LARGE_INTEGER ByteOffset;
	ULONG Flags = FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET;
	KIRQL irql;

	PAGED_CODE();

	DebugTrace (DEBUG_TRACE_ENCRYPT|DEBUG_TRACE_WARN, ("[Enc] EncWriteSig -> To WriteSig %wZ. \n", 
								   &StreamContext->FileName ));

	EncBuffer = ExAllocatePoolWithTag( NonPagedPool, ENC_HEADER_SIZE, CTX_BUFFER_TAG );
	if (!EncBuffer) {

		DebugTrace (DEBUG_TRACE_ENCRYPT|DEBUG_TRACE_ERROR, 
					("[Enc] EncWriteSig -> %wZ Failed to allocate buffer. \n", 
					&StreamContext->FileName ));

		Status = STATUS_INSUFFICIENT_RESOURCES;

		return Status;
	}
 
	RtlZeroMemory (EncBuffer, ENC_HEADER_SIZE);

	EncHeader = (PENC_HEADER)EncBuffer;
	EncHeader->EncFlag = ENC_FLAG;
	RtlCopyMemory (EncHeader->EncSig, ENC_SIG, 32);
	EncHeader->Version = ENC_VERSION;
	EncHeader->Length = ENC_HEADER_SIZE;
	
	ByteOffset.QuadPart = 0;

	Flags |= FLTFL_IO_OPERATION_NON_CACHED;

	Status = FltWriteFile( Cbd->Iopb->TargetInstance,
						   Cbd->Iopb->TargetFileObject,
						   &ByteOffset,
						   ENC_HEADER_SIZE,
						   EncBuffer,
						   Flags,
						   NULL,
						   NULL,
						   NULL );

	if (!NT_SUCCESS (Status)) {

		DebugTrace (DEBUG_TRACE_ENCRYPT|DEBUG_TRACE_ERROR, 
					("[Enc] EncWriteSig -> %wZ Failed to FltWriteFile %x \n", 
					&StreamContext->FileName, Status ));
	}
	
	ExFreePoolWithTag( EncBuffer, CTX_BUFFER_TAG );

	//EncFlushCache(Cbd->Iopb->TargetFileObject, &ByteOffset, ENC_HEADER_SIZE, FALSE);

	if (NT_SUCCESS(Status)) {

		KIRQL irql;

		StreamContext->SignLength = ENC_HEADER_SIZE;

		KeAcquireSpinLock( &StreamContext->Lock, &irql );

		StreamContext->FileSize.QuadPart = 0;
		StreamContext->ValidDataLength.QuadPart = 0;

		KeReleaseSpinLock( &StreamContext->Lock, irql );

		StreamContext->EncryptFile = TRUE;
		StreamContext->DecryptOnRead = TRUE;
	}

	return Status;
}

//
//  某些api操作, 如NtQueryAttributesFile完成后会直接发送irp_close给文件系统, 
//  可能引起fcb被删除, 所以对于这个fileobject不能有任何cache操作;
//  这里读取加密标识采用noncache, 或重新打开文件进行读取.
//

NTSTATUS
EncReadSig (
    __in PFLT_CALLBACK_DATA Cbd,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in PCTX_STREAM_CONTEXT StreamContext
	)
{
	NTSTATUS Status = STATUS_SUCCESS;
	FILE_STANDARD_INFORMATION FileStdInfo;
	PENC_HEADER EncHeader;
	PVOID EncBuffer = NULL;
	LARGE_INTEGER ByteOffset;
	HANDLE FileHandle = NULL;
	PFILE_OBJECT FileObject = Cbd->Iopb->TargetFileObject;
	BOOLEAN OpenFile = FALSE;
	ULONG Flags = FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET;
	KIRQL irql;

	/*
	if (Cbd->Iopb->Parameters.Create.ShareAccess  == (FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE)) {

		OBJECT_ATTRIBUTES ObjectAttributes;
		IO_STATUS_BLOCK IoStatus;

		InitializeObjectAttributes( &ObjectAttributes,
									&StreamContext->FileName, 
									OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE,
									NULL,
									NULL );

		Status = FltCreateFile ( FltObjects->Filter,
								 FltObjects->Instance,
								 &FileHandle,
								 SYNCHRONIZE|FILE_READ_DATA|FILE_READ_ATTRIBUTES,//|FILE_WRITE_DATA,
								 &ObjectAttributes,
								 &IoStatus,
								 NULL,
								 FILE_ATTRIBUTE_NORMAL,
								 FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
								 FILE_OPEN,
								 FILE_NON_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT,
								 NULL,
								 0,
								 IO_NO_PARAMETER_CHECKING );

		if (!NT_SUCCESS(Status)) {

			ASSERT (FALSE);
			DebugTrace (DEBUG_TRACE_ENCRYPT|DEBUG_TRACE_ERROR, ("[Enc] EncReadSig -> %wZ Failed to FltCreateFile %x\n", 
											   &StreamContext->FileName, 
											   Status ));

			return Status;
		}

		Status = ObReferenceObjectByHandle( FileHandle, 
											FILE_READ_DATA|FILE_READ_ATTRIBUTES|FILE_WRITE_DATA, 
											*IoFileObjectType, 
											KernelMode, 
											&FileObject, 
											0 );
		if (!NT_SUCCESS(Status)) {
		
			ASSERT (FALSE);
			DebugTrace (DEBUG_TRACE_ENCRYPT|DEBUG_TRACE_ERROR, ("[Enc] EncReadSig -> %wZ Failed to ObReferenceObjectByHandle %x\n", 
											   &StreamContext->FileName, 
											   Status ));

			FltClose (FileHandle);
			return Status;		
		}

		OpenFile = TRUE;
	}
	*/

	if (!OpenFile) {
		
		Flags |= FLTFL_IO_OPERATION_NON_CACHED;
	}

	try {

		Status = FltQueryInformationFile( Cbd->Iopb->TargetInstance,
										  FileObject,
										  &FileStdInfo,
										  sizeof(FileStdInfo),
										  FileStandardInformation,
										  NULL );
		if (!NT_SUCCESS(Status)) {

			DebugTrace (DEBUG_TRACE_ENCRYPT|DEBUG_TRACE_ERROR, ("[Enc] EncReadSig -> %wZ Failed to FltQueryInformationFile %x\n", 
											   &StreamContext->FileName, 
											   Status ));

			leave;
		}

		if (FileStdInfo.EndOfFile.QuadPart < DEFAULT_ENC_HEADER_SIZE) {

			leave;
		}

		EncBuffer = ExAllocatePoolWithTag( NonPagedPool, DEFAULT_ENC_HEADER_SIZE, CTX_BUFFER_TAG );
		if (!EncBuffer) {

			DebugTrace (DEBUG_TRACE_ENCRYPT|DEBUG_TRACE_ERROR, 
						("[Enc] EncReadSig -> %wZ Failed to allocate buffer. \n", 
						&StreamContext->FileName ));

			Status = STATUS_INSUFFICIENT_RESOURCES;

			leave;
		}
		
		ByteOffset.QuadPart = 0;

		Status = FltReadFile( Cbd->Iopb->TargetInstance,
							  FileObject,
							  &ByteOffset,
							  DEFAULT_ENC_HEADER_SIZE,
							  EncBuffer,
							  Flags,
							  NULL,
							  NULL,
							  NULL );

		if (!NT_SUCCESS (Status)) {

			DebugTrace (DEBUG_TRACE_ENCRYPT|DEBUG_TRACE_ERROR, 
						("[Enc] EncReadSig -> %wZ Failed to FltReadFile %x \n", 
						&StreamContext->FileName, Status ));

			leave;

		} else {

			EncHeader = (PENC_HEADER)EncBuffer;

			if (EncHeader->EncFlag == ENC_FLAG &&
				!memcmp(EncHeader->EncSig, ENC_SIG, 32) &&
				EncHeader->Version == ENC_VERSION) {

				if (EncHeader->Length == 0) {

					EncHeader->Length = DEFAULT_ENC_HEADER_SIZE;
					FltWriteFile( Cbd->Iopb->TargetInstance,
								  FileObject,
								  &ByteOffset,
								  DEFAULT_ENC_HEADER_SIZE,
								  EncBuffer,
								  Flags,
								  NULL,
								  NULL,
								  NULL );

				} else if( EncHeader->Length < MIN_ENC_HEADER_SIZE || 
						   EncHeader->Length > MAX_ENC_HEADER_SIZE) {

					DebugTrace (DEBUG_TRACE_ENCRYPT|DEBUG_TRACE_ERROR, 
								("[Enc] EncReadSig -> %wZ Failed to Get Sig Length\n", 
								&StreamContext->FileName, Status ));

					Status = STATUS_UNSUCCESSFUL;

					leave;

				} else if( EncHeader->Length > DEFAULT_ENC_HEADER_SIZE) {
				
					//
					//  读取整个头标识内容
					//
				}

				StreamContext->SignLength = EncHeader->Length;

				KeAcquireSpinLock( &StreamContext->Lock, &irql );

				StreamContext->FileSize.QuadPart = FileStdInfo.EndOfFile.QuadPart - EncHeader->Length;
				StreamContext->ValidDataLength = StreamContext->FileSize;

				KeReleaseSpinLock( &StreamContext->Lock, irql );

				StreamContext->EncryptFile = TRUE;
				StreamContext->DecryptOnRead = TRUE;
			}
		}

	} finally {
		
		if (EncBuffer) {

			ExFreePoolWithTag( EncBuffer, CTX_BUFFER_TAG );
		}
	}

	if (NT_SUCCESS (Status) && !StreamContext->EncryptFile) {

		//Status = EncEncryptFile(Cbd, StreamContext, &FileStdInfo.EndOfFile);

		Status = STATUS_UNSUCCESSFUL;

		DebugTrace (DEBUG_TRACE_ENCRYPT|DEBUG_TRACE_WARN, 
					("[Enc] EncReadSig -> %wZ is not Encrypt File \n", 
					&StreamContext->FileName, Status ));
	}

	EncFlushCache(FileObject, NULL, 0, FALSE);

	if (OpenFile) {
		
		ObDereferenceObject (FileObject);
		FltClose (FileHandle);
	}

	return Status;
}

NTSTATUS
EncEncryptFile (
    __in PFLT_CALLBACK_DATA Cbd,
	__in PCTX_STREAM_CONTEXT StreamContext,
	__in PLARGE_INTEGER FileSize
	)
{
	NTSTATUS Status;
	PVOID Buffer1 = NULL;
	PVOID Buffer2 = NULL;
	ULONG BytesRead1, BytesRead2;
	PENC_HEADER EncHeader;
	LARGE_INTEGER ByteOffset1, ByteOffset2;
	BOOLEAN First = TRUE;

	DebugTrace (DEBUG_TRACE_ENCRYPT|DEBUG_TRACE_WARN, ("[Enc] EncEncryptFile -> To Encrypt %wZ. \n", 
								   &StreamContext->FileName ));

	try {

		Buffer1 = ExAllocatePoolWithTag( NonPagedPool, ENC_HEADER_SIZE, CTX_BUFFER_TAG );
		if (!Buffer1) {

			DebugTrace (DEBUG_TRACE_ENCRYPT|DEBUG_TRACE_ERROR, 
						("[Enc] EncWriteSig -> %wZ Failed to allocate buffer. \n", 
						&StreamContext->FileName ));

			Status = STATUS_INSUFFICIENT_RESOURCES;

			leave;
		}
	 
		BytesRead1 = ENC_HEADER_SIZE;
		ByteOffset1.QuadPart = 0;
		RtlZeroMemory (Buffer1, ENC_HEADER_SIZE);

		EncHeader = (PENC_HEADER)Buffer1;
		EncHeader->EncFlag = ENC_FLAG;
		RtlCopyMemory (EncHeader->EncSig, ENC_SIG, 32);
		EncHeader->Version = ENC_VERSION;
		EncHeader->Length = ENC_HEADER_SIZE;

		Buffer2 = ExAllocatePoolWithTag( NonPagedPool, ENC_HEADER_SIZE, CTX_BUFFER_TAG );
		if (!Buffer2) {

			DebugTrace (DEBUG_TRACE_ENCRYPT|DEBUG_TRACE_ERROR, 
						("[Enc] EncWriteSig -> %wZ Failed to allocate buffer. \n", 
						&StreamContext->FileName ));

			Status = STATUS_INSUFFICIENT_RESOURCES;

			leave;
		}

		BytesRead2 = 0;
		ByteOffset2.QuadPart = 0;

		while (TRUE) {

			if (ByteOffset2.QuadPart < FileSize->QuadPart) {

				Status = FltReadFile( Cbd->Iopb->TargetInstance,
									   Cbd->Iopb->TargetFileObject,
									   &ByteOffset2,
									   ENC_HEADER_SIZE,
									   Buffer2,
									   FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
									   &BytesRead2,
									   NULL,
									   NULL );

				if (!NT_SUCCESS (Status)) {

					DebugTrace (DEBUG_TRACE_ENCRYPT|DEBUG_TRACE_ERROR, 
								("[Enc] EncEncryptFile -> %wZ Failed to FltReadFile %x \n", 
								&StreamContext->FileName, Status ));
					break;
				}

				if (ByteOffset2.QuadPart + BytesRead2 > FileSize->QuadPart) {
					
					BytesRead2 = (ULONG)(FileSize->QuadPart - ByteOffset2.QuadPart);
				}
			}

			Status = FltWriteFile( Cbd->Iopb->TargetInstance,
								   Cbd->Iopb->TargetFileObject,
								   &ByteOffset1,
								   BytesRead1,
								   Buffer1,
								   FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
								   NULL,
								   NULL,
								   NULL );
			if (!NT_SUCCESS (Status)) {

				DebugTrace (DEBUG_TRACE_ENCRYPT|DEBUG_TRACE_ERROR, 
							("[Enc] EncEncryptFile -> %wZ Failed to FltWriteFile %x \n", 
							&StreamContext->FileName, Status ));
				break;
			}
			
			if (First) {

				KIRQL irql;

				First = FALSE;
				
				StreamContext->SignLength = ENC_HEADER_SIZE;

				KeAcquireSpinLock( &StreamContext->Lock, &irql );

				StreamContext->ValidDataLength.QuadPart = FileSize->QuadPart;
				StreamContext->FileSize.QuadPart = FileSize->QuadPart;

				KeReleaseSpinLock( &StreamContext->Lock, irql );

				EncFlushCache(Cbd->Iopb->TargetFileObject, NULL, 0, FALSE);

				FileSize->QuadPart -= ENC_HEADER_SIZE;

				StreamContext->EncryptFile = TRUE;

			} else {

				KIRQL irql;

				ByteOffset1.QuadPart += BytesRead1;
				ByteOffset2.QuadPart += BytesRead2;
			}

			if (BytesRead2 == 0)
				break;

			RtlCopyMemory (Buffer1, Buffer2, ENC_HEADER_SIZE);
			BytesRead1 = BytesRead2;
			
			BytesRead2 = 0;
		}

		if (NT_SUCCESS (Status)) {
			
			//
			//  扩大文件有效长度
			//

			RtlZeroMemory (Buffer1, ENC_HEADER_SIZE);
			Status = FltWriteFile( Cbd->Iopb->TargetInstance,
								   Cbd->Iopb->TargetFileObject,
								   &ByteOffset1,
								   ENC_HEADER_SIZE,
								   Buffer1,
								   FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
								   NULL,
								   NULL,
								   NULL );
			if (!NT_SUCCESS (Status)) {

				DebugTrace (DEBUG_TRACE_ENCRYPT|DEBUG_TRACE_ERROR, 
							("[Enc] EncEncryptFile -> %wZ Failed to FltWriteFile %x \n", 
							&StreamContext->FileName, Status ));
				leave;
			}

			StreamContext->DecryptOnRead = TRUE;
		}

	} finally {

		if (Buffer1) {

			ExFreePoolWithTag (Buffer1, CTX_BUFFER_TAG);
		}

		if (Buffer2) {

			ExFreePoolWithTag (Buffer2, CTX_BUFFER_TAG);
		}
	}

	return Status;
}

NTSTATUS
EncPostCreate (
    __in PFLT_CALLBACK_DATA Cbd,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in PCTX_STREAM_CONTEXT StreamContext,
	__in BOOLEAN StreamContextCreated,
	__out PBOOLEAN EncryptFile
	)
{
	PFLT_IO_PARAMETER_BLOCK Iopb = Cbd->Iopb;
	NTSTATUS Status;
	BOOLEAN EncryptFolder;
	BOOLEAN RootFolder;
	BOOLEAN DirectoryFile;
	BOOLEAN CreateFile;

	PAGED_CODE();

	Status = EncIsEncryptFolder(&StreamContext->FileName, &EncryptFolder, &RootFolder);
	if (!NT_SUCCESS (Status) || !EncryptFolder) {

		*EncryptFile = EncryptFolder;
		return Status;
	}

	*EncryptFile = EncryptFolder;

	Status = EncIsDirectory(Cbd, StreamContext, &DirectoryFile);
	if (!NT_SUCCESS (Status)) {

		return Status;
	}
	
	//
	//  可能是跟文件夹同名的文件
	//

	if (!DirectoryFile && RootFolder) {

		return Status;
	}

	if (DirectoryFile) {

		StreamContext->EncryptFolder = TRUE;
		return Status;
	}

	CreateFile = TRUE;

	if( !(Cbd->IoStatus.Information == FILE_SUPERSEDED ||
		Cbd->IoStatus.Information == FILE_OVERWRITTEN ||
		Cbd->IoStatus.Information == FILE_CREATED) ) {

		CreateFile = FALSE;
	}

	if (CreateFile) {

		StreamContext->EncryptFile = FALSE;
		StreamContext->EncryptFolder = FALSE;

		Status = EncWriteSig(Cbd, StreamContext);

	} else if (StreamContextCreated) {

		Status = EncReadSig(Cbd, FltObjects, StreamContext);
		
		if (!NT_SUCCESS (Status)) {
		
			ASSERT (!StreamContext->EncryptFile && !StreamContext->EncryptFolder);
			Status = STATUS_SUCCESS;
		}
	}

	return Status;
}
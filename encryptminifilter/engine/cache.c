#include "cache.h"
#include "file.h"

void Cc_ClearFileCache(PFILE_OBJECT FileObject, BOOLEAN bIsFlushCache, PLARGE_INTEGER FileOffset, ULONG Length)
{
	BOOLEAN PurgeRes ;
	BOOLEAN ResourceAcquired = FALSE ;
	BOOLEAN PagingIoResourceAcquired = FALSE ;
	PFSRTL_COMMON_FCB_HEADER Fcb = NULL ;
	LARGE_INTEGER Delay50Milliseconds = {(ULONG)(-50 * 1000 * 10), -1};
	IO_STATUS_BLOCK IoStatus = {0} ;

	if ((FileObject == NULL))
	{
		return ;
	}

    Fcb = (PFSRTL_COMMON_FCB_HEADER)FileObject->FsContext ;
	if (Fcb == NULL)
	{
		return ;
	}
	
Acquire:
	FsRtlEnterFileSystem() ;

	if (Fcb->Resource)
		ResourceAcquired = ExAcquireResourceExclusiveLite(Fcb->Resource, TRUE) ;
	if (Fcb->PagingIoResource)
		PagingIoResourceAcquired = ExAcquireResourceExclusive(Fcb->PagingIoResource,FALSE);
	else
		PagingIoResourceAcquired = TRUE ;
	if (!PagingIoResourceAcquired)
	{
		if (Fcb->Resource)  ExReleaseResource(Fcb->Resource);
		FsRtlExitFileSystem();
		KeDelayExecutionThread(KernelMode,FALSE,&Delay50Milliseconds);	
		goto Acquire;	
	}

	if(FileObject->SectionObjectPointer)
	{
		IoSetTopLevelIrp( (PIRP)FSRTL_FSP_TOP_LEVEL_IRP );

		if (bIsFlushCache)
		{
			CcFlushCache( FileObject->SectionObjectPointer, FileOffset, Length, &IoStatus );
		}

		if(FileObject->SectionObjectPointer->ImageSectionObject)
		{
			MmFlushImageSection(
				FileObject->SectionObjectPointer,
				MmFlushForWrite
				) ;
		}

		if(FileObject->SectionObjectPointer->DataSectionObject)
		{ 
			PurgeRes = CcPurgeCacheSection( FileObject->SectionObjectPointer,
				NULL,
				0,
				FALSE );                                                    
		}
                                      
		IoSetTopLevelIrp(NULL);                                   
	}

	if (Fcb->PagingIoResource)
		ExReleaseResourceLite(Fcb->PagingIoResource );                                       
	if (Fcb->Resource)
		ExReleaseResourceLite(Fcb->Resource );                     

	FsRtlExitFileSystem() ;
}
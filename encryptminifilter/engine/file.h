#ifndef _FILENAME_H_
#define _FILENMAE_H_

#include "common.h"

struct FILE_FLAG ;

#define FILEFLAG_POOL_TAG 'FASV'
#define FILE_FLAG_LENGTH  sizeof(FILE_FLAG)
#define FILE_GUID_LENGTH  16
#define HASH_SIZE 20

#pragma pack(1)

/**
 * File Flag Structure
 * is written into end of file every time when file is closed. 
 */
typedef struct _FILE_FLAG{

	/**
	 * This field holds GUID, GUID is used to distinguish encrypted 
	 * files and un-encrypted files. All encrypted files share 
	 * the same GUID that described in file.c
	 */
	UCHAR    FileFlagHeader[FILE_GUID_LENGTH] ;  
	
	/**
	 * This field holds sha1 digest of key for specified file,
	 * Each file has its own encrypt/decrypt key.
	 */
	UCHAR    FileKeyHash[HASH_SIZE] ;

	/**
	 * This field holds real size of file, so engine 
	 * can return/set right file size for user's query/set
	 * request.
	 */
	LONGLONG FileValidLength ;

	/**
	 * For further usage and sector size alignment.
	 */
	UCHAR    Reserved[SECTOR_SIZE-HASH_SIZE-FILE_GUID_LENGTH-8] ;

}FILE_FLAG,*PFILE_FLAG;

/**
 * declared global file flag infomation,
 * it is used to compare with file flag of open file
 * to judge whether specified file are encrypted or
 * not.
 */
extern PFILE_FLAG g_psFileFlag ;

#pragma pack()

/**
 * read data from specified file by calling underlying file system
 */
NTSTATUS
File_ReadWriteFile(
	    __in ULONG MajorFunction,
	    __in PFLT_INSTANCE Instance,
		__in PFILE_OBJECT FileObject,
		__in PLARGE_INTEGER ByteOffset,
		__in ULONG Length,
		__in PVOID  Buffer,
		__out PULONG BytesReadWrite,
		__in FLT_IO_OPERATION_FLAGS FltFlags
		);

/**
 * write file flag data into end of file
 */
NTSTATUS
File_WriteFileFlag(
	__in  PFLT_CALLBACK_DATA Data,
	__in  PFLT_RELATED_OBJECTS FltObjects,
	__in  PFILE_OBJECT FileObject,
	__in  PSTREAM_CONTEXT pStreamCtx
	) ;

/**
 * read file flag data from end of file
 */
NTSTATUS
File_ReadFileFlag(
	__in  PFLT_CALLBACK_DATA Data,
	__in  PFLT_RELATED_OBJECTS FltObjects,
	__in PVOID Buffer
	) ;

/**
 * encrypt entire file manually, and at the end write file flag
 * into end of file.
 */
NTSTATUS
File_UpdateEntireFileByFileObject(
	__in PFLT_CALLBACK_DATA Data,
	__in PFLT_RELATED_OBJECTS FltObjects,
	__in PFILE_OBJECT FileObject, 
	__in PSTREAM_CONTEXT pStreamCtx,
	__in PVOLUME_CONTEXT pVolCtx
	) ;

/**
 * Get file pointer
 */
NTSTATUS 
File_GetFileOffset(
	__in  PFLT_CALLBACK_DATA Data,
	__in  PFLT_RELATED_OBJECTS FltObjects,
	__out PLARGE_INTEGER FileOffset
	) ;

/**
 * Set file pointer
 */
NTSTATUS 
File_SetFileOffset(
	__in  PFLT_CALLBACK_DATA Data,
	__in  PFLT_RELATED_OBJECTS FltObjects,
	__in PLARGE_INTEGER FileOffset
	) ;

/**
 * Set file size
 */
NTSTATUS 
File_SetFileSize(
	__in PFLT_CALLBACK_DATA Data,
    __in PFLT_RELATED_OBJECTS FltObjects,
	__in PLARGE_INTEGER FileSize
	) ;

/**
 * Get file size, returned size is summation of  
 * file data length, padding length and file flag length
 */
NTSTATUS 
File_GetFileSize(
	__in  PFLT_CALLBACK_DATA Data,
	__in  PFLT_RELATED_OBJECTS FltObjects,
	__in PLARGE_INTEGER FileSize
	) ;

/**
 * Get file information
 */
NTSTATUS 
File_GetFileStandardInfo(
	__in  PFLT_CALLBACK_DATA Data,
	__in  PFLT_RELATED_OBJECTS FltObjects,
	__in PLARGE_INTEGER FileAllocationSize,
	__in PLARGE_INTEGER FileSize,
	__in PBOOLEAN bDirectory
	) ;

/**
 * allocate memory for global file flag information,
 * init global file flag and fill GUID in it.
 */
NTSTATUS
File_InitFileFlag() ;

/**
 * deallocate memory occupied by global file flag,
 * when engine is unloaded.
 */
NTSTATUS
File_UninitFileFlag() ;

#endif
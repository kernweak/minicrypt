#ifndef _COMMON_H_
#define _COMMON_H_

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include "..\include\error.h"
#include "..\include\iocommon.h"

#ifndef MAX_PATH
#define MAX_PATH 260 
#endif 

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#ifndef SECTOR_SIZE
#define SECTOR_SIZE 512
#endif

#ifndef DBG
#define DBG 1
#endif

#define FS_NAME_LENGTH 6*sizeof(WCHAR) // useless now

//
//  This is a volume context, one of these are attached to each volume
//  we monitor.  This is used to get a "DOS" name for debug display.
//
typedef struct _VOLUME_CONTEXT {

    //
    //  Holds the name to display
    //

    UNICODE_STRING Name;

    //  Holds the name of file system mounted on volume(old)
	//  Now it is useless
    UNICODE_STRING FsName;

    //
    //  Holds the sector size for this volume.
    //

    ULONG SectorSize;

	// Holds encryption/decryption context
	///COUNTER_MODE_CONTEXT* aes_ctr_ctx ;

	// key. used to encrypt/decrypt files in the volume
	UCHAR szKey[MAX_KEY_LENGTH] ;
	// key digest. used to verify whether specified file 
	// can be decrypted/encrypted by this key
	UCHAR szKeyHash[HASH_SIZE] ;

	//spinlock to synchornize encryption/decryption process
	KSPIN_LOCK FsCryptSpinLock ;

	// Table to hold file context defined in file.h(old)
	// Now it is useless
	RTL_GENERIC_TABLE FsCtxTable ;
	
	// mutex to synchronize file context table(old)
	// Now it is used to synchronize encryption/decryption process
	FAST_MUTEX FsCtxTableMutex ;

} VOLUME_CONTEXT, *PVOLUME_CONTEXT;


//
//  Stream context data structure
//
typedef struct _STREAM_CONTEXT {

    //Name of the file associated with this context.
    UNICODE_STRING FileName;

	//Volume Name
	WCHAR wszVolumeName[64] ;

	//file key hash
	UCHAR szKeyHash[HASH_SIZE] ;

    //Number of times we saw a create on this stream
	//used to verify whether a file flag can be written
	//into end of file and file data can be flush back.
    LONG RefCount;

	//File Valid Size
	LARGE_INTEGER FileValidLength ;

	//File Size(including real file size, padding length, and file flag data)
	LARGE_INTEGER FileSize ;

	//Trail Length
	ULONG uTrailLength ;

	//desired access
	ULONG uAccess ;

	//Flags
	BOOLEAN bIsFileCrypt ;    //(init false)set after file flag is written into end of file
	BOOLEAN bEncryptOnWrite ; //(init true)set when file is to be supervised, or set when file is already encrypted.
	BOOLEAN bDecryptOnRead ;  //(init false)set when non-encrypted file is first paging written, or set when file is already encrypted.
	BOOLEAN bHasWriteData ;    //(init false)If data is written into file during the life cycle of the stream context. This flag is used to judge whether to write tail flag when file is closed.
	BOOLEAN bFirstWriteNotFromBeg ; //(useless now.)if file is not encrypted yet, whether the first write offset is 0
	BOOLEAN bHasPPTWriteData ;  //(init false)If user click save button in un-encrypts ppt file, this flag is set to TRUE and this file will be encrypted in THE LAST IRP_MJ_CLOSE 

	// Holds encryption/decryption context specified to this file
	///COUNTER_MODE_CONTEXT* aes_ctr_ctx ;
   
	//Lock used to protect this context.
    PERESOURCE Resource;

	//Spin lock used to protect this context when irql is too high
	KSPIN_LOCK Resource1 ;

} STREAM_CONTEXT, *PSTREAM_CONTEXT;

#define STREAM_CONTEXT_SIZE sizeof(STREAM_CONTEXT)

#endif
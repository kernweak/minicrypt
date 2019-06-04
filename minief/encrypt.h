#pragma once

#define ENC_FLAG		'FEM$'
#define ENC_SIG			"117FF395876846908F7860A44C0EDE6C"

#define ENC_VERSION		0x0001

typedef struct _ENC_HEADER {
	ULONG EncFlag;
	UCHAR EncSig[32];
	ULONG Version;
	ULONG Length;
} ENC_HEADER, *PENC_HEADER;

#define SECTOR_SIZE					0x200
#define DEFAULT_ENC_HEADER_SIZE		0x200
#define MIN_ENC_HEADER_SIZE			0x200
#define MAX_ENC_HEADER_SIZE			0x10000
#define ENC_HEADER_SIZE				DEFAULT_ENC_HEADER_SIZE

NTSTATUS
EncEncryptBuffer (
	__in PVOID Buffer,
	__in ULONG Length,
	__out PVOID OutBuffer
	);

NTSTATUS
EncDecryptBuffer (
	__in PVOID Buffer,
	__in ULONG Length,
	__out PVOID OutBuffer
	);

VOID 
EncLockFcb (
	__in PFILE_OBJECT FileObject
	);

VOID
EncUnlockFcb (
	__in PFILE_OBJECT FileObject
	);

VOID 
EncFlushCache (
	__in PFILE_OBJECT FileObject,
	__in_opt PLARGE_INTEGER ByteOffset,
	__in ULONG Length,
	__in BOOLEAN UninitializeCacheMaps
	);

NTSTATUS
EncIsEncryptFolderInternal (
	__in PUNICODE_STRING FileName,
	__in PWCHAR FolderName,
	__out PBOOLEAN EncryptFolder,
	__out PBOOLEAN RootFolder
	);

NTSTATUS
EncIsEncryptFolder (
	__in PUNICODE_STRING FileName,
	__out PBOOLEAN EncryptFolder,
	__out PBOOLEAN RootFolder
	);

NTSTATUS
EncIsDirectory (
	__in PFLT_CALLBACK_DATA Cbd,
	__in PCTX_STREAM_CONTEXT StreamContext,
	__out PBOOLEAN DirectoryFile
	);

NTSTATUS
EncWriteSig (
    __in PFLT_CALLBACK_DATA Cbd,
	__in PCTX_STREAM_CONTEXT StreamContext
	);

NTSTATUS
EncReadSig (
    __in PFLT_CALLBACK_DATA Cbd,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in PCTX_STREAM_CONTEXT StreamContext
	);

NTSTATUS
EncEncryptFile (
    __in PFLT_CALLBACK_DATA Cbd,
	__in PCTX_STREAM_CONTEXT StreamContext,
	__in PLARGE_INTEGER FileSize
	);

NTSTATUS
EncPostCreate (
    __in PFLT_CALLBACK_DATA Cbd,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in PCTX_STREAM_CONTEXT StreamContext,
	__in BOOLEAN StreamContextCreated,
	__out PBOOLEAN EncryptFile
	);

#include <ntddk.h>
#include <stdarg.h>
#include <stdio.h>

HANDLE _logFileHandle = NULL;

NTSTATUS
log_init(PUNICODE_STRING fileName)
{
	OBJECT_ATTRIBUTES	objAttr = { 0 };
	IO_STATUS_BLOCK		ioStatusBlock;
	NTSTATUS			status;

	if(KeGetCurrentIrql() != PASSIVE_LEVEL)
	{
		return STATUS_INVALID_DEVICE_STATE; 
	}
	
	InitializeObjectAttributes(&objAttr, fileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	
	status = ZwCreateFile(&_logFileHandle, FILE_APPEND_DATA | SYNCHRONIZE, &objAttr, &ioStatusBlock, NULL, 
		FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	if (status != STATUS_SUCCESS)
		_logFileHandle = NULL;
	return status;
}

NTSTATUS
log_write(const char *fmt, ...) 
{
	static BOOLEAN IsInit = FALSE;
	va_list args;
	ULONG	length;
	IO_STATUS_BLOCK ioStatus;
	char buff[1024];

	ASSERT(_logFileHandle != NULL);
	
	va_start(args, fmt);
	length = _vsnprintf(buff, sizeof(buff), fmt, args);
	va_end(args);
	
	return ZwWriteFile(_logFileHandle, NULL, NULL, NULL, &ioStatus, buff, length, NULL, NULL);
}

NTSTATUS
log_fini()
{
	if (_logFileHandle)
	{
		ZwClose(_logFileHandle);
		_logFileHandle = NULL;		
	}

	return STATUS_SUCCESS;
}
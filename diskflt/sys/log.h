#ifndef log_h__
#define log_h__


#include <ntstatus.h>

extern HANDLE _logFileHandle;

NTSTATUS
log_init(PUNICODE_STRING fileName);

NTSTATUS
log_write(const char *fmt, ...);

NTSTATUS
log_fini();

#endif // log_h__

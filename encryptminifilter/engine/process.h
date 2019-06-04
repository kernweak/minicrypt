#ifndef _PROCESS_H_
#define _PROCESS_H_

#include "common.h"

#define SYSTEM_PROCESS   1
#define NORMAL_PROCESS   0
#define EXCEL_PROCESS    2
#define POWERPNT_PROCESS 3

/**
 * Callback routine set previously by PsSetCreateProcessNotifyRoutine
//*/
VOID 
Ps_ProcessCallBack(
	IN HANDLE hParentId,
	IN HANDLE hProcessId,
	IN BOOLEAN bCreate
	) ;

/**
 * Extern system call to retrieve process name by PEB
//*/
NTKERNELAPI
UCHAR*
PsGetProcessImageFileName(
	__in PEPROCESS Process
	) ;

/**
 * Get current process name
//*/
PCHAR 
Ps_GetProcessName(
	PCHAR pszProcessName,
	PEPROCESS pEProcess
	) ;

/**
 * Get process name offset in KPEB
 */
ULONG
Ps_GetProcessNameOffset(
	VOID
	) ;

/**
 * Is current process monitored
 */
BOOLEAN
Ps_IsCurrentProcessMonitored(
	WCHAR* pwszFilePathName,
	ULONG  uLength,
	BOOLEAN* bIsSystemProcess,
	BOOLEAN* bIsPPTFile
	) ;

/**
 * get all of process info
 */
PVOID
Ps_GetAllProcessInfo(
   __out PVOID  pProcessInfo,
   __out PULONG puCount
   ) ;

/**
 * set process info
 */
BOOLEAN
Ps_SetProcessInfo(
   __in PVOID InputBuffer
   ) ;

/**
 * set monitored or un-monitored
 */
BOOLEAN
Ps_SetMonitored(
   __in PVOID InputBuffer
   ) ;

/**
 * get monitored or un-monitored
 */
BOOLEAN
Ps_GetMonitorStatus(
   __out PVOID OutputBuffer
   ) ;

/**
 * add process info in list
 */
VOID
Ps_AddProcessInfo(
   __in  PVOID pAddProcInfo,
   __out PVOID pAddProcRes
   ) ;

/**
 * delete process info in list
 */
VOID
Ps_DelProcessInfo(
   __in  PVOID pDelProcInfo,
   __out PVOID pDelProcRes
   ) ;

#pragma pack(1)

/**
 * process list used to monitor user processes
 */
typedef struct _iPROCESS_INFO{
	CHAR    szProcessName[16] ;
	BOOLEAN bMonitor ;
	WCHAR   wsszRelatedExt[64][6] ; /*< related file extension, containing maximum 10 extensions and each length is 6 characters */
	LIST_ENTRY ProcessList ;
}iPROCESS_INFO,*PiPROCESS_INFO ;

#pragma pack()

extern ULONG g_nProcessNameOffset ; /*< process name offset in PEB*/
extern LIST_ENTRY g_ProcessListHead ; /*< process info list */
extern KSPIN_LOCK g_ProcessListLock ; /*< process list operation lock */

#endif
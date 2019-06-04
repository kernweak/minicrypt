#include "process.h"
#include "..\include\iocommon.h"
#include "..\include\interface.h"

ULONG g_nProcessNameOffset = 0 ;
LIST_ENTRY g_ProcessListHead ;
KSPIN_LOCK g_ProcessListLock ;

static BOOLEAN Psi_SetProcessMonitor(PPROCESS_INFO psProcInfo, BOOLEAN bAll) ;
static BOOLEAN Psi_SearchForSpecifiedProcessInList(PUCHAR pszProcessName, BOOLEAN bRemove) ;
static ULONG   Psi_AddProcessInfo(PUCHAR pszProcessName, BOOLEAN bMonitor) ;
static ULONG   Psi_DelProcessInfo(PUCHAR pszProcessName, BOOLEAN bMonitor) ;

VOID Ps_ProcessCallBack(
	__in HANDLE hParentId,
	__in HANDLE hProcessId,
	__in BOOLEAN bCreate
	)
{
	NTSTATUS status = STATUS_SUCCESS ;
	PEPROCESS EProcess ;
	UCHAR szProcessName[16] = {0} ;	

	UNREFERENCED_PARAMETER(bCreate) ;
	UNREFERENCED_PARAMETER(hParentId) ;

	try{

		if (!bCreate)
			_leave ;

		/**
		 * get process environment block(PEB)
		 */
		status = PsLookupProcessByProcessId(hProcessId, &EProcess) ;
		if (!NT_SUCCESS(status))
		{
			_leave ;
		}

		/**
		 * get process name
		 */
		Ps_GetProcessName(szProcessName, EProcess) ;

		/**
		 * add process info in list, if exists, donnot insert into list again.
		 */
		Psi_AddProcessInfo(szProcessName, FALSE) ;

	}
	finally{
		/**/
		//Todo some post work here
	}
}


BOOLEAN Ps_IsCurrentProcessMonitored(WCHAR* pwszFilePathName, ULONG uLength, BOOLEAN* bIsSystemProcess, BOOLEAN* bIsPPTFile)
{
	BOOLEAN bRet = TRUE ;
	UCHAR szProcessName[16] = {0} ;
	PLIST_ENTRY TmpListEntryPtr = NULL ;
	PiPROCESS_INFO psProcessInfo = NULL ;
	WCHAR wszFilePathName[MAX_PATH] = {0} ;
	WCHAR* pwszExt = NULL ;

	try{
		Ps_GetProcessName(szProcessName, NULL) ;

		// save file path name in local buffer
		RtlCopyMemory(wszFilePathName, pwszFilePathName, uLength*sizeof(WCHAR)) ;

		// recognize process name and return to caller
		if (bIsSystemProcess != NULL)
		{
		    if ((strlen(szProcessName) == strlen("explorer.exe")) && !_strnicmp(szProcessName, "explorer.exe", strlen(szProcessName)))
			{
				*bIsSystemProcess = SYSTEM_PROCESS ;
			}
			else
			{
				*bIsSystemProcess = NORMAL_PROCESS ;
		    	if ((strlen(szProcessName) == strlen("excel.exe")) && !_strnicmp(szProcessName, "excel.exe", strlen(szProcessName)))
				{
					*bIsSystemProcess = EXCEL_PROCESS ;
				}
		    	if ((strlen(szProcessName) == strlen("powerpnt.exe")) && !_strnicmp(szProcessName, "powerpnt.exe", strlen(szProcessName)))
				{
					*bIsSystemProcess = POWERPNT_PROCESS ;
				}				
			}
		}

		_wcslwr(wszFilePathName) ;
		if (wcsstr(wszFilePathName, L"\\local settings\\temp\\~wrd"))
		{
			bRet = TRUE ;
			///__leave ;
		}

		// go to end of file path name, save pointer in pwszExt
		pwszExt = wszFilePathName + uLength - 1 ;

		// verify file attribute, if directory, return false
		if (pwszFilePathName[uLength-1] == L'\\')
		{//if directory, filter it
			bRet = FALSE ;
			__leave ;
		}

		// redirect to file extension name(including point)
		while (((pwszExt != wszFilePathName) && (*pwszExt != L'\\')) && ((*pwszExt) != L'.')) //定向至扩展名
		{//direct into file extension
			pwszExt -- ;
		}

		// verify this is a file without extension name
		if ((pwszExt == wszFilePathName) || (*pwszExt == L'\\'))
		{//no file extension exists in input filepath name, filter it.
			///bRet = FALSE ;
			///__leave ;
			pwszExt[0] = L'.' ;
			pwszExt[1] = L'\0' ;
		}

		// verify tmp file
		if ((bIsPPTFile != NULL) && !_wcsnicmp(pwszExt, L".ppt", wcslen(L".ppt")))
		{
			*bIsPPTFile = TRUE ;
		}

		// compare current process name with process info in monitored list
		// if existing, match file extension name
		TmpListEntryPtr = g_ProcessListHead.Flink ;
		while(&g_ProcessListHead != TmpListEntryPtr)
		{
			psProcessInfo = CONTAINING_RECORD(TmpListEntryPtr, iPROCESS_INFO, ProcessList) ;

			if (!_strnicmp(psProcessInfo->szProcessName, szProcessName, strlen(szProcessName)))
			{
				int nIndex = 0 ;

				if (psProcessInfo->wsszRelatedExt[0][0] == L'\0')
				{//no filter file extension, return monitor flag
					bRet = psProcessInfo->bMonitor;
					__leave ;
				}

				while (TRUE)
				{// judge wether current file extension name is matched with monitored file type in list
					if (psProcessInfo->wsszRelatedExt[nIndex][0] == L'\0')
					{
						bRet = FALSE ;
						break ;
					}
					else if ((wcslen(pwszExt) == wcslen(psProcessInfo->wsszRelatedExt[nIndex])) && !_wcsnicmp(pwszExt, psProcessInfo->wsszRelatedExt[nIndex], wcslen(pwszExt)))
					{// matched, return monitor flag
						bRet = psProcessInfo->bMonitor ;
						break ;
					}
					nIndex ++ ;
				}
				__leave ;
			}

			// move to next process info in list
			TmpListEntryPtr = TmpListEntryPtr->Flink ;
		}

		bRet = FALSE ;
	}
	finally{
		/**/
		//Todo some post work here
	}

	return bRet ;
}


PVOID
Ps_GetAllProcessInfo(
   __out PVOID  pProcessInfo,
   __out PULONG puCount
   )
{
	KIRQL oldIrql ;
	PLIST_ENTRY TmpListEntryPtr = NULL ;
	PiPROCESS_INFO psProcessInfo = NULL ;
	PMSG_GET_ALL_PROCESS_INFO psGetAllProcInfo = (PMSG_GET_ALL_PROCESS_INFO)pProcessInfo ;

	try{

		*puCount = 0 ;
		KeAcquireSpinLock(&g_ProcessListLock, &oldIrql) ;
		TmpListEntryPtr = g_ProcessListHead.Flink ;
		while(&g_ProcessListHead != TmpListEntryPtr)
		{
			if (NULL != psGetAllProcInfo)
			{//get all process info if needed
				psProcessInfo = CONTAINING_RECORD(TmpListEntryPtr, iPROCESS_INFO, ProcessList) ;
				RtlCopyMemory(psGetAllProcInfo->sProcInfo[*puCount].szProcessName, psProcessInfo->szProcessName, strlen(psProcessInfo->szProcessName)) ;
				psGetAllProcInfo->sProcInfo[*puCount].bMonitor = psProcessInfo->bMonitor ;
				psGetAllProcInfo->uCount ++ ;
			}

			(*puCount) ++ ; //get process count
			TmpListEntryPtr = TmpListEntryPtr->Flink ;
		}

	}
	finally{
		/**/
		//Todo some post work here
		KeReleaseSpinLock(&g_ProcessListLock, oldIrql) ;
	}

	return pProcessInfo ;
}

BOOLEAN
Ps_SetProcessInfo(
   __in PVOID InputBuffer
   )
{
	PMSG_SEND_SET_PROCESS_INFO psSendSetProcInfo = (PMSG_SEND_SET_PROCESS_INFO)InputBuffer ;
	try{
		if (NULL == psSendSetProcInfo)
			_leave ;
		if (IOCTL_SET_PROCESS_MONITOR == psSendSetProcInfo->sSendType.uSendType)
		{
			Psi_SetProcessMonitor(&psSendSetProcInfo->sProcInfo, FALSE) ;
		}
	}
	finally{
	}

	return TRUE ;
}

VOID Ps_AddProcessInfo(PVOID pAddProcInfo, PVOID pAddProcRes)
{
	PMSG_SEND_ADD_PROCESS_INFO psSendAddProcInfo = (PMSG_SEND_ADD_PROCESS_INFO)pAddProcInfo ;
	PMSG_GET_ADD_PROCESS_INFO psGetAddProcInfo = (PMSG_GET_ADD_PROCESS_INFO)pAddProcRes ;

	try{
		if ((NULL == psSendAddProcInfo) || (NULL == psGetAddProcInfo))
		{
			_leave ;
		}
		psGetAddProcInfo->uResult = Psi_AddProcessInfo(psSendAddProcInfo->sProcInfo.szProcessName, psSendAddProcInfo->sProcInfo.bMonitor) ;
	}
	finally{
	}
}

VOID Ps_DelProcessInfo(PVOID pDelProcInfo, PVOID pDelProcRes)
{
	PMSG_SEND_DEL_PROCESS_INFO psSendDelProcInfo = (PMSG_SEND_DEL_PROCESS_INFO)pDelProcInfo ;
	PMSG_GET_DEL_PROCESS_INFO psGetDelProcInfo = (PMSG_GET_DEL_PROCESS_INFO)pDelProcRes ;

	try{
		if ((NULL == psSendDelProcInfo) || (NULL == psGetDelProcInfo))
		{
			_leave ;
		}
		psGetDelProcInfo->uResult = Psi_DelProcessInfo(psSendDelProcInfo->sProcInfo.szProcessName, psSendDelProcInfo->sProcInfo.bMonitor) ;
	}
	finally{
	}
}

ULONG Psi_AddProcessInfo(PUCHAR pszProcessName, BOOLEAN bMonitor)
{
	ULONG uRes = MGAPI_RESULT_SUCCESS ;
	PiPROCESS_INFO psProcInfo = NULL ;
	BOOLEAN bRet ;

	try{
		if (NULL == pszProcessName)
		{
			uRes = MGAPI_RESULT_INTERNEL_ERROR ;
			_leave ;
		}

		/**
		* search for process name, if exists, donnot insert again
		*/
		bRet = Psi_SearchForSpecifiedProcessInList(pszProcessName, FALSE) ;
		if (bRet)
		{
			uRes = MGAPI_RESULT_ALREADY_EXIST ;
			_leave ;
		}

		/**
		* allocate process info structure
		*/
		psProcInfo = ExAllocatePoolWithTag(NonPagedPool, sizeof(iPROCESS_INFO), 'ipws') ;
		if (NULL == psProcInfo)
		{
			uRes = MGAPI_RESULT_INTERNEL_ERROR ;
			_leave ;
		}

		RtlZeroMemory(psProcInfo, sizeof(iPROCESS_INFO)) ;

		/**
		* initialize process info and insert it into global process list
		*/
		if (!_strnicmp(pszProcessName, "WINWORD.EXE", strlen("WINWORD.EXE")))
		{
			wcscpy(psProcInfo->wsszRelatedExt[0],  L".html") ;
			wcscpy(psProcInfo->wsszRelatedExt[1],  L".txt") ;
			wcscpy(psProcInfo->wsszRelatedExt[2], L".mh_") ; //relative to .mht and .mhtml extension
			wcscpy(psProcInfo->wsszRelatedExt[3],  L".rtf") ;
			wcscpy(psProcInfo->wsszRelatedExt[4], L".ht_") ; //relative to .htm and .html extension
			wcscpy(psProcInfo->wsszRelatedExt[5],  L".xml") ;
			wcscpy(psProcInfo->wsszRelatedExt[6],  L".mht") ;
			wcscpy(psProcInfo->wsszRelatedExt[7],  L".mhtml") ;
			wcscpy(psProcInfo->wsszRelatedExt[8],  L".htm") ;
			wcscpy(psProcInfo->wsszRelatedExt[9],  L".dot") ;
			wcscpy(psProcInfo->wsszRelatedExt[10],  L".tmp") ;
			wcscpy(psProcInfo->wsszRelatedExt[11], L".docm") ;
			wcscpy(psProcInfo->wsszRelatedExt[12], L".docx") ;
			wcscpy(psProcInfo->wsszRelatedExt[13],  L".doc") ;
		}
		else if (!_strnicmp(pszProcessName, "notepad.exe", strlen("notepad.exe")))
		{
			wcscpy(psProcInfo->wsszRelatedExt[0],  L".txt") ;
		}
		else if (!_strnicmp(pszProcessName, "EXCEL.EXE", strlen("EXCEL.EXE")))
		{
			wcscpy(psProcInfo->wsszRelatedExt[0],  L".xls") ;
			wcscpy(psProcInfo->wsszRelatedExt[1],  L".xml") ;
			wcscpy(psProcInfo->wsszRelatedExt[2],  L".mht") ;
			wcscpy(psProcInfo->wsszRelatedExt[3],  L".mhtml") ;
			wcscpy(psProcInfo->wsszRelatedExt[4],  L".htm") ;
			wcscpy(psProcInfo->wsszRelatedExt[5],  L".html") ;
			wcscpy(psProcInfo->wsszRelatedExt[6],  L".mh_") ; //relative to .mht extension
			wcscpy(psProcInfo->wsszRelatedExt[7],  L".ht_") ; //relative to .htm and .html extension
			wcscpy(psProcInfo->wsszRelatedExt[8],  L".xlt") ;
			wcscpy(psProcInfo->wsszRelatedExt[9],  L".txt") ;
			wcscpy(psProcInfo->wsszRelatedExt[10], L".") ;
		}
		else if (!_strnicmp(pszProcessName, "POWERPNT.EXE", strlen("POWERPNT.EXE")))
		{
			wcscpy(psProcInfo->wsszRelatedExt[0],  L".ppt") ;
			wcscpy(psProcInfo->wsszRelatedExt[1],  L".tmp") ;
			wcscpy(psProcInfo->wsszRelatedExt[2],  L".rtf") ;
			wcscpy(psProcInfo->wsszRelatedExt[3],  L".pot") ;
			wcscpy(psProcInfo->wsszRelatedExt[4],  L".ppsm") ;
			wcscpy(psProcInfo->wsszRelatedExt[5],  L".mht") ;
			wcscpy(psProcInfo->wsszRelatedExt[6],  L".mhtml") ;
			wcscpy(psProcInfo->wsszRelatedExt[7],  L".htm") ;
			wcscpy(psProcInfo->wsszRelatedExt[8],  L".html") ;	
			wcscpy(psProcInfo->wsszRelatedExt[9],  L".pps") ;
			wcscpy(psProcInfo->wsszRelatedExt[10], L".ppa") ;
			wcscpy(psProcInfo->wsszRelatedExt[11], L".pptx") ;
			wcscpy(psProcInfo->wsszRelatedExt[12], L".pptm") ;
			wcscpy(psProcInfo->wsszRelatedExt[13], L".potx") ;
			wcscpy(psProcInfo->wsszRelatedExt[14], L".potm") ;
			wcscpy(psProcInfo->wsszRelatedExt[15], L".ppsx") ;
			wcscpy(psProcInfo->wsszRelatedExt[16], L".mh_") ; //relative to .mht and .mhtml extension
			wcscpy(psProcInfo->wsszRelatedExt[17], L".ht_") ; //relative to .htm and .html extension		
		}
		else if (!_strnicmp(pszProcessName, "wmplayer.exe", strlen("wmplayer.exe")))
		{
			wcscpy(psProcInfo->wsszRelatedExt[0],  L".mid") ;
			wcscpy(psProcInfo->wsszRelatedExt[1],  L".rmi") ;
			wcscpy(psProcInfo->wsszRelatedExt[2],  L".midi") ;
			wcscpy(psProcInfo->wsszRelatedExt[3],  L".asf") ;
			wcscpy(psProcInfo->wsszRelatedExt[4],  L".wm") ;
			wcscpy(psProcInfo->wsszRelatedExt[5],  L".wma") ;
			wcscpy(psProcInfo->wsszRelatedExt[6],  L".wmv") ;
			wcscpy(psProcInfo->wsszRelatedExt[7],  L".avi") ;
			wcscpy(psProcInfo->wsszRelatedExt[8],  L".wav") ;
			wcscpy(psProcInfo->wsszRelatedExt[9],  L".mpg") ;
			wcscpy(psProcInfo->wsszRelatedExt[10], L".mpeg") ;
			wcscpy(psProcInfo->wsszRelatedExt[11], L".mp2") ;
			wcscpy(psProcInfo->wsszRelatedExt[12], L".mp3") ;
		}
		else if (!_strnicmp(pszProcessName, "explorer.exe", strlen("explorer.exe")))
		{
			wcscpy(psProcInfo->wsszRelatedExt[0], L".mp3") ;
			wcscpy(psProcInfo->wsszRelatedExt[1],L".mp2") ;	
			wcscpy(psProcInfo->wsszRelatedExt[2], L".xml") ;
			wcscpy(psProcInfo->wsszRelatedExt[3], L".mht") ;
			wcscpy(psProcInfo->wsszRelatedExt[4], L".mhtml") ;
			wcscpy(psProcInfo->wsszRelatedExt[5], L".htm") ;
			wcscpy(psProcInfo->wsszRelatedExt[6], L".html") ;	
			wcscpy(psProcInfo->wsszRelatedExt[7], L".xlt") ;
			wcscpy(psProcInfo->wsszRelatedExt[8], L".mid") ;
			wcscpy(psProcInfo->wsszRelatedExt[9], L".rmi") ;
			wcscpy(psProcInfo->wsszRelatedExt[10],L".midi") ;
			wcscpy(psProcInfo->wsszRelatedExt[11],L".asf") ;
			wcscpy(psProcInfo->wsszRelatedExt[12],L".wm") ;
			wcscpy(psProcInfo->wsszRelatedExt[13],L".wma") ;
			wcscpy(psProcInfo->wsszRelatedExt[14],L".wmv") ;
			wcscpy(psProcInfo->wsszRelatedExt[15],L".avi") ;
			wcscpy(psProcInfo->wsszRelatedExt[16],L".wav") ;
			wcscpy(psProcInfo->wsszRelatedExt[17],L".mpg") ;
			wcscpy(psProcInfo->wsszRelatedExt[18],L".mpeg") ;
			wcscpy(psProcInfo->wsszRelatedExt[19], L".xls") ;
			wcscpy(psProcInfo->wsszRelatedExt[20], L".ppt") ;
		}
		else if (!_strnicmp(pszProcessName, "System", strlen("System")))
		{
			wcscpy(psProcInfo->wsszRelatedExt[0],  L".doc") ;
			wcscpy(psProcInfo->wsszRelatedExt[1],  L".xls") ;
			wcscpy(psProcInfo->wsszRelatedExt[2],  L".ppt") ;
			wcscpy(psProcInfo->wsszRelatedExt[3],  L".txt") ;
			wcscpy(psProcInfo->wsszRelatedExt[4], L".mp2") ;
			wcscpy(psProcInfo->wsszRelatedExt[5],  L".rtf") ;
			wcscpy(psProcInfo->wsszRelatedExt[6], L".mp3") ;
			wcscpy(psProcInfo->wsszRelatedExt[7],  L".xml") ;
			wcscpy(psProcInfo->wsszRelatedExt[8],  L".mht") ;
			wcscpy(psProcInfo->wsszRelatedExt[9],  L".mhtml") ;
			wcscpy(psProcInfo->wsszRelatedExt[10], L".htm") ;
			wcscpy(psProcInfo->wsszRelatedExt[11], L".html") ;
			wcscpy(psProcInfo->wsszRelatedExt[12], L".docx") ;
			wcscpy(psProcInfo->wsszRelatedExt[13], L".docm") ;	
			wcscpy(psProcInfo->wsszRelatedExt[14], L".pps") ;
			wcscpy(psProcInfo->wsszRelatedExt[15], L".ppa") ;
			wcscpy(psProcInfo->wsszRelatedExt[16], L".pptx") ;
			wcscpy(psProcInfo->wsszRelatedExt[17], L".pptm") ;
			wcscpy(psProcInfo->wsszRelatedExt[18], L".potx") ;
			wcscpy(psProcInfo->wsszRelatedExt[19], L".potm") ;
			wcscpy(psProcInfo->wsszRelatedExt[20], L".ppsx") ;	
			wcscpy(psProcInfo->wsszRelatedExt[21], L".pot") ;
			wcscpy(psProcInfo->wsszRelatedExt[22], L".ppsm") ;	
			wcscpy(psProcInfo->wsszRelatedExt[23], L".mh_") ; //relative to .mht extension
			wcscpy(psProcInfo->wsszRelatedExt[24], L".ht_") ; //relative to .htm and .html extension
			wcscpy(psProcInfo->wsszRelatedExt[25], L".xlt") ;
			wcscpy(psProcInfo->wsszRelatedExt[26], L".mid") ;
			wcscpy(psProcInfo->wsszRelatedExt[27], L".rmi") ;
			wcscpy(psProcInfo->wsszRelatedExt[28], L".midi") ;
			wcscpy(psProcInfo->wsszRelatedExt[29], L".asf") ;
			wcscpy(psProcInfo->wsszRelatedExt[30], L".wm") ;
			wcscpy(psProcInfo->wsszRelatedExt[31], L".wma") ;
			wcscpy(psProcInfo->wsszRelatedExt[32], L".wmv") ;
			wcscpy(psProcInfo->wsszRelatedExt[33], L".avi") ;
			wcscpy(psProcInfo->wsszRelatedExt[34], L".wav") ;
			wcscpy(psProcInfo->wsszRelatedExt[35], L".mpg") ;
			wcscpy(psProcInfo->wsszRelatedExt[36], L".mpeg");
			
			
			wcscpy(psProcInfo->wsszRelatedExt[37],  L".tmp") ;
			wcscpy(psProcInfo->wsszRelatedExt[38],  L".dot") ;
		}	
		psProcInfo->bMonitor = bMonitor ;
		RtlCopyMemory(psProcInfo->szProcessName, pszProcessName, strlen(pszProcessName)) ;
		ExInterlockedInsertTailList(&g_ProcessListHead, &psProcInfo->ProcessList, &g_ProcessListLock) ;
	}
	finally{
	}

	return uRes ;
}

ULONG Psi_DelProcessInfo(PUCHAR pszProcessName, BOOLEAN bMonitor) 
{
	ULONG uRes = MGAPI_RESULT_SUCCESS ;
	BOOLEAN bRet ;

	try{
		if (NULL == pszProcessName)
		{
			uRes = MGDPI_RESULT_INTERNEL_ERROR ;
			_leave ;
		}

		/**
		* search for process name, if exists, donnot insert again
		*/
		bRet = Psi_SearchForSpecifiedProcessInList(pszProcessName, TRUE) ;
		if (!bRet)
		{
			uRes = MGDPI_RESULT_NOT_EXIST ;
			_leave ;
		}
	}
	finally{
	}

	return uRes ;
}

BOOLEAN
Ps_SetMonitored(
   __in PVOID InputBuffer
   )
{
	PMSG_SEND_SET_PROCESS_INFO psSendSetProcInfo = (PMSG_SEND_SET_PROCESS_INFO)InputBuffer ;
	try{
		if (NULL == psSendSetProcInfo)
			_leave ;
		if (IOCTL_SET_MONITOR == psSendSetProcInfo->sSendType.uSendType)
		{
			Psi_SetProcessMonitor(&psSendSetProcInfo->sProcInfo, TRUE) ;
		}
	}
	finally{
	}

	return TRUE ;
}

BOOLEAN
Ps_GetMonitorStatus(
   __out PVOID OutputBuffer
   )
{	
	KIRQL oldIrql ;
	PLIST_ENTRY TmpListEntryPtr = NULL ;
	PiPROCESS_INFO psProcessInfo = NULL ;
	PMSG_SEND_SET_PROCESS_INFO psSendSetProcInfo = (PMSG_SEND_SET_PROCESS_INFO)OutputBuffer ;
	
	try{
		if (NULL == psSendSetProcInfo)
			_leave ;
		KeAcquireSpinLock(&g_ProcessListLock, &oldIrql) ;
		TmpListEntryPtr = g_ProcessListHead.Flink ;
		if(&g_ProcessListHead != TmpListEntryPtr)
		{
			psProcessInfo = CONTAINING_RECORD(TmpListEntryPtr, iPROCESS_INFO, ProcessList) ;
			psSendSetProcInfo->sProcInfo.bMonitor = psProcessInfo->bMonitor ;
		}
		KeReleaseSpinLock(&g_ProcessListLock, oldIrql) ;
	}
	finally{
	}

	return TRUE ;
}


BOOLEAN Psi_SetProcessMonitor(PPROCESS_INFO psProcInfo, BOOLEAN bAll)
{
	BOOLEAN bRet = TRUE ;
	KIRQL oldIrql ;
	PLIST_ENTRY TmpListEntryPtr = NULL ;
	PiPROCESS_INFO psProcessInfo = NULL ;

	try{

		KeAcquireSpinLock(&g_ProcessListLock, &oldIrql) ;
		TmpListEntryPtr = g_ProcessListHead.Flink ;
		while(&g_ProcessListHead != TmpListEntryPtr)
		{
			psProcessInfo = CONTAINING_RECORD(TmpListEntryPtr, iPROCESS_INFO, ProcessList) ;

			if (!bAll)
			{
				if (!_strnicmp(psProcessInfo->szProcessName, psProcInfo->szProcessName, strlen(psProcInfo->szProcessName)))
				{
					psProcessInfo->bMonitor = psProcInfo->bMonitor ;
					break ;
				}
			}
			else
			{
				psProcessInfo->bMonitor = psProcInfo->bMonitor ;
			}

			TmpListEntryPtr = TmpListEntryPtr->Flink ;
		}

		if(!bAll)
			bRet = FALSE ;
	}
	finally{
		/**/
		//Todo some post work here
		KeReleaseSpinLock(&g_ProcessListLock, oldIrql) ;
	}

	return bRet ;
}

static BOOLEAN Psi_SearchForSpecifiedProcessInList(PUCHAR pszProcessName, BOOLEAN bRemove)
{
	BOOLEAN bRet = TRUE ;
	KIRQL oldIrql ;
	PLIST_ENTRY TmpListEntryPtr = NULL ;
	PiPROCESS_INFO psProcessInfo = NULL ;

	try{

		TmpListEntryPtr = g_ProcessListHead.Flink ;
		while(&g_ProcessListHead != TmpListEntryPtr)
		{
			psProcessInfo = CONTAINING_RECORD(TmpListEntryPtr, iPROCESS_INFO, ProcessList) ;

			if (!_strnicmp(psProcessInfo->szProcessName, pszProcessName, strlen(pszProcessName)))
			{
				bRet = TRUE;
				if (bRemove)
				{
					KeAcquireSpinLock(&g_ProcessListLock, &oldIrql) ;
					RemoveEntryList(&psProcessInfo->ProcessList) ;
					KeReleaseSpinLock(&g_ProcessListLock, oldIrql) ;
					ExFreePool(psProcessInfo) ;
					psProcessInfo = NULL ;
				}
				__leave ;
			}

			TmpListEntryPtr = TmpListEntryPtr->Flink ;
		}

		bRet = FALSE ;
	}
	finally{
		/**/
		//Todo some post work here
	}

	return bRet ;
}


PCHAR Ps_GetProcessName(PCHAR pszProcessName, PEPROCESS pEProcess)
{
	PEPROCESS curproc = pEProcess;
	char *nameptr ;

	if (g_nProcessNameOffset)
	{
		if (!curproc)
		{
			curproc = PsGetCurrentProcess() ;
		}
		nameptr = (PCHAR)curproc + g_nProcessNameOffset ;
		strncpy(pszProcessName, nameptr, 15) ;
	}
	else
	{
		strcpy(pszProcessName, "???") ;
	}

	return pszProcessName ;
}

ULONG
Ps_GetProcessNameOffset(
	VOID
	)
{
	PEPROCESS curproc = NULL ;
	int i = 0 ;

	curproc = PsGetCurrentProcess() ;

	for (i=0; i<3*PAGE_SIZE; i++)
	{
		if (!strncmp("System", (PCHAR)curproc+i, strlen("System")))
		{
			return i ;
		}
	}

	return 0 ;
}
#include "message.h"
#include "..\include\iocommon.h"
#include "..\include\interface.h"
#include "process.h"
#include "key.h"

PFLT_PORT g_pClientPort = NULL ;
PFLT_FILTER gFilterHandle;
PFLT_PORT g_pServerPort = NULL ; // port for communication between user and kernel

NTSTATUS 
Msg_CreateCommunicationPort(
	  IN PFLT_FILTER pFilter
	  )
{
	NTSTATUS status ;

	UNICODE_STRING uPortName ;
	OBJECT_ATTRIBUTES ob ;

	PSECURITY_DESCRIPTOR pSecurityDescriptor = NULL ;

	/*
	    Build security descriptor
	//*/
	status = FltBuildDefaultSecurityDescriptor(&pSecurityDescriptor, FLT_PORT_ALL_ACCESS) ;
	if (!NT_SUCCESS(status))
	{
		return status ;
	}

	/*
	    Init server port name
	//*/
	RtlInitUnicodeString(&uPortName, SERVER_PORTNAME) ;
	InitializeObjectAttributes(&ob, 
		&uPortName, 
		OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE, 
		NULL,
		pSecurityDescriptor) ;

	/* 
	    Create a new server port
	//*/
	status = FltCreateCommunicationPort(
		pFilter, 
		&g_pServerPort,
		&ob,
		NULL,
		Msg_ConnectNotifyCallback, 
		Msg_DisconnectNotifyCallback,
		Msg_MessageNotifyCallback,
		1
		) ;

	/*
	    Free security descriptor
	//*/
	FltFreeSecurityDescriptor(pSecurityDescriptor) ;

	return status ;
}

NTSTATUS
Msg_CloseCommunicationPort(
	  IN PFLT_PORT ServerPort
	  ) 
{
	FltCloseCommunicationPort(ServerPort) ;

	return STATUS_SUCCESS ;
}

NTSTATUS
Msg_ConnectNotifyCallback(
	  IN PFLT_PORT ClientPort,
	  IN PVOID ServerPortCookie,
	  IN PVOID ConnectionContext,
	  IN ULONG SizeOfContext,
	  OUT PVOID* ConnectionPortCookie
	  )
{
	g_pClientPort = ClientPort ;

	return STATUS_SUCCESS ;
}

VOID
Msg_DisconnectNotifyCallback(
	  IN PVOID ConnectionCookie
	  )
{
	PAGED_CODE() ;

	FltCloseClientPort(gFilterHandle, &g_pClientPort) ;
}

NTSTATUS
Msg_MessageNotifyCallback(
	  IN PVOID PortCookie,
	  IN PVOID InputBuffer,
	  IN ULONG InputBufferLength,
	  OUT PVOID OutputBuffer,
	  IN ULONG OutputBufferLength,
	  OUT PULONG ReturnOutputBufferLength
	  )
{
	NTSTATUS status = STATUS_SUCCESS ;
	PMSG_SEND_TYPE psSendType= (PMSG_SEND_TYPE)InputBuffer ;
	ULONG uType  = psSendType->uSendType ;

	switch (uType)
	{
	case IOCTL_GET_PROCESS_COUNT:
		{
			if (InputBufferLength < sizeof(MSG_SEND_TYPE))
			{
				return STATUS_BUFFER_TOO_SMALL ;
			}
			Ps_GetAllProcessInfo(NULL, OutputBuffer) ;
			*ReturnOutputBufferLength = OutputBufferLength ;
			break ;
		}
	case IOCTL_GET_ALL_PROCESS_INFO:
		{
			ULONG uCount = 0 ;
			
			if (InputBufferLength < sizeof(MSG_SEND_TYPE))
			{
				return STATUS_BUFFER_TOO_SMALL ;
			}
			
			Ps_GetAllProcessInfo(OutputBuffer, &uCount) ;
			*ReturnOutputBufferLength = OutputBufferLength ;
			break ;
		}
	case IOCTL_SET_PROCESS_MONITOR:
		{
			if (InputBufferLength < sizeof(MSG_SEND_SET_PROCESS_INFO))
			{
				return STATUS_BUFFER_TOO_SMALL ;
			}
			Ps_SetProcessInfo(InputBuffer) ;
			*ReturnOutputBufferLength = 0 ;
			break ;
		}
	case IOCTL_ADD_PROCESS_INFO:
		{
			if (InputBufferLength < sizeof(MSG_SEND_ADD_PROCESS_INFO))
			{
				return STATUS_BUFFER_TOO_SMALL ; 
			}
			Ps_AddProcessInfo(InputBuffer, OutputBuffer) ;
			break ;
		}
	case IOCTL_DEL_PROCESS_INFO:
		{
			if (InputBufferLength < sizeof(MSG_SEND_DEL_PROCESS_INFO))
			{
				return STATUS_BUFFER_TOO_SMALL ;
			}
			Ps_DelProcessInfo(InputBuffer, OutputBuffer) ;
			break ;
		}
	case IOCTL_SET_FILEKEY_INFO:
		{
			PMSG_SEND_SET_FILEKEY_INFO psSetFileKeyInfo ;
			extern UCHAR g_szCurFileKey[MAX_KEY_LENGTH] ;
			extern UCHAR g_szCurFileKeyDigest[HASH_SIZE] ;
			extern BOOLEAN g_bInitCurKey ;

			if (InputBufferLength < sizeof(MSG_SEND_SET_FILEKEY_INFO))
			{
				return STATUS_BUFFER_TOO_SMALL ;
			}
			
			psSetFileKeyInfo = (PMSG_SEND_SET_FILEKEY_INFO)InputBuffer ;
			RtlCopyMemory(g_szCurFileKey, psSetFileKeyInfo->szKey, MAX_KEY_LENGTH) ;
			RtlCopyMemory(g_szCurFileKeyDigest, psSetFileKeyInfo->szKeyDigest, HASH_SIZE) ;
			g_bInitCurKey = TRUE ;
			*ReturnOutputBufferLength = 0 ;
			break ;
		}
	case IOCTL_SET_MONITOR:
		{
			if (InputBufferLength < sizeof(MSG_SEND_SET_PROCESS_INFO))
			{
				return STATUS_BUFFER_TOO_SMALL ;
			}
			Ps_SetMonitored(InputBuffer) ;
			*ReturnOutputBufferLength = 0 ;
			break ;
		}
	case IOCTL_GET_MONITOR:
		{
			if (InputBufferLength < sizeof(MSG_SEND_SET_PROCESS_INFO))
			{
				return STATUS_BUFFER_TOO_SMALL ;
			}
			Ps_GetMonitorStatus(OutputBuffer) ;
			*ReturnOutputBufferLength = sizeof(MSG_SEND_SET_PROCESS_INFO) ;
			break ;
		}
	case IOCTL_SET_KEYLIST:
		{
			if (InputBufferLength < sizeof(MSG_SEND_SET_HISKEY_INFO))
			{
				return STATUS_BUFFER_TOO_SMALL ;
			}
			Key_InitKeyList(InputBuffer) ;
			*ReturnOutputBufferLength = 0 ;
			break ;
		}
	default:
		break ;
	}

	return status ;
}
#ifndef _COMMUNICATION_H_
#define _COMMUNICATION_H_

#include "common.h"

NTSTATUS 
Msg_CreateCommunicationPort(
	  IN PFLT_FILTER pFilter
	  ) ;

NTSTATUS
Msg_CloseCommunicationPort(
	  IN PFLT_PORT ServerPort
	  ) ;

NTSTATUS
Msg_ConnectNotifyCallback(
	  IN PFLT_PORT ClientPort,
	  IN PVOID ServerPortCookie,
	  IN PVOID ConnectionContext,
	  IN ULONG SizeOfContext,
	  OUT PVOID* ConnectionPortCookie
	  ) ;

VOID
Msg_DisconnectNotifyCallback(
	  IN PVOID ConnectionCookie
	  ) ;

NTSTATUS
Msg_MessageNotifyCallback(
	  IN PVOID PortCookie,
	  IN PVOID InputBuffer,
	  IN ULONG InputBufferLength,
	  OUT PVOID OutputBuffer,
	  IN ULONG OutputBufferLength,
	  OUT PULONG ReturnOutputBufferLength
	  ) ;

extern PFLT_PORT g_pClientPort ;
extern PFLT_FILTER gFilterHandle ;
extern PFLT_PORT g_pServerPort ;


#endif
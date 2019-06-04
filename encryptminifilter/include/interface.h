//this file defines some interface between driver and application.

#ifndef _INTERFACE_H_
#define _INTERFACE_H_

#include "iocommon.h"

#define SERVER_PORTNAME L"\\EnginePort"

#define IOCTL_GET_ALL_PROCESS_INFO 0x00000001
#define IOCTL_GET_PROCESS_COUNT    0x00000002
#define IOCTL_SET_PROCESS_MONITOR  0x00000003
#define IOCTL_ADD_PROCESS_INFO     0x00000004
#define IOCTL_DEL_PROCESS_INFO     0x00000005
#define IOCTL_SET_FILEKEY_INFO     0x00000006
#define IOCTL_SET_MONITOR          0x00000007
#define IOCTL_SET_KEYLIST          0x00000008
#define IOCTL_GET_MONITOR          0x00000009

#define TAG_LENGTH     4 
#define VERSION_LENGTH 4
#define IV_LENGTH      16
#define SECTION_SIZE       512

#pragma pack(1)

typedef struct _MSG_SEND_TYPE{
	ULONG uSendType ; 
}MSG_SEND_TYPE,*PMSG_SEND_TYPE ;

/**
 * get current process count
 */
typedef struct _MSG_GET_PROCESS_COUNT{
	ULONG uCount ;
}MSG_GET_PROCESS_COUNT,*PMSG_GET_PROCESS_COUNT ;

/**
 * get all process info
 */
typedef struct _MSG_GET_ALL_PROCESS_INFO{
	ULONG uCount ;
	PROCESS_INFO sProcInfo[1] ;
}MSG_GET_ALL_PROCESS_INFO,*PMSG_GET_ALL_PROCESS_INFO ;

/**
 * set process monitor on/off
 */
typedef struct _MSG_SEND_SET_PROCESS_INFO{
	MSG_SEND_TYPE sSendType ;
	PROCESS_INFO sProcInfo ;
}MSG_SEND_SET_PROCESS_INFO,*PMSG_SEND_SET_PROCESS_INFO ;

/**
 * add process info to process list
 */
typedef MSG_SEND_SET_PROCESS_INFO MSG_SEND_ADD_PROCESS_INFO  ;
typedef MSG_SEND_SET_PROCESS_INFO* PMSG_SEND_ADD_PROCESS_INFO ;

/**
 * result of add process info 
 */
#define MGAPI_RESULT_SUCCESS        0x00000000
#define MGAPI_RESULT_ALREADY_EXIST  0x00000001
#define MGAPI_RESULT_INTERNEL_ERROR 0x00000002

typedef struct _MSG_GET_ADD_PROCESS_INFO{
	ULONG uResult ;
}MSG_GET_ADD_PROCESS_INFO,*PMSG_GET_ADD_PROCESS_INFO ;

/**
 * delete specified process info in process list
 */
typedef MSG_SEND_SET_PROCESS_INFO MSG_SEND_DEL_PROCESS_INFO  ;
typedef MSG_SEND_SET_PROCESS_INFO* PMSG_SEND_DEL_PROCESS_INFO ;

/**
 * result of delete process info
 */
#define MGDPI_RESULT_SUCCESS MGAPI_RESULT_SUCCESS        
#define MGDPI_RESULT_NOT_EXIST MGAPI_RESULT_ALREADY_EXIST   
#define MGDPI_RESULT_INTERNEL_ERROR MGAPI_RESULT_INTERNEL_ERROR 

typedef MSG_GET_ADD_PROCESS_INFO  MSG_GET_DEL_PROCESS_INFO ;
typedef MSG_GET_ADD_PROCESS_INFO* PMSG_GET_DEL_PROCESS_INFO ;

/**
 * set encryption/decryption key
 */
typedef struct _MSG_SEND_SET_FILEKEY_INFO{
	
	MSG_SEND_TYPE sSendType ;
	UCHAR szKey[MAX_KEY_LENGTH+1] ;
	UCHAR szKeyDigest[HASH_SIZE+1] ;

}MSG_SEND_SET_FILEKEY_INFO,*PMSG_SEND_SET_FILEKEY_INFO ;

typedef struct _FILEKEY_INFO{

	UCHAR szCurKeyHash[HASH_SIZE] ;
	UCHAR szCurKeyCipher[MAX_KEY_LENGTH] ;

}FILEKEY_INFO,*PFILEKEY_INFO ;

typedef struct _KEYLIST_INFO{
	ULONG uItemCount ;
	FILEKEY_INFO sFileKeyInfo[1] ;
}KEYLIST_INFO,*PKEYLIST_INFO ;

/**
 * set history key list info
 */
typedef struct _MSG_SEND_SET_HISKEY_INFO{

	MSG_SEND_TYPE sSendType ;
	KEYLIST_INFO sKeyListInfo ;

}MSG_SEND_SET_HISKEY_INFO,*PMSG_SEND_SET_HISKEY_INFO ;

typedef struct _CFG_SECTION1{

	UCHAR szCheckSum[HASH_SIZE] ;
	UCHAR Reserved[SECTION_SIZE-HASH_SIZE] ;

}CFG_SECTION1,*PCFG_SECTION1 ;

typedef struct _CFG_SECTION2{
	
	UCHAR szTag[TAG_LENGTH] ;
	UCHAR szVersion[VERSION_LENGTH] ;
	HINT_INFO sHintInfo ;
	UCHAR Reserved[SECTION_SIZE-sizeof(HINT_INFO)-8] ;

}CFG_SECTION2,*PCFG_SECTION2 ;

typedef struct _CFG_SECTION3{

	UCHAR szCurPwdHash[HASH_SIZE] ;
	FILEKEY_INFO szCurFileKeyInfo ;
	ULONG uModifyPwdCount ;
	FILEKEY_INFO szHistoryFileKeyInfo[1] ;

}CFG_SECTION3,*PCFG_SECTION3 ;

#pragma pack()

#endif
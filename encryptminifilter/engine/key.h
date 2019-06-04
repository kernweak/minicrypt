#ifndef _KEY_H_
#define _KEY_H_

#include "common.h"
#include "..\include\interface.h"

BOOLEAN
Key_InitKeyList(
	PVOID InputBuffer
	) ;

BOOLEAN 
Key_AddKeyInfoInList(
	UCHAR* pszCurKeyHash,
	ULONG  uHashSize,
	UCHAR* pszCurKeyCipher,
	ULONG  uKeyLength
	) ;

BOOLEAN
Key_GetKeyByDigest(
	UCHAR* pszFileKeyHash,
	ULONG  uHashSize,
	UCHAR* pszFileKey,
	ULONG  uKeyLength
	) ;

BOOLEAN
Key_DestroyKeyList(
	) ;

#define KEY_POOL_TAG 'KASV'
extern PKEYLIST_INFO g_psKeyListInfo ;

#endif//_KEY_H_
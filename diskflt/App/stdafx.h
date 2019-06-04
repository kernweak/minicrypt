// stdafx.h : include file for standard system include files,
//  or project specific include files that are used frequently, but
//      are changed infrequently
//

#if !defined(AFX_STDAFX_H__FABDF0CD_5E3B_4283_9637_DC27D95A1152__INCLUDED_)
#define AFX_STDAFX_H__FABDF0CD_5E3B_4283_9637_DC27D95A1152__INCLUDED_

// Change these values to use different versions
#define WINVER		0x0400
//#define _WIN32_WINNT	0x0400
#define _WIN32_IE	0x0400
#define _RICHEDIT_VER	0x0100

#include <atlbase.h>
#include <atlapp.h>

extern CAppModule _Module;
extern BOOL	_isSysInstall;
extern char	_passWord[256];
#include <atlwin.h>
#include "CoolControlsManager.h"

// 文件名为8.3格式
#define SERVICE_NAME	_T("diskflt")


//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_STDAFX_H__FABDF0CD_5E3B_4283_9637_DC27D95A1152__INCLUDED_)

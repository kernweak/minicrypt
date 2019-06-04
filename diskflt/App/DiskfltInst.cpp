// DiskfltInst.cpp : main source file for DiskfltInst.exe
//

#include "stdafx.h"

#include <atlframe.h>
#include <atlctrls.h>
#include <atldlgs.h>
#include <atlctrlw.h>

#include "resource.h"
#include "maindlg.h"
#include "LoginDlg.h"
CAppModule _Module;

BOOL	_isSysInstall = FALSE;
char	_passWord[256];

BOOL isServiceRunning(TCHAR * serviceName)
{
	BOOL		ret = FALSE;
	SC_HANDLE   scmHandle = NULL;
	SC_HANDLE   serviceHandle = NULL;
	
	scmHandle = OpenSCManager(NULL, NULL, GENERIC_READ);
	
	if(NULL == scmHandle )
	{
		return ret;
	}
	
	serviceHandle = OpenService(scmHandle, serviceName, GENERIC_READ);
	
	if(NULL != serviceHandle )
	{
		SERVICE_STATUS	status;
		if (QueryServiceStatus(serviceHandle, &status))
		{
			if (SERVICE_RUNNING == status.dwCurrentState)
			{
				ret = TRUE;
			}
		}
	}
	
	if( scmHandle != NULL )
	{
		CloseServiceHandle( scmHandle );
	}
	
	if( serviceHandle != NULL )
	{
		CloseServiceHandle( serviceHandle ); 
	}
	
	return ret;
}


BOOL
login(char * passWord)
{
	BOOL	ret = FALSE;
	DWORD	retBytes = 0;
	HANDLE handle = CreateFile(DISKFILTER_WIN32_DEVICE_NAME,
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	
	if (handle != INVALID_HANDLE_VALUE)
	{
		ret = DeviceIoControl(handle, IOCTL_DISKFLT_LOGIN, passWord, lstrlen(passWord), 0, 0, &retBytes, NULL);
		CloseHandle(handle);
	} 
	return ret;
}

int Run(LPTSTR /*lpstrCmdLine*/ = NULL, int nCmdShow = SW_SHOWDEFAULT)
{
	CMessageLoop theLoop;
	_Module.AddMessageLoop(&theLoop);

	CMainDlg dlgMain;

	if(dlgMain.Create(NULL) == NULL)
	{
		ATLTRACE(_T("Main dialog creation failed!\n"));
		return 0;
	}

	dlgMain.ShowWindow(nCmdShow);

	int nRet = theLoop.Run();

	_Module.RemoveMessageLoop();
	return nRet;
}

int WINAPI _tWinMain(HINSTANCE hInstance, HINSTANCE /*hPrevInstance*/, LPTSTR lpstrCmdLine, int nCmdShow)
{
	HRESULT hRes = ::CoInitialize(NULL);
// If you are running on NT 4.0 or higher you can use the following call instead to 
// make the EXE free threaded. This means that calls come in on a random RPC thread.
//	HRESULT hRes = ::CoInitializeEx(NULL, COINIT_MULTITHREADED);
	ATLASSERT(SUCCEEDED(hRes));

	// this resolves ATL window thunking problem when Microsoft Layer for Unicode (MSLU) is used
	::DefWindowProc(NULL, 0, 0, 0L);

	AtlInitCommonControls(ICC_COOL_CLASSES | ICC_BAR_CLASSES);	// add flags to support other controls

	hRes = _Module.Init(NULL, hInstance);
	ATLASSERT(SUCCEEDED(hRes));

	_isSysInstall = isServiceRunning(SERVICE_NAME);

	int nRet = EXIT_SUCCESS;
	if (_isSysInstall)
	{
		while (1)
		{
			CLoginDlg	dlg;
			if (IDOK == dlg.DoModal(NULL))
			{
				if (login(dlg.m_passWord.GetBuffer(0)))
				{
					lstrcpy(_passWord, dlg.m_passWord.GetBuffer(0));
					Run(lpstrCmdLine, nCmdShow);
					break;
				}
				else
				{
					MessageBox(NULL, _T("√‹¬Î¥ÌŒÛ£¨«Î÷ÿ–¬ ‰»Î√‹¬Î!"), _T("¥ÌŒÛ"), MB_OK | MB_ICONERROR);
				}
			}
			else
			{
				break;
			}
		}

	}
	else
	{
		nRet = Run(lpstrCmdLine, nCmdShow);
	}

	_Module.Term();
	::CoUninitialize();

	return nRet;
}

// maindlg.h : interface of the CMainDlg class
//
/////////////////////////////////////////////////////////////////////////////

#if !defined(AFX_MAINDLG_H__A938A04E_5C46_4A0D_B560_8CC3B270F7C7__INCLUDED_)
#define AFX_MAINDLG_H__A938A04E_5C46_4A0D_B560_8CC3B270F7C7__INCLUDED_

#if _MSC_VER >= 1000
#pragma once
#endif // _MSC_VER >= 1000
#include <shlwapi.h>
#include <atlctrlx.h>
#include <atlmisc.h>
#include "GetPassWordDlg.h"
#include "md5.h"
#include "ntdll.h"
#include "../sys/diskflt.h"

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "ntdll.lib")

enum 
{
	COMMAND_PROTECT, 
	COMMAND_NOPROTECT, 
	COMMAND_NONE,
};

enum
{
	STATE_PROTECT,
	STATE_NOPROTECT
};
typedef struct 
{
	BYTE	volume;
	BYTE	isProtected;
	BYTE	command;
	BYTE	Reserved;
} VOLUME_INFO, *PVOLUME_INFO;


USHORT   
ChkSum(   
       ULONG PartialSum,   
       PUSHORT Source,   
       ULONG Length   
       )   
	   
{   
	
    while (Length--) {   
        PartialSum += *Source++;   
        PartialSum = (PartialSum >> 16) + (PartialSum & 0xffff);   
    }   
	
	
    return (USHORT)(((PartialSum >> 16) + PartialSum) & 0xffff);   
}   

BOOL AdjustCheckSum(TCHAR *fileName)   
{   
    DWORD fileLength;   
    PWORD AdjustSum;   
    HANDLE hFile=CreateFile(fileName,GENERIC_READ|GENERIC_WRITE,0,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);   
    if(hFile==INVALID_HANDLE_VALUE)   
    {    
        return FALSE;   
    }   
    fileLength = GetFileSize(hFile,NULL);   
	
    HANDLE hMap=CreateFileMapping(hFile,NULL,PAGE_READWRITE,NULL,NULL,NULL);   
    if(hMap==INVALID_HANDLE_VALUE)   
    {   
        return FALSE;   
    }   
	
    LPVOID lpBase=MapViewOfFile(hMap,FILE_MAP_WRITE,0,0,0);   
    if(lpBase==NULL)   
    {   
        return FALSE;      
    }

    USHORT PartialSum;   
    PIMAGE_NT_HEADERS32 ntHeader;   
    PIMAGE_DOS_HEADER dosHeader;   
    PartialSum = ChkSum(0, (PUSHORT)lpBase, (fileLength + 1) >> 1);   
    dosHeader=(PIMAGE_DOS_HEADER)lpBase;   
    ntHeader=(PIMAGE_NT_HEADERS32)(dosHeader->e_lfanew+(DWORD)lpBase);   
    if(ntHeader->OptionalHeader.Magic == 0x10B)   
    {    
        AdjustSum = (PUSHORT)(&((PIMAGE_NT_HEADERS32)ntHeader)->OptionalHeader.CheckSum);   
        PartialSum -= (PartialSum < AdjustSum[0]);   
        PartialSum -= AdjustSum[0];   
        PartialSum -= (PartialSum < AdjustSum[1]);   
        PartialSum -= AdjustSum[1];   
		
    }   
    ntHeader->OptionalHeader.CheckSum=(DWORD)PartialSum+fileLength;   
    FlushViewOfFile(lpBase,0);   
    UnmapViewOfFile(lpBase);   
    CloseHandle(hMap);   
    CloseHandle(hFile);   
    return TRUE;
}

BOOL ReleaseResource(HMODULE hModule, WORD wResourceID, LPCTSTR lpType, LPCTSTR lpFileName)
{
	HGLOBAL hRes;
	HRSRC hResInfo;
	HANDLE hFile;
	DWORD dwBytes;
	hResInfo = FindResource(hModule, MAKEINTRESOURCE(wResourceID), lpType);
	if (hResInfo == NULL)
		return FALSE;
	hRes = LoadResource(hModule, hResInfo);
	if (hRes == NULL)
		return FALSE;
	hFile = CreateFile
			(
			lpFileName, 
			GENERIC_WRITE, 
			FILE_SHARE_WRITE, 
			NULL, 
			CREATE_ALWAYS,
			FILE_ATTRIBUTE_NORMAL, 
			NULL
			);
	if (hFile == NULL)
		return FALSE;

	WriteFile(hFile, hRes, SizeofResource(NULL, hResInfo), &dwBytes, NULL);

	CloseHandle(hFile);
	FreeResource(hRes);
	return TRUE;		
}


BOOL DebugPrivilege(TCHAR * PName, BOOL bEnable)
{
	BOOL              result = TRUE;
	HANDLE            token;
	TOKEN_PRIVILEGES  tokenPrivileges;
	
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &token))
	{
		result = FALSE;
		return result;
	}
	tokenPrivileges.PrivilegeCount = 1;
	tokenPrivileges.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;
	
	LookupPrivilegeValue(NULL, PName, &tokenPrivileges.Privileges[0].Luid);
	AdjustTokenPrivileges(token, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
	if (GetLastError() != ERROR_SUCCESS)
	{
		result = FALSE;
	}
	
	CloseHandle(token);
	return result;	
}

void ShutdownWindows( DWORD dwReason )
{
	DebugPrivilege(SE_SHUTDOWN_NAME,TRUE);
	ExitWindowsEx(dwReason, 0);
	DebugPrivilege(SE_SHUTDOWN_NAME,FALSE);	
}

int memfind(const char *mem, const char *str, int sizem, int sizes)   
{   
	int   da,i,j;   
	if (sizes == 0) da = strlen(str);   
	else da = sizes;   
	for (i = 0; i < sizem; i++)   
	{   
		for (j = 0; j < da; j ++)   
			if (mem[i+j] != str[j])	break;   
			if (j == da) return i;   
	}   
	return -1;   
}

BOOL
getProtectInfo(PPROTECT_INFO protectInfo)
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
		ret = DeviceIoControl(handle, IOCTL_DISKFLT_GETINFO, 0, 0, protectInfo, sizeof(PROTECT_INFO), &retBytes, NULL);
		CloseHandle(handle);
	} 
	return ret;
}


BOOL changeProtectInfo(PPROTECT_INFO protectInfo, BOOL isLock = FALSE, char * passWord = NULL)
{
	TCHAR	fileName[MAX_PATH];
    DWORD fileLength;   
    PWORD AdjustSum;
	BOOL	ret = FALSE;
	
	GetSystemDirectory(fileName, sizeof(fileName));
	lstrcat(fileName, _T("\\drivers\\diskflt.sys"));
	
    HANDLE hFile=CreateFile(fileName,GENERIC_READ|GENERIC_WRITE,0,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);   
    if(hFile==INVALID_HANDLE_VALUE)   
    {    
        return FALSE;   
    }   
    fileLength = GetFileSize(hFile,NULL);   
	
    HANDLE hMap = CreateFileMapping(hFile,NULL,PAGE_READWRITE,NULL,NULL,NULL);   
    if(hMap==INVALID_HANDLE_VALUE)   
    {   
        return FALSE;   
    }   
    LPVOID lpBase = MapViewOfFile(hMap,FILE_MAP_WRITE,0,0,0);   
    if (lpBase == NULL)   
    {   
        return FALSE;      
    }
	
	int pos = memfind((char *)lpBase, MAGIC_CHAR, fileLength, 0);
	if (pos > 0)
	{
		memcpy((char *)lpBase + pos + sizeof(protectInfo->magicChar), (char *)protectInfo + sizeof(protectInfo->magicChar), 
			sizeof(PROTECT_INFO) - sizeof(protectInfo->magicChar));
	}
	
	
	// 修正检验和
	
    USHORT PartialSum;   
    PIMAGE_NT_HEADERS32 ntHeader;   
    PIMAGE_DOS_HEADER dosHeader;   
    PartialSum = ChkSum(0, (PUSHORT)lpBase, (fileLength + 1) >> 1);
    dosHeader=(PIMAGE_DOS_HEADER)lpBase;   
    ntHeader=(PIMAGE_NT_HEADERS32)(dosHeader->e_lfanew+(DWORD)lpBase);   
	//  if(ntHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)   
    {    
        AdjustSum = (PUSHORT)(&((PIMAGE_NT_HEADERS32)ntHeader)->OptionalHeader.CheckSum);   
        PartialSum -= (PartialSum < AdjustSum[0]);   
        PartialSum -= AdjustSum[0];   
        PartialSum -= (PartialSum < AdjustSum[1]);   
        PartialSum -= AdjustSum[1];   
		
    }   
    ntHeader->OptionalHeader.CheckSum=(DWORD)PartialSum+fileLength;
	
	if (isLock)
	{		
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
			ret = DeviceIoControl(handle, IOCTL_DISKFLT_LOCK, passWord, lstrlen(passWord), 0, 0, &retBytes, NULL);
			if (ret)
			{
				FlushViewOfFile(lpBase, 0); 
				DeviceIoControl(handle, IOCTL_DISKFLT_UNLOCK, 0, 0, 0, 0, &retBytes, NULL);
			}
			
			CloseHandle(handle);
		}
		
		
	}
	else
	{
		FlushViewOfFile(lpBase, 0);
		
		ret = TRUE;
	}
	
    UnmapViewOfFile(lpBase);
    CloseHandle(hMap);   
    CloseHandle(hFile); 
	return ret;
}

BOOL
enableProtectSys(BOOL enable, char * passWord)
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
		DWORD	ioCode = enable ? IOCTL_DISKFLT_PROTECTSYS : IOCTL_DISKFLT_NOPROTECTSYS;
		ret = DeviceIoControl(handle, ioCode, passWord, lstrlen(passWord), 
			NULL, 0, &retBytes, NULL);
		CloseHandle(handle);
	} 
	
	return ret;
}


typedef struct _FILE_FS_SIZE_INFORMATION {
    LARGE_INTEGER   TotalAllocationUnits;
    LARGE_INTEGER   AvailableAllocationUnits;
    ULONG           SectorsPerAllocationUnit;
    ULONG           BytesPerSector;
} FILE_FS_SIZE_INFORMATION, *PFILE_FS_SIZE_INFORMATION;

__int64 calcDiskUsed(char diskNumber)
{
	char	fileName[MAX_PATH];
	wsprintf(fileName, "\\\\.\\%c:", diskNumber);
	
	HANDLE	Handle = CreateFile(fileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, 0);
	
	FILE_FS_SIZE_INFORMATION	info;
	IO_STATUS_BLOCK	IoStatusBlock;
	
	NTSTATUS status = ZwQueryVolumeInformationFile(Handle,
		&IoStatusBlock,
		&info,
		sizeof(FILE_FS_SIZE_INFORMATION),
		FileFsSizeInformation);
	
	DWORD _bytesPerCluster = info.BytesPerSector * info.SectorsPerAllocationUnit;
	
	__int64	needMemory = ((info.TotalAllocationUnits.QuadPart * info.SectorsPerAllocationUnit * 2)
		/ 8) + (info.TotalAllocationUnits.QuadPart / 8);
	
	CloseHandle(Handle);
    return needMemory;
}

BOOL Install(TCHAR * serviceName)
{
	BOOL	ret = FALSE;
	LONG	result;
	TCHAR	sysDirPath[MAX_PATH];
	TCHAR	targetPath[MAX_PATH];

	GetSystemDirectory(sysDirPath, sizeof(sysDirPath));
	wsprintf(targetPath, "%s\\Drivers\\%s.sys", sysDirPath, serviceName);

	// 释放文件
	if (!ReleaseResource(NULL, IDR_BIN1, _T("BIN"), targetPath))
	{
		return FALSE;
	}

	HKEY regKey;
	result =::RegOpenKeyEx(HKEY_LOCAL_MACHINE,
								_T("SYSTEM\\CurrentControlSet\\Services"),
								0,
								KEY_ALL_ACCESS,
								&regKey);

	if (SUCCEEDED(result))
	{
		HKEY	subKey;
		if (SUCCEEDED(RegCreateKey(regKey, serviceName, &subKey)))
		{
			DWORD	data = 0x1;
#define SET_DWORD(_key, _valueName, _data) {data = _data; RegSetValueEx(_key, _valueName, NULL, REG_DWORD, (LPBYTE)&data, sizeof(DWORD));}
			data = 0x1;

			SET_DWORD(subKey, _T("ErrorControl"), SERVICE_ERROR_NORMAL);
			SET_DWORD(subKey, _T("Start"), SERVICE_BOOT_START);
			SET_DWORD(subKey, _T("Type"), SERVICE_KERNEL_DRIVER);
			SET_DWORD(subKey, _T("Tag"), 10);
			RegFlushKey(subKey);
			RegCloseKey(subKey);
		}
		RegCloseKey(regKey);
	}
	
	result =::RegOpenKeyEx(HKEY_LOCAL_MACHINE,
								_T("SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E967-E325-11CE-BFC1-08002BE10318}"),
								0,
								KEY_READ|KEY_WRITE,
								&regKey);
    
	if (SUCCEEDED(result))
	{
		TCHAR buff[1024];
        DWORD retLen = sizeof(buff);
		ULONG type = REG_MULTI_SZ;
		
		memset( buff, 0, sizeof(buff));

		RegQueryValueEx( regKey,
			_T("UpperFilters"),
			0,
			&type,
			(LPBYTE)buff, 
			&retLen);

		BOOL	alreadyExists = FALSE;
		TCHAR * ptr = NULL;
		for (ptr = buff; *ptr; ptr += lstrlen(ptr) + 1)
		{
			if(lstrcmpi(ptr, serviceName) == 0)
			{
				alreadyExists = TRUE;
				break;
			}
		}

		if (!alreadyExists)
		{
			DWORD	added = lstrlen(serviceName);
			memcpy(ptr, serviceName, added * sizeof(TCHAR));

			ptr += added;

			*ptr = '\0';
			*(ptr+1) = '\0';

			result = RegSetValueEx(regKey, _T("UpperFilters"), 0, REG_MULTI_SZ, (LPBYTE)buff, retLen + ((added + 1) * sizeof(TCHAR)));
		}

		ret = TRUE;

		RegCloseKey(regKey);
	}

	return ret;
}


BOOL Uninstall(TCHAR * serviceName)
{
	BOOL	ret = FALSE;

	TCHAR	sysDirPath[MAX_PATH];
	TCHAR	targetPath[MAX_PATH];
	
	GetSystemDirectory(sysDirPath, sizeof(sysDirPath));
	wsprintf(targetPath, "%s\\Drivers\\%s.sys", sysDirPath, serviceName);

	DeleteFile(targetPath);

	HKEY regKey;
	LONG result;
	result =::RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		_T("SYSTEM\\CurrentControlSet\\Services"),
		0,
		KEY_READ|KEY_WRITE,
		&regKey);
	if( ERROR_SUCCESS == result )
	{
		SHDeleteKey(regKey, serviceName);
		// 一定要flush,否则不保存
		RegFlushKey(regKey);
	}

	result =::RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		_T("SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E967-E325-11CE-BFC1-08002BE10318}"),
		0,
		KEY_READ|KEY_WRITE,
		&regKey);

	if( ERROR_SUCCESS == result )
	{
		TCHAR buff[1024];
		DWORD retLen = sizeof(buff);
		ULONG type = REG_MULTI_SZ;
		
		memset( buff, 0, sizeof(buff));
		
		RegQueryValueEx( regKey,
			_T("UpperFilters"),
			0,
			&type,
			(LPBYTE)buff, 
			&retLen);
		
		BOOL	alreadyExists = FALSE;
		for (TCHAR * ptr = buff; *ptr; ptr += lstrlen(ptr) + 1)
		{
			if(lstrcmpi(ptr, serviceName) == 0)
			{
				DWORD	removeLength = (lstrlen(ptr) + 1) * sizeof(TCHAR);
				memmove(ptr, (char *)ptr + removeLength, ((char *)ptr + removeLength - (char *)buff) *  sizeof(TCHAR));
				
				result = RegSetValueEx(regKey, _T("UpperFilters"), 0, REG_MULTI_SZ, (LPBYTE)buff, retLen - removeLength);
				break;
			}
		}
		
		ret = TRUE;
		RegFlushKey(regKey);
		RegCloseKey(regKey);
	}
	return ret;
}


BOOL
isProtectSys()
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
		ret = DeviceIoControl(handle, IOCTL_DISKFLT_PROTECTSYS_STATE, 0, 0, 0, 0, &retBytes, NULL);
		CloseHandle(handle);
	} 
	return ret;
}


void showLastError()
{
	LPVOID	msgBuf = NULL;
	DWORD	errorCode = GetLastError();
	FormatMessage
		(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM 
		| FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		errorCode,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
		(LPTSTR) &msgBuf,
		0,
		NULL
		); 
	
	CString	str;
	str.Format(_T("error(%d): %s"), errorCode, msgBuf);
	MessageBox(GetForegroundWindow(), str, NULL, MB_OK | MB_ICONERROR);
	
	LocalFree(msgBuf);
}

class CMainDlg : public CDialogImpl<CMainDlg>, public CUpdateUI<CMainDlg>,
		public CMessageFilter, public CIdleHandler
{
public:
	enum { IDD = IDD_MAINDLG };

	CSortListViewCtrl	m_volumeList;
	CComboBox	m_command;
	CHyperLink	m_link;
//	CCoolControlsManager	m_coolSkin;

	PROTECT_INFO	m_protectInfo;
	
	virtual BOOL PreTranslateMessage(MSG* pMsg)
	{
		return CWindow::IsDialogMessage(pMsg);
	}

	virtual BOOL OnIdle()
	{
		return FALSE;
	}

	BEGIN_UPDATE_UI_MAP(CMainDlg)
	END_UPDATE_UI_MAP()

	BEGIN_MSG_MAP(CMainDlg)
		MESSAGE_HANDLER(WM_INITDIALOG, OnInitDialog)
		COMMAND_ID_HANDLER(IDOK, OnOK)
		COMMAND_ID_HANDLER(IDCANCEL, OnCancel)
		COMMAND_HANDLER(IDC_INSTALLSYS, BN_CLICKED, OnClickedInstallsys)
		COMMAND_HANDLER(IDC_APPLY, BN_CLICKED, OnClickedApply)
		COMMAND_HANDLER(IDC_COMMAND, CBN_SELCHANGE, OnSelchangeCommand)
		COMMAND_HANDLER(IDC_MODIFYPWD, BN_CLICKED, OnClickedModifypwd)
		NOTIFY_HANDLER(IDC_VOLUMELIST, NM_CLICK, OnClickVolumelist)
		COMMAND_HANDLER(IDC_EXIT, BN_CLICKED, OnClickedExit)
		COMMAND_HANDLER(IDC_PROTECTSYS, BN_CLICKED, OnClickedProtectsys)
	END_MSG_MAP()

// Handler prototypes (uncomment arguments if needed):
//	LRESULT MessageHandler(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/)
//	LRESULT CommandHandler(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
//	LRESULT NotifyHandler(int /*idCtrl*/, LPNMHDR /*pnmh*/, BOOL& /*bHandled*/)

	LRESULT OnInitDialog(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/)
	{
		// center the dialog on the screen
		CenterWindow();

		// set icons
		HICON hIcon = (HICON)::LoadImage(_Module.GetResourceInstance(), MAKEINTRESOURCE(IDR_MAINFRAME), 
			IMAGE_ICON, ::GetSystemMetrics(SM_CXICON), ::GetSystemMetrics(SM_CYICON), LR_DEFAULTCOLOR);
		SetIcon(hIcon, TRUE);
		HICON hIconSmall = (HICON)::LoadImage(_Module.GetResourceInstance(), MAKEINTRESOURCE(IDR_MAINFRAME), 
			IMAGE_ICON, ::GetSystemMetrics(SM_CXSMICON), ::GetSystemMetrics(SM_CYSMICON), LR_DEFAULTCOLOR);
		SetIcon(hIconSmall, FALSE);

	//	m_coolSkin.Install(m_hWnd);

		struct
		{
			TCHAR *	text;
			int		width;
		} columnTable[] =
		{
			{_T("盘符"),		40},
			{_T("分区类型"),	65},
			{_T("总空间(MB)"),	80},
			{_T("已使用(MB)"),	80},
			{_T("状态"),	60},
			{_T("命令"),	60},
		};

		m_link.SubclassWindow(GetDlgItem(IDC_VER));
		m_link.SetHyperLink(_T("http://www.dbgger.com/"));
		m_link.SetHyperLinkExtendedStyle(HLINK_NOTUNDERLINED | HLINK_UNDERLINEHOVER);
		m_volumeList.SubclassWindow(GetDlgItem(IDC_VOLUMELIST));
		m_command = GetDlgItem(IDC_COMMAND);

		m_command.SetItemData(m_command.AddString(_T("保护")), COMMAND_PROTECT);
		m_command.SetItemData(m_command.AddString(_T("不保护")), COMMAND_NOPROTECT);
		m_command.SetItemData(m_command.AddString(_T("无命令")), COMMAND_NONE);
		m_command.SetCurSel(2);

		m_volumeList.SetExtendedListViewStyle(LVS_EX_CHECKBOXES | LVS_EX_FULLROWSELECT);


		for (int i = 0; i < _countof(columnTable); i++)
		{
			m_volumeList.InsertColumn(i, columnTable[i].text, LVCFMT_LEFT, columnTable[i].width);
		}

		m_volumeList.SetColumnSortType(2, LVCOLSORT_LONG);
		m_volumeList.SetColumnSortType(3, LVCOLSORT_LONG);

		memset(&m_protectInfo, 0, sizeof(m_protectInfo));
		getProtectInfo(&m_protectInfo);

		TCHAR	buff[256];
		TCHAR	drives[256];
		GetLogicalDriveStrings(sizeof(drives), drives);

		int	index = 0;
		for (TCHAR * drive = drives; *drive; drive += lstrlen(drive) + 1)
		{
			if ((*drive < 'C') || (DRIVE_FIXED != GetDriveType(drive)))
				continue;

			wsprintf(buff, "%C", *drive);

			int	nItem = m_volumeList.InsertItem(index++, buff);

			// 磁盘类型
			GetVolumeInformation(drive, NULL, 0, NULL, NULL, NULL, buff, MAX_PATH);
			m_volumeList.SetItemText(nItem, 1, buff);

			// 磁盘大小

			BOOL	isProtect = m_protectInfo.volumeInfo[toupper(*drive) - 'A'];

			unsigned __int64	HDAmount = 0;
			unsigned __int64	HDFreeSpace = 0;

			if (GetDiskFreeSpaceEx(drive, (PULARGE_INTEGER)&HDFreeSpace, (PULARGE_INTEGER)&HDAmount, NULL))
			{	
				wsprintf(buff, "%d", (unsigned long)(HDAmount / 1024 / 1024));
				m_volumeList.SetItemText(nItem, 2, buff);

				wsprintf(buff, "%d", (unsigned long)((HDAmount - HDFreeSpace) / 1024 / 1024));
				m_volumeList.SetItemText(nItem, 3, buff);

				if (isProtect)
				{
					m_volumeList.SetItemText(nItem, 4, "保护");
				}
				else
				{
					m_volumeList.SetItemText(nItem, 4, "不保护");
				}
				
				m_volumeList.SetItemText(nItem, 5, "无命令");
			}

			VOLUME_INFO volumeInfo;
			volumeInfo.volume = *drive;
			volumeInfo.isProtected = isProtect;
			volumeInfo.command = COMMAND_NONE;

			m_volumeList.SetItemData(nItem, *(DWORD *)&volumeInfo);
		}

		if (!_isSysInstall)
		{
			::EnableWindow(GetDlgItem(IDC_COMMAND), FALSE);
			::EnableWindow(GetDlgItem(IDC_APPLY), FALSE);
			::EnableWindow(GetDlgItem(IDC_MODIFYPWD), FALSE);
			::EnableWindow(GetDlgItem(IDC_PROTECTSYS), FALSE);
			::EnableWindow(GetDlgItem(IDC_VOLUMELIST), FALSE);
		}
		else
		{
			SetDlgItemText(IDC_INSTALLSYS, _T("卸载驱动"));
		}

		((CButton)GetDlgItem(IDC_PROTECTSYS)).SetCheck(isProtectSys());


		// register object for message filtering and idle updates
		CMessageLoop* pLoop = _Module.GetMessageLoop();
		ATLASSERT(pLoop != NULL);
		pLoop->AddMessageFilter(this);
		pLoop->AddIdleHandler(this);

		UIAddChildWindowContainer(m_hWnd);

		return TRUE;
	}

	LRESULT OnOK(WORD /*wNotifyCode*/, WORD wID, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
	{
		// TODO: Add validation code 
		CloseDialog(wID);
		return 0;
	}

	LRESULT OnCancel(WORD /*wNotifyCode*/, WORD wID, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
	{
		CloseDialog(wID);
		return 0;
	}

	void CloseDialog(int nVal)
	{
		DestroyWindow();
		::PostQuitMessage(nVal);
	}
	LRESULT OnClickedInstallsys(WORD wNotifyCode, WORD wID, HWND hWndCtl, BOOL& bHandled)
	{
		// TODO : Add Code for control notification handler.
		BOOL ret = FALSE;
		TCHAR	sysDir[MAX_PATH];
		GetSystemDirectory(sysDir, sizeof(sysDir));

		if (!_isSysInstall)
		{
			CGetPassWorldDlg	dlg;
			dlg.setMode(CGetPassWorldDlg::MODE_INIT);
			if (IDOK == dlg.DoModal(m_hWnd))
			{

				PROTECT_INFO	info;
				memset(&info, 0, sizeof(info));
				
				// 安装时候默认保护系统盘
				info.volumeInfo[*(TCHAR *)sysDir - 'A'] = 1;

				CalcMD5(dlg.m_passWord, dlg.m_passWord.GetLength(), &info.passWord);
		
				ret = Install(SERVICE_NAME);

				if (ret)
				{
					changeProtectInfo(&info);
				}
			}
			else
			{
				return 0;
			}
		}
		else
		{
 			if (1 == m_protectInfo.volumeInfo[*(TCHAR *)sysDir - 'A'])
			{
 				MessageBox(_T("请在系统盘未受保护的情况下卸载还原!"), _T("错误"), MB_OK | MB_ICONERROR);
 				return 0;
 			}
 			else
			{
				if (IDCANCEL == MessageBox(_T("确认是否卸载?"), _T("询问"), MB_OKCANCEL | MB_ICONQUESTION))
				{
					return 0;
				}
				ret = Uninstall(SERVICE_NAME);				
			}
						
		}

		if (ret)
		{
			MessageBox(_T("操作成功,系统将重新启动!"), _T("提示"), MB_OK | MB_ICONWARNING);
			ShutdownWindows(EWX_REBOOT | EWX_FORCE);
		}
		else
		{
			showLastError();
		}

		return 0;
	}

	LRESULT OnClickedApply(WORD wNotifyCode, WORD wID, HWND hWndCtl, BOOL& bHandled)
	{
		// TODO : Add Code for control notification handler.
		int	count = m_volumeList.GetItemCount();

		PROTECT_INFO	protectInfo;
		memcpy(&protectInfo, &m_protectInfo, sizeof(protectInfo));

		for (int i = 0; i < count; i++)
		{
			DWORD	data = m_volumeList.GetItemData(i);
			PVOLUME_INFO volumeInfo = (PVOLUME_INFO)&data;

			BOOL	isProtect = FALSE;
			if (COMMAND_PROTECT == volumeInfo->command)
			{
				isProtect = 1;
			}
			else if (COMMAND_NOPROTECT == volumeInfo->command)
			{
				isProtect = 0;
			}
			else if (COMMAND_NONE == volumeInfo->command)
			{
				isProtect = volumeInfo->isProtected;
			}

			protectInfo.volumeInfo[toupper(volumeInfo->volume - 'A')] = isProtect;
		}

		if (0 == memcmp(&protectInfo, &m_protectInfo, sizeof(protectInfo)))
		{
			MessageBox(_T("配置没有发生任何改变!"), _T("提示"), MB_OK | MB_ICONERROR);
			return 0;
		}


		__int64	needMemory = 0;

		TCHAR	drives[256];
		GetLogicalDriveStrings(sizeof(drives), drives);
		for (TCHAR * drive = drives; *drive; drive += lstrlen(drive) + 1)
		{
			if ((*drive < 'C') || (DRIVE_FIXED != GetDriveType(drive)))
				continue;
			if (protectInfo.volumeInfo[toupper(*drive) - 'A'])
			{
				needMemory += calcDiskUsed(*drive);
			}			
		}
		
		// 给系统预留10M
		int	sysReserve = 1024 * 1024 * 10;
		needMemory += sysReserve;

		MEMORYSTATUS	memStatus;   
		memStatus.dwLength = sizeof(MEMORYSTATUS);   
		GlobalMemoryStatus(&memStatus); 

		__int64	added = (needMemory - memStatus.dwAvailPhys) / 1024 / 1024;

		CString	str;
		if (needMemory >= memStatus.dwAvailPhys)
		{
			str.Format(_T("物理内存可用空间太小, 最少需要再增加 %d MB !"), (int)added);
			MessageBox(str, _T("错误"), MB_OK | MB_ICONERROR);
		}
		else
		{
			BOOL ret = changeProtectInfo(&protectInfo, TRUE, _passWord);
			
			if (ret)
			{
				str.Format(_T("提示 (%d MB)"), (int)((needMemory - sysReserve) / 1024 / 1024));
				MessageBox(_T("操作成功,系统将重新启动!"), str, MB_OK | MB_ICONWARNING);
				ShutdownWindows(EWX_REBOOT | EWX_FORCE);
			}
			else
			{
				showLastError();
			}
		}
		return 0;
	}

	LRESULT OnSelchangeCommand(WORD wNotifyCode, WORD wID, HWND hWndCtl, BOOL& bHandled)
	{
		// TODO : Add Code for control notification handler.

		TCHAR	commandStr[256];
		m_command.GetLBText(m_command.GetCurSel(), commandStr);

		DWORD	command = m_command.GetItemData(m_command.GetCurSel());

		for (int i = 0; i < m_volumeList.GetItemCount(); i++)
		{
			if (m_volumeList.GetCheckState(i))
			{
				DWORD	data = m_volumeList.GetItemData(i);
				((PVOLUME_INFO)&data)->command = (BYTE)command;
				m_volumeList.SetItemData(i, data);
				m_volumeList.SetItemText(i, 5, commandStr);
			}
		}
		return 0;
	}
	LRESULT OnClickedModifypwd(WORD wNotifyCode, WORD wID, HWND hWndCtl, BOOL& bHandled)
	{
		// TODO : Add Code for control notification handler.
		BOOL	ret = FALSE;
		CGetPassWorldDlg	dlg;
		dlg.setMode(CGetPassWorldDlg::MODE_MODIFY);
	
		if (IDOK == dlg.DoModal(m_hWnd))
		{
			PROTECT_INFO	protectInfo;
			memcpy(&protectInfo, &m_protectInfo, sizeof(protectInfo));

			CalcMD5(dlg.m_passWord, dlg.m_passWord.GetLength(), &protectInfo.passWord);
			ret = changeProtectInfo(&protectInfo, TRUE, dlg.m_oldPassWord.GetBuffer(0));

			if (ret)
			{
				MessageBox(_T("操作成功,系统将重新启动!"), _T("提示"), MB_OK | MB_ICONWARNING);
				ShutdownWindows(EWX_REBOOT | EWX_FORCE);
			}
			else
			{
				showLastError();
			}
		}
		return 0;
	}

	LRESULT OnClickVolumelist(int idCtrl, LPNMHDR pnmh, BOOL& bHandled)
	{
		// TODO : Add Code for control notification handler.

	//	m_volumeList.SetCheckState(m_volumeList.GetSelectionMark(), TRUE);

		return 0;
	}
	LRESULT OnClickedExit(WORD wNotifyCode, WORD wID, HWND hWndCtl, BOOL& bHandled)
	{
		// TODO : Add Code for control notification handler.
		CloseDialog(wID);
		return 0;
	}
	LRESULT OnClickedProtectsys(WORD wNotifyCode, WORD wID, HWND hWndCtl, BOOL& bHandled)
	{
		// TODO : Add Code for control notification handler.
		if (!enableProtectSys(((CButton)GetDlgItem(IDC_PROTECTSYS)).GetCheck(), _passWord))
		{
			showLastError();
		}
		return 0;
	}
};


/////////////////////////////////////////////////////////////////////////////

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_MAINDLG_H__A938A04E_5C46_4A0D_B560_8CC3B270F7C7__INCLUDED_)

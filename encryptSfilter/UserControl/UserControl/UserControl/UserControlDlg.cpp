// UserControlDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "UserControl.h"
#include "UserControlDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
END_MESSAGE_MAP()


// CUserControlDlg 对话框




CUserControlDlg::CUserControlDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CUserControlDlg::IDD, pParent)
	, str(_T(""))
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CUserControlDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_RULE_LIST, m_rulelist);
	DDX_Text(pDX, IDC_EDIT_PROC, str);
}

BEGIN_MESSAGE_MAP(CUserControlDlg, CDialog)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	//}}AFX_MSG_MAP
	ON_LBN_SELCHANGE(IDC_RULE_LIST, &CUserControlDlg::OnLbnSelchangeRuleList)
	ON_BN_CLICKED(IDC_ADD_PROC, &CUserControlDlg::OnBnClickedAddProc)
	ON_BN_CLICKED(IDOK, &CUserControlDlg::OnBnClickedOk)
	ON_BN_CLICKED(IDCANCEL, &CUserControlDlg::OnBnClickedCancel)
END_MESSAGE_MAP()


// CUserControlDlg 消息处理程序

BOOL CUserControlDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		CString strAboutMenu;
		strAboutMenu.LoadString(IDS_ABOUTBOX);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
	m_rulelist.SetCheckStyle(BS_CHECKBOX);
	m_rulelist.AddString(_T("explorer.exe"));
	m_rulelist.AddString(_T("notepad.exe"));
	m_rulelist.AddString(_T("wordpad.exe"));
	m_rulelist.AddString(_T("WINWORD.EXE"));
	

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CUserControlDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CUserControlDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CUserControlDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


void CUserControlDlg::OnLbnSelchangeRuleList()
{
	int i=m_rulelist.GetCurSel();
	if(i<0)return;
	if(m_rulelist.GetCheck(i)<1)
		m_rulelist.SetCheck(i,1);
	else
		m_rulelist.SetCheck(i,0);
}

void CUserControlDlg::OnBnClickedAddProc()
{
	CEdit*   pEdit;   
	pEdit=(CEdit*) GetDlgItem(IDC_EDIT_PROC);   
	pEdit->GetWindowText(str);
	m_rulelist.AddString(str);
}

void CUserControlDlg::OnBnClickedOk()
{
	CString str_proc,str_proclist;

	int proc_num = m_rulelist.GetCount();
	
	for (int i=0;i<proc_num;i++)
	{
		if(m_rulelist.GetCheck(i))
		{
			m_rulelist.GetText(i,str_proc);
			str_proclist = str_proclist + str_proc + _T(";");
		}
	}
	int nLen = str_proclist.GetLength();
	str_proclist = str_proclist.Left(nLen-1);
	PWCHAR InputBuffer = str_proclist.GetBuffer();
	//printf("%wZ\n",InputBuffer);
	//WCHAR pInputBuffer[1024] = str_proclist.AllocSysString();
	//WCHAR InputBuffer[1024] = _T("1234567890");

	//以下是打开Sfilter的CDO进行通信
	
	HANDLE hDevice = 
		CreateFile(_T("\\\\.\\EncryptSystem"),
		GENERIC_READ | GENERIC_WRITE,
		0,		// share mode none
		NULL,	// no security
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL );		// no template

	if (hDevice == INVALID_HANDLE_VALUE)
	{
		AfxMessageBox(_T("Open failed!"));
		//CloseHandle(hDevice);
		OnOK();
		return;
	}

	UCHAR OutputBuffer[10];
	DWORD dwOutput;
	if(! DeviceIoControl(hDevice, IOCTL_SET_PROC_RULE, InputBuffer, 1024, &OutputBuffer, 10, &dwOutput, NULL))
	{	
		
		CString errorcode;
		errorcode.Format(_T("%d"),GetLastError());
		//AfxMessageBox(_T("通信失败!"));
		AfxMessageBox(errorcode);
		CloseHandle(hDevice);
		hDevice = INVALID_HANDLE_VALUE;
		OnOK();
		return;
		
		//CloseHandle(hDevice);		

	}
	AfxMessageBox(_T("规则设置成功!"));
	CloseHandle(hDevice);
	

	OnOK();
}

void CUserControlDlg::OnBnClickedCancel()
{
	// TODO: 在此添加控件通知处理程序代码
	OnCancel();
}

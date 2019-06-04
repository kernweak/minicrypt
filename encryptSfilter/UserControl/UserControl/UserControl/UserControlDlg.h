// UserControlDlg.h : 头文件
//

#pragma once
#include "afxwin.h"


// CUserControlDlg 对话框
class CUserControlDlg : public CDialog
{
// 构造
public:
	CUserControlDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
	enum { IDD = IDD_USERCONTROL_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	CCheckListBox m_rulelist;
	afx_msg void OnLbnSelchangeRuleList();
	afx_msg void OnBnClickedAddProc();
	CString str;
	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedCancel();
};

#define IOCTL_SET_PROC_RULE CTL_CODE(\
	FILE_DEVICE_FILE_SYSTEM, \
	0x800, \
	METHOD_BUFFERED, \
	FILE_ANY_ACCESS)

#define IOCTL_SET_DIR_RULE CTL_CODE(\
	FILE_DEVICE_FILE_SYSTEM, \
	0x801, \
	METHOD_BUFFERED, \
	FILE_ANY_ACCESS)


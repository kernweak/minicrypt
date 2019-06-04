

#ifndef GetPassWordDlg_h__
#define GetPassWordDlg_h__

class CGetPassWorldDlg : public CDialogImpl<CGetPassWorldDlg>
{
public:

	enum { IDD = IDD_GETPASS };

	enum { MODE_INIT, MODE_MODIFY};

	ULONG	m_Mode;
	CString	m_passWord;
	CString m_oldPassWord;

	BEGIN_MSG_MAP(CGetPassWorldDlg)
		MESSAGE_HANDLER(WM_INITDIALOG, OnInitDialog)
		COMMAND_ID_HANDLER(IDCANCEL, OnCloseCmd)
		COMMAND_ID_HANDLER(IDOK, OnCloseCmd)
	END_MSG_MAP()

// Handler prototypes (uncomment arguments if needed):
//	LRESULT MessageHandler(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/)
//	LRESULT CommandHandler(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
//	LRESULT NotifyHandler(int /*idCtrl*/, LPNMHDR /*pnmh*/, BOOL& /*bHandled*/)

	void setMode(ULONG mode)
	{
		m_Mode = mode;
	}

	LRESULT OnInitDialog(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/)
	{
		if (MODE_INIT ==m_Mode)
		{
			::EnableWindow(GetDlgItem(IDC_CURRENT_PWD), FALSE);
			::SetFocus(GetDlgItem(IDC_NEW_PWD));
		}
		else
		{
			::SetFocus(GetDlgItem(IDC_CURRENT_PWD));
		}
		return FALSE;
	}

	LRESULT OnCloseCmd(WORD /*wNotifyCode*/, WORD wID, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
	{
		if (IDOK == wID)
		{
			TCHAR	oldPassWord[256];
			TCHAR	newPassWord[256];
			TCHAR	confirmPassWord[256];
			GetDlgItemText(IDC_CURRENT_PWD, oldPassWord, sizeof(oldPassWord));
			GetDlgItemText(IDC_NEW_PWD, newPassWord, sizeof(newPassWord));
			GetDlgItemText(IDC_CONFIRM_PWD, confirmPassWord, sizeof(confirmPassWord));
			
			if (0 != lstrcmpi(newPassWord, confirmPassWord))
			{
				MessageBox(_T("两次输入密码不一致, 请重新输入!"), _T("错误"), MB_OK | MB_ICONERROR);
				return 0;
			}

			if (0 == lstrlen(newPassWord))
			{
				return 0;
			}

			if ((MODE_MODIFY == m_Mode) && (0 == lstrlen(oldPassWord)))
			{
				return 0;
			}


			m_passWord = newPassWord;
			m_oldPassWord = oldPassWord;
		}

		EndDialog(wID);
		return 0;
	}
};

#endif // GetPassWordDlg_h__


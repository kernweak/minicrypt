#ifndef _IOCOMMON_H_
#define _IOCOMMON_H_

//maximum path length
#ifndef 	MAX_PATH
#define 	MAX_PATH					260
#endif

// max user name length
#define  MAX_USER_NAME_LENGTH			128

//password length limitation(in bytes)
#define  MAX_PASSWORD_LENGTH			20
#define  MIN_PASSWORD_LENGTH			4

//maximum key length
#define MAX_KEY_LENGTH  32

//password question length limitation(in bytes)
#define  MAX_SECRETQUESTION_LENGTH		64
#define  MAX_SECRETANSWER_LENGTH		32
#define  MAX_PASSWORDHINT_LENGTH		32

#define  HASH_SIZE  20
#define  SECTION_SIZE 512

typedef void* HANDLE ;

typedef enum {OFF, ON}STATE ;

#pragma pack(1)

typedef struct _PROCESS_INFO{
	CHAR    szProcessName[16] ;
	BOOLEAN bMonitor ;
}PROCESS_INFO,*PPROCESS_INFO; 

/**
 * password
 */
typedef struct _PASSWORD_INFO
{
	UCHAR	password[MAX_PASSWORD_LENGTH + 1];
}PASSWORD_INFO, *PPASSWORD_INFO;

/**
 * file path name info
 */
typedef struct _FILE_PATH_INFO
{
	TCHAR	FileName[MAX_PATH];
}FILE_PATH_INFO, *PFILE_PATH_INFO;

/**
 * password question
 */
typedef struct _PASSWORD_HINT_QUESTION
{
	UCHAR 	HintQuestion[MAX_SECRETQUESTION_LENGTH + 1];
}PASSWORD_HINT_QUESTION, *PPASSWORD_HINT_QUESTION;

/**
 * password answer
 */
typedef struct _PASSWORD_HINT_ANSWER
{
	UCHAR 	HintAnswer[MAX_SECRETANSWER_LENGTH + 1];
}PASSWORD_HINT_ANSWER, *PPASSWORD_HINT_ANSWER;

/**
 * password hint
 */
typedef struct _PASSWORD_HINT
{
	UCHAR 	Hint[MAX_PASSWORDHINT_LENGTH + 1];
}PASSWORD_HINT, *PPASSWORD_HINT;

/**
 * password hint info
 */
typedef struct _HINT_INFO
{
	PASSWORD_HINT_QUESTION PwdHintQue;
	PASSWORD_HINT_ANSWER   PwdHintAns;
	PASSWORD_HINT		   pwdHint;
}HINT_INFO, *PHINT_INFO;

#pragma pack()

typedef void (*GETRESULTCALLBACK)(PVOID pUserParam, TCHAR* pszProcessPathName) ;

#endif
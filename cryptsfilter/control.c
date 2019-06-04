#include "Ioctlcmd.h"

//我需要一个链表来存放所有的文件路径
typedef struct _COMPATH
{
	WCHAR	Name[MAXPATHLEN];
	struct _COMPATH *next;
} COMPATH, *PCOMPATH;


//这个暂时还没用
typedef struct _HIDEPATH
{
	WCHAR	Name[MAXPATHLEN];
	WCHAR    Hider[HIDERLEN];
	struct _HIDEPATH *next;
} HIDEPATH, *PHIDEPATH;

//一下三个结构体  源于"Ioctlcmd.h"
////禁止访问与删除的文件块
typedef struct _ALLFile{
	WCHAR   name[MAXRULES][MAXPATHLEN];		// 存放多条记录
	ULONG		num;						// 实际拥有的记录
} ALLFile, *PAllFile;

//一条 隐藏的文件 所用的数据结构
typedef struct _Hider{
	WCHAR fatherpath[MAXPATHLEN];//文件的父目录
	WCHAR  filename[HIDERLEN];//文件名
	WCHAR  hiddenallpath[MAXPATHLEN];
	ULONG flag;
}Hider ,*PHider;


//隐藏文件 数据块
typedef struct _ALLFileHide{
	Hider hider[MAXRULES];
	ULONG		num;						// 实际拥有的记录
} ALLFileHide, *PAllFileHide;

typedef struct  _Reparser
{
	LIST_ENTRY ListEntry;
	WCHAR Sourcefile[MAXPATHLEN];
	WCHAR Targetfile[MAXPATHLEN];
}Reparser ,*PReparser;

//重定向///////////////////////////////////////////////////////////////////////////////////////////////////////
static LIST_ENTRY gReparseList;
FAST_MUTEX ReparseMutex;
static ULONG ReparseNum=0;

//初始化链表语句 要在Driverentry中调用下
//InitializeListHead(&gReparseList);


//禁止访问//////////////////////////////////////////////////////////////////////////////////////////////////////

PCOMPATH  gNoAccess;
FAST_MUTEX NoAceMutex;
static ULONG NoAceNum=0;

//禁止删除/////////////////////////////////////////////////////////////////////////////////////////////////////

PCOMPATH  gNoDelete;
FAST_MUTEX NoDelMutex;
static ULONG NoDelNum=0;

//文件隐藏时用到的禁止访问/////////////////////////////////////////////////////////////////////////////////////
PCOMPATH  gHidNoAccess;
FAST_MUTEX NoHidAceMutex;
static ULONG NoHidAceNum=0;


//禁止访问的增加元素函数
VOID
SfAddComPathAce(
			 IN PWSTR Name//这个是路径名
			 )
{
	PCOMPATH temp=gNoAccess,newComPath;
	newComPath= ExAllocatePoolWithTag(PagedPool, sizeof(COMPATH), 'COMP');
	ExAcquireFastMutex( &NoAceMutex );
	if (newComPath)
	{	
	gNoAccess=newComPath;//将新的元素转化为表头
	wcscpy(gNoAccess->Name,Name);
	gNoAccess->next=temp;//原来的head放入后面
    NoAceNum++;
	}

	ExReleaseFastMutex(&NoAceMutex);
}
//禁止访问的删除元素函数
VOID
SfDeleteComPathAce(
				   IN PWSTR DelName
				   )
{
	PCOMPATH temp;
    PCOMPATH tempbefore; 
	if (!gNoAccess)
    {
		return;
    }	
	ExAcquireFastMutex( &NoAceMutex );	
	if (!wcscmp(DelName,gNoAccess->Name))
	{
        temp=gNoAccess;
		gNoAccess=gNoAccess->next;            
		ExFreePoolWithTag(temp,'COMP');	
		NoAceNum--;
	}
    else
	{
		for (temp=gNoAccess;temp!=NULL;tempbefore=temp,temp=temp->next)
		{
			if (!wcscmp(DelName,temp->Name))
			{
				tempbefore->next=temp->next;
				ExFreePoolWithTag(temp,'COMP');	
				NoAceNum--;
			}
		}
	}
    ExReleaseFastMutex(&NoAceMutex); 
}

//禁止删除增加元素函数
VOID
SfAddComPathDel(
				IN PWSTR Name//这个是路径名
				)
{
	PCOMPATH temp=gNoDelete,newComPath;
	newComPath= ExAllocatePoolWithTag(PagedPool, sizeof(COMPATH), 'COMP');
	ExAcquireFastMutex( &NoDelMutex );
	if (newComPath)
	{	
		gNoDelete=newComPath;//将新的元素转化为表头
		wcscpy(gNoDelete->Name,Name);
		gNoDelete->next=temp;//原来的head放入后面
		NoDelNum++;
//		KdPrint(("#$$$$$$$$$$$$$$$$$  %s\n",gNoDelete->Name));
	}
	
	ExReleaseFastMutex(&NoDelMutex);
}

//禁止删除删除元素函数
VOID
SfDeleteComPathDel(
				   IN PWSTR DelName
				   )
{
	PCOMPATH temp;
	PCOMPATH tempbefore; 
	if (!gNoDelete)
	{
		return;
	}	
	ExAcquireFastMutex( &NoDelMutex );	
	if (!wcscmp(DelName,gNoDelete->Name))
	{
		temp=gNoDelete;
		gNoDelete=gNoDelete->next;            
		ExFreePoolWithTag(temp,'COMP');
		NoDelNum--;
	}
	else
	{
		for (temp=gNoDelete;temp!=NULL;tempbefore=temp,temp=temp->next)
		{
			if (!wcscmp(DelName,temp->Name))
			{
				tempbefore->next=temp->next;
				ExFreePoolWithTag(temp,'COMP');	
				NoDelNum--;
			}
		}
	}
	ExReleaseFastMutex(&NoDelMutex); 
	
}

//查询匹配函数  禁止删除与禁止访问中都要调用这个
BOOLEAN
SfCompareFullPath(
				  IN PCOMPATH HeadComPath,//哪一个链表所在的头
				  IN PFAST_MUTEX  Mutex,//链表对应的锁
				  IN PWSTR  fullpath
				  )
{	
	PCOMPATH temp;
	if(!HeadComPath) 
	{
		return FALSE;
	}
	//KdPrint(("SfCompareFullPath   %s\n",HeadComPath->next));
	ExAcquireFastMutex( Mutex );
	for (temp=HeadComPath;temp!=NULL;temp=temp->next)
	{	
		if (!wcscmp(fullpath,temp->Name))
		{
			ExReleaseFastMutex(Mutex);
			return TRUE;
		}
	}
	ExReleaseFastMutex(Mutex);
	return FALSE;
}

//禁止访问的增加元素函数
VOID
SfAddComPathHidAce(
				IN PWSTR Name//这个是路径名
				)
{
	PCOMPATH temp=gHidNoAccess,newComPath;
	newComPath= ExAllocatePoolWithTag(PagedPool, sizeof(COMPATH), 'COMP');
	ExAcquireFastMutex( &NoHidAceMutex );
	if (newComPath)
	{	
		gHidNoAccess=newComPath;//将新的元素转化为表头
		wcscpy(gHidNoAccess->Name,Name);
		gHidNoAccess->next=temp;//原来的head放入后面
		NoHidAceNum++;
	}
	
	ExReleaseFastMutex(&NoHidAceMutex);
}
//禁止访问的删除元素函数
VOID
SfDeleteComPathHidAce(
				   IN PWSTR DelName
				   )
{
	PCOMPATH temp;
    PCOMPATH tempbefore; 
	if (!gHidNoAccess)
    {
		return;
    }	
	ExAcquireFastMutex( &NoHidAceMutex );	
	if (!wcscmp(DelName,gHidNoAccess->Name))
	{
        temp=gHidNoAccess;
		gHidNoAccess=gHidNoAccess->next;            
		ExFreePoolWithTag(temp,'COMP');	
		NoHidAceNum--;
	}
    else
	{
		for (temp=gHidNoAccess;temp!=NULL;tempbefore=temp,temp=temp->next)
		{
			if (!wcscmp(DelName,temp->Name))
			{
				tempbefore->next=temp->next;
				ExFreePoolWithTag(temp,'COMP');	
				NoHidAceNum--;
			}
		}
	}
    ExReleaseFastMutex(&NoHidAceMutex); 
}


VOID AddReparse(PReparser NewReparse)
{
	PReparser temp=(PReparser)ExAllocatePoolWithTag(NonPagedPool,sizeof(Reparser),'Repa');
	wcscpy(temp->Sourcefile,NewReparse->Sourcefile);
	wcscpy(temp->Targetfile,NewReparse->Targetfile);
	ExAcquireFastMutex( &ReparseMutex );	
	InsertHeadList(&gReparseList,(PLIST_ENTRY)temp);
	ReparseNum++;
	ExReleaseFastMutex(&ReparseMutex); 
}

BOOLEAN DelReparse(PWSTR FileFullPath)
{		
	PLIST_ENTRY p;
	PReparser temp;
	ExAcquireFastMutex( &ReparseMutex );	
	for(p=gReparseList.Flink;p!=&gReparseList;p=p->Flink)
	{
		temp=(PReparser)p;
		if (!wcscmp(FileFullPath,temp->Sourcefile))
		{
			RemoveEntryList((PLIST_ENTRY)temp);
			ExReleaseFastMutex(&ReparseMutex); 
			ReparseNum--;
			ExFreePool(temp);
			return TRUE;
		}
	}
    ExReleaseFastMutex(&ReparseMutex);
	return FALSE;
}

BOOLEAN FindReparsePath(IN OUT PWSTR FileFullPath)
{
	PLIST_ENTRY p;
	PReparser temp;
	ExAcquireFastMutex( &ReparseMutex );	
	for(p=gReparseList.Flink;p!=&gReparseList;p=p->Flink)
	{
		temp=(PReparser)p;
		if (!wcscmp(FileFullPath,temp->Sourcefile))
		{
		    wcscpy(FileFullPath,temp->Targetfile);    
			ExReleaseFastMutex(&ReparseMutex);
			return TRUE;
		}
	}    
	ExReleaseFastMutex(&ReparseMutex);
	return FALSE;		
}

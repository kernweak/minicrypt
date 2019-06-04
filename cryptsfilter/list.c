
//#include "sfilter.h"

/////////////////////////////////////////////////////////////////////////////
//
//                 链表 以及相关函数的实现
//
/////////////////////////////////////////////////////////////////////////////

//
//读取文件的信息并传送到应用层    为此要增加的函数以及数据结构和全局变量
//

#define LOGBUFSIZE ((ULONG)(64*0x400-(3*sizeof(ULONG)+1)))//保证小于64K


typedef struct _log 
{
	ULONG           Len;
	struct _log   * Next;
	CHAR            Data[LOGBUFSIZE];
} LOG_BUF, *PLOG_BUF;


PLOG_BUF            CurrentLog = NULL;
ULONG               NumLog = 0;
ULONG               MaxLog = (1024*1024) / LOGBUFSIZE;
FAST_MUTEX          LogMutex;

//
//当当前的缓冲区满了就进行调用   
//用于分配一个新的缓冲区 并将其放入链表的前端
// IOCTL_FILEMON_GETSTATS和driverentry
//

VOID
SfAllocateLog(
	      VOID
	      )
{
	PLOG_BUF prev = CurrentLog, newLog;
	// 若已经分配到最大了 就释放一个最早的
	if( MaxLog == NumLog ) {
		KdPrint((" ***** Dropping records *****"));
		CurrentLog->Len = 0;
		return; 
	}
	KdPrint(("SfAllocateLog: num: %d max: %d\n", NumLog, MaxLog ));
	//如果我们当前使用的输出缓冲区是空的，就去使用它 即实际不需要分配了
	if( !CurrentLog->Len ) {
		return;
	}
	//分配新的
	newLog =(PLOG_BUF) ExAllocatePool( NonPagedPool, sizeof(*CurrentLog) );
	if( newLog ) { 
		//分配成功 添加到链表头
		CurrentLog       = newLog;
		CurrentLog->Len  = 0;
		CurrentLog->Next = prev;
		NumLog++;
	} else {
		//失败就重置现在的缓冲区
		CurrentLog->Len = 0;
	}
}
VOID 
SfRecordLog(PANSI_STRING name)
{
	ULONG i=(ULONG)((name->Length)/sizeof(CHAR));
	ULONG k=(CurrentLog->Len);
	ExAcquireFastMutex( &LogMutex );
	if (k+i>=LOGBUFSIZE)
	{
		SfAllocateLog();
	}
	CurrentLog->Len=k+1;
	RtlCopyMemory(((CurrentLog->Data)+k),(name->Buffer),i);
	CurrentLog->Len=k+i+1;
	CurrentLog->Data[k+i]='\n';
	KdPrint(("the new added buffer is %s\n",CurrentLog->Data+k+1));
	//	Kdprint(("len = %d \n",(int)(CurrentLog->Len)));
	ExReleaseFastMutex( &LogMutex ); 
}
VOID 
SfFreeLog(//释放我们当前已经分配的所有的数据输出缓冲区   Unload
	  VOID 
	  )
{
	PLOG_BUF  prev;	
	ExAcquireFastMutex( &LogMutex );
	while( CurrentLog ) 
	{
		prev = CurrentLog->Next;
		ExFreePool( CurrentLog );
		CurrentLog = prev;
	}   
	ExReleaseFastMutex( &LogMutex ); 
	KdPrint(("SfFreeLog\n"));
}   
PLOG_BUF 
SfGetOldestLog(//获取最早的一个输出缓冲区 IOCTL_FILEMON_GETSTATS
	       VOID 
	       )
{
	PLOG_BUF  ptr = CurrentLog, prev = NULL;
	//遍历链表  
	while( ptr->Next ) {
		ptr = (prev = ptr)->Next;
	}
	//将该块从链表卸下
	if( prev ) {
		prev->Next = NULL;    
		NumLog--;
	}
	return ptr;
}
VOID 
SfResetLog(//对所有的缓冲区清空  在GUI退出时 IRP_MJ_CLOSE中调用
	   VOID
	   )
{
	PLOG_BUF  current, next;
	ExAcquireFastMutex( &LogMutex );
	//遍历
	current = CurrentLog->Next;
	while( current ) {
		//释放
		next = current->Next;
		ExFreePool( current );
		current = next;
	}
	NumLog = 1;
	CurrentLog->Len = 0;
	CurrentLog->Next = NULL;
	ExReleaseFastMutex( &LogMutex );    
}
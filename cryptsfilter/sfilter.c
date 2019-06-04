#include "ntifs.h"
#include "sfilter.h"
#include "Ioctlcmd.h"
#include "hash.c"
//#include "list.c"
#include "hide.c"
#include "fastio.c"
#include "crypt.c"


#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#if DBG
#pragma alloc_text(PAGE, DriverUnload)
#endif
#pragma alloc_text(PAGE, SfFsNotification)
#pragma alloc_text(PAGE, SfCreate)
#pragma alloc_text(PAGE, SfRead)
#pragma alloc_text(PAGE, SfWrite)
#pragma alloc_text(PAGE, SfClose)
#pragma alloc_text(PAGE, SfCleanup)
#pragma alloc_text(PAGE, SfDirectoryControl)
#pragma alloc_text(PAGE, SfSetInformation)
#pragma alloc_text(PAGE, SfFsControl)

#pragma alloc_text(PAGE, SfFsControlMountVolume)
#pragma alloc_text(PAGE, SfFsControlMountVolumeComplete)
#pragma alloc_text(PAGE, SfFsControlLoadFileSystem)
#pragma alloc_text(PAGE, SfFsControlLoadFileSystemComplete)

#pragma alloc_text(PAGE, SfAttachDeviceToDeviceStack)
#pragma alloc_text(PAGE, SfAttachToFileSystemDevice)
#pragma alloc_text(PAGE, SfDetachFromFileSystemDevice)
#pragma alloc_text(PAGE, SfAttachToMountedDevice)
#pragma alloc_text(PAGE, SfIsAttachedToDevice)

#pragma alloc_text(PAGE, SfIsShadowCopyVolume)
#pragma alloc_text(INIT, SfLoadDynamicFunctions)
#pragma alloc_text(INIT, SfGetCurrentVersion)
#pragma alloc_text(PAGE, SfEnumerateFileSystemVolumes)


#endif


//这是用于控制是否开启重定向的标志符  默认为不开启
BOOLEAN bRedirectFileOpen=TRUE;


NTSTATUS
DriverEntry (
	     IN PDRIVER_OBJECT DriverObject,
	     IN PUNICODE_STRING RegistryPath
	     )
{
    PFAST_IO_DISPATCH fastIoDispatch;
	UNICODE_STRING nameString;
	NTSTATUS status;
	ULONG i;
	UNICODE_STRING LinkName;	

	//清除编译器的警告   暂时用不上注册路径
	UNREFERENCED_PARAMETER(RegistryPath);
	
	//
	//动态加载
	//
	SfLoadDynamicFunctions();

	//
	//获得当前操作系统版本
	//
	SfGetCurrentVersion();

	//
	//保存设备对象
	//
	gSFilterDriverObject = DriverObject;

	//
	//在调试模式下 设置卸载例程
	//
	#if DBG 
	if (NULL != gSfDynamicFunctions.EnumerateDeviceObjectList) 
	{        
		gSFilterDriverObject->DriverUnload = DriverUnload;
	}
	#endif

	//
	//初始化Mutex
	//
	
	ExInitializeFastMutex( &ReparseMutex );
	ExInitializeFastMutex( &NoDelMutex );	
	ExInitializeFastMutex( &NoAceMutex );
	ExInitializeFastMutex( &NoHidAceMutex );
	
	//初始化文件访问控制的全局数据块
	gNoDelete=NULL;
	gNoAccess=NULL;
	gHidNoAccess=NULL;
	InitializeListHead(&gReparseList);

	NoAceNum = 0;
	NoDelNum = 0;
	NoHidAceNum=0;
	ReparseNum=0;
	/////////////////////////////////////透明加密中的初始化////////////////////////////
    
	cfCurProcNameInit();               //找出进程名的偏移
	cfListInit();                      //初始化文件加密链表
	
	///////////////////////////////////////////////////////////////////////////////////
	//
	//hash初始化一个资源变量
	//
	ExInitializeResourceLite( &HashResource );
	
	//
	//初始化用于文件隐藏的LIST_ENTRY
	//
	
	InitializeListHead(&g_HideObjHead);
	//
	//初始化绑定卷要用的快速互斥体
	//

	ExInitializeFastMutex( &gSfilterAttachLock );



	RtlInitUnicodeString( &nameString, L"\\FileSystem\\Filters\\SFilter" );//初始化UNICODE字符串
	
	status = IoCreateDevice( DriverObject,	//创建设备对象
			0,                      //无设备扩展
			&nameString,		//输入设备对象的名字
			FILE_DEVICE_DISK_FILE_SYSTEM,//磁盘文件系统设备对象
			FILE_DEVICE_SECURE_OPEN,//设置FILE_DEVICE_SECURE_OPEN 可以防止潜在的安全漏洞
			FALSE,			//该对象不可在内核模式下使用
			&gSFilterControlDeviceObject //函数返回的对象地址存入此变量中
			);

	if (!NT_SUCCESS( status ))	//CDO失败
	{
		KdPrint(( "SFilter!DriverEntry: Error creating control device object \"%wZ\", status=%08x\n", &nameString, status ));
		return status;
	}

	
	//
	//创建符号连接
	//

	RtlInitUnicodeString( &LinkName, DOS_DEVICE_NAME);

	status = IoCreateSymbolicLink( &LinkName, &nameString );
	if (!NT_SUCCESS( status ))
	{//创建符号链接 失败！
		KdPrint(( "SFilter!DriverEntry: IoCreateSymbolicLink failed\n"));		
		IoDeleteDevice(gSFilterControlDeviceObject);
		return status;	
	}


	//
	//默认IRP开始分发
	//

	for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		DriverObject->MajorFunction[i] = SfPassThrough;
	}

	DriverObject->MajorFunction[IRP_MJ_CREATE] = 
	DriverObject->MajorFunction[IRP_MJ_CREATE_NAMED_PIPE] = 
	DriverObject->MajorFunction[IRP_MJ_CREATE_MAILSLOT] = SfCreate;
	DriverObject->MajorFunction[IRP_MJ_FILE_SYSTEM_CONTROL] = SfFsControl;
	DriverObject->MajorFunction[IRP_MJ_CLEANUP] = SfCleanup;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = SfClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]=SfDeviceIOControl;
	DriverObject->MajorFunction[IRP_MJ_DIRECTORY_CONTROL] = SfDirectoryControl;//设置这个IRP来对文件隐藏
	DriverObject->MajorFunction[IRP_MJ_SET_INFORMATION] = SfSetInformation;
	DriverObject->MajorFunction[IRP_MJ_READ] = SfRead;
	DriverObject->MajorFunction[IRP_MJ_WRITE] = SfWrite;
	DriverObject->MajorFunction[IRP_MJ_QUERY_INFORMATION] = SfQueryInformation;


	fastIoDispatch = ExAllocatePoolWithTag( NonPagedPool, sizeof( FAST_IO_DISPATCH ), SFLT_POOL_TAG );
	
	//
	//申请内存是否成功
	//
	if (!fastIoDispatch) 
	{
		
		IoDeleteDevice( gSFilterControlDeviceObject );
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	
	RtlZeroMemory( fastIoDispatch, sizeof( FAST_IO_DISPATCH ) );//内存清零
	fastIoDispatch->SizeOfFastIoDispatch = sizeof( FAST_IO_DISPATCH );
	fastIoDispatch->FastIoCheckIfPossible = SfFastIoCheckIfPossible;
	fastIoDispatch->FastIoRead = SfFastIoRead;
	fastIoDispatch->FastIoWrite = SfFastIoWrite;
	fastIoDispatch->FastIoQueryBasicInfo = SfFastIoQueryBasicInfo;
	fastIoDispatch->FastIoQueryStandardInfo = SfFastIoQueryStandardInfo;
	fastIoDispatch->FastIoLock = SfFastIoLock;
	fastIoDispatch->FastIoUnlockSingle = SfFastIoUnlockSingle;
	fastIoDispatch->FastIoUnlockAll = SfFastIoUnlockAll;
	fastIoDispatch->FastIoUnlockAllByKey = SfFastIoUnlockAllByKey;
	fastIoDispatch->FastIoDeviceControl = SfFastIoDeviceControl;
	fastIoDispatch->FastIoDetachDevice = SfFastIoDetachDevice;
	fastIoDispatch->FastIoQueryNetworkOpenInfo = SfFastIoQueryNetworkOpenInfo;
	fastIoDispatch->MdlRead = SfFastIoMdlRead;
	fastIoDispatch->MdlReadComplete = SfFastIoMdlReadComplete;
	fastIoDispatch->PrepareMdlWrite = SfFastIoPrepareMdlWrite;
	fastIoDispatch->MdlWriteComplete = SfFastIoMdlWriteComplete;
	fastIoDispatch->FastIoReadCompressed = SfFastIoReadCompressed;
	fastIoDispatch->FastIoWriteCompressed = SfFastIoWriteCompressed;
	fastIoDispatch->MdlReadCompleteCompressed = SfFastIoMdlReadCompleteCompressed;
	fastIoDispatch->MdlWriteCompleteCompressed = SfFastIoMdlWriteCompleteCompressed;
	fastIoDispatch->FastIoQueryOpen = SfFastIoQueryOpen;
	
	DriverObject->FastIoDispatch = fastIoDispatch;
	{
		FS_FILTER_CALLBACKS fsFilterCallbacks;//这个结构体WDK里有说明
		if (NULL != gSfDynamicFunctions.RegisterFileSystemFilterCallbacks) {
			//这里只是简单给出一个用一个函数处理所有例程的例子
			fsFilterCallbacks.SizeOfFsFilterCallbacks = sizeof( FS_FILTER_CALLBACKS );
			fsFilterCallbacks.PreAcquireForSectionSynchronization = SfPreFsFilterPassThrough;
			fsFilterCallbacks.PostAcquireForSectionSynchronization = SfPostFsFilterPassThrough;
			fsFilterCallbacks.PreReleaseForSectionSynchronization = SfPreFsFilterPassThrough;
			fsFilterCallbacks.PostReleaseForSectionSynchronization = SfPostFsFilterPassThrough;
			fsFilterCallbacks.PreAcquireForCcFlush = SfPreFsFilterPassThrough;
			fsFilterCallbacks.PostAcquireForCcFlush = SfPostFsFilterPassThrough;
			fsFilterCallbacks.PreReleaseForCcFlush = SfPreFsFilterPassThrough;
			fsFilterCallbacks.PostReleaseForCcFlush = SfPostFsFilterPassThrough;
			fsFilterCallbacks.PreAcquireForModifiedPageWriter = SfPreFsFilterPassThrough;
			fsFilterCallbacks.PostAcquireForModifiedPageWriter = SfPostFsFilterPassThrough;
			fsFilterCallbacks.PreReleaseForModifiedPageWriter = SfPreFsFilterPassThrough;
			fsFilterCallbacks.PostReleaseForModifiedPageWriter = SfPostFsFilterPassThrough;
			status = (gSfDynamicFunctions.RegisterFileSystemFilterCallbacks)( DriverObject, //_SF_DYNAMIC_FUNCTION_POINTERS结构体的第一个函数的使用
				&fsFilterCallbacks );//通知回调函数被调用
		
			//
			//若失败就释放内存并删除符号链接
			//
			if (!NT_SUCCESS( status )) 
			{ 
				               
				DriverObject->FastIoDispatch = NULL;
				ExFreePool( fastIoDispatch );
				IoDeleteDevice( gSFilterControlDeviceObject );
				return status;
			}
		}
	}


	//
	//注册回调函数
	//
	status = IoRegisterFsRegistrationChange( DriverObject, SfFsNotification );
	
	if (!NT_SUCCESS( status )) 
	{
		KdPrint(( "SFilter!DriverEntry: Error registering FS change notification, status=%08x\n", status ));
		DriverObject->FastIoDispatch = NULL;
		ExFreePool( fastIoDispatch );
		IoDeleteDevice( gSFilterControlDeviceObject );
		return status;
	}


	//
	//创建完毕
	//清除DO_DEVICE_INITIALIZING标记：
	//

	ClearFlag( gSFilterControlDeviceObject->Flags, DO_DEVICE_INITIALIZING );
	
	return STATUS_SUCCESS;
}//driverentry结束


//卸载函数
#if DBG
VOID
DriverUnload (   
	      IN PDRIVER_OBJECT DriverObject
	      )
{
	//
	//与设备扩展有关的一个结构体  
	//

	PSFILTER_DEVICE_EXTENSION devExt;

	PFAST_IO_DISPATCH fastIoDispatch;

	NTSTATUS status;
	ULONG numDevices;//设备的数量
	ULONG i;
	LARGE_INTEGER interval;//64位的联合体
	UNICODE_STRING LinkName;

	#define DEVOBJ_LIST_SIZE 64
	PDEVICE_OBJECT devList[DEVOBJ_LIST_SIZE];

	//*****************************************************************************
	PLIST_ENTRY pdLink = NULL;
	PHIDE_FILE  pHideObj = NULL;
	PHIDE_DIRECTOR pHideDir = NULL;
	PLIST_ENTRY pdLinkDir = NULL;
	PLIST_ENTRY HeadList;
	//******************************************************************************

	//
	//删除符号链接
	//
	RtlInitUnicodeString( &LinkName, DOS_DEVICE_NAME);	
	IoDeleteSymbolicLink(&LinkName );
	
	//////////////////////////////////////////////////////////////////////////////////////////
	ASSERT(DriverObject == gSFilterDriverObject);

	//
	//不用再获得任何的文件系统的消息了  
	//解除回调函数
	//

	IoUnregisterFsRegistrationChange( DriverObject, SfFsNotification );

	//
	//死循环 直到numDevices <= 0时跳出
	//该循环将获得所有该驱动设备对象
	//
	for (;;) 
	{
		ASSERT( NULL != gSfDynamicFunctions.EnumerateDeviceObjectList );
		status = (gSfDynamicFunctions.EnumerateDeviceObjectList)(
                        DriverObject,
                        devList,
                        sizeof(devList),
                        &numDevices);

		if (numDevices <= 0) 
		{
			break;
		}
		numDevices = min( numDevices, DEVOBJ_LIST_SIZE );

		//
		//首先遍历列表并解绑每个设备
		//CDO没有设备扩展不用绑定任何东西到上面 所以不用绑定它
		//

		for (i=0; i < numDevices; i++) 
		{
			devExt = devList[i]->DeviceExtension;
			if (NULL != devExt) 
			{
				IoDetachDevice( devExt->AttachedToDeviceObject );
			}
		}

		//
		//等待5秒
		//让当前IRP完成
		//
		
		interval.QuadPart = (5 * DELAY_ONE_SECOND);      
		
		KeDelayExecutionThread( KernelMode, FALSE, &interval );
		
		//
		//回到设备链  删除设备对象
		//

		for (i=0; i < numDevices; i++) 
		{
			//
			//设备扩展为空的就是我们的CDO
			//

			if (NULL != devList[i]->DeviceExtension) 
			{
				
				SfCleanupMountedDevice( devList[i] );
			}
			else
			{
				ASSERT(devList[i] == gSFilterControlDeviceObject);
				gSFilterControlDeviceObject = NULL;
			}
			
			//
			//删除设备
			//
			IoDeleteDevice( devList[i] );

			//
			//减少计数（IoEnumerateDeviceObjectList会增加计数）
			//

			ObDereferenceObject( devList[i] );
		}
	}//死循环结束

	//
	//释放fastio表  内存释放
	//

	fastIoDispatch = DriverObject->FastIoDispatch;
	DriverObject->FastIoDispatch = NULL;
	
	//
	//释放hashtable
	//
	SfHashCleanup();

	/////////////////////////////////////////
	//
	//释放隐藏文件链表
	//////////////////////////////这是我修改的卸载函数///////////
	while(!IsListEmpty(&g_HideObjHead))
	{
		pdLinkDir = RemoveHeadList(&g_HideObjHead);
		pHideDir = CONTAINING_RECORD(pdLinkDir, HIDE_DIRECTOR, linkfield);
		HeadList = &(pHideDir->link);
		while (!IsListEmpty(HeadList))
		{
			pdLink = RemoveHeadList(HeadList);
			pHideObj = CONTAINING_RECORD(pdLink, HIDE_FILE, linkfield);
			ExFreePool(pHideObj);
		}
		ExFreePool(pHideDir);
	}	
	///////////////////////////////////////////////////////////////////////////////////

	
	
}//DriverUnload结束


#endif//#if DBG



//
//此函数可以尝试加载不同版本的OS的函数指针
//
VOID
SfLoadDynamicFunctions (
			)
{
	UNICODE_STRING functionName;
	
	RtlZeroMemory( &gSfDynamicFunctions, sizeof( gSfDynamicFunctions ) );
	RtlInitUnicodeString( &functionName, L"FsRtlRegisterFileSystemFilterCallbacks" );
	gSfDynamicFunctions.RegisterFileSystemFilterCallbacks = MmGetSystemRoutineAddress( &functionName );
	RtlInitUnicodeString( &functionName, L"IoAttachDeviceToDeviceStackSafe" );
	gSfDynamicFunctions.AttachDeviceToDeviceStackSafe = MmGetSystemRoutineAddress( &functionName );
	RtlInitUnicodeString( &functionName, L"IoEnumerateDeviceObjectList" );
	gSfDynamicFunctions.EnumerateDeviceObjectList = MmGetSystemRoutineAddress( &functionName );
	RtlInitUnicodeString( &functionName, L"IoGetLowerDeviceObject" );
	gSfDynamicFunctions.GetLowerDeviceObject = MmGetSystemRoutineAddress( &functionName );
	RtlInitUnicodeString( &functionName, L"IoGetDeviceAttachmentBaseRef" );
	gSfDynamicFunctions.GetDeviceAttachmentBaseRef = MmGetSystemRoutineAddress( &functionName );
	RtlInitUnicodeString( &functionName, L"IoGetDiskDeviceObject" );
	gSfDynamicFunctions.GetDiskDeviceObject = MmGetSystemRoutineAddress( &functionName );
	RtlInitUnicodeString( &functionName, L"IoGetAttachedDeviceReference" );
	gSfDynamicFunctions.GetAttachedDeviceReference = MmGetSystemRoutineAddress( &functionName );
	RtlInitUnicodeString( &functionName, L"RtlGetVersion" );
	gSfDynamicFunctions.GetVersion = MmGetSystemRoutineAddress( &functionName ); 
	
}

//
//获得OS版本
//
VOID
SfGetCurrentVersion (  
		     )
{
	
	if (NULL != gSfDynamicFunctions.GetVersion) 
	{
		//直接assert好了
		RTL_OSVERSIONINFOW versionInfo;
		NTSTATUS status;
		versionInfo.dwOSVersionInfoSize = sizeof( RTL_OSVERSIONINFOW );
		status = (gSfDynamicFunctions.GetVersion)( &versionInfo );
		ASSERT( NT_SUCCESS( status ) );
		gSfOsMajorVersion = versionInfo.dwMajorVersion;
		gSfOsMinorVersion = versionInfo.dwMinorVersion;        
	} 
	else 
	{
		PsGetVersion( &gSfOsMajorVersion,
			&gSfOsMinorVersion,
			NULL,
			NULL );
	}
	
}


//
//回调例程,当文件系统被激活或者撤销时调用  
//在该例程中,完成对文件系统控制设备对象的绑定.
//

// 这个例程创建一个设备对象将它附加到指定的文件系统控制设备对象
// 的对象栈上,这就允许这个设备对象过滤所有发送给文件系统的请求.
// 这样,我们就能获得一个挂载卷的请求,就可以附加到这个新的卷设备对象
// 的设备对象栈上
// DeviceObject: 指向被激活或者撤销的文件系统的控制设备对象
// FsActive: 激活或者撤销标
//
VOID
SfFsNotification (
		  IN PDEVICE_OBJECT DeviceObject,
		  IN BOOLEAN FsActive
		  )
		 
{
	UNICODE_STRING name;	//文件控制对象的设备名
	WCHAR nameBuffer[MAX_DEVNAME_LENGTH];
	PAGED_CODE();
	
	//
	//内存清空
	//

	RtlInitEmptyUnicodeString( &name, nameBuffer, sizeof(nameBuffer) );
	
	SfGetObjectName( DeviceObject, &name );
	

	//
	//控制 绑定或者解绑（从所给的文件系统中）
	//

	if (FsActive) 
	{
		
		SfAttachToFileSystemDevice( DeviceObject, &name );
	} 
	else 
	{		
		
		SfDetachFromFileSystemDevice( DeviceObject );
	}
	
}

///////////////////////////////////////////////////////////////////////////
/////Write  加密处理
///////////////////////////////////////////////////////////////////////////
NTSTATUS
SfWrite(
		IN PDEVICE_OBJECT DeviceObject,
		IN PIRP Irp
		)
{
	PIO_STACK_LOCATION currentIrpStack;
	PFILE_OBJECT FileObject;
	NTSTATUS status;
	KEVENT waitEvent;
	PVOID context;                   //写操作是保存上下文指针，这是用来传递参数的
	
	
	BOOLEAN proc_sec = cfIsCurProcSec();    //判断当前是否是加密进程
    BOOLEAN crypting;
	
	ASSERT(!IS_MY_CONTROL_DEVICE_OBJECT( DeviceObject ));
    ASSERT(IS_MY_DEVICE_OBJECT( DeviceObject ));
	
	//获得当前IRP栈  
    currentIrpStack = IoGetCurrentIrpStackLocation(Irp);
	FileObject = currentIrpStack->FileObject;
	
	/////////////////////////////////////////透明加密///////////////////////
	// 是否是一个已经被加密进程打开的文件
	
	if(!cfListInited())
	{
		IoSkipCurrentIrpStackLocation(Irp);
		return IoCallDriver( ((PSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->AttachedToDeviceObject, Irp );
	}
	
    cfListLock();
    crypting = cfIsFileCrypting(currentIrpStack->FileObject);
    cfListUnlock();
	
	if (proc_sec&&crypting&&(Irp->Flags & (IRP_PAGING_IO|IRP_SYNCHRONOUS_PAGING_IO|IRP_NOCACHE)))
	{
		if (cfIrpWritePre(Irp,currentIrpStack,&context))
		{
			PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
			//等待事件用于等待处理结束
			KeInitializeEvent( &waitEvent, NotificationEvent, FALSE );
			//拷贝当前I/O堆栈到下一个堆栈并设置我们的完成例程
			IoCopyCurrentIrpStackLocationToNext( Irp );
			IoSetCompletionRoutine(
				Irp,
				SfWriteCompletion,//完成例程
				&waitEvent,
				TRUE,
				TRUE,
				TRUE );
			//调用栈中的下一个驱动
			status = IoCallDriver( ((PSFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject, Irp );
			//等待内核事件
			if (STATUS_PENDING == status) {
				NTSTATUS localStatus = KeWaitForSingleObject(	&waitEvent, 
					Executive,//等待的原因
					KernelMode,//必须是这个参数
					FALSE,
					NULL//无限的等下去
					);
				ASSERT(STATUS_SUCCESS == localStatus);
			}
			//验证IoCompleteRequest被调用了
			ASSERT(KeReadStateEvent(&waitEvent) ||!NT_SUCCESS(Irp->IoStatus.Status));		
			///////////////////////////////////////	
			//加密处理
			
			ASSERT(crypting);
			
            cfIrpWritePost(Irp,irpSp,context);
			
			//////////////////////////////////////////////////////////////////////////
			status = Irp->IoStatus.Status;
			IoCompleteRequest( Irp, IO_NO_INCREMENT );
            return status;
		} 
		else
		{
			status = Irp->IoStatus.Status;
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return status;
		}
		
	}
	
	IoSkipCurrentIrpStackLocation( Irp );
    return IoCallDriver( ((PSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->AttachedToDeviceObject, Irp );
}

NTSTATUS
SfWriteCompletion (
					IN PDEVICE_OBJECT DeviceObject,
					IN PIRP Irp,
					IN PVOID Context
					)
					//完成例程 若不可以调试 那么这个的功能就是打印成功被文件系统打开的文件的文件名
{
    PKEVENT event = Context;
    UNREFERENCED_PARAMETER( DeviceObject );
    UNREFERENCED_PARAMETER( Irp );
    ASSERT(IS_MY_DEVICE_OBJECT( DeviceObject ));
    KeSetEvent(event, IO_NO_INCREMENT, FALSE);//设置等待事件
    return STATUS_MORE_PROCESSING_REQUIRED;//返回需要进一步处理
}

///////////////////////////////////////////////////////////////////////////
/////Read  解密处理
//////////////////////////////////////////////////////////////////////////
NTSTATUS
SfRead(
	   IN PDEVICE_OBJECT DeviceObject,
	   IN PIRP Irp
	   )
{
	PIO_STACK_LOCATION currentIrpStack;
	PFILE_OBJECT FileObject;
	NTSTATUS status;
	KEVENT waitEvent; 
	//好像没有必要，暂时先不加
	//BOOLEAN proc_sec = cfIsCurProcSec();    //判断当前是否是加密进程
    BOOLEAN crypting;
	
	ASSERT(!IS_MY_CONTROL_DEVICE_OBJECT( DeviceObject ));
    ASSERT(IS_MY_DEVICE_OBJECT( DeviceObject ));
	
	//获得当前IRP栈  
    currentIrpStack = IoGetCurrentIrpStackLocation(Irp);
	FileObject = currentIrpStack->FileObject;
    
    /////////////////////////////////////透明加密////////////////////////////////
	//应该保证被读的对象是加密进程且是加密文件才这样读，其他的下发
	
	if(!cfListInited())
	{
		IoSkipCurrentIrpStackLocation(Irp);
		return IoCallDriver( ((PSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->AttachedToDeviceObject, Irp );
	}
	
	// 是否是一个已经被加密进程打开的文件
    cfListLock();
    crypting = cfIsFileCrypting(currentIrpStack->FileObject);
    cfListUnlock();
	
	if(crypting&&(Irp->Flags & (IRP_PAGING_IO|IRP_SYNCHRONOUS_PAGING_IO|IRP_NOCACHE)))
	{
		PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
		//确定他们符合要求后，先做写操作预处理
		cfIrpReadPre(Irp,currentIrpStack);
		
        //下面就是设置完成事件等待，写操作的最后处理
		//等待事件用于等待处理结束
		KeInitializeEvent( &waitEvent, NotificationEvent, FALSE );
		//拷贝当前I/O堆栈到下一个堆栈并设置我们的完成例程
		IoCopyCurrentIrpStackLocationToNext( Irp );
		IoSetCompletionRoutine(
			Irp,
			SfReadCompletion,//完成例程
			&waitEvent,
			TRUE,
			TRUE,
			TRUE );
		//调用栈中的下一个驱动
		status = IoCallDriver( ((PSFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject, Irp );
		//等待内核事件
		if (STATUS_PENDING == status) {
			NTSTATUS localStatus = KeWaitForSingleObject(	&waitEvent, 
				Executive,//等待的原因
				KernelMode,//必须是这个参数
				FALSE,
				NULL//无限的等下去
				);
			ASSERT(STATUS_SUCCESS == localStatus);
		}
		//验证IoCompleteRequest被调用了
		ASSERT(KeReadStateEvent(&waitEvent) ||!NT_SUCCESS(Irp->IoStatus.Status));		
		//////////////////////////////////////////////////////////////////////////
		//解密处理
		ASSERT(crypting);
		
        cfIrpReadPost(Irp,irpSp);
		
		//////////////////////////////////////////////////////////////////////////
		status = Irp->IoStatus.Status;
		IoCompleteRequest( Irp, IO_NO_INCREMENT );
		return status;
	}
	
    IoSkipCurrentIrpStackLocation( Irp );
    return IoCallDriver( ((PSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->AttachedToDeviceObject, Irp );
}
NTSTATUS
SfReadCompletion (
				   IN PDEVICE_OBJECT DeviceObject,
				   IN PIRP Irp,
				   IN PVOID Context
				   )
				   //完成例程 若不可以调试 那么这个的功能就是打印成功被文件系统打开的文件的文件名
{
    PKEVENT event = Context;
    UNREFERENCED_PARAMETER( DeviceObject );
    UNREFERENCED_PARAMETER( Irp );
    ASSERT(IS_MY_DEVICE_OBJECT( DeviceObject ));
    KeSetEvent(event, IO_NO_INCREMENT, FALSE);//设置等待事件
    return STATUS_MORE_PROCESSING_REQUIRED;//返回需要进一步处理
}

NTSTATUS
SfQueryInformation(
				   IN PDEVICE_OBJECT DeviceObject,
				   IN PIRP Irp
				   )
{
	NTSTATUS status;
	PIO_STACK_LOCATION  irpSp= IoGetCurrentIrpStackLocation(Irp);	//当前Irp(IO_STACK_LOCATION)的参数
	PSFILTER_DEVICE_EXTENSION devExt = DeviceObject->DeviceExtension;
	PFILE_BOTH_DIR_INFORMATION dirInfo = NULL;
	KEVENT waitEvent;
	BOOLEAN crypting;           //判断这个文件是否在加密表中
	
	
	ASSERT(gSFilterControlDeviceObject != DeviceObject);
	ASSERT(IS_MY_DEVICE_OBJECT(DeviceObject));
	
	//既然下面要用到这个表，那如果这还没初始化好，则直接下发
	if(!cfListInited())
	{
		IoSkipCurrentIrpStackLocation(Irp);
		return IoCallDriver(devExt->AttachedToDeviceObject, Irp);
	}
	////////////////////////////////////////////////////////////////////
	// 是否是一个已经被加密进程打开的文件
    cfListLock();
    // 如果是create,不需要恢复文件长度。如果是其他请求，在pre的
    // 时候就应该已经恢复了。
    crypting = cfIsFileCrypting(irpSp->FileObject);
    cfListUnlock();
	
	if (crypting && (irpSp->Parameters.QueryFile.FileInformationClass == FileAllInformation ||
		irpSp->Parameters.QueryFile.FileInformationClass == FileAllocationInformation ||
		irpSp->Parameters.QueryFile.FileInformationClass == FileEndOfFileInformation ||
		irpSp->Parameters.QueryFile.FileInformationClass == FileStandardInformation ||
		irpSp->Parameters.QueryFile.FileInformationClass == FilePositionInformation ||
        irpSp->Parameters.QueryFile.FileInformationClass == FileValidDataLengthInformation))
	{
		//设置完成回调函数  这个不知道以后会不会使用到   所以先留着
		KeInitializeEvent(&waitEvent, NotificationEvent, FALSE);
		IoCopyCurrentIrpStackLocationToNext(Irp);
		
		IoSetCompletionRoutine(	
			Irp,
			SfQueryInformationCompletion,		//CompletionRoutine
			&waitEvent,					//context parameter
			TRUE,
			TRUE,
			TRUE
			);	
		status = IoCallDriver(devExt->AttachedToDeviceObject, Irp);
		
		if (STATUS_PENDING == status)
		{
			//等待完成
			status = KeWaitForSingleObject(&waitEvent,
				Executive,
				KernelMode,
				FALSE,
				NULL
				);
			ASSERT(STATUS_SUCCESS == status);
		}
		ASSERT(KeReadStateEvent(&waitEvent) ||
			!NT_SUCCESS(Irp->IoStatus.Status));
		
		ASSERT(crypting);
        cfIrpQueryInforPost(Irp,irpSp);
		
		status = Irp->IoStatus.Status;
        IoCompleteRequest( Irp, IO_NO_INCREMENT );
		
		return status;
	}else{
		//其它情况直接下发
		IoSkipCurrentIrpStackLocation(Irp);
		return IoCallDriver(devExt->AttachedToDeviceObject, Irp);
	}
}

NTSTATUS
SfQueryInformationCompletion(
							 IN PDEVICE_OBJECT DeviceObject,
							 IN PIRP Irp,
							 IN PVOID Context
							 )
{
	PKEVENT event = Context;
	UNREFERENCED_PARAMETER( Irp );
	UNREFERENCED_PARAMETER( DeviceObject );
	KeSetEvent(event, IO_NO_INCREMENT, FALSE);
	return STATUS_MORE_PROCESSING_REQUIRED;	//注：必须返回这个值
}

///////////////////////////////////////////////////////////////////////////
/////文件隐藏             IRP控制例程//////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
NTSTATUS
SfDirectoryControl(
		   IN PDEVICE_OBJECT DeviceObject,
		   IN PIRP Irp
		   )
{
	NTSTATUS status;

	PLIST_ENTRY headListEntry = &g_HideObjHead;
	PLIST_ENTRY tmpListEntry = headListEntry;
	PHIDE_DIRECTOR temHideDir = NULL;

	PIO_STACK_LOCATION  irpSp= IoGetCurrentIrpStackLocation(Irp);	
	PSFILTER_DEVICE_EXTENSION devExt = DeviceObject->DeviceExtension;
	PFILE_BOTH_DIR_INFORMATION dirInfo = NULL;
	KEVENT waitEvent;

	ASSERT(gSFilterControlDeviceObject != DeviceObject);

	ASSERT(IS_MY_DEVICE_OBJECT(DeviceObject));

	//
	//判断IRP主版本号 是否为 IRP_MN_QUERY_DIRECTORY
	//
	if (IRP_MN_QUERY_DIRECTORY != irpSp->MinorFunction)
	{
		goto SkipHandle;
	}
	//
	//IRP 标头的 RequestorMode 值来确定 I/O 请求来自
	//内核模式还是用户模式调用
	//
	if (Irp->RequestorMode == KernelMode)
	{
		goto SkipHandle;
	}
	//
	//FileInformationClass 是否为 FileBothDirectoryInformation
	//FileBothDirectoryInformation 即隐藏
	//FileDispositionInformation   是删除
	//
	if (FileBothDirectoryInformation != ((PQUERY_DIRECTORY)&irpSp->Parameters)->FileInformationClass) 
	{	
		goto SkipHandle;
	}

	//
	//设置完成回调函数,初始化一个事件
	//

	KeInitializeEvent(&waitEvent, NotificationEvent, FALSE);

	//
	//传递IRP堆栈
	//

	IoCopyCurrentIrpStackLocationToNext(Irp);

	//
	//IoCompleteRequest函数会 倒序 依次调用上层的所有完成例程
	//除非其中某个IoCompletion例程返回了STATUS_MORE_PROCESSING_REQUIRED
	//

	IoSetCompletionRoutine(	
		Irp,
		SfDirectoryControlCompletion,		//CompletionRoutine
		&waitEvent,				//context parameter
		TRUE,
		TRUE,
		TRUE
		);
	
	status = IoCallDriver(devExt->AttachedToDeviceObject, Irp);

	if (STATUS_PENDING == status)
	{
		//
		//等待完成
		//

		status = KeWaitForSingleObject(&waitEvent,
			Executive,
			KernelMode,
			FALSE,
			NULL
			);
		ASSERT(STATUS_SUCCESS == status);
	}

	//
	//两种情况IRP返回  IoCallDriver失败或是userbuffer中没有信息
	//

	if (!NT_SUCCESS(status) ||(0 == irpSp->Parameters.QueryFile.Length)) 
	{	
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return status;
	}
	
//这边是隐藏的主要操作 需要重写   重点研究下Irp->UserBuffer中的内容
 	{
		WCHAR  fullpath[1024];
		if(SfGetFullPath(irpSp->FileObject, fullpath))
		{	
		    while (tmpListEntry->Flink != headListEntry)//遍历整个父目录列表
			{
				//遍历父列表，取出他们所有的值
				tmpListEntry = tmpListEntry->Flink;
				temHideDir = (PHIDE_DIRECTOR)CONTAINING_RECORD(tmpListEntry, HIDE_DIRECTOR, linkfield);
				//tmpHideFile = (PHIDE_FILE)CONTAINING_RECORD((temHideDir->link.Flink), HIDE_FILE, linkfield);
				
				if (!wcscmp(temHideDir->fatherPath,fullpath))
				{
					HandleDirectory(Irp->UserBuffer,  &((PQUERY_DIRECTORY)&irpSp->Parameters)->Length,temHideDir);
					break;
				}
			}
		}
		
 	}

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
	
SkipHandle:
	IoSkipCurrentIrpStackLocation(Irp);
	return IoCallDriver(devExt->AttachedToDeviceObject, Irp);

}



NTSTATUS
SfDirectoryControlCompletion(
			     IN PDEVICE_OBJECT DeviceObject,
			     IN PIRP Irp,
			     IN PVOID Context
			     )
{
	UNREFERENCED_PARAMETER( Irp );
	UNREFERENCED_PARAMETER( DeviceObject );



	KeSetEvent((PKEVENT)Context, IO_NO_INCREMENT, FALSE);
	return STATUS_MORE_PROCESSING_REQUIRED;	//注：必须返回这个值
}


///////////////////////////////////////////////////////////////////////////
/////禁止删除             IRP控制例程//////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
NTSTATUS
SfSetInformation(
				 IN PDEVICE_OBJECT DeviceObject,
				 IN PIRP Irp
				 )
{
//	NTSTATUS status;
	PIO_STACK_LOCATION  irpSp= IoGetCurrentIrpStackLocation(Irp);	//当前Irp(IO_STACK_LOCATION)的参数
	PSFILTER_DEVICE_EXTENSION devExt = DeviceObject->DeviceExtension;
	PFILE_BOTH_DIR_INFORMATION dirInfo = NULL;
//	KEVENT waitEvent;
	BOOLEAN file_sec;
	WCHAR fullpath[1024];

	ASSERT(gSFilterControlDeviceObject != DeviceObject);
	ASSERT(IS_MY_DEVICE_OBJECT(DeviceObject));

	if(!cfListInited())
	{
		IoSkipCurrentIrpStackLocation(Irp);
		return IoCallDriver(devExt->AttachedToDeviceObject, Irp);
	}

	cfListLock();
    file_sec = cfIsFileCrypting(irpSp->FileObject);
    cfListUnlock();


	//设置完成回调函数  这个不知道以后会不会使用到   所以先留着
//    KeInitializeEvent(&waitEvent, NotificationEvent, FALSE);
//     IoCopyCurrentIrpStackLocationToNext(Irp);
//     IoSetCompletionRoutine(	
// 		Irp,
// 		SfSetInformationCompletion,		//CompletionRoutine
// 		&waitEvent,					//context parameter
// 		TRUE,
// 		TRUE,
// 		TRUE
// 		);	
// 	status = IoCallDriver(devExt->AttachedToDeviceObject, Irp);
// 	if (STATUS_PENDING == status)
// 	{
// 		//等待完成
//         status = KeWaitForSingleObject(&waitEvent,
// 			Executive,
// 			KernelMode,
// 			FALSE,
// 			NULL
// 			);
//         ASSERT(STATUS_SUCCESS == status);
// 	}
//	KdPrint(("file object in IRP_MJ_SET_INFORMATION is %08x\n",irpSp->FileObject));

	/////////////////////////////////////透明加密//////////////////////////////////
	if (file_sec&&(irpSp->Parameters.SetFile.FileInformationClass == FileAllocationInformation ||
		irpSp->Parameters.SetFile.FileInformationClass == FileEndOfFileInformation ||
		irpSp->Parameters.SetFile.FileInformationClass == FileValidDataLengthInformation ||
		irpSp->Parameters.SetFile.FileInformationClass == FileStandardInformation ||
		irpSp->Parameters.SetFile.FileInformationClass == FileAllInformation ||
		irpSp->Parameters.SetFile.FileInformationClass == FilePositionInformation))
	{
		cfIrpSetInforPre(Irp,irpSp);         //设置大小
	}
	///////////////////////////////////////////////////////////////////////////////

	if((NoDelNum!=0)&&SfGetFullPath(irpSp->FileObject,fullpath))	
	if(SfGetFullPath(irpSp->FileObject, fullpath))
	{	
        if (SfCompareFullPath(gNoDelete,&NoDelMutex,fullpath))
        {
			KdPrint(("NO!  you can't delete!"));
			Irp->IoStatus.Status = STATUS_ACCESS_DENIED;            
			Irp->IoStatus.Information = 0;    
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
			return STATUS_ACCESS_DENIED;
        }
	}

	IoSkipCurrentIrpStackLocation(Irp);
	return IoCallDriver(devExt->AttachedToDeviceObject, Irp);

}

NTSTATUS
SfSetInformationCompletion(
							 IN PDEVICE_OBJECT DeviceObject,
							 IN PIRP Irp,
							 IN PVOID Context
							 )
{
	UNREFERENCED_PARAMETER( Irp );
	UNREFERENCED_PARAMETER( DeviceObject );
	KeSetEvent((PKEVENT)Context, IO_NO_INCREMENT, FALSE);
	return STATUS_MORE_PROCESSING_REQUIRED;	//注：必须返回这个值
}



///////////////////////////////////////////////////////////////////////////////
/////IRP_MJ_DEVICE_CONTROL    IRP控制例程//////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
NTSTATUS
SfDeviceIOControl(
				  IN PDEVICE_OBJECT DeviceObject,
				  IN PIRP Irp
				  )
{
	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION irpStack;
	ULONG InputBufferLength;
	ULONG OutputBufferLength;
	ULONG code;
	HANDLE hEvent = NULL;				
	//缓冲区方式IOCTL
	PVOID* InputBuffer = Irp->AssociatedIrp.SystemBuffer;				
	//操作输出缓冲区
	PVOID* OutputBuffer = Irp->AssociatedIrp.SystemBuffer;
	if (DeviceObject == gSFilterControlDeviceObject) //只对CDO进行DeviceIOControl处理
	{
		//设置
		Irp->IoStatus.Information = 0;
		//得到当前堆栈
		irpStack = IoGetCurrentIrpStackLocation( Irp );
		//得到输入缓冲区大小
		InputBufferLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
		//得到输出缓冲区大小
		OutputBufferLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
		//得到IOCTL码
		code=irpStack->Parameters.DeviceIoControl.IoControlCode;								
		
		switch (code)
		{	
			// 		case IOCTL_CONTROLLOG:
			// 			{
			// 				gLogOn=!gLogOn;	
			// 				break;
			// 			}
			// 		case IOCTL_GETLOGBUF:
			// 			{
			// 				PLOG_BUF  oldLog;    
			// 				BOOLEAN             logMutexReleased;
			// 				KdPrint (("IOCTL_GETLOGBUF\n"));
			// 				// If the output buffer is too large to fit into the caller's buffer
			// 				if( LOGBUFSIZE > OutputBufferLength )  {
			// 					//					IoStatus->Status = STATUS_BUFFER_TOO_SMALL;
			// 					return STATUS_BUFFER_TOO_SMALL;
			// 				}
			// 				ExAcquireFastMutex( &LogMutex );
			// 				if( CurrentLog->Len  ||  CurrentLog->Next ) {
			// 					// Start output to a new output buffer
			// 					SfAllocateLog();
			// 					// Fetch the oldest to give to user
			// 					oldLog = SfGetOldestLog();
			// 					if( oldLog != CurrentLog ) {
			// 						logMutexReleased = TRUE;
			// 						ExReleaseFastMutex( &LogMutex );
			// 					} else {
			// 						logMutexReleased = FALSE;
			// 					}
			// 					// Copy it to the caller's buffer
			// 					memcpy( OutputBuffer, oldLog->Data, oldLog->Len );
			// 					// Return length of copied info
			// 					Irp->IoStatus.Information=oldLog->Len;
			// 					// Deallocate buffer - unless its the last one
			// 					if( logMutexReleased ) {
			// 						ExFreePool( oldLog );
			// 					} else {
			// 						CurrentLog->Len = 0;
			// 						ExReleaseFastMutex( &LogMutex );                    
			// 					}
			// 				} else {
			// 					// There is no unread data
			// 					ExReleaseFastMutex( &LogMutex );
			// 					Irp->IoStatus.Information = 0;
			// 				}
			// 			}
			// 			//清空logbuf  这个还没投入使用
			// 		case IOCTL_ZEROLOGBUF:
			// 			{ 			
			// 				PLOG_BUF  oldLog;
			// 				KdPrint (("IOCTL_ZEROLOGBUF\n"));
			// 				ExAcquireFastMutex( &LogMutex );
			// 				while( CurrentLog->Next )  {
			// 					// Free all but the first output buffer
			// 					oldLog = CurrentLog->Next;
			// 					CurrentLog->Next = oldLog->Next;
			// 					ExFreePool( oldLog );
			// 					NumLog--;
			// 				}
			// 				// Set the output pointer to the start of the output buffer
			// 				CurrentLog->Len = 0;
			// 				//            Sequence = 0;
			// 				ExReleaseFastMutex( &LogMutex );
			// 				break;
			// 			}
			// 			//新的隐藏做好后 这个就不用了
			// // 		case IOCTL_ADDHIDE_FILE:
			// // 			{	KdPrint(("IOCTL_ADDHIDE_FILE %s",InputBuffer));		
			// // 			AddHideObject(InputBuffer, HIDE_FLAG_FILE);
			// // 			break;
			// // 			}
			// // 		case IOCTL_ADDHIDE_DIRECTORY:
			// // 			{	KdPrint(("IOCTL_ADDHIDE_DIRECTORY %s",InputBuffer));		
			// // 			AddHideObject(InputBuffer, HIDE_FLAG_DIRECTORY);
			// // 			break;
			// // 			}
			
			//禁止访问
			// 初始化的时候增加所有禁止访问的文件
			// 		case IOCTL_INIT_NOACCESSFILE  : 
			// 			{
			// 
			// 				break;
			//          }
			// 程序跑起来后增加一个禁止访问的文件
		case IOCTL_ADD_REPARSE:
			{
				AddReparse((PReparser)InputBuffer);
				break;
			}
		case IOCTL_DEL_REPARSE:
			{
				DelReparse((PWSTR)InputBuffer);
				break;
			}
		case IOCTL_ADD_HIDE:
			{
                AddHideObject((PHider)InputBuffer);
				break;
			}
		case IOCTL_DEL_HIDE:
			{
				DelHideObject((PHider)InputBuffer);
				break;
			}
		case IOCTL_ADD_NOACCESSFILE : 
			{
				SfAddComPathAce((PWSTR)InputBuffer);
				break;
			}
			// 程序跑起来后删除一个禁止访问的文件
		case IOCTL_DEL_NOACCESSFILE :
			{
				SfDeleteComPathAce((PWSTR)InputBuffer);
				break;
			}
			
			//禁止删除
			// 初始化的时候增加所有禁止删除的文件
			// 		case IOCTL_INIT_NODELETEFILE  : 
			// 			{
			// 
			// 				break;
			//          }
			// 程序跑起来后增加一个禁止删除的文件			
		case IOCTL_ADD_NODELETEFILE : 
			{
				SfAddComPathDel((PWSTR)InputBuffer );
				break;
			}
			// 程序跑起来后删除一个禁止删除的文件
		case IOCTL_DEL_NODELETEFILE :
			{
				SfDeleteComPathDel((PWSTR)InputBuffer);
				break;
			}
			//隐藏  还没投入使用
			// 初始化的时候增加所有隐藏的文件 		
			// 		case IOCTL_ADD_NODELETEFILE : 
			// 			{
			// 				break;
			//          }
			// 程序跑起来后增加一个隐藏的文件
			// 		case IOCTL_ADD_NODELETEFILE : 
			// 			{
			// 				break;
			// 			}
			// 程序跑起来后删除一个禁隐藏的文件
			// 		case IOCTL_DEL_NODELETEFILE :
			// 			{
			// 				break;
			// 			}
		default:
			break;     
		}
		
		Irp->IoStatus.Status = status;
		IoCompleteRequest( Irp, IO_NO_INCREMENT );
		return status;
	}
	IoSkipCurrentIrpStackLocation(Irp);    
	// Call the appropriate file system driver with the request.
	//
	return IoCallDriver(((PSFILTER_DEVICE_EXTENSION)  DeviceObject->DeviceExtension)->AttachedToDeviceObject, Irp);	
}

///////////////////////////////////////////////////////////////////////////////
//IRP控制例程//////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
NTSTATUS
SfPassThrough (//最简单的IRP处理passthrough 
	       IN PDEVICE_OBJECT DeviceObject,
	       IN PIRP Irp
	       )
{
	ASSERT(!IS_MY_CONTROL_DEVICE_OBJECT( DeviceObject ));
	ASSERT(IS_MY_DEVICE_OBJECT( DeviceObject ));
	IoSkipCurrentIrpStackLocation( Irp );
	return IoCallDriver( ((PSFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject, Irp );
}


NTSTATUS
SfCreate (//过滤create/open操作 
		  IN PDEVICE_OBJECT DeviceObject,
		  IN PIRP Irp
		  )
{
	NTSTATUS status;	
	
	PIO_STACK_LOCATION  currentIrpStack = IoGetCurrentIrpStackLocation(Irp);
	PFILE_OBJECT        FileObject = currentIrpStack->FileObject;
	PSFILTER_DEVICE_EXTENSION DevExt = (PSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
	PFILE_OBJECT RelatedFileObject = FileObject->RelatedFileObject;
	//以下：用于获取文件路径
	PUNICODE_STRING name;
	GET_NAME_CONTROL nameControl;
	WCHAR FullPathName[MAXPATHLEN]={0};//用于禁止访问
	
	//重定向
    PIO_STACK_LOCATION IrpSp;
    PVOID            FileNameBuffer;
//	UNICODE_STRING        NewFileName;
	PUNICODE_STRING FileName = &(currentIrpStack->FileObject->FileName);	
	
	ULONG Return;
	BOOLEAN crypting=FALSE;
	BOOLEAN proc_later=FALSE;
	
	
	//查看当前进程是否是加密进程
	BOOLEAN proc_sec = cfIsCurProcSec();
	PAGED_CODE();	
	
	if (IS_MY_CONTROL_DEVICE_OBJECT(DeviceObject)) 
	{
		Irp->IoStatus.Status = STATUS_SUCCESS;  //此处修改
		Irp->IoStatus.Information = 0;		
		IoCompleteRequest( Irp, IO_NO_INCREMENT );
		return STATUS_SUCCESS;  //此处修改
	}
	
	if (FileObject == NULL)
	{
		IoSkipCurrentIrpStackLocation( Irp );
		return IoCallDriver( ((PSFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject, Irp );
	}
	
	ASSERT(IS_MY_DEVICE_OBJECT( DeviceObject ));
	
	if (DevExt->DriveLetter == L'\0') 
	{
		
		UNICODE_STRING DosName;
		
		status = SfVolumeDeviceNameToDosName(&DevExt->DeviceName, &DosName);
		if (NT_SUCCESS(status)) 
		{
			DevExt->DriveLetter = DosName.Buffer[0];
			ExFreePool(DosName.Buffer);	
			
			//转换为大写
			if ((DevExt->DriveLetter >= L'a') && (DevExt->DriveLetter <= L'z')) 
			{
				DevExt->DriveLetter += L'A' - L'a';
			}
		} 
		else 
		{
			KdPrint(("sfilter!SfCreate: SfVolumeDeviceNameToDosName(%x) failed(%x)\n",
				DevExt->StorageStackDeviceObject, status));
		}
	}
	
	// 
	// Open Volume Device directly
	//对于直接打开磁盘的情况  我们就passthru了 
	if ((FileObject->FileName.Length == 0) && !RelatedFileObject)
	{
		IoSkipCurrentIrpStackLocation(Irp);
		return IoCallDriver(DevExt->AttachedToDeviceObject, Irp);
	}
	
	//#//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	//#//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////			
	/*//重定向的代码：				
	if (bRedirectFileOpen)
	{   // 					在做文件重定向时,应该在IRP_MJ_CREATE里进行重定向,而且应该这样做:
		// 					1,先释放原FileObject->FileName;
		// 					2,重新分配一个UNICODE_STRING,并将其Buffer设置为你想打开的文件*全路径*;
		// 					3,Irp->IoStatus.Status=STATUS_REPARSE;
		// 					Irp->IoStatus.Informiation=IO_REPARSE;
		// 					IoCompleteRequeset(Irp,IO_NO_INCEMENT);
		// 					return STATUS_REPARSE;
		UNICODE_STRING Uceshi;
		RtlInitUnicodeString(&Uceshi, L"\\ceshi.doc" );
		if (RtlEqualUnicodeString(FileName,&Uceshi,TRUE))
		{					
			
			RtlInitUnicodeString(&NewFileName,L"\\??\\C:\\1122\\CFilter.exe");
			FileNameBuffer = ExAllocatePool( NonPagedPool, NewFileName.MaximumLength );
			if (!FileNameBuffer)
			{
				Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
				Irp->IoStatus.Information = 0;	
				IoCompleteRequest( Irp, IO_NO_INCREMENT );
				return STATUS_INSUFFICIENT_RESOURCES;
			}
			ExFreePool( FileName->Buffer );
			FileName->Buffer = FileNameBuffer;
			FileName->MaximumLength = NewFileName.MaximumLength;
			RtlCopyUnicodeString( FileName, &NewFileName );
			Irp->IoStatus.Status = STATUS_REPARSE;
			Irp->IoStatus.Information = IO_REPARSE;
			IoCompleteRequest( Irp, IO_NO_INCREMENT );
			return STATUS_REPARSE;
		}	
	}*/
	//#/////////////////////////////////////////////////////////////////////////////////////////////////////////////
	//#/////////////////////////////////////////////////////////////////////////////////////////////////////////////
				//如果是加密进程
	if ((cfListInited()) && proc_sec)
	{
		Return=cfIrpCreatePre(Irp,currentIrpStack,FileObject,((PSFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject);
		
	}
	else
	{
		//这边当做普通进程来处理，作为普通进程，不允许打开一个正在加密的文件
		//因为这边还没办法判断，所以先GO_ON
		Return = SF_IRP_GO_ON;
	}
				
	if (Return == SF_IRP_PASS)
	{
		//不知道这边的这几个irp要怎么处理，主要是不知道会不会，和禁止访问冲突
		//暂时先把它直接不管，我想把这个下发，做成去执行禁止访问的代码
		goto SkipHandle;
	}
	if (Return == SF_IRP_COMPLETED)
	{
		return  status;
	}
	if(Return == SF_IRP_GO_ON)
	{
		KEVENT waitEvent; 
		PIO_STACK_LOCATION  currentIrpStack = IoGetCurrentIrpStackLocation(Irp);
		PFILE_OBJECT        FileObject = currentIrpStack->FileObject;
		
		//////////////////////////////////原来部分////////////////////////
		//清除任何的存放在哈希表中的fileobject/name
		if (FileObject)//偶来加个判断吧  防止为空 BSOD    
		{SfFreeHashEntry( FileObject );}
		//====================================================================================
		
		//等待事件用于等待处理结束
		KeInitializeEvent( &waitEvent, NotificationEvent, FALSE );
		//拷贝当前I/O堆栈到下一个堆栈并设置我们的完成例程
		IoCopyCurrentIrpStackLocationToNext( Irp );
		IoSetCompletionRoutine(
			Irp,
			SfCreateCompletion,//完成例程
			&waitEvent,
			TRUE,
			TRUE,
			TRUE );
		//调用栈中的下一个驱动
		status = IoCallDriver( ((PSFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject, Irp );
		//等待内核事件
		if (STATUS_PENDING == status) {
			NTSTATUS localStatus = KeWaitForSingleObject(	&waitEvent, 
				Executive,//等待的原因
				KernelMode,//必须是这个参数
				FALSE,
				NULL//无限的等下去
				);
			ASSERT(STATUS_SUCCESS == localStatus);
		}
		
		//验证IoCompleteRequest被调用了
		ASSERT(KeReadStateEvent(&waitEvent) ||
			!NT_SUCCESS(Irp->IoStatus.Status));		
		
		
		proc_later = cfIsCurProcSec();    //判断是否为加密进程
		//PIO_STACK_LOCATION irpsp = IoGetCurrentIrpStackLocation(Irp);
		// 是否是一个已经被加密进程打开的文件
		cfListLock();
		crypting = cfIsFileCrypting(FileObject);
		cfListUnlock();
		
		if (proc_later)
		{
			//是加密进程，但不再加密链表中，则追加入加密链表
			
			ASSERT(crypting == FALSE);
			if (!cfFileCryptAppendLk(FileObject))
			{
				//如果加入不成功，那否决这个操作
				IoCancelFileOpen(((PSFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject,FileObject);
				Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
				Irp->IoStatus.Information = 0;
				//KdPrint(("OnSfilterIrpPost: file %wZ failed to call cfFileCryptAppendLk!!!\r\n",&file->FileName));
			} 
			else
			{
				//KdPrint(("OnSfilterIrpPost: file %wZ begin to crypting.\r\n",&file->FileName));
			}
		} 
		else
		{
			// 是普通进程。根据是否是加密文件。如果是加密文件，
			// 否决这个操作。
			if(crypting)
			{
				IoCancelFileOpen(((PSFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject,FileObject);
				Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
				Irp->IoStatus.Information = 0;
			}
		}
		
		//这是用于获取文件路径
		IrpSp = IoGetCurrentIrpStackLocation( Irp );	
		//获得文件对象的名称
		name = SfGetFileName( IrpSp->FileObject,
			Irp->IoStatus.Status, 
			&nameControl );
		SfAddIntoHashTable(//若是需要加入log记录 就在这个函数里面添加
			FileObject,
			name, 
			&DevExt->DeviceName,
			DevExt->DriveLetter
			);	
		SfGetFileNameCleanup( &nameControl );//清除
		
		if(SfGetFullPath(FileObject,FullPathName))
		{
			if(NoAceNum!=0)
			{			
				KdPrint(("%ws\n",FullPathName));
				if(SfCompareFullPath(gNoAccess,&NoAceMutex,FullPathName))
				{
					KdPrint(("NO!  you can't access!"));
					Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
					Irp->IoStatus.Information = 0;    
					IoCompleteRequest(Irp, IO_NO_INCREMENT);
					return STATUS_ACCESS_DENIED;	
				}				
			}
			
			//进程访问隐藏文件
			if(NoHidAceNum!=0)
			{			
				KdPrint(("%ws\n",FullPathName));
				if(SfCompareFullPath(gHidNoAccess,&NoHidAceMutex,FullPathName))
				{
					KdPrint(("NO!  you can't access!"));
					Irp->IoStatus.Status = STATUS_OBJECT_PATH_SYNTAX_BAD;
					Irp->IoStatus.Information = 0;    
					IoCompleteRequest(Irp, IO_NO_INCREMENT);
					return STATUS_OBJECT_PATH_SYNTAX_BAD;
				}
			}
			

			if (ReparseNum!=0)
			{   
				if (FindReparsePath(FullPathName)==TRUE)
				{					
					FileNameBuffer = ExAllocatePool( NonPagedPool,sizeof(WCHAR)*1024);
					if (!FileNameBuffer)
					{
						Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
						Irp->IoStatus.Information = 0;	
						IoCompleteRequest( Irp, IO_NO_INCREMENT );
						return STATUS_INSUFFICIENT_RESOURCES;
					}
					ExFreePool( FileName->Buffer );

			        RtlZeroMemory(FileNameBuffer,2*MAXPATHLEN);
					RtlCopyMemory(FileNameBuffer,FullPathName,2*wcslen(FullPathName));					
					//重设filename
					FileName->Length=2*wcslen(FullPathName);				
					FileName->Buffer = FileNameBuffer;
					FileName->MaximumLength = 2*MAXPATHLEN;
					
					Irp->IoStatus.Status = STATUS_REPARSE;
					Irp->IoStatus.Information = IO_REPARSE;	
					IoCompleteRequest( Irp, IO_NO_INCREMENT );
					return STATUS_REPARSE;
				}
			}	
		}
		
		//  保存status并且继续处理IRP
		status = Irp->IoStatus.Status;
		IoCompleteRequest( Irp, IO_NO_INCREMENT );
		return status;
	}
SkipHandle:
	IoSkipCurrentIrpStackLocation( Irp );
	return IoCallDriver( ((PSFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject, Irp );
}


NTSTATUS
SfCreateCompletion (
		    IN PDEVICE_OBJECT DeviceObject,
		    IN PIRP Irp,
		    IN PVOID Context
		    )
		    //完成例程 若不可以调试 那么这个的功能就是打印成功被文件系统打开的文件的文件名
{
	PKEVENT event = Context;
	UNREFERENCED_PARAMETER( DeviceObject );
	UNREFERENCED_PARAMETER( Irp );
	ASSERT(IS_MY_DEVICE_OBJECT( DeviceObject ));
	KeSetEvent(event, IO_NO_INCREMENT, FALSE);//设置等待事件
	return STATUS_MORE_PROCESSING_REQUIRED;//返回需要进一步处理
}

NTSTATUS
SfCleanup (
	   IN PDEVICE_OBJECT DeviceObject,
	   IN PIRP Irp
	   )
	   //cleanup request 处理
{

	PAGED_CODE();
	if (DeviceObject == gSFilterControlDeviceObject) 
	{
		Irp->IoStatus.Status = STATUS_SUCCESS;
		Irp->IoStatus.Information = 0;

		IoCompleteRequest( Irp, IO_NO_INCREMENT );
		return STATUS_SUCCESS;
	}
	

	
	ASSERT(!IS_MY_CONTROL_DEVICE_OBJECT( DeviceObject ));
	ASSERT(IS_MY_DEVICE_OBJECT( DeviceObject ));
	IoSkipCurrentIrpStackLocation( Irp );
	return IoCallDriver( ((PSFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject, Irp );
}

NTSTATUS
SfClose (
	 IN PDEVICE_OBJECT DeviceObject,
	 IN PIRP Irp
	 )
	 //cleanup/close request 处理
{
	NTSTATUS status;
	PIO_STACK_LOCATION  currentIrpStack = IoGetCurrentIrpStackLocation(Irp);
	PFILE_OBJECT        FileObject = currentIrpStack->FileObject;
	BOOLEAN file_sec;
	PAGED_CODE();
	//  Sfilter不允许控制CDO被创建 所以没有CDO的IRP通过  filespy的该例程应该不同 
	/////////////////////////////////////////////////////////////////////////
	//此处为添加代码段，一定要在此位置添加，添加到后面机子会重启
	if (DeviceObject == gSFilterControlDeviceObject) {
		Irp->IoStatus.Status = STATUS_SUCCESS;
		Irp->IoStatus.Information = 0;

		IoCompleteRequest( Irp, IO_NO_INCREMENT );
		return STATUS_SUCCESS;
	}


	ASSERT(!IS_MY_CONTROL_DEVICE_OBJECT( DeviceObject ));
	ASSERT(IS_MY_DEVICE_OBJECT( DeviceObject ));     

	if (FileObject)
	{
		SfFreeHashEntry( FileObject );
	}

	//////////////////////////透明加密////////////////////////////////////////////
	if (!cfListInited())
	{
		IoSkipCurrentIrpStackLocation( Irp );
		return IoCallDriver( ((PSFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject, Irp );
	}
	cfListLock();
    file_sec = cfIsFileCrypting(FileObject);
    cfListUnlock();
	//如果好似加密链表中的对象
	if (file_sec)
	{
		KEVENT waitEvent; 
		BOOLEAN crypting;
		
		//等待事件用于等待处理结束
		KeInitializeEvent( &waitEvent, NotificationEvent, FALSE );
		//拷贝当前I/O堆栈到下一个堆栈并设置我们的完成例程
		IoCopyCurrentIrpStackLocationToNext( Irp );
		IoSetCompletionRoutine(
			Irp,
			SfCreateCompletion,//完成例程
			&waitEvent,
			TRUE,
			TRUE,
			TRUE );
		//调用栈中的下一个驱动
		status = IoCallDriver( ((PSFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject, Irp );
		//等待内核事件
		if (STATUS_PENDING == status) {
			NTSTATUS localStatus = KeWaitForSingleObject(	&waitEvent, 
				Executive,//等待的原因
				KernelMode,//必须是这个参数
				FALSE,
				NULL//无限的等下去
				);
			ASSERT(STATUS_SUCCESS == localStatus);
		}
		//验证IoCompleteRequest被调用了
		ASSERT(KeReadStateEvent(&waitEvent) ||
			!NT_SUCCESS(Irp->IoStatus.Status));		
		
		{
			PIO_STACK_LOCATION  irpSpLater = IoGetCurrentIrpStackLocation(Irp);
			PFILE_OBJECT        file = irpSpLater->FileObject;
			
			cfListLock();
			crypting = cfIsFileCrypting(file);
            cfListUnlock();
			
			ASSERT(crypting);
            cfCryptFileCleanupComplete(file);   //删除一个节点
		}		
		
		//  保存status并且继续处理IRP
		status = Irp->IoStatus.Status;
		IoCompleteRequest( Irp, IO_NO_INCREMENT );
		
		return status;
	}
	//////////////////////////透明加密////////////////////////////////////////////

	IoSkipCurrentIrpStackLocation( Irp );
	return IoCallDriver( ((PSFILTER_DEVICE_EXTENSION) DeviceObject->DeviceExtension)->AttachedToDeviceObject, Irp );
}


NTSTATUS
SfFsControl (
	     IN PDEVICE_OBJECT DeviceObject,
	     IN PIRP Irp
	     )
	     //该例程被调用于IRP_MJ_FILE_SYSTEM_CONTROL 也是简单的passed through 但是有些需要特殊处理
{
	PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation( Irp );
	PAGED_CODE();
	
	ASSERT(!IS_MY_CONTROL_DEVICE_OBJECT( DeviceObject ));
	ASSERT(IS_MY_DEVICE_OBJECT( DeviceObject ));
	switch (irpSp->MinorFunction) 
	{
        
	case IRP_MN_MOUNT_VOLUME:
		return SfFsControlMountVolume( DeviceObject, Irp );
        
	case IRP_MN_LOAD_FILE_SYSTEM://当一个文件识别器（见上文）决定加载真正的文件系统的时候，会产生一个这样的irp
		//		如果我们已经绑定了文件系统识别器，现在就应该解除绑定并销毁设备，同时生成新的设备去绑定真的文件系统
		return SfFsControlLoadFileSystem( DeviceObject, Irp );
		
	}    
    
	// 传递所有的其他对文件系统控制请求穿过
	IoSkipCurrentIrpStackLocation( Irp );
	
	return IoCallDriver( ((PSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->AttachedToDeviceObject, Irp );
}

NTSTATUS
SfFsControlCompletion (
		       IN PDEVICE_OBJECT DeviceObject,
		       IN PIRP Irp,
		       IN PVOID Context
		       )
		       //完成例程 Control的 这个只是直接的把例程返回 没做什么处理
{
	UNREFERENCED_PARAMETER( DeviceObject );//UNREFERENCED_PARAMETER 的意义在于，去掉C 编译器对于没有使用的这个参数所产生的一条警告。
	UNREFERENCED_PARAMETER( Irp );//UNREFERENCED_PARAMETER很有用！！！
	ASSERT(IS_MY_DEVICE_OBJECT( DeviceObject ));
	ASSERT(Context != NULL);
	if (IS_WINDOWSXP_OR_LATER()) {
		
		KeSetEvent((PKEVENT)Context, IO_NO_INCREMENT, FALSE);
		
	} 

	return STATUS_MORE_PROCESSING_REQUIRED;
}


NTSTATUS
SfFsControlMountVolume (
			IN PDEVICE_OBJECT DeviceObject,
			IN PIRP Irp
			)
{
	PSFILTER_DEVICE_EXTENSION devExt = DeviceObject->DeviceExtension;
	PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation( Irp );
	PDEVICE_OBJECT newDeviceObject;
	PDEVICE_OBJECT storageStackDeviceObject;
	PSFILTER_DEVICE_EXTENSION newDevExt;
	NTSTATUS status;
	BOOLEAN isShadowCopyVolume;
	KEVENT waitEvent;


	PAGED_CODE();
	ASSERT(IS_MY_DEVICE_OBJECT( DeviceObject ));
	ASSERT(IS_DESIRED_DEVICE_TYPE(DeviceObject->DeviceType));
	storageStackDeviceObject = irpSp->Parameters.MountVolume.Vpb->RealDevice;//先保存  防止其他的处理会修改这个值
	//VBP把际存储媒介设备对象和文件系统上的卷设备对象联系起来.  从VPB 中再得到对应的卷设备
	
	status = SfIsShadowCopyVolume ( storageStackDeviceObject,//判断是否为卷影 
		&isShadowCopyVolume );
	
	if (NT_SUCCESS(status) && 
		isShadowCopyVolume ) 
	{
		//到下一个驱动  卷影就不绑定了
		IoSkipCurrentIrpStackLocation( Irp );
		return IoCallDriver( devExt->AttachedToDeviceObject, Irp );
	}

	status = IoCreateDevice( gSFilterDriverObject,
		sizeof( SFILTER_DEVICE_EXTENSION ),
		NULL,
		DeviceObject->DeviceType,//设备类型 与该驱动（绑定到的上面的驱动不是我们的过滤驱动）的控制设备类型相同
		0, 
		FALSE,
		&newDeviceObject );//创建新的设备对象该对象绑定到文件系统的卷设备对象上
	if (!NT_SUCCESS( status )) 
	{//创建失败
		// 如果不能绑定 说明不允许绑定 
		KdPrint(( "SFilter!SfFsControlMountVolume: Error creating volume device object, status=%08x\n", status ));
		Irp->IoStatus.Information = 0;
		Irp->IoStatus.Status = status;
		IoCompleteRequest( Irp, IO_NO_INCREMENT );//结束 IRP 处理失败
		return status;
	}

	//  填写设备扩展
	newDevExt = newDeviceObject->DeviceExtension;//获得新的设备的设备扩展
	
	//填写前先保证下这是空的
	RtlZeroMemory(newDevExt, sizeof(SFILTER_DEVICE_EXTENSION));
	
	newDevExt->StorageStackDeviceObject = storageStackDeviceObject;//前面保存的存入新的设备扩展中
	RtlInitEmptyUnicodeString( &newDevExt->DeviceName, 
		newDevExt->DeviceNameBuffer, 
		sizeof(newDevExt->DeviceNameBuffer));
	SfGetObjectName( storageStackDeviceObject,  //获得设备名
		&newDevExt->DeviceName );
	
	ASSERT(IS_WINDOWSXP_OR_LATER()); //这个是必然的	
	KeInitializeEvent( 
					  &waitEvent, 
					  NotificationEvent, 
					  FALSE);
	
	IoCopyCurrentIrpStackLocationToNext ( Irp );
	IoSetCompletionRoutine( Irp,
		SfFsControlCompletion,//完成例程
		&waitEvent,     //context parameter
		TRUE,
		TRUE,
		TRUE );
	status = IoCallDriver( devExt->AttachedToDeviceObject, Irp );
	//等待完成
	if (STATUS_PENDING == status) {
		status = KeWaitForSingleObject( &waitEvent,
			Executive,
			KernelMode,
			FALSE,
			NULL );
		ASSERT( STATUS_SUCCESS == status );
	}
	ASSERT(KeReadStateEvent(&waitEvent) ||
		!NT_SUCCESS(Irp->IoStatus.Status));
	status = SfFsControlMountVolumeComplete( 
											DeviceObject,
											Irp,
											newDeviceObject );
	
	return status;
}

NTSTATUS
SfFsControlMountVolumeComplete (
				IN PDEVICE_OBJECT DeviceObject,
				IN PIRP Irp,
				IN PDEVICE_OBJECT NewDeviceObject
				)
				//post-Mount work必须在PASSIVE_LEVEL上运行
{
	PVPB vpb;
	PSFILTER_DEVICE_EXTENSION newDevExt;
	PIO_STACK_LOCATION irpSp;
	PDEVICE_OBJECT attachedDeviceObject;
	NTSTATUS status;
	PAGED_CODE();
	UNREFERENCED_PARAMETER(DeviceObject);
	newDevExt = NewDeviceObject->DeviceExtension;//获得设备扩展
	irpSp = IoGetCurrentIrpStackLocation( Irp );//获得本层设备对应的IO_STACK_LOCATION
	//从真实的设备对象中获得当前的VPB保存到我们的设备扩展中 
	//这样做是因为VPB in the IRP stack也许不是我们当前得到的VPB 
	//下面的文件系统也许会改变VPBs（当检测是否卷被安装时）
	
	//问题：StorageStackDeviceObject的值是在
	//“newDevExt->StorageStackDeviceObject(是PDEVICE_OBJECT类型) = storageStackDeviceObject(是PDEVICE_OBJECT类型);//前面保存的存入新的设备扩展中”
	//赋值
	//而后面的storageStackDeviceObject = irpSp->Parameters.MountVolume.Vpb->RealDevice;//先保存  防止其他的处理会修改这个值
	//irpSp->Parameters.MountVolume.Vpb->RealDevice是PDEVICE_OBJECT类型
	//所以	irpSp->Parameters.MountVolume.Vpb->RealDevice==newDevExt->StorageStackDeviceObject->Vpb？
	//那么VBP这个数据结构就只有一个参数RealDevice存在 且这个参数是PDEVICE_OBJECT类型？
	//那么不就是PVPB==PDEVICE_OBJECT吗？  除非这些赋值中隐含有强制的类型转换
	vpb = newDevExt->StorageStackDeviceObject->Vpb;//我们前面保存过的vpb,获得
	if (vpb != irpSp->Parameters.MountVolume.Vpb) {//就是看看VPB是否改变了  改变了 就打印出信息
		KdPrint(("SFilter!SfFsControlMountVolume:              VPB in IRP stack changed   %p IRPVPB=%p VPB=%p\n",
			vpb->DeviceObject,
			irpSp->Parameters.MountVolume.Vpb,
			vpb));
	}

	//看是否安装成功
	if (NT_SUCCESS( Irp->IoStatus.Status ))
	{
		// 获得一个互斥体,以便我们可以原子的判断我们是否绑定过一个卷设备.这可以防止
		// 我们对一个卷绑定两次。.
		ExAcquireFastMutex( &gSfilterAttachLock );
		if (!SfIsAttachedToDevice( vpb->DeviceObject, &attachedDeviceObject )) 
		{//没有绑定到设备上去
			status = SfAttachToMountedDevice( vpb->DeviceObject,// 调用 来完成真正的绑定.
				NewDeviceObject );
			if (!NT_SUCCESS( status )) 
			{ //绑定失败 那么只好清除
				SfCleanupMountedDevice( NewDeviceObject );
				IoDeleteDevice( NewDeviceObject );
			}
			ASSERT( NULL == attachedDeviceObject );
		} 
		else 
		{//绑上去的就显示信息
			SfCleanupMountedDevice( NewDeviceObject );
			IoDeleteDevice( NewDeviceObject );
			ObDereferenceObject( attachedDeviceObject );//减少计数
		}
		ExReleaseFastMutex( &gSfilterAttachLock );//释放锁
	} 
	else 
	{//安装请求失败的处理

		//清除并删除我们创建的设备对象
		SfCleanupMountedDevice( NewDeviceObject );
		IoDeleteDevice( NewDeviceObject );
	}
	//结束请求 我们必须要在结束前保存status 因为在结束IRP后我们将无法再获得（它也许会被释放）
	status = Irp->IoStatus.Status;
	IoCompleteRequest( Irp, IO_NO_INCREMENT );
	return status;
}
NTSTATUS
SfFsControlLoadFileSystem (
						   IN PDEVICE_OBJECT DeviceObject,
						   IN PIRP Irp
						   )
{
	PSFILTER_DEVICE_EXTENSION devExt = DeviceObject->DeviceExtension;
	NTSTATUS status;
	KEVENT waitEvent; 
	PAGED_CODE();
	
	ASSERT(IS_WINDOWSXP_OR_LATER()); 
		
	KeInitializeEvent( &waitEvent, 
		NotificationEvent, 
		FALSE );
	IoCopyCurrentIrpStackLocationToNext( Irp );        
	IoSetCompletionRoutine( Irp,
		SfFsControlCompletion,
		&waitEvent,     //context parameter
		TRUE,
		TRUE,
		TRUE );
	status = IoCallDriver( devExt->AttachedToDeviceObject, Irp );
	//  等待操作完成
	if (STATUS_PENDING == status) {
		status = KeWaitForSingleObject( &waitEvent,
			Executive,
			KernelMode,
			FALSE,
			NULL );
		ASSERT( STATUS_SUCCESS == status );
	}

	ASSERT(KeReadStateEvent(&waitEvent) ||
		!NT_SUCCESS(Irp->IoStatus.Status));
	status = SfFsControlLoadFileSystemComplete( DeviceObject,
		Irp );
	
	return status;
}


NTSTATUS
SfFsControlLoadFileSystemComplete (
				   IN PDEVICE_OBJECT DeviceObject,
				   IN PIRP Irp
				   )
{
	PSFILTER_DEVICE_EXTENSION devExt;
	NTSTATUS status;
	PAGED_CODE();
	devExt = DeviceObject->DeviceExtension;

	//  检查操作的 status 
	if (!NT_SUCCESS( Irp->IoStatus.Status ) && 
		(Irp->IoStatus.Status != STATUS_IMAGE_ALREADY_LOADED)) {
		SfAttachDeviceToDeviceStack( DeviceObject, 
			devExt->AttachedToDeviceObject,
			&devExt->AttachedToDeviceObject );
		ASSERT(devExt->AttachedToDeviceObject != NULL);
	} else {
		//加载成功 清除设备并删除设备对象  
		SfCleanupMountedDevice( DeviceObject );
		IoDeleteDevice( DeviceObject );
	}
	//继续处理操作
	status = Irp->IoStatus.Status;
	IoCompleteRequest( Irp, IO_NO_INCREMENT );
	return status;
}

NTSTATUS
SfAttachDeviceToDeviceStack (
			     IN PDEVICE_OBJECT SourceDevice,
			     IN PDEVICE_OBJECT TargetDevice,
			     IN OUT PDEVICE_OBJECT *AttachedToDeviceObject
			     )
{
	PAGED_CODE();
	
	ASSERT (IS_WINDOWSXP_OR_LATER()); 
	
		ASSERT( NULL != gSfDynamicFunctions.AttachDeviceToDeviceStackSafe );
		
		return (gSfDynamicFunctions.AttachDeviceToDeviceStackSafe)( SourceDevice,
			TargetDevice,
			AttachedToDeviceObject );
	
} 
NTSTATUS
SfAttachToFileSystemDevice(
			   IN PDEVICE_OBJECT DeviceObject,
			   IN PUNICODE_STRING DeviceName
			   )
{
	PDEVICE_OBJECT newDeviceObject; // 我们创建的过滤设备对象
	PSFILTER_DEVICE_EXTENSION devExt; // 设备对象扩展
	NTSTATUS status;
	UNICODE_STRING fsName;// 文件驱动名
	WCHAR fsNameBuffer[MAX_DEVNAME_LENGTH];
	UNICODE_STRING fsrecName; // 文件系统识别器名  
	PAGED_CODE();
	
	//
	// 如果不是文件系统类型,则返回
	if(!IS_DESIRED_DEVICE_TYPE(DeviceObject->DeviceType))
	{
		
		return STATUS_SUCCESS;
	}

	//排除文件系统识别器	
	RtlInitEmptyUnicodeString(&fsName,// 关联初始化文件驱动名
		fsNameBuffer,
		sizeof(fsNameBuffer));
	

		// 根据我们不要绑定识别器
		SfGetObjectName(DeviceObject->DriverObject,// 获得指定文件系统的驱动名
			&fsName);
		// 初始化文件系统识别器名
		// 注意,这里是微软标准的文件识别器名
		// 还有不标准的,在控制操作中过滤
		RtlInitUnicodeString(&fsrecName, L"\\FileSystem\\Fs_Rec");
		if (RtlCompareUnicodeString(&fsName, &fsrecName, TRUE) == 0)// 过滤掉微软标准文件识别器
		{
			
			return STATUS_SUCCESS;
		}
	
	status = IoCreateDevice(gSFilterDriverObject,
		sizeof(SFILTER_DEVICE_EXTENSION),
		NULL,
		DeviceObject->DeviceType,
		0,
		FALSE,
		&newDeviceObject);
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	//
	// 下面是复制文件系统控制设备对象的标志到我们新的设备对象上
	// 因为我们新的设备对象要附加到文件系统的设备栈上,所以,我们的
	// 设备对象必须和文件系统的设备对象的标志一致.
	// 这也是设备栈制定的规则吧
	if ( FlagOn( DeviceObject->Flags, DO_BUFFERED_IO ))
	{SetFlag( newDeviceObject->Flags, DO_BUFFERED_IO );}
	if ( FlagOn( DeviceObject->Flags, DO_DIRECT_IO ))
	{SetFlag( newDeviceObject->Flags, DO_DIRECT_IO );}
	if ( FlagOn( DeviceObject->Characteristics, FILE_DEVICE_SECURE_OPEN ) )
	{SetFlag( newDeviceObject->Characteristics, FILE_DEVICE_SECURE_OPEN );}
	// 设备扩展
	devExt = newDeviceObject->DeviceExtension;

	RtlZeroMemory(devExt, sizeof(SFILTER_DEVICE_EXTENSION));
	// 帮定我们的设备对象到文件系统的设备控制对象的设备栈上
	// 注意: 原先设备栈顶端的设备对象,附加后为我们设备对象的下一级设备对象
	// 保存在我们设备对象的设备扩展中.
	status = SfAttachDeviceToDeviceStack(newDeviceObject,
		DeviceObject,
		&devExt->AttachedToDeviceObject);
	if(!NT_SUCCESS(status))
	{
		goto ErrorCleanupDevice;
	}
	// 保存该文件系统控制设备对象
	//这个步骤在sfilter中没有（下面四行有效的代码 两个函数）
	RtlInitEmptyUnicodeString(&devExt->DeviceName,
		devExt->DeviceNameBuffer,
		sizeof(devExt->DeviceNameBuffer));
	RtlCopyUnicodeString(&devExt->DeviceName, DeviceName);


	ASSERT (IS_WINDOWSXP_OR_LATER());
	
		ASSERT(NULL != gSfDynamicFunctions.EnumerateDeviceObjectList &&
			NULL != gSfDynamicFunctions.GetDiskDeviceObject &&
			NULL != gSfDynamicFunctions.GetDeviceAttachmentBaseRef &&
			NULL != gSfDynamicFunctions.GetLowerDeviceObject
			);
		//枚举所有的当前安装的设备 并绑定它们
		status = SfEnumerateFileSystemVolumes(DeviceObject, &fsName);
		if (!NT_SUCCESS(status))
		{
			IoDetachDevice(devExt->AttachedToDeviceObject);
			goto ErrorCleanupDevice;
		}
	
	return STATUS_SUCCESS;
ErrorCleanupDevice:// 错误:
	SfCleanupMountedDevice( newDeviceObject );
	IoDeleteDevice( newDeviceObject );
	return status;
}
VOID
SfDetachFromFileSystemDevice(
			     IN PDEVICE_OBJECT DeviceObject//要分离的文件系统设备
			     )
			     //给予最基本（下层？）的文件系统设备对象，这将扫描附着链寻找我们绑定的设备对象 如果找到就从链中分离
{
	PDEVICE_OBJECT ourAttachedDevice;
//	PSFILTER_DEVICE_EXTENSION devExt;
	PAGED_CODE();
	// 跳过基本的文件系统设备 它们不是我们要的
	ourAttachedDevice = DeviceObject->AttachedDevice;
	while (NULL != ourAttachedDevice) 
	{		//循环找到最下面
		if (IS_MY_DEVICE_OBJECT(ourAttachedDevice)) 
		{	//是我们的设备		
			
			SfCleanupMountedDevice(ourAttachedDevice);
			IoDetachDevice(DeviceObject);//释放该设备
			IoDeleteDevice(ourAttachedDevice);//清除之
			return;// 跳出该函数了  就删掉一个设备
		}

		// 不是我们的设备 所以就继续往下找
		DeviceObject = ourAttachedDevice;
		ourAttachedDevice = ourAttachedDevice->AttachedDevice;
	}
}

NTSTATUS
SfEnumerateFileSystemVolumes (
							  IN PDEVICE_OBJECT FSDeviceObject,//我们要列举的文件系统设备对象
							  IN PUNICODE_STRING Name//已定义的UNICODE字符串用于检索名称 传递这个是为了减少栈上的字符串的个数
							  ) 
							  //列举所有的卷设备（当前在文件系统中的）并绑定它们
							  //这样做是因为过滤驱动会在任何时候加载 这时也许已经有卷在系统中安装了
{
	PDEVICE_OBJECT newDeviceObject;
	PSFILTER_DEVICE_EXTENSION newDevExt;
	PDEVICE_OBJECT *devList;
	PDEVICE_OBJECT storageStackDeviceObject;
	NTSTATUS status;
	ULONG numDevices;
	ULONG i;
	BOOLEAN isShadowCopyVolume;		
	PAGED_CODE();
	status = (gSfDynamicFunctions.EnumerateDeviceObjectList)(//这函数要两次调用 第一次为了寻找要多大的空间
		FSDeviceObject->DriverObject,
		NULL,
		0,
		&numDevices);
	if (NT_SUCCESS( status )) 
	{
		return status;
	}
	ASSERT(STATUS_BUFFER_TOO_SMALL == status);		// 为已知大小的设备链分配内存 
	numDevices += 8;        // 稍微大一些 （防止缓冲区溢出吧!）
	devList = ExAllocatePoolWithTag( 
									NonPagedPool, 
									(numDevices * sizeof(PDEVICE_OBJECT)), 
									SFLT_POOL_TAG );
	if (NULL == devList) 
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	// 获得设备链。出现错误就只能over了
	ASSERT( NULL != gSfDynamicFunctions.EnumerateDeviceObjectList );
	status = (gSfDynamicFunctions.EnumerateDeviceObjectList)(//第二次调用 得到设备的表（链）
															 FSDeviceObject->DriverObject,
															 devList,
															 (numDevices * sizeof(PDEVICE_OBJECT)),
															 &numDevices);
	if (!NT_SUCCESS( status ))  
	{
		ExFreePoolWithTag( devList, SFLT_POOL_TAG );
		return status;
	}
	// 遍历 看我们要绑定哪些        
	for (i=0; i < numDevices; i++) 
	{
		storageStackDeviceObject = NULL;
		try 
		{
			//CDO 不符合的类型 已经绑过的	这三种不用绑了
			if ((devList[i] == FSDeviceObject) ||
				(devList[i]->DeviceType != FSDeviceObject->DeviceType) ||
				SfIsAttachedToDevice( devList[i], NULL )) 
			{
				leave;
			}
			// 看这个设备有名字没有 有的话就说明驱动有超过一个的CDO（如FastFat）
			SfGetBaseDeviceObjectName( devList[i], Name );
			if (Name->Length > 0) 
			{
				leave;
			}
			// 获得真正的（磁盘，存储栈）设备对象与文件系统设备对象有关 如果有一个磁盘设备对象只试着去绑定 
			ASSERT( NULL != gSfDynamicFunctions.GetDiskDeviceObject );
			status = (gSfDynamicFunctions.GetDiskDeviceObject)( devList[i], &storageStackDeviceObject );
			if (!NT_SUCCESS( status )) 
			{
				leave;
			}

			//判断是不是一个卷影 是的话 就不绑定 
			status = SfIsShadowCopyVolume (storageStackDeviceObject, &isShadowCopyVolume );
			if (NT_SUCCESS(status) && isShadowCopyVolume ) 
			{
				UNICODE_STRING shadowDeviceName;
				WCHAR shadowNameBuffer[MAX_DEVNAME_LENGTH];
				// 获得debug名称用于打印 
				RtlInitEmptyUnicodeString( &shadowDeviceName, 
					shadowNameBuffer, 
					sizeof(shadowNameBuffer) );
				SfGetObjectName( storageStackDeviceObject, 
					&shadowDeviceName );
				leave;
			}
			// 分配一个新的设备对象来绑定 
			status = IoCreateDevice( gSFilterDriverObject,
				sizeof( SFILTER_DEVICE_EXTENSION ),
				NULL,
				devList[i]->DeviceType,
				0,
				FALSE,
				&newDeviceObject );
			if (!NT_SUCCESS( status )) 
			{
				leave;
			}
			// 设置磁盘设备对象	
			newDevExt = newDeviceObject->DeviceExtension;
			RtlZeroMemory(newDevExt, sizeof(SFILTER_DEVICE_EXTENSION));
			newDevExt->StorageStackDeviceObject = storageStackDeviceObject;
			// 设置存储栈设备名称
			RtlInitEmptyUnicodeString( &newDevExt->DeviceName,
				newDevExt->DeviceNameBuffer,
				sizeof(newDevExt->DeviceNameBuffer) );
			SfGetObjectName( storageStackDeviceObject, 
				&newDevExt->DeviceName );
			//最后一步测试看是否我们已绑定了这个设备对象
			//在有锁的情况下再次测试 如果没绑定进行绑定 锁用来进行原子测试
			ExAcquireFastMutex( &gSfilterAttachLock );
			if (!SfIsAttachedToDevice( devList[i], NULL )) 
			{
				//  绑定到卷
				status = SfAttachToMountedDevice( devList[i], 
					newDeviceObject );
				if (!NT_SUCCESS( status )) 
				{ 
					//绑定失败 清除
					SfCleanupMountedDevice( newDeviceObject );
					IoDeleteDevice( newDeviceObject );
				}
				
			} 
			else 
			{
				//我们绑定了 清除这个设备对象
				SfCleanupMountedDevice( newDeviceObject );
				IoDeleteDevice( newDeviceObject );
			}
			//释放锁
			ExReleaseFastMutex( &gSfilterAttachLock );
		} 
		finally 
		{
			if (storageStackDeviceObject != NULL) 
			{
				ObDereferenceObject( storageStackDeviceObject );
			}
			//减少计数 IoEnumerateDeviceObjectList)
			ObDereferenceObject( devList[i] );
		}
	}
	//绑定时我们将无视任何错误  出现错误时我们简单的不去绑定任何卷
	status = STATUS_SUCCESS;
	// 释放我们分配的表的内存
	ExFreePoolWithTag( devList, SFLT_POOL_TAG );
	return status;
}


NTSTATUS
SfAttachToMountedDevice (
			 IN PDEVICE_OBJECT DeviceObject,
			 IN PDEVICE_OBJECT SFilterDeviceObject
			 )
{
	PSFILTER_DEVICE_EXTENSION newDevExt = SFilterDeviceObject->DeviceExtension;
	NTSTATUS status;
	ULONG i;
	PAGED_CODE();
	ASSERT(IS_MY_DEVICE_OBJECT( SFilterDeviceObject ));
	ASSERT(!SfIsAttachedToDevice ( DeviceObject, NULL ));
	// 设备标记的复制
	if (FlagOn( DeviceObject->Flags, DO_BUFFERED_IO )) {
		SetFlag( SFilterDeviceObject->Flags, DO_BUFFERED_IO );
	}
	if (FlagOn( DeviceObject->Flags, DO_DIRECT_IO )) {
		SetFlag( SFilterDeviceObject->Flags, DO_DIRECT_IO );
	}
	// 循环尝试绑定.绑定有可能失败。这可能和其他用户恰好试图对这个磁盘做特殊的操作比如
	// mount 或者dismount 有关.反复进行8 次尝试以避开这些巧合.
	for (i=0; i < 8; i++) 
	{
		LARGE_INTEGER interval;
		status = SfAttachDeviceToDeviceStack( SFilterDeviceObject,
			DeviceObject,
			&newDevExt->AttachedToDeviceObject );
		if (NT_SUCCESS(status)) 
		{
			ClearFlag( SFilterDeviceObject->Flags, DO_DEVICE_INITIALIZING );
			return STATUS_SUCCESS;
		}
		// 把这个线程延迟500 毫秒后再继续.
		interval.QuadPart = (500 * DELAY_ONE_MILLISECOND);
		KeDelayExecutionThread ( KernelMode, FALSE, &interval );
	}
	return status;
}


VOID
SfCleanupMountedDevice (
			IN PDEVICE_OBJECT DeviceObject
			)
//清理任何必要的存在于设备扩展中的数据 以释放内存
{        
	
	UNREFERENCED_PARAMETER( DeviceObject );
	ASSERT(IS_MY_DEVICE_OBJECT( DeviceObject ));
}


VOID 
SfGetObjectName   ( 
		   IN   PVOID   Object, 
		   IN   OUT   PUNICODE_STRING   Name 
		   ) 
{ 
	NTSTATUS   status; 
	CHAR   nibuf[512];              //buffer   that   receives   NAME   information   and   name 
	POBJECT_NAME_INFORMATION  nameInfo=(POBJECT_NAME_INFORMATION)nibuf; 
	ULONG   retLength; 
	status=ObQueryNameString(Object,nameInfo,sizeof(nibuf),&retLength); 
	Name->Length=0; 
	if(NT_SUCCESS(status))
	{ 
		RtlCopyUnicodeString(Name,&nameInfo->Name); 
		KdPrint(("SfGetObjectName &nameInfo->Name=%wZ\n",&nameInfo-> Name));
	} 
}


VOID
SfGetBaseDeviceObjectName (
			   IN PDEVICE_OBJECT DeviceObject,//我们想要其名称的设备对象指针
			   IN OUT PUNICODE_STRING Name//已经初始化过的缓冲区 存放设备对象名称
			   )
			   //位于给定的绑定链基本的文件对象 并返回对象名 如果没有找到名称 返回空
			   // 这个基地位于设备对象在给定的附件链，然后
			   // 返回该对象的名称。 
			   // 如果没有任何可以找到的名字，一个空字符串返回。
{
	//  获得基本的文件系统设备对象
	ASSERT( NULL != gSfDynamicFunctions.GetDeviceAttachmentBaseRef );
	DeviceObject = (gSfDynamicFunctions.GetDeviceAttachmentBaseRef)( DeviceObject );
	//获得对象名称
	SfGetObjectName( DeviceObject, Name );
	//减少因调用IoGetDeviceAttachmentBaseRef而增加的计数
	ObDereferenceObject( DeviceObject );
}


PUNICODE_STRING
SfGetFileName(//获得文件名 这个确保随时返回一个可打印的字符串（也可能是NULL） 如果需要将会分配缓冲区
	      IN PFILE_OBJECT FileObject,
	      IN NTSTATUS CreateStatus,
	      IN OUT PGET_NAME_CONTROL NameControl
	      )
{
	POBJECT_NAME_INFORMATION nameInfo;
	NTSTATUS status;
	ULONG size;
	ULONG bufferSize;
	// 还没有分配缓冲区
	NameControl->allocatedBuffer = NULL;
	//用结构体中小的缓冲区存放名称
	nameInfo = (POBJECT_NAME_INFORMATION)NameControl->smallBuffer;
	bufferSize = sizeof(NameControl->smallBuffer);
	//如果打开成功 获得文件名 若失败返回的设备名
	status = ObQueryNameString(
		((NT_SUCCESS( CreateStatus ) ?(PVOID)FileObject:(PVOID)FileObject->DeviceObject)),
		nameInfo,
		bufferSize,
		&size );
	//查看缓冲区是否小
	if (status == STATUS_INFO_LENGTH_MISMATCH) { //STATUS_BUFFER_OVERFLOW
		//小的话就分配足够大的
		bufferSize = size + sizeof(WCHAR);
		NameControl->allocatedBuffer = ExAllocatePoolWithTag( 
			NonPagedPool,
			bufferSize,
			SFLT_POOL_TAG );
   
		if (NULL == NameControl->allocatedBuffer) 
		{
			//缓冲区分配失败 返回名字为空的字符串
			RtlInitEmptyUnicodeString(
				(PUNICODE_STRING)&NameControl->smallBuffer,
				(PWCHAR)(NameControl->smallBuffer + sizeof(UNICODE_STRING)),
				(USHORT)(sizeof(NameControl->smallBuffer) - sizeof(UNICODE_STRING)) );
			return (PUNICODE_STRING)&NameControl->smallBuffer;
		}     
		RtlZeroMemory(NameControl->allocatedBuffer,bufferSize);
		//设置分配的缓冲区 再次获取名称
		nameInfo = (POBJECT_NAME_INFORMATION)NameControl->allocatedBuffer;
		status = ObQueryNameString(
			FileObject,
			nameInfo,
			bufferSize,
			&size );
	}
	//若我们获得一个名字并打开文件错误那么我们获取设备名
	//在文件对象中得到其他的名称（注意 只有在Create被调用时才执行）
	// 只在我们的以错误返回create时才发生 
	if (NT_SUCCESS( status ) && 
		!NT_SUCCESS( CreateStatus )) {
		ULONG newSize;
		PCHAR newBuffer;
		POBJECT_NAME_INFORMATION newNameInfo;
		//计算需要存放名称联合的缓冲区的大小
		newSize = size + FileObject->FileName.Length;
		//如果相关的文件对象增加 
		//  If there is a related file object add in the length
		//  of that plus space for a separator
		//
		if (NULL != FileObject->RelatedFileObject) {
			newSize += FileObject->RelatedFileObject->FileName.Length + 
				sizeof(WCHAR);
		}
		//  See if it will fit in the existing buffer
		if (newSize > bufferSize) {
			//  It does not fit, allocate a bigger buffer
			newBuffer = ExAllocatePoolWithTag( 
				NonPagedPool,
				newSize,
				SFLT_POOL_TAG );
			if (NULL == newBuffer) 
			{
				// 分配内存失败 返回一个名称的空字符串
				RtlInitEmptyUnicodeString(
					(PUNICODE_STRING)&NameControl->smallBuffer,
					(PWCHAR)(NameControl->smallBuffer + sizeof(UNICODE_STRING)),
					(USHORT)(sizeof(NameControl->smallBuffer) - sizeof(UNICODE_STRING)) );
				return (PUNICODE_STRING)&NameControl->smallBuffer;
			}
			RtlZeroMemory(newBuffer,newSize);
			//用旧的缓冲区的内容初始化新的缓冲区 
			newNameInfo = (POBJECT_NAME_INFORMATION)newBuffer;
			RtlInitEmptyUnicodeString(
				&newNameInfo->Name,
				(PWCHAR)(newBuffer + sizeof(OBJECT_NAME_INFORMATION)),
				(USHORT)(newSize - sizeof(OBJECT_NAME_INFORMATION)) );
			RtlCopyUnicodeString( &newNameInfo->Name, 
				&nameInfo->Name );
			// 释放旧的缓冲区 Free the old allocated buffer (if there is one)
			//  and save off the new allocated buffer address.  It
			//  would be very rare that we should have to free the
			//  old buffer because device names should always fit
			//  inside it.
			if (NULL != NameControl->allocatedBuffer) 
			{
				ExFreePool( NameControl->allocatedBuffer );
			}
			//  Readjust our pointers
			NameControl->allocatedBuffer = newBuffer;
			bufferSize = newSize;
			nameInfo = newNameInfo;
		} else 
		{
			//  The MaximumLength was set by ObQueryNameString to
			//  one char larger then the length.  Set it to the
			//  true size of the buffer (so we can append the names)
			nameInfo->Name.MaximumLength = (USHORT)(bufferSize - 
				sizeof(OBJECT_NAME_INFORMATION));
		}
		//如果有相关的文件对象 首先附加名称到到设备对象with a 分隔符
		if (NULL != FileObject->RelatedFileObject) 
		{
			RtlAppendUnicodeStringToString(
				&nameInfo->Name,
				&FileObject->RelatedFileObject->FileName );
			RtlAppendUnicodeToString( &nameInfo->Name, L"\\" );
		}
		//文件对象附加名称
		RtlAppendUnicodeStringToString(
			&nameInfo->Name,
			&FileObject->FileName );
		ASSERT(nameInfo->Name.Length <= nameInfo->Name.MaximumLength);//名称大小没有溢出
	}
	//	返回名称
	return &nameInfo->Name;
}


VOID
SfGetFileNameCleanup(//查看缓冲区是否被分配 若是的话则释放
		     IN OUT PGET_NAME_CONTROL NameControl//用于检索名称的控制结构
		     )
{
	if (NULL != NameControl->allocatedBuffer) {
		ExFreePool( NameControl->allocatedBuffer);
		NameControl->allocatedBuffer = NULL;
	}
}



BOOLEAN
SfIsAttachedToDevice (
		      PDEVICE_OBJECT DeviceObject,
		      PDEVICE_OBJECT *AttachedDeviceObject OPTIONAL
		      )
{
	PDEVICE_OBJECT currentDevObj;
	PDEVICE_OBJECT nextDevObj;
	PAGED_CODE();
	// 	ASSERT( NULL != gSfDynamicFunctions.GetLowerDeviceObject &&
	// 		NULL != gSfDynamicFunctions.GetDeviceAttachmentBaseRef );
	// 获得绑定链顶层的设备对象 
	ASSERT(NULL != gSfDynamicFunctions.GetAttachedDeviceReference);
	currentDevObj = (gSfDynamicFunctions.GetAttachedDeviceReference)(DeviceObject);
	do {//向下遍历链表 找到我们的设备对象
		if (IS_MY_DEVICE_OBJECT( currentDevObj ))
		{
			if (ARGUMENT_PRESENT(AttachedDeviceObject))
			{//判断是否为NULL
				*AttachedDeviceObject = currentDevObj;
			} 
			else 
			{
				ObDereferenceObject( currentDevObj );
			}
			return TRUE;
		}
		//  获得下一个绑定的对象 Get the next attached object.  This puts a reference on 
		//  the device object.
		ASSERT( NULL != gSfDynamicFunctions.GetLowerDeviceObject );
		nextDevObj = (gSfDynamicFunctions.GetLowerDeviceObject)( currentDevObj );
		//指向下一个前将计数减少  
		ObDereferenceObject( currentDevObj );
		currentDevObj = nextDevObj;
	} while (NULL != currentDevObj);
	//没有在绑定链上发现我们自己的 返回空 和返回没有找到 
	if (ARGUMENT_PRESENT(AttachedDeviceObject)) 
	{//若不为空 就让它为空
		*AttachedDeviceObject = NULL;
	}
	return FALSE;
}    



NTSTATUS
SfIsShadowCopyVolume (//查看StorageStackDeviceObject是否为卷影
		      IN PDEVICE_OBJECT StorageStackDeviceObject,
		      OUT PBOOLEAN IsShadowCopy
		      )
{
	PAGED_CODE();
	*IsShadowCopy = FALSE;

	if (IS_WINDOWSXP()) 
	{
		UNICODE_STRING volSnapDriverName;
		WCHAR buffer[MAX_DEVNAME_LENGTH];
		PUNICODE_STRING storageDriverName;
		ULONG returnedLength;
		NTSTATUS status;
		//  In Windows XP所有的卷影类型都是FILE_DISK_DEVICE.反之则不成立
		if (FILE_DEVICE_DISK != StorageStackDeviceObject->DeviceType) 
		{
			return STATUS_SUCCESS;
		}
		//  还要查看驱动名称是否为 \Driver\VolSnap 
		storageDriverName = (PUNICODE_STRING) buffer;
		RtlInitEmptyUnicodeString( storageDriverName, 
			Add2Ptr( storageDriverName, sizeof( UNICODE_STRING ) ),
			sizeof( buffer ) - sizeof( UNICODE_STRING ) );
		status = ObQueryNameString( StorageStackDeviceObject,
			(POBJECT_NAME_INFORMATION)storageDriverName,
			storageDriverName->MaximumLength,
			&returnedLength );
		if (!NT_SUCCESS( status )) 
		{
			return status;
		}
		RtlInitUnicodeString( &volSnapDriverName, L"\\Driver\\VolSnap" );
		if (RtlEqualUnicodeString( storageDriverName, &volSnapDriverName, TRUE ))
		{
			//是卷影 所以设置返回值真 
			*IsShadowCopy = TRUE;
		} else 
		{
			// 不是卷影
			NOTHING;
		}
		
	} 
	return STATUS_SUCCESS;
}


//
//sfilter提供的两个回调函数接口
//
NTSTATUS
SfPreFsFilterPassThrough(
			 IN PFS_FILTER_CALLBACK_DATA Data,
			 OUT PVOID *CompletionContext
			 )
{
	UNREFERENCED_PARAMETER( Data );
	UNREFERENCED_PARAMETER( CompletionContext );
	
	ASSERT( IS_MY_DEVICE_OBJECT( Data->DeviceObject ) );
	
	return STATUS_SUCCESS;
}

VOID
SfPostFsFilterPassThrough (
			   IN PFS_FILTER_CALLBACK_DATA Data,
			   IN NTSTATUS OperationStatus,
			   IN PVOID CompletionContext
			   )
{
	UNREFERENCED_PARAMETER( Data );
	UNREFERENCED_PARAMETER( OperationStatus );
	UNREFERENCED_PARAMETER( CompletionContext );
	
	ASSERT( IS_MY_DEVICE_OBJECT( Data->DeviceObject ) );
}




NTSTATUS
SfQuerySymbolicLink(
					IN  PUNICODE_STRING SymbolicLinkName,
					OUT PUNICODE_STRING LinkTarget
					)			  
//这是用于获取符号链接名的函数									
{
    HANDLE Handle;
    OBJECT_ATTRIBUTES ObjAttribute;
    NTSTATUS Status;

	//初始化OBJECT_ATTRIBUTES结构体 
    InitializeObjectAttributes(
							   &ObjAttribute, 
							   SymbolicLinkName, 
							   OBJ_CASE_INSENSITIVE,
							   0, 
							   0);
	
	//试图打开设备  获取句柄
    Status = ZwOpenSymbolicLinkObject(&Handle, GENERIC_READ, &ObjAttribute);
    if (!NT_SUCCESS(Status))
        return Status;
	
    LinkTarget->MaximumLength = 200*sizeof(WCHAR);
    LinkTarget->Length = 0;
    LinkTarget->Buffer = ExAllocatePool(PagedPool, LinkTarget->MaximumLength);
    if (!LinkTarget->Buffer)
    {
        ZwClose(Handle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
	
	//通过句柄获取链接名
    Status = ZwQuerySymbolicLinkObject(Handle, LinkTarget, NULL);
    ZwClose(Handle);
	
    if (!NT_SUCCESS(Status))
        ExFreePool(LinkTarget->Buffer);
	
    return Status;
}

NTSTATUS
SfVolumeDeviceNameToDosName(
							IN PUNICODE_STRING VolumeDeviceName,
							OUT PUNICODE_STRING DosName
							)
//这个函数返回dosname，当不需要时must call ExFreePool on DosName->Buffer																	
{
    WCHAR Buffer[30]=L"\\??\\C:";
    UNICODE_STRING DriveLetterName;
    UNICODE_STRING LinkTarget;
    WCHAR Char;
    NTSTATUS Status;


    RtlInitUnicodeString(&DriveLetterName, Buffer);
	
    for (Char = 'A'; Char <= 'Z'; Char++)
    {
        DriveLetterName.Buffer[4] = Char;
		
        Status = SfQuerySymbolicLink(&DriveLetterName, &LinkTarget);
        if (!NT_SUCCESS(Status))
            continue;
		
        if (RtlEqualUnicodeString(&LinkTarget, VolumeDeviceName, TRUE))
        {
            ExFreePool(LinkTarget.Buffer);
            break;
        }
		
        ExFreePool(LinkTarget.Buffer);
    }
	
    if (Char <= 'Z')
    {
        DosName->Buffer = ExAllocatePool(PagedPool, 3*sizeof(WCHAR));
        if (!DosName->Buffer)
            return STATUS_INSUFFICIENT_RESOURCES;
		
        DosName->MaximumLength = 6;
        DosName->Length = 4;
        DosName->Buffer[0] = Char;
        DosName->Buffer[1] = ':';
        DosName->Buffer[2] = 0;
		
        return STATUS_SUCCESS;
    }
	
    return STATUS_UNSUCCESSFUL;
}
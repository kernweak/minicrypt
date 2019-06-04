//#include "list.c"

#include "control.c"
#pragma warning(error:4100)   // Unreferenced formal parameter
#pragma warning(error:4101)   // Unreferenced local variable

/////////////////////////////////////////////////////////////////////////////
//
//                  一些定义
//
/////////////////////////////////////////////////////////////////////////////

//
//Add2Ptr指针相加
//
#ifndef Add2Ptr		
#define Add2Ptr(P,I) ((PVOID)((PUCHAR)(P) + (I)))
#endif

//
//设备名最大长度
//
#define MAX_DEVNAME_LENGTH 64

//
//操作系统版本判断
//
#define IS_WINDOWSXP() \
((gSfOsMajorVersion == 5) && (gSfOsMinorVersion == 1))

#define IS_WINDOWSXP_OR_LATER() \
	(((gSfOsMajorVersion == 5) && (gSfOsMinorVersion >= 1)) || \
(gSfOsMajorVersion > 5))

//
//  内存申请时的标签
//
#define SFLT_POOL_TAG   'trFS'


//
//KeDelayExecutionThread()函数等待的时间定义
//
#define DELAY_ONE_MICROSECOND   (-10)
#define DELAY_ONE_MILLISECOND   (DELAY_ONE_MICROSECOND*1000)
#define DELAY_ONE_SECOND        (DELAY_ONE_MILLISECOND*1000)

//
//判断是否我们创建的设备对象
//
#define IS_MY_DEVICE_OBJECT(_devObj) \
	(((_devObj) != NULL) && \
	((_devObj)->DriverObject == gSFilterDriverObject) && \
	((_devObj)->DeviceExtension != NULL))

//
//判断是否我们创建的控制设备对象
//
#define IS_MY_CONTROL_DEVICE_OBJECT(_devObj) \
	(((_devObj) == gSFilterControlDeviceObject) ? \
	(ASSERT(((_devObj)->DriverObject == gSFilterDriverObject) && \
	((_devObj)->DeviceExtension == NULL)), TRUE) : \
	FALSE)

//
//判断设备对象类型
//
#define IS_DESIRED_DEVICE_TYPE(_type) \
	(((_type) == FILE_DEVICE_DISK_FILE_SYSTEM) || \
	((_type) == FILE_DEVICE_CD_ROM_FILE_SYSTEM) || \
	((_type) == FILE_DEVICE_NETWORK_FILE_SYSTEM))


//
//FASTIO
//
#define VALID_FAST_IO_DISPATCH_HANDLER(_FastIoDispatchPtr, _FieldName) \
	(((_FastIoDispatchPtr) != NULL) && \
	(((_FastIoDispatchPtr)->SizeOfFastIoDispatch) >= \
	(FIELD_OFFSET(FAST_IO_DISPATCH, _FieldName) + sizeof(void *))) && \
	((_FastIoDispatchPtr)->_FieldName != NULL))



//
//给一个设备类型 返回一个有用的名称
//
#define GET_DEVICE_TYPE_NAME( _type ) \
	((((_type) > 0) && ((_type) < (sizeof(DeviceTypeNames) / sizeof(PCHAR)))) ? \
	DeviceTypeNames[ (_type) ] : \
	"[Unknown]")






//*****************************************************************************************************







/////////////////////////////////////////////////////////////////////////////
//
//                  typedef
//以下函数指针组成结构体 有助于版本移植 因为不同版本下这些函数的入口地址可能不同
/////////////////////////////////////////////////////////////////////////////

typedef
NTSTATUS
(*PSF_REGISTER_FILE_SYSTEM_FILTER_CALLBACKS) (
					      IN PDRIVER_OBJECT DriverObject,
					      IN PFS_FILTER_CALLBACKS Callbacks
					      );
typedef
NTSTATUS
(*PSF_ENUMERATE_DEVICE_OBJECT_LIST) (
				     IN  PDRIVER_OBJECT DriverObject,
				     IN  PDEVICE_OBJECT *DeviceObjectList,
				     IN  ULONG DeviceObjectListSize,
				     OUT PULONG ActualNumberDeviceObjects
				     );
typedef
NTSTATUS
(*PSF_ATTACH_DEVICE_TO_DEVICE_STACK_SAFE) (
					   IN PDEVICE_OBJECT SourceDevice,
					   IN PDEVICE_OBJECT TargetDevice,
					   OUT PDEVICE_OBJECT *AttachedToDeviceObject
					   );
typedef    
PDEVICE_OBJECT
(*PSF_GET_LOWER_DEVICE_OBJECT) (
				IN  PDEVICE_OBJECT  DeviceObject
				);
typedef
PDEVICE_OBJECT
(*PSF_GET_DEVICE_ATTACHMENT_BASE_REF) (
				       IN PDEVICE_OBJECT DeviceObject
				       );
typedef
NTSTATUS
(*PSF_GET_DISK_DEVICE_OBJECT) (
			       IN  PDEVICE_OBJECT  FileSystemDeviceObject,
			       OUT PDEVICE_OBJECT  *DiskDeviceObject
			       );
typedef
PDEVICE_OBJECT
(*PSF_GET_ATTACHED_DEVICE_REFERENCE) (
				      IN PDEVICE_OBJECT DeviceObject
				      );
typedef
NTSTATUS
(*PSF_GET_VERSION) (
		    IN OUT PRTL_OSVERSIONINFOW VersionInformation
		    );



/////////////////////////////////////////////////////////////////////////////
//
//                  结构体
//
/////////////////////////////////////////////////////////////////////////////


//
// 文件过滤系统驱动的设备扩展
//
typedef struct _SFILTER_DEVICE_EXTENSION 
{
	// 我们所绑定的文件系统设备
	PDEVICE_OBJECT AttachedToDeviceObject;
	
	// 与我们的文件系统设备相关的真实设备（磁盘），这个用于绑定时使用。
	PDEVICE_OBJECT StorageStackDeviceObject;
	
	// 如果我们绑定了一个卷，这是物理磁盘卷名。否则这是我们绑定的控制设备名。
	UNICODE_STRING DeviceName;
	
	// 用来保存名字字符串的缓冲区
	WCHAR DeviceNameBuffer[MAX_DEVNAME_LENGTH];

	WCHAR DriveLetter;
} SFILTER_DEVICE_EXTENSION, *PSFILTER_DEVICE_EXTENSION;


//
//函数指针组成的结构体 可以获取以下函数的入口地址 见SfLoadDynamicFunctions
//
typedef struct _SF_DYNAMIC_FUNCTION_POINTERS 
{
	
	PSF_REGISTER_FILE_SYSTEM_FILTER_CALLBACKS RegisterFileSystemFilterCallbacks;	//FsRtlRegisterFileSystemFilterCallbacks
	PSF_ATTACH_DEVICE_TO_DEVICE_STACK_SAFE AttachDeviceToDeviceStackSafe;			//IoEnumerateDeviceObjectList
	PSF_ENUMERATE_DEVICE_OBJECT_LIST EnumerateDeviceObjectList;						//IoGetLowerDeviceObject
	PSF_GET_LOWER_DEVICE_OBJECT GetLowerDeviceObject;								//IoGetLowerDeviceObject
	PSF_GET_DEVICE_ATTACHMENT_BASE_REF GetDeviceAttachmentBaseRef;					//IoGetDeviceAttachmentBaseRef
	PSF_GET_DISK_DEVICE_OBJECT GetDiskDeviceObject;									//IoGetDiskDeviceObject
	PSF_GET_ATTACHED_DEVICE_REFERENCE GetAttachedDeviceReference;					//IoGetAttachedDeviceReference
	PSF_GET_VERSION GetVersion;														//RtlGetVersion
} SF_DYNAMIC_FUNCTION_POINTERS, *PSF_DYNAMIC_FUNCTION_POINTERS;



//这个结构体和这些例程用来获得文件对象的名称
//来防止每次分配内存获得名称 这个结构体包含一个小缓冲区（将存放90+%全部名称）  
//如果溢出了这个缓冲区 我们将会分配一个足够大的

typedef struct _GET_NAME_CONTROL 
{
	PCHAR allocatedBuffer;
	CHAR smallBuffer[256];    
} GET_NAME_CONTROL, *PGET_NAME_CONTROL;


typedef struct tag_QUERY_DIRECTORY
{
	ULONG Length;
	PUNICODE_STRING FileName;
	FILE_INFORMATION_CLASS FileInformationClass;
	ULONG FileIndex;
} QUERY_DIRECTORY, *PQUERY_DIRECTORY;
 
typedef struct _HIDE_OBJECT
{
 	LIST_ENTRY linkfield;//listentry 双向链表	
 	WCHAR	Name[256];//存放名称
 	ULONG	Flag;//标志  为HIDE_FLAG_FILE或HIDE_FLAG_DIRECTORY
} HIDE_FILE, *PHIDE_FILE;//该数据结构用于存放要隐藏的文件的信息
 
typedef struct _HIDE_DIRECTOR
{
	LIST_ENTRY linkfield;
	LIST_ENTRY link;
	WCHAR fatherPath[1024];
}HIDE_DIRECTOR,*PHIDE_DIRECTOR;


/////////////////////////////////////////////////////////////////////////////
//
//                 全局变量
//
/////////////////////////////////////////////////////////////////////////////



SF_DYNAMIC_FUNCTION_POINTERS gSfDynamicFunctions = {0};

//
//版本号
//
ULONG gSfOsMajorVersion = 0;//主要的版本号
ULONG gSfOsMinorVersion = 0;//副的

//
//存放本驱动的驱动对象
//
PDRIVER_OBJECT gSFilterDriverObject = NULL;

//
//CDO指针
//
PDEVICE_OBJECT gSFilterControlDeviceObject = NULL;


//
//这个锁用来同步绑定的设备对象 
//
FAST_MUTEX gSfilterAttachLock;//快速互斥体


//应用层是否获取logbuf的控制按钮
//BOOL gLogOn;



//
//已知的设备类型名称
//
static const PCHAR DeviceTypeNames[] =
{
		"",
		"BEEP",
		"CD_ROM",
		"CD_ROM_FILE_SYSTEM",
		"CONTROLLER",
		"DATALINK",
		"DFS",
		"DISK",
		"DISK_FILE_SYSTEM",
		"FILE_SYSTEM",
		"INPORT_PORT",
		"KEYBOARD",
		"MAILSLOT",
		"MIDI_IN",
		"MIDI_OUT",
		"MOUSE",
		"MULTI_UNC_PROVIDER",
		"NAMED_PIPE",
		"NETWORK",
		"NETWORK_BROWSER",
		"NETWORK_FILE_SYSTEM",
		"NULL",
		"PARALLEL_PORT",
		"PHYSICAL_NETCARD",
		"PRINTER",
		"SCANNER",
		"SERIAL_MOUSE_PORT",
		"SERIAL_PORT",
		"SCREEN",
		"SOUND",
		"STREAMS",
		"TAPE",
		"TAPE_FILE_SYSTEM",
		"TRANSPORT",
		"UNKNOWN",
		"VIDEO",
		"VIRTUAL_DISK",
		"WAVE_IN",
		"WAVE_OUT",
		"8042_PORT",
		"NETWORK_REDIRECTOR",
		"BATTERY",
		"BUS_EXTENDER",
		"MODEM",
		"VDM",
		"MASS_STORAGE",
		"SMB",
		"KS",
		"CHANGER",
		"SMARTCARD",
		"ACPI",
		"DVD",
		"FULLSCREEN_VIDEO",
		"DFS_FILE_SYSTEM",
		"DFS_VOLUME",
		"SERENUM",
		"TERMSRV",
		"KSEC"
};



/////////////////////////////////////////////////////////////////////////////
//
//                 函数的声明
//
/////////////////////////////////////////////////////////////////////////////

PUNICODE_STRING
SfGetFileName(
	      IN PFILE_OBJECT FileObject,
	      IN NTSTATUS CreateStatus,
	      IN OUT PGET_NAME_CONTROL NameControl
	      );
VOID
SfGetFileNameCleanup(
		     IN OUT PGET_NAME_CONTROL NameControl
		     );


NTSTATUS
DriverEntry(
	    IN PDRIVER_OBJECT DriverObject,
	    IN PUNICODE_STRING RegistryPath
	    );

#if DBG
VOID
DriverUnload(
	     IN PDRIVER_OBJECT DriverObject
	     );
#endif
VOID
SfLoadDynamicFunctions (
			);
VOID
SfGetCurrentVersion (
		     );
NTSTATUS
SfPassThrough(
	      IN PDEVICE_OBJECT DeviceObject,
	      IN PIRP Irp
	      );
NTSTATUS
SfDeviceIOControl(
		  IN PDEVICE_OBJECT DeviceObject,
		  IN PIRP Irp
		  );
NTSTATUS
SfCreate(
	 IN PDEVICE_OBJECT DeviceObject,
	 IN PIRP Irp
	 );
NTSTATUS
SfCreateCompletion(
		   IN PDEVICE_OBJECT DeviceObject,
		   IN PIRP Irp,
		   IN PVOID Context
		   );
NTSTATUS
SfCleanup(
	  IN PDEVICE_OBJECT DeviceObject,
	  IN PIRP Irp
	  );
NTSTATUS
SfClose(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	);
NTSTATUS
SfFsControl(
	    IN PDEVICE_OBJECT DeviceObject,
	    IN PIRP Irp
	    );
NTSTATUS
SfFsControlMountVolume (
			IN PDEVICE_OBJECT DeviceObject,
			IN PIRP Irp
			);
////////////////////////////////////////////////////////////////////////////
NTSTATUS
SfDirectoryControl(
		   IN PDEVICE_OBJECT DeviceObject,
		   IN PIRP Irp
		   );
NTSTATUS
SfDirectoryControlCompletion(
			     IN PDEVICE_OBJECT DeviceObject,
			     IN PIRP Irp,
			     IN PVOID Context
			     );
NTSTATUS
SfSetInformation(
		 IN PDEVICE_OBJECT DeviceObject,
		 IN PIRP Irp
		 );
NTSTATUS
SfSetInformationCompletion(
			   IN PDEVICE_OBJECT DeviceObject,
			   IN PIRP Irp,
			   IN PVOID Context
			   );

NTSTATUS
SfWrite(
		IN PDEVICE_OBJECT DeviceObject,
		IN PIRP Irp
		);
NTSTATUS
SfRead(
	   IN PDEVICE_OBJECT DeviceObject,
	   IN PIRP Irp
	   );
NTSTATUS
SfWriteCompletion (
				   IN PDEVICE_OBJECT DeviceObject,
				   IN PIRP Irp,
				   IN PVOID Context
				   );
NTSTATUS
SfReadCompletion (
				  IN PDEVICE_OBJECT DeviceObject,
				  IN PIRP Irp,
				  IN PVOID Context
				  );

NTSTATUS
SfQueryInformation(
				   IN PDEVICE_OBJECT DeviceObject,
				   IN PIRP Irp
				   );

NTSTATUS
SfQueryInformationCompletion(
							 IN PDEVICE_OBJECT DeviceObject,
							 IN PIRP Irp,
							 IN PVOID Context
			               );

NTSTATUS
SfFsControlMountVolumeComplete (
				IN PDEVICE_OBJECT DeviceObject,
				IN PIRP Irp,
				IN PDEVICE_OBJECT NewDeviceObject
				);
NTSTATUS
SfFsControlLoadFileSystem (
			   IN PDEVICE_OBJECT DeviceObject,
			   IN PIRP Irp
			   );
NTSTATUS
SfFsControlLoadFileSystemComplete (
				   IN PDEVICE_OBJECT DeviceObject,
				   IN PIRP Irp
				   );
NTSTATUS
SfFsControlCompletion(
		      IN PDEVICE_OBJECT DeviceObject,
		      IN PIRP Irp,
		      IN PVOID Context
		      );



BOOLEAN
SfFastIoCheckIfPossible(
			IN PFILE_OBJECT FileObject,
			IN PLARGE_INTEGER FileOffset,
			IN ULONG Length,
			IN BOOLEAN Wait,
			IN ULONG LockKey,
			IN BOOLEAN CheckForReadOperation,
			OUT PIO_STATUS_BLOCK IoStatus,
			IN PDEVICE_OBJECT DeviceObject
			);
BOOLEAN
SfFastIoRead(
	     IN PFILE_OBJECT FileObject,
	     IN PLARGE_INTEGER FileOffset,
	     IN ULONG Length,
	     IN BOOLEAN Wait,
	     IN ULONG LockKey,
	     OUT PVOID Buffer,
	     OUT PIO_STATUS_BLOCK IoStatus,
	     IN PDEVICE_OBJECT DeviceObject
	     );
BOOLEAN
SfFastIoWrite(
	      IN PFILE_OBJECT FileObject,
	      IN PLARGE_INTEGER FileOffset,
	      IN ULONG Length,
	      IN BOOLEAN Wait,
	      IN ULONG LockKey,
	      IN PVOID Buffer,
	      OUT PIO_STATUS_BLOCK IoStatus,
	      IN PDEVICE_OBJECT DeviceObject
	      );
BOOLEAN
SfFastIoQueryBasicInfo(
		       IN PFILE_OBJECT FileObject,
		       IN BOOLEAN Wait,
		       OUT PFILE_BASIC_INFORMATION Buffer,
		       OUT PIO_STATUS_BLOCK IoStatus,
		       IN PDEVICE_OBJECT DeviceObject
		       );
BOOLEAN
SfFastIoQueryStandardInfo(
			  IN PFILE_OBJECT FileObject,
			  IN BOOLEAN Wait,
			  OUT PFILE_STANDARD_INFORMATION Buffer,
			  OUT PIO_STATUS_BLOCK IoStatus,
			  IN PDEVICE_OBJECT DeviceObject
			  );
BOOLEAN
SfFastIoLock(
	     IN PFILE_OBJECT FileObject,
	     IN PLARGE_INTEGER FileOffset,
	     IN PLARGE_INTEGER Length,
	     PEPROCESS ProcessId,
	     ULONG Key,
	     BOOLEAN FailImmediately,
	     BOOLEAN ExclusiveLock,
	     OUT PIO_STATUS_BLOCK IoStatus,
	     IN PDEVICE_OBJECT DeviceObject
	     );
BOOLEAN
SfFastIoUnlockSingle(
		     IN PFILE_OBJECT FileObject,
		     IN PLARGE_INTEGER FileOffset,
		     IN PLARGE_INTEGER Length,
		     PEPROCESS ProcessId,
		     ULONG Key,
		     OUT PIO_STATUS_BLOCK IoStatus,
		     IN PDEVICE_OBJECT DeviceObject
		     );
BOOLEAN
SfFastIoUnlockAll(
		  IN PFILE_OBJECT FileObject,
		  PEPROCESS ProcessId,
		  OUT PIO_STATUS_BLOCK IoStatus,
		  IN PDEVICE_OBJECT DeviceObject
		  );
BOOLEAN
SfFastIoUnlockAllByKey(
		       IN PFILE_OBJECT FileObject,
		       PVOID ProcessId,
		       ULONG Key,
		       OUT PIO_STATUS_BLOCK IoStatus,
		       IN PDEVICE_OBJECT DeviceObject
		       );
BOOLEAN
SfFastIoDeviceControl(
		      IN PFILE_OBJECT FileObject,
		      IN BOOLEAN Wait,
		      IN PVOID InputBuffer OPTIONAL,
		      IN ULONG InputBufferLength,
		      OUT PVOID OutputBuffer OPTIONAL,
		      IN ULONG OutputBufferLength,
		      IN ULONG IoControlCode,
		      OUT PIO_STATUS_BLOCK IoStatus,
		      IN PDEVICE_OBJECT DeviceObject
		      );
VOID
SfFastIoDetachDevice(
		     IN PDEVICE_OBJECT SourceDevice,
		     IN PDEVICE_OBJECT TargetDevice
		     );
BOOLEAN
SfFastIoQueryNetworkOpenInfo(
			     IN PFILE_OBJECT FileObject,
			     IN BOOLEAN Wait,
			     OUT PFILE_NETWORK_OPEN_INFORMATION Buffer,
			     OUT PIO_STATUS_BLOCK IoStatus,
			     IN PDEVICE_OBJECT DeviceObject
			     );
BOOLEAN
SfFastIoMdlRead(
		IN PFILE_OBJECT FileObject,
		IN PLARGE_INTEGER FileOffset,
		IN ULONG Length,
		IN ULONG LockKey,
		OUT PMDL *MdlChain,
		OUT PIO_STATUS_BLOCK IoStatus,
		IN PDEVICE_OBJECT DeviceObject
		);
BOOLEAN
SfFastIoMdlReadComplete(
			IN PFILE_OBJECT FileObject,
			IN PMDL MdlChain,
			IN PDEVICE_OBJECT DeviceObject
			);
BOOLEAN
SfFastIoPrepareMdlWrite(
			IN PFILE_OBJECT FileObject,
			IN PLARGE_INTEGER FileOffset,
			IN ULONG Length,
			IN ULONG LockKey,
			OUT PMDL *MdlChain,
			OUT PIO_STATUS_BLOCK IoStatus,
			IN PDEVICE_OBJECT DeviceObject
			);
BOOLEAN
SfFastIoMdlWriteComplete(
			 IN PFILE_OBJECT FileObject,
			 IN PLARGE_INTEGER FileOffset,
			 IN PMDL MdlChain,
			 IN PDEVICE_OBJECT DeviceObject
			 );
BOOLEAN
SfFastIoReadCompressed(
		       IN PFILE_OBJECT FileObject,
		       IN PLARGE_INTEGER FileOffset,
		       IN ULONG Length,
		       IN ULONG LockKey,
		       OUT PVOID Buffer,
		       OUT PMDL *MdlChain,
		       OUT PIO_STATUS_BLOCK IoStatus,
		       OUT struct _COMPRESSED_DATA_INFO *CompressedDataInfo,
		       IN ULONG CompressedDataInfoLength,
		       IN PDEVICE_OBJECT DeviceObject
		       );
BOOLEAN
SfFastIoWriteCompressed(
			IN PFILE_OBJECT FileObject,
			IN PLARGE_INTEGER FileOffset,
			IN ULONG Length,
			IN ULONG LockKey,
			IN PVOID Buffer,
			OUT PMDL *MdlChain,
			OUT PIO_STATUS_BLOCK IoStatus,
			IN struct _COMPRESSED_DATA_INFO *CompressedDataInfo,
			IN ULONG CompressedDataInfoLength,
			IN PDEVICE_OBJECT DeviceObject
			);
BOOLEAN
SfFastIoMdlReadCompleteCompressed(
				  IN PFILE_OBJECT FileObject,
				  IN PMDL MdlChain,
				  IN PDEVICE_OBJECT DeviceObject
				  );
BOOLEAN
SfFastIoMdlWriteCompleteCompressed(
				   IN PFILE_OBJECT FileObject,
				   IN PLARGE_INTEGER FileOffset,
				   IN PMDL MdlChain,
				   IN PDEVICE_OBJECT DeviceObject
				   );
BOOLEAN
SfFastIoQueryOpen(
		  IN PIRP Irp,
		  OUT PFILE_NETWORK_OPEN_INFORMATION NetworkInformation,
		  IN PDEVICE_OBJECT DeviceObject
		  );
NTSTATUS
SfPreFsFilterPassThrough (
			  IN PFS_FILTER_CALLBACK_DATA Data,
			  OUT PVOID *CompletionContext
			  );

VOID
SfPostFsFilterPassThrough (
			   IN PFS_FILTER_CALLBACK_DATA Data,
			   IN NTSTATUS OperationStatus,
			   IN PVOID CompletionContext
			   );
VOID
SfFsNotification(
		 IN PDEVICE_OBJECT DeviceObject,
		 IN BOOLEAN FsActive
		 );
NTSTATUS
SfAttachDeviceToDeviceStack (
			     IN PDEVICE_OBJECT SourceDevice,
			     IN PDEVICE_OBJECT TargetDevice,
			     IN OUT PDEVICE_OBJECT *AttachedToDeviceObject
			     );
NTSTATUS
SfAttachToFileSystemDevice(
			   IN PDEVICE_OBJECT DeviceObject,
			   IN PUNICODE_STRING DeviceName
			   );
VOID
SfDetachFromFileSystemDevice (
			      IN PDEVICE_OBJECT DeviceObject
			      );
NTSTATUS
SfAttachToMountedDevice (
			 IN PDEVICE_OBJECT DeviceObject,
			 IN PDEVICE_OBJECT SFilterDeviceObject
			 );
VOID
SfCleanupMountedDevice(
		       IN PDEVICE_OBJECT DeviceObject
		       );

NTSTATUS
SfEnumerateFileSystemVolumes(
			     IN PDEVICE_OBJECT FSDeviceObject,
			     IN PUNICODE_STRING FSName
			     );
VOID
SfGetObjectName(
		IN PVOID Object,
		IN OUT PUNICODE_STRING Name
		);
VOID
SfGetBaseDeviceObjectName(
			  IN PDEVICE_OBJECT DeviceObject,
			  IN OUT PUNICODE_STRING DeviceName
			  );
BOOLEAN
SfIsAttachedToDevice(
		     PDEVICE_OBJECT DeviceObject,
		     PDEVICE_OBJECT *AttachedDeviceObject OPTIONAL
		     );

NTSTATUS
SfIsShadowCopyVolume (
		      IN PDEVICE_OBJECT StorageStackDeviceObject,
		      OUT PBOOLEAN IsShadowCopy
		      );

NTSTATUS
SfVolumeDeviceNameToDosName(
							IN PUNICODE_STRING VolumeDeviceName,
							OUT PUNICODE_STRING DosName
							);

//////////////////////////////////////////////////////////////////////////



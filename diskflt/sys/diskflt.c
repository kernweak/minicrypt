
#include <ntddk.h>
#include <ntdddisk.h>
#include <windef.h>
#include <stdio.h>
#include <stdarg.h>
#include <ntddvol.h>
#include "ntifs.h"
#include "GenericTable.h"

#include "fatlbr.h"

#include "diskfltlib.h"

#include "ntimage.h"
#include "mempool/mempool.h"
#include "diskflt.h"
#include "md5.h"
#include "notify.h"

#define RTL_CONSTANT_STRING(s) { sizeof( s ) - sizeof( (s)[0] ), sizeof( s ), s}
#define	__free_Safe(_buffer)	{if (_buffer)__free(_buffer);}

#define dprintf	if (DBG) DbgPrint


typedef struct {
	
    LARGE_INTEGER StartingLcn;
    LARGE_INTEGER BitmapSize;
    BYTE  Buffer[1];
	
} VOLUME_BITMAP_BUFFER, *PVOLUME_BITMAP_BUFFER;

typedef struct {
	
    LARGE_INTEGER StartingLcn;
	
} STARTING_LCN_INPUT_BUFFER, *PSTARTING_LCN_INPUT_BUFFER;

#ifndef _countof
#define _countof(_Array) (sizeof(_Array) / sizeof(_Array[0]))
#endif

typedef struct _PAIR
{
	ULONGLONG	orgIndex;	// 原始簇地址
	ULONGLONG	mapIndex;		// 重定向后的地址
} PAIR, *PPAIR;


typedef struct _FILTER_DEVICE_EXTENSION
{
	// 是否在保护状态
	BOOL					Protect;
	//这个卷上的保护系统使用的请求队列
	LIST_ENTRY				list_head;
	//这个卷上的保护系统使用的请求队列的锁
	KSPIN_LOCK				list_lock;
	//这个卷上的保护系统使用的请求队列的同步事件
	KEVENT					ReqEvent;
	//这个卷上的保护系统使用的请求队列的处理线程之线程句柄
	PVOID					thread_read_write;
	CLIENT_ID				thread_read_write_id;

	// 回收线程
//	PVOID					thread_reclaim;	
//	CLIENT_ID				thread_reclaim_id;
	//统使用的请求队列的处理线程之结束标志
	BOOLEAN					terminate_thread;
} FILTER_DEVICE_EXTENSION, *PFILTER_DEVICE_EXTENSION;


typedef struct _DP_BITMAP_
{
	ULONG		bitMapSize;
	// 每个块代表多少位
    ULONG		regionSize;
	// 每个块占多少byte
	ULONG		regionBytes;
	// 这个bitmap总共有多少个块
    ULONG		regionNumber;
	// 指向bitmap存储空间的指针
    UCHAR **	buffer; 
} DP_BITMAP, * PDP_BITMAP;


typedef struct _VOLUME_INFO
{
	BOOLEAN		isValid;			// 是否有效
	BOOLEAN		isProtect;			// 是否保护该卷
//	BOOLEAN		isDiskFull;			// 磁盘是否已经用完

	WCHAR		volume;				// 卷标

	ULONG		diskNumber;			// 此卷所在的硬盘号

	DWORD		partitionNumber;	// 分区索引
	BYTE		partitionType;		// 分区类型
	BOOLEAN		bootIndicator;		// 是否启动分区

	LONGLONG	physicalStartingOffset;		// 分区在磁盘里的偏移也就是开始地址

	LONGLONG	bytesTotal;			// 这个卷的总大小，以byte为单位
	ULONG		bytesPerSector;		// 每个扇区的大小
	ULONG		bytesPerCluster;	// 每簇大小
	ULONGLONG	firstDataSector;	// 第一个扇区的开始地址，也指位图上第一个簇的开始地址,NTFS固定为0,FAT专有

	
	//这个卷设备对应的过滤设备的下层设备对象
	PDEVICE_OBJECT	LowerDevObj;

	// 此卷逻辑上有多少个簇
	ULONGLONG		sectorCount;
	
	// 标记空闲簇 空闲簇bit为0, 初始化的时候复制bitMap_OR
	PDP_BITMAP		bitMap_Free;
	// 标记簇是否重定向
	PDP_BITMAP		bitMap_Redirect;
	// 直接放过读写的簇(force write)，如pagefile.sys hiberfil.sys, 位图跟是磁盘逻辑位图的一小部分
	PDP_BITMAP		bitMap_Protect;
	
	// 上次扫描的空闲簇的位置
	ULONGLONG		last_scan_index;
	
	// 簇重定向表
	RTL_GENERIC_TABLE	redirectMap;

} VOLUME_INFO, *PVOLUME_INFO;


PROTECT_INFO	_protectInfo = {MAGIC_CHAR, 0, 0, 0};
// 卷的全局信息
VOLUME_INFO		_volumeList[MAX_DOS_DRIVES];

// 硬盘下层设备对像信息
PDEVICE_OBJECT	_lowerDeviceObject[MAX_DOS_DRIVES];

PFILTER_DEVICE_EXTENSION	_deviceExtension = NULL;

ULONG	_processNameOfffset = 0;
ULONG	_systemProcessId = 0;

// 拒绝加载驱动
BOOL	_sysPatchEnable = FALSE;


// 锁定此进程可以穿透diskflt.sys修改配置
ULONG	_lockProcessId = -1;

// 位图一次最多申请2M
#define SLOT_SIZE	(1024 * 1024 * 2)

void DPBitMap_Free(DP_BITMAP * bitmap)
{
	//释放bitmap
	DWORD i = 0;
	
	if (NULL != bitmap)
	{
		if (NULL != bitmap->buffer)
		{
			for (i = 0; i < bitmap->regionNumber; i++)
			{
				if (NULL != bitmap->buffer[i])
				{
					//从最底层的块开始释放，所有块都轮询一次				
					__free(bitmap->buffer[i]);
				}
			}
			//释放块的指针
			__free(bitmap->buffer);
		}	
		//释放bitmap本身
		__free(bitmap);
	}
}

NTSTATUS
DPBitMap_Create(
	DP_BITMAP ** bitmap,	// 位图句柄指针
	ULONGLONG bitMapSize,	// 位图有多少个单位
	ULONGLONG regionBytes	// 位图粒度，分成N块，一块占多少byte
	)	
{
	NTSTATUS	status = STATUS_UNSUCCESSFUL;
	int		i = 0;
	DP_BITMAP *	myBitmap = NULL;

	//检查参数，以免使用了错误的参数导致发生处零错等错误
	if (NULL == bitmap || 0 == regionBytes  || 0 == bitMapSize)
	{
		return status;
	}
	__try
	{
		*bitmap = NULL;
		//分配一个bitmap结构，这是无论如何都要分配的，这个结构相当于一个bitmap的handle	
		if (NULL == (myBitmap = (DP_BITMAP *)__malloc(sizeof(DP_BITMAP))))
		{
			__leave;
		}
		
		//清空结构
		memset(myBitmap, 0, sizeof(DP_BITMAP));

		myBitmap->regionSize = regionBytes * 8;
		if (myBitmap->regionSize > bitMapSize)
		{
			myBitmap->regionSize = bitMapSize / 2;
		}
		//根据参数对结构中的成员进行赋值
		myBitmap->bitMapSize = bitMapSize;
		myBitmap->regionBytes = (myBitmap->regionSize / 8) + sizeof(int);

		myBitmap->regionNumber = bitMapSize / myBitmap->regionSize;
		if (bitMapSize % myBitmap->regionSize)
		{
			myBitmap->regionNumber++;
		}

		//分配出regionNumber那么多个指向region的指针，这是一个指针数组
		if (NULL == (myBitmap->buffer = (UCHAR **)__malloc(sizeof(UCHAR *) * myBitmap->regionNumber)))
		{
			__leave;
		}
		//清空指针数组
		memset(myBitmap->buffer, 0, sizeof(UCHAR *) * myBitmap->regionNumber);
		*bitmap = myBitmap;
		status = STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		status = GetExceptionCode();
	}
	if (!NT_SUCCESS(status))
	{
		if (NULL != myBitmap)
		{
			DPBitMap_Free(myBitmap);
		}
		*bitmap = NULL;
	}
	return status;
}


ULONGLONG
DPBitMap_FindNext(DP_BITMAP * bitMap, ULONGLONG startIndex, BOOL set)
{
	LONG	jmpValue = set ? 0 : 0xFFFFFFFF;
	ULONG	slot = 0;
	
	// 遍历slot
	for (slot = startIndex / bitMap->regionSize; slot < bitMap->regionNumber; slot++)
	{
		ULONGLONG	max = 0;
		
		// 还没有分配
		if (!bitMap->buffer[slot])
		{
			if (set)
			{
				startIndex = (slot + 1) * bitMap->regionSize;
				continue;
			}
			else
			{
				return startIndex;
			}
		}
		
		for (max = min((slot + 1) * bitMap->regionSize, bitMap->bitMapSize); 
		startIndex < max; )
		{
			ULONG	sIndex = startIndex % bitMap->regionSize;

			// 查找下一个置位的索引

			if (jmpValue == ((PULONG)bitMap->buffer[slot])[sIndex / 32])
			{
				// 快速跳越
				startIndex += 32 - (sIndex % 32);
				continue;
			}
			
			if (set == ((((PULONG)bitMap->buffer[slot])[sIndex / 32] & (1 << (sIndex % 32))) > 0))
			{
				// 找到
				return startIndex;
			}	
			startIndex++;
		}
	}
	
	return -1;
}

NTSTATUS
DPBitMap_Set(DP_BITMAP * bitMap, ULONGLONG index, BOOL set)
{
	ULONG	slot = index / bitMap->regionSize;
	if (slot > (bitMap->regionNumber-1))
	{
		dprintf("DPBitMap_Set out of range slot %d\n", slot);
		return STATUS_UNSUCCESSFUL;
	}

	if (!bitMap->buffer[slot])
	{
		if (!set)
		{
			return STATUS_SUCCESS;
		}
		bitMap->buffer[slot] = (UCHAR *)__malloc(bitMap->regionBytes);
		if (!bitMap->buffer[slot])
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		memset(bitMap->buffer[slot], 0, bitMap->regionBytes);
	}
	
	index %= bitMap->regionSize;
	
    if (set)
        ((ULONG *)bitMap->buffer[slot])[index / 32] |= (1 << (index % 32));
    else
        ((ULONG *)bitMap->buffer[slot])[index / 32] &= ~(1 << (index % 32));

	return STATUS_SUCCESS;
}

BOOL
DPBitMap_Test(DP_BITMAP * bitMap, ULONGLONG index)
{
	ULONG	slot = index / bitMap->regionSize;
	if (slot > (bitMap->regionNumber-1))
	{
		dprintf("DPBitMap_Test out of range slot %d\n", slot);
		return FALSE;
	}
	// 还没分配
	if (!bitMap->buffer[slot])
	{
		return FALSE;
	}

	index %= bitMap->regionSize;	

	return (((ULONG *)bitMap->buffer[slot])[index / 32] & (1 << (index % 32)) ? TRUE : FALSE);
}

NTSTATUS
ksleep(ULONG microSecond)
{
	LARGE_INTEGER	timeout = RtlConvertLongToLargeInteger(-10000 * microSecond);
	KeDelayExecutionThread(KernelMode, FALSE, &timeout);
	return STATUS_SUCCESS;
}

/*
void cls()
{
	UCHAR SpareColor = 4;   // blue
	UCHAR BackColor = 3;    // green
	UCHAR TextColor = 15;   // white

	if (InbvIsBootDriverInstalled())
	{
		InbvAcquireDisplayOwnership();

		InbvResetDisplay();

		// c:\boot.ini 里如果在启动上加上了 /noguiboot, 就不会显示开机load界面
		// 驱动打印出来的字体上面也不会有windows的logo效果

		//InbvSolidColorFill(0, 0, 639, 479, SpareColor);         // blue, 640x480

		InbvSetTextColor(TextColor);

	//	InbvInstallDisplayStringFilter(NULL);
		InbvEnableDisplayString(TRUE);
	}
}

ULONG
kprintf(const char *fmt, ...) 
{
	va_list args;
	int ret;
	char buff[1024];

	va_start(args, fmt);
	ret = _vsnprintf(buff, sizeof(buff), fmt, args);
	va_end(args);

	InbvDisplayString(buff);

	return ret;
}

*/
PVOID getFileClusterList(HANDLE hFile)
{
	
	NTSTATUS status;
	IO_STATUS_BLOCK iosb;
	LARGE_INTEGER StartVcn;
	PRETRIEVAL_POINTERS_BUFFER pVcnPairs;
	ULONG ulOutPutSize = 0;
	ULONG uCounts = 200;
	
	StartVcn.QuadPart=0;
	ulOutPutSize = sizeof(RETRIEVAL_POINTERS_BUFFER) + uCounts* sizeof(pVcnPairs->Extents)+sizeof(LARGE_INTEGER);
	pVcnPairs = (RETRIEVAL_POINTERS_BUFFER *)__malloc(ulOutPutSize);
	if(pVcnPairs == NULL)
	{
		return NULL;
	}
	
	while( (status = ZwFsControlFile( hFile,NULL, NULL, 0, &iosb,
		FSCTL_GET_RETRIEVAL_POINTERS,
		&StartVcn, sizeof(LARGE_INTEGER),
		pVcnPairs, ulOutPutSize ) ) == STATUS_BUFFER_OVERFLOW)
	{
		uCounts+=200;
		ulOutPutSize = sizeof(RETRIEVAL_POINTERS_BUFFER) + uCounts* sizeof(pVcnPairs->Extents)+sizeof(LARGE_INTEGER);
		__free(pVcnPairs);
		
		pVcnPairs = (RETRIEVAL_POINTERS_BUFFER *)__malloc(ulOutPutSize);
		if(pVcnPairs == NULL)
		{
			dprintf("__malloc %d bytes faild", ulOutPutSize);
			return FALSE;
		}
	}
	
	if(!NT_SUCCESS(status))
	{
		dprintf(" --ZwFsControlFile --->> FSCTL_GET_RETRIEVAL_POINTERS  failed");
		dprintf(" --status %x",status);
		__free(pVcnPairs);
		return NULL;
	}
	
	return pVcnPairs;
}



//--------------------------------------------------------------------------------------
PVOID GetSysInf(SYSTEM_INFORMATION_CLASS InfoClass)
{    
    NTSTATUS ns;
    ULONG RetSize, Size = 0x100;
    PVOID Info;
	
    while (1) 
    {    
        if ((Info = __malloc(Size)) == NULL) 
        {
            dprintf("__malloc() fails\n");
            return NULL;
        }
		
        ns = ZwQuerySystemInformation(InfoClass, Info, Size, &RetSize);
        if (ns == STATUS_INFO_LENGTH_MISMATCH)
        {       
            __free(Info);
            Size += 0x100;
        }
        else
		{
            break;    
		}
    }
	
    if (!NT_SUCCESS(ns))
    {
        dprintf("ZwQuerySystemInformation() fails; status: 0x%.8x\n", ns);
		
        if (Info)
		{
            __free(Info);
		}
		
        return NULL;
    }
	
    return Info;
}


HANDLE searchFileHandle(PUNICODE_STRING fileName)
{
	NTSTATUS status;
	ULONG i,sysBuffer =0;
	PSYSTEM_HANDLE_INFORMATION pProcesses;
	POBJECT_NAME_INFORMATION ObjectName;
	
	char ObjectNameBuf[1024];
	ULONG ReturnLen;
	HANDLE hPageFile ;
	
	ObjectName = (POBJECT_NAME_INFORMATION)ObjectNameBuf;
	ObjectName->Name.MaximumLength = 510;
	
	sysBuffer = (ULONG)GetSysInf(SystemHandleInformation);

	if(sysBuffer == NULL)
	{
		dprintf("DiskGetHandleList error\n");
		return (HANDLE)-1;
	}

	pProcesses = (PSYSTEM_HANDLE_INFORMATION)(sysBuffer + 4);
	for (i=0;i<((ULONG)(*(ULONG*)sysBuffer));i++)
    {
		if(pProcesses[i].ProcessId == _systemProcessId)
		{
			status = ZwQueryObject((HANDLE)pProcesses[i].Handle, ObjectNameInfo, 
				ObjectName, sizeof(ObjectNameBuf), &ReturnLen);

	//		dprintf("0x%x > %wZ\n", pProcesses[i].Handle, &ObjectName->Name);
			if(status == 0 && (RtlEqualUnicodeString(&ObjectName->Name, fileName,TRUE)==TRUE))
			{
				hPageFile = (HANDLE)pProcesses[i].Handle;
				__free((PVOID)sysBuffer);
				return hPageFile;
			}
		}
	}
	
	__free((PVOID)sysBuffer);

    return (HANDLE)-1;
}
//--------------------------------------------------------------------------------------
NTSTATUS
RtlAllocateUnicodeString(PUNICODE_STRING us, ULONG maxLength)
{
	NTSTATUS	status = STATUS_UNSUCCESSFUL;
	
    ULONG ulMaximumLength = maxLength;
	
    if (maxLength > 0)
    {
        if ((us->Buffer = (PWSTR)__malloc(ulMaximumLength)) != NULL)
		{
			RtlZeroMemory(us->Buffer, ulMaximumLength);
			
			us->Length = 0;
			us->MaximumLength = (USHORT)maxLength;
			
			status = STATUS_SUCCESS;
		}
		else
		{
			status = STATUS_NO_MEMORY;
		}
    }
	
    return status;
}


NTSTATUS
flt_getFileHandleReadOnly(PHANDLE fileHandle, PUNICODE_STRING fileName)
{
	OBJECT_ATTRIBUTES	oa;
	IO_STATUS_BLOCK IoStatusBlock;
		
	InitializeObjectAttributes(&oa,
		fileName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);
	
	return ZwCreateFile(fileHandle,
		GENERIC_READ | SYNCHRONIZE,
		&oa,
		&IoStatusBlock,
		NULL,
		0,
		FILE_SHARE_READ,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);
}

NTSTATUS
flt_getFatFirstSectorOffset(HANDLE fileHandle, PULONGLONG firstDataSector)
{
	NTSTATUS	status;
	IO_STATUS_BLOCK	IoStatusBlock;
	FAT_LBR		fatLBR = { 0 };

	LARGE_INTEGER	pos;
	pos.QuadPart = 0;

	if (!firstDataSector)
	{
		return STATUS_NOT_FOUND;
	}

	status = ZwReadFile(fileHandle, NULL, NULL, NULL, &IoStatusBlock, &fatLBR, sizeof(fatLBR), &pos, NULL);
	
	if (NT_SUCCESS(status) && sizeof(FAT_LBR) == IoStatusBlock.Information)
	{
		DWORD dwRootDirSectors	= 0;
		DWORD dwFATSz			= 0;
	
		// Validate jump instruction to boot code. This field has two
		// allowed forms: 
		// jmpBoot[0] = 0xEB, jmpBoot[1] = 0x??, jmpBoot[2] = 0x90 
		// and
		// jmpBoot[0] = 0xE9, jmpBoot[1] = 0x??, jmpBoot[2] = 0x??
		// 0x?? indicates that any 8-bit value is allowed in that byte.
		// JmpBoot[0] = 0xEB is the more frequently used format.
		
		if(( fatLBR.wTrailSig       != 0xAA55 ) ||
			( ( fatLBR.pbyJmpBoot[ 0 ] != 0xEB || 
			fatLBR.pbyJmpBoot[ 2 ] != 0x90 ) &&
			( fatLBR.pbyJmpBoot[ 0 ] != 0xE9 ) ) )
		{
			status = STATUS_NOT_FOUND;
			goto __faild;
		}
		
		// Compute first sector offset for the FAT volumes:		


		// First, we determine the count of sectors occupied by the
		// root directory. Note that on a FAT32 volume the BPB_RootEntCnt
		// value is always 0, so on a FAT32 volume dwRootDirSectors is
		// always 0. The 32 in the above is the size of one FAT directory
		// entry in bytes. Note also that this computation rounds up.
		
		dwRootDirSectors = 
			( ( ( fatLBR.bpb.wRootEntCnt * 32 ) + 
			( fatLBR.bpb.wBytsPerSec - 1  ) ) / 
			fatLBR.bpb.wBytsPerSec );
		
		// The start of the data region, the first sector of cluster 2,
		// is computed as follows:
		
		dwFATSz = fatLBR.bpb.wFATSz16;		
		if( !dwFATSz )
			dwFATSz = fatLBR.ebpb32.dwFATSz32;
		

		if( !dwFATSz )
		{
			status = STATUS_NOT_FOUND;
			goto __faild;
		}
		

		// 得到数据区开始，就是第一簇的位置
		*firstDataSector = 
			( fatLBR.bpb.wRsvdSecCnt + 
			( fatLBR.bpb.byNumFATs * dwFATSz ) + 
			dwRootDirSectors );		
		}

	status = STATUS_SUCCESS;
__faild:

	return status;
}

/*
	获取卷信息
	diskNumber
	LowerDevObj

	partitionNumber
	partitionType
	physicalStartingOffset
	bootIndicator
	firstSectorOffset
	bytesPerSector
	bytesPerCluster
	bytesTotal
*/
NTSTATUS
flt_getVolumeInfo(WCHAR volume, PVOLUME_INFO info)
{
	NTSTATUS	status;
	HANDLE		fileHandle;
	UNICODE_STRING	fileName;
	OBJECT_ATTRIBUTES	oa;
	IO_STATUS_BLOCK IoStatusBlock;
	
	WCHAR	volumeDosName[50];

	swprintf(volumeDosName, L"\\??\\%c:", volume);
	
	RtlInitUnicodeString(&fileName, volumeDosName);
	
	InitializeObjectAttributes(&oa,
		&fileName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);
	
	status = ZwCreateFile(&fileHandle,
		GENERIC_ALL | SYNCHRONIZE,
		&oa,
		&IoStatusBlock,
		NULL,
		0,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,	// 同步读写
		NULL,
		0);

	dprintf("open %wZ ret 0x%x\n", &fileName, status);

	if (NT_SUCCESS(status))
	{		
		IO_STATUS_BLOCK				ioBlock;
		PARTITION_INFORMATION		partitionInfo;
		FILE_FS_SIZE_INFORMATION	sizeoInfo;

		ULONG	buff[256];
		PVOLUME_DISK_EXTENTS		diskExtents;

		diskExtents = (PVOLUME_DISK_EXTENTS)buff;

		// 得到此卷所在的硬盘号，不考虑跨盘卷
		status = ZwDeviceIoControlFile( fileHandle, 
			NULL, 
			NULL, 
			NULL, 
			&ioBlock, 
			IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, 
			NULL, 
			0, 
			diskExtents, 
			sizeof(buff)
			);

		if (NT_SUCCESS(status))
		{
			info->diskNumber = diskExtents->Extents[0].DiskNumber;
			// 得到下层设备
			info->LowerDevObj = _lowerDeviceObject[info->diskNumber];
		}

		// 得到此卷的一类型，在物理硬盘的上的偏移等信息

		status = ZwDeviceIoControlFile( fileHandle, 
			NULL, 
			NULL, 
			NULL, 
			&ioBlock, 
			IOCTL_DISK_GET_PARTITION_INFO, 
			NULL, 
			0, 
			&partitionInfo, 
			sizeof(partitionInfo)
			);


		if (NT_SUCCESS(status))
		{
			info->partitionNumber = partitionInfo.PartitionNumber;
			info->partitionType = partitionInfo.PartitionType;
			info->physicalStartingOffset = partitionInfo.StartingOffset.QuadPart;
			info->bootIndicator = partitionInfo.BootIndicator;
			info->firstDataSector = 0;
			
			// FAT分区，获取LBR, 得到第一个簇的偏移
 			if ((PARTITION_FAT_12 == partitionInfo.PartitionType) ||
 				(PARTITION_FAT_16 == partitionInfo.PartitionType) ||
				(PARTITION_HUGE == partitionInfo.PartitionType) ||
				(PARTITION_FAT32 == partitionInfo.PartitionType) ||
 				(PARTITION_FAT32_XINT13 == partitionInfo.PartitionType) ||
				(PARTITION_XINT13 == partitionInfo.PartitionType))
			{
				status = flt_getFatFirstSectorOffset(fileHandle, &info->firstDataSector);
			}
		}

		// 得到簇，扇区等大小
		status = ZwQueryVolumeInformationFile(fileHandle,
			&IoStatusBlock,
			&sizeoInfo,
			sizeof(sizeoInfo),
			FileFsSizeInformation);

		if (NT_SUCCESS(status))
		{
			info->bytesPerSector = sizeoInfo.BytesPerSector;
			info->bytesPerCluster = sizeoInfo.BytesPerSector * sizeoInfo.SectorsPerAllocationUnit;

			// 相乘得到的磁盘大小，不包含LBR等信息
			info->bytesTotal = partitionInfo.PartitionLength.QuadPart;
		}
		
		ZwClose(fileHandle);
	}

	return status;
}

/*
	获取卷位图信息
	diskNumber
	LowerDevObj

	partitionNumber
	partitionType
	physicalStartingOffset
	bootIndicator
	firstSectorOffset
	bytesPerSector
	bytesPerCluster
	bytesTotal
*/
NTSTATUS
flt_getVolumeBitmapInfo(WCHAR volume, PVOLUME_BITMAP_BUFFER * bitMap)
{
	NTSTATUS	status;
	HANDLE		fileHandle;
	UNICODE_STRING	fileName;
	OBJECT_ATTRIBUTES	oa;
	IO_STATUS_BLOCK IoStatusBlock;
	
	WCHAR	volumeDosName[10];
	
	if (NULL == bitMap)
	{
		return STATUS_UNSUCCESSFUL;
	}
	
	swprintf(volumeDosName, L"\\??\\%c:", volume);
	
	RtlInitUnicodeString(&fileName, volumeDosName);
	
	InitializeObjectAttributes(&oa,
		&fileName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);
	
	status = ZwCreateFile(&fileHandle,
		GENERIC_ALL | SYNCHRONIZE,
		&oa,
		&IoStatusBlock,
		NULL,
		0,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,	// 同步读写
		NULL,
		0);

	dprintf("Open %wZ ret 0x%x\n", &fileName, status);
	
	if (NT_SUCCESS(status))
	{		
		IO_STATUS_BLOCK	ioBlock;
		PVOLUME_BITMAP_BUFFER	info;
		STARTING_LCN_INPUT_BUFFER StartingLCN;

		ULONG	BitmapSize = 0;
		
		StartingLCN.StartingLcn.QuadPart = 0;
		
		
		/*
		// 必须锁定此卷, 在得到卷位图前
		status = ZwFsControlFile( fileHandle, 
					NULL, 
					NULL, 
					NULL, 
					&ioBlock, 
					FSCTL_LOCK_VOLUME, 
					NULL, 0, NULL, 0
					);
		
		dprintf("FSCTL_LOCK_VOLUME = 0x%x\n", status);
		
		*/

		do 
		{
			BitmapSize += 10240;
			
			info = (PVOLUME_BITMAP_BUFFER)__malloc(BitmapSize);
			// 内存不够用
			if (!info)
			{
				status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}
			
			status = ZwFsControlFile( fileHandle, 
				NULL, 
				NULL, 
				NULL, 
				&ioBlock, 
				FSCTL_GET_VOLUME_BITMAP, 
				&StartingLCN,
				sizeof (StartingLCN),
				info, 
				BitmapSize
				);

			if (STATUS_BUFFER_OVERFLOW == status)
			{
				__free(info);
			}
			
		} while(STATUS_BUFFER_OVERFLOW == status);
		
		dprintf("FSCTL_GET_VOLUME_BITMAP ret 0x%x\n", status);

		if (!NT_SUCCESS(status))
		{
			if (info)
			{
				__free(info);
			}
			*bitMap = NULL;
		}
		else
		{
			dprintf("%c: bitMapinfo (%d / %d) cluster = %I64d\n", volume, ioBlock.Information, BitmapSize, info->BitmapSize.QuadPart);

			*bitMap = info;
		}

		
		/*
		status = ZwFsControlFile( fileHandle, 
			NULL, 
			NULL, 
			NULL, 
			&ioBlock, 
			FSCTL_UNLOCK_VOLUME, 
			NULL, 0, NULL, 0
				);

		dprintf("FSCTL_UNLOCK_VOLUME ret 0x%x\n", status);
		*/
		

		ZwClose(fileHandle);
	}
	
	return status;
}

NTSTATUS
flt_SendToNextDriver(
				   IN	PDEVICE_OBJECT	TgtDevObj,
				   IN	PIRP			Irp
				   )
{	
	//跳过当前的irp stack
	IoSkipCurrentIrpStackLocation(Irp);
	//调用目标设备来处理这个irp
	return IoCallDriver(TgtDevObj, Irp);
}

NTSTATUS
flt_CompleteRequest(
				  IN	PIRP			Irp,
				  IN	NTSTATUS		Status,
				  IN	CCHAR			Priority
				  )
{	
	//将IRP的io状态赋值为传入的参数
	Irp->IoStatus.Status = Status;
	//调用IoCompleteRequest来完成这个Irp
	IoCompleteRequest(Irp, Priority);
	return STATUS_SUCCESS;
}


RTL_GENERIC_COMPARE_RESULTS
NTAPI CompareRoutine(
					 struct _RTL_GENERIC_TABLE *Table,
					 PVOID FirstStruct,
					 PVOID SecondStruct
					 )
{
	PPAIR first = (PPAIR) FirstStruct;
	PPAIR second = (PPAIR) SecondStruct;
	
	UNREFERENCED_PARAMETER(Table);

	if (first->orgIndex < second->orgIndex)
		return GenericLessThan;
	else if (first->orgIndex > second->orgIndex)
		return GenericGreaterThan;
	else
		return GenericEqual;
}

PVOID NTAPI AllocateRoutine (
							 struct _RTL_GENERIC_TABLE *Table,
							 LONG ByteSize
							 )
{
	UNREFERENCED_PARAMETER(Table);

	return __malloc(ByteSize);
}

VOID
NTAPI FreeRoutine (
				   struct _RTL_GENERIC_TABLE *Table,
				   PVOID Buffer
				   )
{
	
	UNREFERENCED_PARAMETER(Table);
	
	__free(Buffer);
}

BOOL bitmap_test (ULONG * bitMap, ULONGLONG index)
{
	//	return ((BYTE *)BitmapDetail)[Cluster / 8] & (1 << (Cluster % 8));
	return ((bitMap[index / 32] & (1 << (index % 32))) ? TRUE : FALSE);   
}

void bitmap_set (ULONG * bitMap, ULONGLONG index, BOOL Used)
{
    if (Used)
        bitMap[index / 32] |= (1 << (index % 32));
    else
        bitMap[index / 32] &= ~(1 << (index % 32));
}


// 位图填充为可以直接读写的文件的簇
NTSTATUS
setBitmapDirectRWFile(WCHAR volume, WCHAR * path, PDP_BITMAP bitmap)
{
	NTSTATUS	status;
	HANDLE	linkHandle = NULL;
	HANDLE	linkHandle1 = NULL;
	OBJECT_ATTRIBUTES	oa;
	ULONG	ret;
	BOOLEAN	needClose = FALSE;
	BOOLEAN	needFree = FALSE;
	UNICODE_STRING	symbol;
	UNICODE_STRING	target;
	WCHAR	tempBuffer[256];
	
	PVOID lpFileObject = NULL;
	HANDLE fileHandle = (HANDLE)-1;
	
	ULONG   Cls, r;
	LARGE_INTEGER PrevVCN, Lcn;	
	PRETRIEVAL_POINTERS_BUFFER pVcnPairs = NULL;

	PEPROCESS	eProcess = NULL;
	if (!NT_SUCCESS( PsLookupProcessByProcessId((PVOID)_systemProcessId, &eProcess)))
	{
		goto __faild;
	}

	ObDereferenceObject(eProcess);
	// 注意，要切入到系统进程获取句柄
	KeAttachProcess(eProcess);

	swprintf(tempBuffer, L"\\??\\%c:%ls", volume, path);

	RtlInitUnicodeString(&target, tempBuffer);

	// 直接打开失败，尝试从句柄表中获取

	status = flt_getFileHandleReadOnly(&fileHandle, &target);
	if (NT_SUCCESS(status))
	{
		needClose = TRUE;
	}
	// 访问拒绝，尝试从HANDLE表中获取
	else if (STATUS_SHARING_VIOLATION == status)
	{
		dprintf("Try to open %wZ from handle list\n", &target);

		swprintf(tempBuffer, L"\\??\\%c:", volume);
		
		RtlInitUnicodeString(&symbol, tempBuffer);
		
		RtlAllocateUnicodeString(&target, 1024);

		needFree = TRUE;
		

		InitializeObjectAttributes(&oa,
			&symbol,
			OBJ_CASE_INSENSITIVE,
			NULL,
			NULL);
		
		// 将\\??\\C:映射为真实路径\\Device\\HarddiskVolume1 这样的路径
		
		status = ZwOpenSymbolicLinkObject(&linkHandle, GENERIC_READ, &oa);
		
		if (!NT_SUCCESS(status))
		{
			dprintf("ZwOpenSymbolicLinkObject %wZ fail 0x%x\n", &symbol, status);
			goto __faild;
		}
		
		status = ZwQuerySymbolicLinkObject(linkHandle, &target, &ret);
		
		if (!NT_SUCCESS(status))
		{
			dprintf("ZwQuerySymbolicLinkObject %wZ fail 0x%x\n", &symbol, status);
			goto __faild;
		}

		while (1)
		{
			// 看是否查询出来的路径指向的还是symbolicLink
			InitializeObjectAttributes(&oa,
				&target,
				OBJ_CASE_INSENSITIVE,
				NULL,
				NULL);
			
			// 将\\??\\C:映射为真实路径\\Device\\HarddiskVolume1 这样的路径
			
			status = ZwOpenSymbolicLinkObject(&linkHandle1, GENERIC_READ, &oa);
			
			// 他奶奶地，又指向了symbollink,靠
			if (NT_SUCCESS(status))
			{
				dprintf("SymbolicLink > SymbolicLink\n");
				ZwClose(linkHandle);
				linkHandle = linkHandle1;
				status = ZwQuerySymbolicLinkObject(linkHandle, &target, &ret);
				if (!NT_SUCCESS(status))
				{
					goto __faild;
				}			
			}
			else
			{
				break;
			}
		}
		
		// 合并路径
		
		RtlAppendUnicodeToString(&target, path);
	
		fileHandle = searchFileHandle(&target);

		needClose = FALSE;
	}
	
	if((HANDLE)-1 == fileHandle)
	{
		dprintf("getFileHandle %wZ fail\n", &target);
		goto __faild;
	}
	
	pVcnPairs = getFileClusterList(fileHandle);
	
	if(NULL == pVcnPairs)
	{
		dprintf("getFileClusterList fail\n");
		goto __faild;
	}
	
	PrevVCN = pVcnPairs->StartingVcn;
	for (r = 0, Cls = 0; r < pVcnPairs->ExtentCount; r++)
	{
		ULONG	CnCount;
		Lcn = pVcnPairs->Extents[r].Lcn;
		
		for (CnCount = (ULONG)(pVcnPairs->Extents[r].NextVcn.QuadPart - PrevVCN.QuadPart);
		CnCount; CnCount--, Cls++, Lcn.QuadPart++) 
		{
			// 设置位图
			DPBitMap_Set(bitmap, Lcn.QuadPart, TRUE);
		}
		
		PrevVCN = pVcnPairs->Extents[r].NextVcn;
	}

	dprintf("set %wZ force RW bit map success\n", &target);
	
	__free_Safe(pVcnPairs);
	
__faild:
	
	if (linkHandle)
		ZwClose(linkHandle);

	if (needClose && ((HANDLE)-1 != fileHandle))
		ZwClose(fileHandle);

	if (needFree)
		__free_Safe(target.Buffer);

	if (eProcess)
	{
		KeDetachProcess();		
	}
	
	return status;
}


// from wdk wdm.h
#define SL_KEY_SPECIFIED                0x01
#define SL_OVERRIDE_VERIFY_VOLUME       0x02
#define SL_WRITE_THROUGH                0x04
#define SL_FT_SEQUENTIAL_WRITE          0x08
#define SL_FORCE_DIRECT_WRITE           0x10


NTSTATUS 
FltReadWriteSectorsCompletion( 
	IN PDEVICE_OBJECT DeviceObject, 
	IN PIRP Irp, 
	IN PVOID Context 
	) 
	/*++ 
	Routine Description: 
	A completion routine for use when calling the lower device objects to 
	which our filter deviceobject is attached. 

	Arguments: 

	DeviceObject - Pointer to deviceobject 
	Irp        - Pointer to a PnP Irp. 
	Context    - NULL or PKEVENT 
	Return Value: 

	NT Status is returned. 

	--*/ 
{ 
    PMDL    mdl; 
	
    UNREFERENCED_PARAMETER(DeviceObject); 
	
    // 
    // Free resources 
    // 
	
    if (Irp->AssociatedIrp.SystemBuffer && (Irp->Flags & IRP_DEALLOCATE_BUFFER)) { 
        __free(Irp->AssociatedIrp.SystemBuffer); 
    } 
	
	if (Irp->IoStatus.Status)
	{
		DbgPrint("!!!!!!!!!!Read Or Write HD Error Code====0x%x\n", Irp->IoStatus.Status);
	}
	/*
	因为这个 IRP 就是在我这层次建立的，上层本就不知道有这么一个 IRP。
	那么到这里我就要在 CompleteRoutine 中使用 IoFreeIrp()来释放掉这个 IRP，
	并返回STATUS_MORE_PROCESSING_REQUIRED不让它继续传递。这里一定要注意，
	在 CompleteRoutine函数返回后，这个 IRP 已经释放了，
	如果这个时候在有任何关于这个 IRP 的操作那么后果是灾难性的，必定导致 BSOD 错误。
	*/
    while (Irp->MdlAddress) { 
        mdl = Irp->MdlAddress; 
        Irp->MdlAddress = mdl->Next; 
        MmUnlockPages(mdl); 
        IoFreeMdl(mdl); 
    } 
	
    if (Irp->PendingReturned && (Context != NULL)) { 
        *Irp->UserIosb = Irp->IoStatus; 
        KeSetEvent((PKEVENT) Context, IO_DISK_INCREMENT, FALSE); 
    } 
	
    IoFreeIrp(Irp); 
	
    // 
    // Don't touch irp any more 
    // 
    return STATUS_MORE_PROCESSING_REQUIRED; 
} 


NTSTATUS 
fastFsdRequest( 
	IN PDEVICE_OBJECT DeviceObject, 
	ULONG majorFunction,
	IN LONGLONG ByteOffset,
	OUT PVOID Buffer, 
	IN ULONG Length, 			    
	IN BOOLEAN Wait 
	)
{ 
    PIRP                irp; 
    IO_STATUS_BLOCK        iosb; 
    KEVENT                event; 
    NTSTATUS            status; 
	
	//
    irp = IoBuildAsynchronousFsdRequest(majorFunction, DeviceObject, 
        Buffer, Length, (PLARGE_INTEGER) &ByteOffset, &iosb); 
    if (!irp) { 
        return STATUS_INSUFFICIENT_RESOURCES; 
    } 

	// vista 对直接磁盘写入进行了保护, 驱动操作需要在IRP的FLAGS加上SL_FORCE_DIRECT_WRITE标志
	/*
	If the SL_FORCE_DIRECT_WRITE flag is set, kernel-mode drivers can write to volume areas that they 
	normally cannot write to because of direct write blocking. Direct write blocking was implemented for 
	security reasons in Windows Vista and later operating systems. This flag is checked both at the file 
	system layer and storage stack layer. For more 
	information about direct write blocking, see Blocking Direct Write Operations to Volumes and Disks. 
	The SL_FORCE_DIRECT_WRITE flag is available in Windows Vista and later versions of Windows. 
	http://msdn.microsoft.com/en-us/library/ms795960.aspx
	*/
	if (IRP_MJ_WRITE == majorFunction)
	{
		IoGetNextIrpStackLocation(irp)->Flags |= SL_FORCE_DIRECT_WRITE;
	}
	
    if (Wait) { 
        KeInitializeEvent(&event, NotificationEvent, FALSE); 
        IoSetCompletionRoutine(irp, FltReadWriteSectorsCompletion, 
            &event, TRUE, TRUE, TRUE); 
	
        status = IoCallDriver(DeviceObject, irp); 
        if (STATUS_PENDING == status) { 
            KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL); 
            status = iosb.Status; 
        } 
    } else { 
        IoSetCompletionRoutine(irp, FltReadWriteSectorsCompletion, 
            NULL, TRUE, TRUE, TRUE); 
        irp->UserIosb = NULL; 
        status = IoCallDriver(DeviceObject, irp); 
    } 
	
	if (!NT_SUCCESS(status))
	{
		dprintf("IoCallDriver 0x%x fail 0x%x\n", majorFunction, status);
	}
    return status; 
} 

__inline
BOOL isSectorProtect (PVOLUME_INFO volumeInfo, ULONGLONG index)
{
	if (index < volumeInfo->firstDataSector)
	{
		return FALSE;
	}

	return DPBitMap_Test(volumeInfo->bitMap_Protect,
		(index - volumeInfo->firstDataSector) / (volumeInfo->bytesPerCluster / volumeInfo->bytesPerSector));
}

// 获取真实需要处理的簇
ULONGLONG
getRealSectorForRead(PVOLUME_INFO volumeInfo, ULONGLONG orgIndex)
{
	ULONGLONG	mapIndex = orgIndex;

	// 此簇是否允许直接操作
	if (isSectorProtect(volumeInfo, orgIndex))
	{
		return orgIndex;
	}

	// 此簇是否已经被重定向
	if (DPBitMap_Test(volumeInfo->bitMap_Redirect, orgIndex))
	{
		// 找到重定向到哪里, 并返回	
		PAIR *	result;
		PAIR	pair;
		pair.orgIndex = orgIndex;

		result = (PAIR *)RtlLookupElementGenericTable(&volumeInfo->redirectMap, &pair);

		if (result)
		{
			mapIndex = result->mapIndex;
		}
	}
	
	return mapIndex;
}


// 获取真实需要处理的簇
ULONGLONG
getRealSectorForWrite(PVOLUME_INFO volumeInfo, ULONGLONG orgIndex)
{
	ULONGLONG	mapIndex = -1;

	// 此扇区是否允许直接写
	if (isSectorProtect(volumeInfo, orgIndex))
	{
		return orgIndex;
	}

	// 此簇是否已经被重定向
	if (DPBitMap_Test(volumeInfo->bitMap_Redirect, orgIndex))
	{
		// 找到重定向到哪里, 并返回	
		PAIR *	result;
		PAIR	pair;
		pair.orgIndex = orgIndex;
		
		result = (PAIR *)RtlLookupElementGenericTable(&volumeInfo->redirectMap, &pair);
		
		if (result)
		{
			mapIndex = result->mapIndex;
		}
	}
	else
	{
		// 查找下一个可用的空闲扇区
		mapIndex = DPBitMap_FindNext(volumeInfo->bitMap_Free, volumeInfo->last_scan_index, FALSE);

		if (mapIndex != -1)
		{
			// lastScan = 当前用到的 + 1
			volumeInfo->last_scan_index = mapIndex + 1;

			// 标记为非空闲
			DPBitMap_Set(volumeInfo->bitMap_Free, mapIndex, TRUE);
			
			// 标记此扇区已被重定向(orgIndex)
			DPBitMap_Set(volumeInfo->bitMap_Redirect, orgIndex, TRUE);
			
			// 加入重定向列表
			{
				PAIR	pair;
				pair.orgIndex = orgIndex;
				pair.mapIndex = mapIndex;				
				RtlInsertElementGenericTable(&volumeInfo->redirectMap, &pair, sizeof(PAIR), NULL);
			}
		}
	}

	return mapIndex;
}

// 模拟读
NTSTATUS
handle_disk_request(
	PVOLUME_INFO volumeInfo,
	ULONG majorFunction,
	ULONGLONG logicOffset,  
	void * buff,
	ULONG length)
{
	NTSTATUS	status;
	
	// 当前操作的物理偏移
	ULONGLONG	physicalOffset = 0;
	ULONGLONG	sectorIndex;
	ULONGLONG	realIndex;
	ULONG		bytesPerSector = volumeInfo->bytesPerSector;
	
	// 以下几个参数为判断为处理的簇是连续的簇而设
	BOOLEAN		isFirstBlock = TRUE;
	ULONGLONG	prevIndex = -1;
	ULONGLONG	prevOffset = -1;
	PVOID		prevBuffer = NULL;
	ULONG		totalProcessBytes = 0;

	// 判断上次要处理的簇跟这次要处理的簇是否连续，连续了就一起处理，否则单独处理, 加快速度
	while (length)
	{
		sectorIndex = logicOffset / bytesPerSector;	
		
		if (IRP_MJ_READ == majorFunction)
		{
			realIndex = getRealSectorForRead(volumeInfo, sectorIndex);
		}
		else
		{
			// 传入后两个参数判断是否复制原簇数据
			realIndex = getRealSectorForWrite(volumeInfo, sectorIndex);
		}
		
		// 哥不是吧，硬盘太几巴小了, 老子不干了
		if (-1 == realIndex)
		{
			dprintf("no enough disk space\n");
			return STATUS_DISK_FULL;
		}
		
		physicalOffset = realIndex * bytesPerSector;

__reInit:		
		// 初始prevIndex
		if (isFirstBlock)
		{
			prevIndex = realIndex;
			prevOffset = physicalOffset;
			prevBuffer = buff;
			totalProcessBytes = bytesPerSector;
			
			isFirstBlock = FALSE;
			
			goto __next;
		}
		
		// 测试是否连继,  如果连续，跳到下个判断
		if (prevIndex == (realIndex - 1))
		{
			prevIndex = realIndex;
			totalProcessBytes += bytesPerSector;
			goto __next;
		}
		// 处理上次连续需要处理的簇, 重置isFirstBlock
		else
		{
			isFirstBlock = TRUE;
			status = fastFsdRequest(volumeInfo->LowerDevObj, majorFunction, volumeInfo->physicalStartingOffset + prevOffset, 
				prevBuffer, totalProcessBytes, TRUE);

			// 重新初始化
			goto __reInit;
		}
__next:		
		// 最后一簇。。也就是完成了已经
		if (bytesPerSector >= length)
		{
			status = fastFsdRequest(volumeInfo->LowerDevObj, majorFunction, volumeInfo->physicalStartingOffset + prevOffset, 
				prevBuffer, totalProcessBytes, TRUE);

			// 中断退出
			break;
		}
		
		// 跳到下一簇, 处理剩余的数据
		logicOffset += (ULONGLONG)bytesPerSector;
		buff = (char *)buff + bytesPerSector;
		length -= bytesPerSector;
	}
	
	return status;
}
  
//
// For backward compatibility with Windows NT 4.0 by Bruce Engle.
//
#ifndef MmGetSystemAddressForMdlSafe
#define MmGetSystemAddressForMdlSafe(MDL, PRIORITY) MmGetSystemAddressForMdlPrettySafe(MDL)

PVOID
MmGetSystemAddressForMdlPrettySafe (
    PMDL Mdl
    )
{
    CSHORT  MdlMappingCanFail;
    PVOID   MappedSystemVa;

    MdlMappingCanFail = Mdl->MdlFlags & MDL_MAPPING_CAN_FAIL;

    Mdl->MdlFlags |= MDL_MAPPING_CAN_FAIL;

    MappedSystemVa = MmGetSystemAddressForMdl(Mdl);

    if (MdlMappingCanFail == 0)
    {
        Mdl->MdlFlags &= ~MDL_MAPPING_CAN_FAIL;
    }

    return MappedSystemVa;
}
#endif

/*
// 回收线程
VOID
flt_thread_reclaim (
	IN PVOID Context
	)
{
	ULONG	i = 0;
	ULONG	timeout = getTickCount();
	PFILTER_DEVICE_EXTENSION	device_extension = (PFILTER_DEVICE_EXTENSION)Context;

	while (!device_extension->terminate_thread)
	{
		if ((getTickCount() - timeout) > (1000 * 60))
		{
			for (i = 0; i < _countof(_volumeList); i++)
			{
				if (_volumeList[i].isProtect && _volumeList[i].isProtect && _volumeList[i].isDiskFull)
				{
					// 回收
					reclaimDiskSpace(&_volumeList[i]);
				}
				
			}
			
			timeout = getTickCount();
		}
	}

	PsTerminateSystemThread(STATUS_SUCCESS);
}
*/
VOID
flt_thread_read_write (
					   IN PVOID Context
					   )
{
	//NTSTATUS类型的函数返回值
	NTSTATUS					status = STATUS_SUCCESS;
	//用来指向过滤设备的设备扩展的指针
	PFILTER_DEVICE_EXTENSION	device_extension = (PFILTER_DEVICE_EXTENSION)Context;
	//请求队列的入口
	PLIST_ENTRY			ReqEntry = NULL;
	//irp指针
	PIRP				Irp = NULL;
	//irp stack指针
	PIO_STACK_LOCATION	io_stack = NULL;
	//irp中包括的数据地址
	PVOID				buffer = NULL;
	//irp中的数据长度
	ULONG				length = 0;
	//irp要处理的偏移量
	LARGE_INTEGER		offset = { 0 };

	//irp要处理的偏移量
	LARGE_INTEGER		cacheOffset = { 0 };

	

	//设置这个线程的优先级
	KeSetPriorityThread(KeGetCurrentThread(), LOW_REALTIME_PRIORITY);
	//下面是线程的实现部分，这个循环永不退出
	for (;;)
	{	
		//先等待请求队列同步事件，如果队列中没有irp需要处理，我们的线程就等待在这里，让出cpu时间给其它线程
		KeWaitForSingleObject(
			&device_extension->ReqEvent,
			Executive,
			KernelMode,
			FALSE,
			NULL
			);
		//如果有了线程结束标志，那么就在线程内部自己结束自己
		if (device_extension->terminate_thread)
		{
			//这是线程的唯一退出地点
			PsTerminateSystemThread(STATUS_SUCCESS);
			return;
		}
		//从请求队列的首部拿出一个请求来准备处理，这里使用了自旋锁机制，所以不会有冲突
		while (ReqEntry = ExInterlockedRemoveHeadList(
			&device_extension->list_head,
			&device_extension->list_lock
			))
		{
			PVOLUME_INFO	volumeInfo;

			void * newbuff = NULL;

			//从队列的入口里找到实际的irp的地址
			Irp = CONTAINING_RECORD(ReqEntry, IRP, Tail.Overlay.ListEntry);

			//取得irp stack
			io_stack = IoGetCurrentIrpStackLocation(Irp);

			// 获取卷信息
			volumeInfo = &_volumeList[(ULONG)Irp->IoStatus.Pointer];

			if (IRP_MJ_READ == io_stack->MajorFunction)
			{
				//如果是读的irp请求，我们在irp stack中取得相应的参数作为offset和length
				offset = io_stack->Parameters.Read.ByteOffset;
				length = io_stack->Parameters.Read.Length;
			}
			else if (IRP_MJ_WRITE == io_stack->MajorFunction)
			{
				//如果是写的irp请求，我们在irp stack中取得相应的参数作为offset和length
				offset = io_stack->Parameters.Write.ByteOffset;
				length = io_stack->Parameters.Write.Length;				
			}
			else
			{
				//除此之外，offset和length都是0
				cacheOffset.QuadPart = 0;
				offset.QuadPart = 0;
				length = 0;
			}	

			// 得到在卷中的偏移 磁盘偏移-卷逻辑偏移
			cacheOffset.QuadPart = offset.QuadPart - volumeInfo->physicalStartingOffset;

// 			DbgPrint("0x%x UserBuffer = 0x%x MdlAddress = 0x%x SystemBuffer = 0x%x\n", io_stack->MajorFunction,
// 				Irp->UserBuffer, Irp->MdlAddress, Irp->AssociatedIrp.SystemBuffer);

			if (Irp->MdlAddress)
			{
				buffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
			}
			else if (Irp->UserBuffer)
			{
				buffer = Irp->UserBuffer;
			}
			else
			{
				buffer = Irp->AssociatedIrp.SystemBuffer;
			}
	
			if (!buffer || !length)
			{
				goto __faild;
			}

			if (0 != (length % volumeInfo->bytesPerSector))
			{
				DbgPrint("fuck read %d\n", length);
			}
			
			// 不能和上次传来的buffer用同一个缓冲区，不然
			// 会出现 PFN_LIST_CORRUPT (0x99, ...) A PTE or PFN is corrupt 错误
			// 频繁申请内存也不是办法，用缓冲池吧
			newbuff = __malloc(length);

			if (newbuff)
			{
				if (IRP_MJ_READ == io_stack->MajorFunction)
				{
					status = handle_disk_request(volumeInfo, io_stack->MajorFunction, cacheOffset.QuadPart,
					 newbuff, length);
					RtlCopyMemory(buffer, newbuff, length);
				}
				else
				{
					RtlCopyMemory(newbuff, buffer, length);
					status = handle_disk_request(volumeInfo, io_stack->MajorFunction, cacheOffset.QuadPart,
					 newbuff, length);
				}
				__free(newbuff);
			}
			else
			{
				status = STATUS_NO_MEMORY;
			}

			// 赋值Information
			if (NT_SUCCESS(status))
			{
				Irp->IoStatus.Information = length;
			}
			else
			{
				Irp->IoStatus.Information = 0;
			}

			flt_CompleteRequest(
				Irp,
				status,
				IO_NO_INCREMENT
				);
			continue;
__faild:

			flt_SendToNextDriver(volumeInfo->LowerDevObj, Irp);
			continue;			
		}
	}
}

// 保护一个卷
void protect_Volume(WCHAR volume, BOOLEAN protect)
{
	_volumeList[volume - L'A'].isProtect = protect;
}

NTSTATUS
flt_initVolumeLogicBitMap(PVOLUME_INFO volumeInfo)
{
	NTSTATUS	status;
	PVOLUME_BITMAP_BUFFER	bitMap = NULL;	

	// 逻辑位图大小
	ULONGLONG	logicBitMapMaxSize = 0;
	
	ULONG		sectorsPerCluster = 0;

	ULONGLONG	index = 0;
	ULONGLONG	i = 0;

	status = flt_getVolumeBitmapInfo(volumeInfo->volume, &bitMap);
	
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	sectorsPerCluster = volumeInfo->bytesPerCluster / volumeInfo->bytesPerSector;

	// 获取此卷上有多少个扇区, 用bytesTotal这个比较准确，如果用其它的比如fsinfo,会少几个扇区发现
	volumeInfo->sectorCount = volumeInfo->bytesTotal / volumeInfo->bytesPerSector;
	
	// 得到逻辑位图的大小bytes
	logicBitMapMaxSize = (volumeInfo->sectorCount / 8) + 1;

	// 上次扫描的空闲簇的位置
	volumeInfo->last_scan_index = 0;

	
	dprintf("------------------------\n");
	dprintf("extend cluster = %08I64d physicalStartingOffset = 0x%08I64x bitMapSize = 0x%I64x\n"
		"bytesPerSector = %d bytesPerCluster = %d sectorsPerCluster = %d\n", 
		volumeInfo->firstDataSector, volumeInfo->physicalStartingOffset, logicBitMapMaxSize,
		volumeInfo->bytesPerSector, volumeInfo->bytesPerCluster, sectorsPerCluster);
	
	// 以扇区为单位的位图
	if (!NT_SUCCESS(DPBitMap_Create(&volumeInfo->bitMap_Redirect, volumeInfo->sectorCount, SLOT_SIZE)))
	{
		status = STATUS_UNSUCCESSFUL;
		goto __faild;	
	}
	
	// 以簇为单位的位图
	if (!NT_SUCCESS(DPBitMap_Create(&volumeInfo->bitMap_Protect, volumeInfo->sectorCount / sectorsPerCluster, SLOT_SIZE)))
	{
		status = STATUS_UNSUCCESSFUL;
		goto __faild;	
	}

	// 以扇区为单位的位图, 如果一次申请内存过大，会失败，用dpbitmap申请不连续的内存
	if (!NT_SUCCESS(DPBitMap_Create(&volumeInfo->bitMap_Free, volumeInfo->sectorCount, SLOT_SIZE)))
	{
		status = STATUS_UNSUCCESSFUL;
		goto __faild;	
	}

	// 正式簇开始前的簇都标记为已使用
	for (i = 0; i < volumeInfo->firstDataSector; i++)
	{
		DPBitMap_Set(volumeInfo->bitMap_Free, i, TRUE);
	}

	// FAT32正式簇开始前的数据跳过
	for (i = 0; i < bitMap->BitmapSize.QuadPart; i++)
	{		
		if (bitmap_test((PULONG)&bitMap->Buffer, i))
		{
			ULONGLONG	j = 0;
			ULONGLONG	base = volumeInfo->firstDataSector + (i * sectorsPerCluster);
			for (j = 0; j < sectorsPerCluster; j++)
			{
				if (!NT_SUCCESS(DPBitMap_Set(volumeInfo->bitMap_Free, base + j, TRUE)))
				{
					status = STATUS_UNSUCCESSFUL;
					goto __faild;
				}
			}
		}
	}

	// 放过这几个文件的直接读写
	// bootstat.dat如果不让写，下次启动会显示非正常启动

	setBitmapDirectRWFile(volumeInfo->volume, 
		(*NtBuildNumber >= 2600) ? L"\\Windows\\bootstat.dat" : L"\\WINNT\\bootstat.dat",
		volumeInfo->bitMap_Protect);
	// SAM？算了，保护吧
// 	setBitmapDirectRWFile(volumeInfo->volume, 
// 		(*NtBuildNumber >= 2600) ? L"\\Windows\\system32\\config\\sam" : L"\\WINNT\\system32\\config\\sam",
// 		volumeInfo->bitMap_Protect);

	// 页面文件
	setBitmapDirectRWFile(volumeInfo->volume, L"\\pagefile.sys", volumeInfo->bitMap_Protect);

	// 休眠文件
	setBitmapDirectRWFile(volumeInfo->volume, L"\\hiberfil.sys", volumeInfo->bitMap_Protect);	
	
	// 初始化clusterMap
	RtlInitializeGenericTable(&volumeInfo->redirectMap, CompareRoutine, AllocateRoutine, FreeRoutine, NULL);

	status = STATUS_SUCCESS;

__faild:

	if (!NT_SUCCESS(status))
	{
		if (volumeInfo->bitMap_Redirect)
		{
			DPBitMap_Free(volumeInfo->bitMap_Redirect);
			volumeInfo->bitMap_Redirect = NULL;
		}
		if (volumeInfo->bitMap_Protect)
		{
			DPBitMap_Free(volumeInfo->bitMap_Protect);
			volumeInfo->bitMap_Protect = NULL;
		}
		if (volumeInfo->bitMap_Free)
		{
			DPBitMap_Free(volumeInfo->bitMap_Free);
			volumeInfo->bitMap_Free = NULL;
		}
	}

	__free_Safe(bitMap);


	return STATUS_SUCCESS;
}

BOOLEAN	_signal = FALSE;

// 改变被保护的分区的图标
VOID
changeDriveIcon(WCHAR volume)
{
	HANDLE	keyHandle;
	UNICODE_STRING	keyPath;
	OBJECT_ATTRIBUTES	objectAttributes;
	ULONG		ulResult;
	NTSTATUS	status;
	
	RtlInitUnicodeString( &keyPath, L"\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\DriveIcons");   
	
    //初始化objectAttributes 
    InitializeObjectAttributes(&objectAttributes,   
		&keyPath,   
		OBJ_CASE_INSENSITIVE| OBJ_KERNEL_HANDLE,//对大小写敏感     
		NULL,
		NULL);
	
	status = ZwCreateKey( &keyHandle,   
		KEY_ALL_ACCESS,   
		&objectAttributes,   
		0,   
		NULL,   
		REG_OPTION_VOLATILE,   // 重启后无效
		&ulResult);
	
	if (NT_SUCCESS(status))
	{
		WCHAR	volumeName[10];
		HANDLE	subKey;
		swprintf(volumeName, L"%c", volume);
		
		RtlInitUnicodeString( &keyPath, volumeName);
		
		InitializeObjectAttributes(&objectAttributes,   
			&keyPath,   
			OBJ_CASE_INSENSITIVE| OBJ_KERNEL_HANDLE,//对大小写敏感     
			keyHandle,
			NULL);
		
		status = ZwCreateKey( &subKey,   
			KEY_ALL_ACCESS,   
			&objectAttributes,   
			0,   
			NULL,   
			REG_OPTION_VOLATILE,   // 重启后无效
			&ulResult);
		
		if (NT_SUCCESS(status))
		{
			HANDLE	subsubKey;
			RtlInitUnicodeString( &keyPath, L"DefaultIcon");
			
			InitializeObjectAttributes(&objectAttributes,   
				&keyPath,   
				OBJ_CASE_INSENSITIVE| OBJ_KERNEL_HANDLE,//对大小写敏感     
				subKey,
				NULL);
			
			status = ZwCreateKey( &subsubKey,   
				KEY_ALL_ACCESS,   
				&objectAttributes,   
				0,   
				NULL,   
				REG_OPTION_VOLATILE,   // 重启后无效
				&ulResult);
			
			if (NT_SUCCESS(status))
			{
				UNICODE_STRING	keyName;
				WCHAR iconPath[] = L"%SystemRoot%\\System32\\drivers\\diskflt.sys,0";
				WCHAR iconPathWin7[] = L"%SystemRoot%\\System32\\drivers\\diskflt.sys,1";

				RtlInitUnicodeString(&keyName, L"");
				
				if (*NtBuildNumber <= 2600)
				{
					status = ZwSetValueKey(subsubKey, &keyName, 0,REG_SZ, iconPath, sizeof(iconPath));
				}
				else
				{
					status = ZwSetValueKey(subsubKey, &keyName, 0,REG_SZ, iconPathWin7, sizeof(iconPathWin7));
				}				
				
				ZwClose(subsubKey);
			}
			
			ZwClose(subKey);
		}	
		
		ZwClose(keyHandle);
	}
}




ULONG GetProcessNameOffset(void)
{
    PEPROCESS Process = PsGetCurrentProcess();
	
    __try
    {
		ULONG i = 0;
        for (i = 0; i < PAGE_SIZE * 3; i++)
        {
            if (!strncmp("System", (char *)Process + i, 6))
            {
                return i;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        
    }
	
    return 0;
}

wchar_t * wcsstr_n(const wchar_t *string, size_t count, const wchar_t *strCharSet)
{
	wchar_t   *cp=(wchar_t *)string;   
	wchar_t   *s1, *s2;   
    
	if(!*strCharSet)   
		return ((wchar_t *)string);   
    
	while(count && *cp  )   
	{   
		s1   =   cp;
		s2   =   (wchar_t*)strCharSet;   
		
		while(*s1 && *s2 && !(toupper(*s1)-toupper(*s2)))   
			s1++,   s2++;   
		
		if(!*s2)   
			return(cp);   
		cp++;
		count--;
	}   
    
	return(NULL);   	
}


// 测试。。。。
NTSTATUS
testPartition(WCHAR * partitionName)
{
	NTSTATUS	status;
	HANDLE		fileHandle;
	UNICODE_STRING	fileName;
	OBJECT_ATTRIBUTES	oa;
	IO_STATUS_BLOCK IoStatusBlock;
	PVOLUME_BITMAP_BUFFER	bitMap = NULL;

	
	RtlInitUnicodeString(&fileName, partitionName);
	
	InitializeObjectAttributes(&oa,
		&fileName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);
	
	status = ZwCreateFile(&fileHandle,
		GENERIC_ALL | SYNCHRONIZE,
		&oa,
		&IoStatusBlock,
		NULL,
		0,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,	// 同步读写
		NULL,
		0);

	dprintf("Open %wZ ret 0x%x\n", &fileName, status);
	
	if (NT_SUCCESS(status))
	{		
		IO_STATUS_BLOCK	ioBlock;
		PVOLUME_BITMAP_BUFFER	info;
		STARTING_LCN_INPUT_BUFFER StartingLCN;

		ULONG	BitmapSize = 0;
		
		StartingLCN.StartingLcn.QuadPart = 0;
		
		
		// 必须锁定此卷, 在得到卷位图前
		status = ZwFsControlFile( fileHandle, 
					NULL, 
					NULL, 
					NULL, 
					&ioBlock, 
					FSCTL_LOCK_VOLUME, 
					NULL, 0, NULL, 0
					);
		
		dprintf("FSCTL_LOCK_VOLUME = 0x%x\n", status);
		

		do 
		{
			BitmapSize += 10240;
			
			info = (PVOLUME_BITMAP_BUFFER)__malloc(BitmapSize);
			
			status = ZwFsControlFile( fileHandle, 
				NULL, 
				NULL, 
				NULL, 
				&ioBlock, 
				FSCTL_GET_VOLUME_BITMAP, 
				&StartingLCN,
				sizeof (StartingLCN),
				info, 
				BitmapSize
				);

			if (STATUS_BUFFER_OVERFLOW == status)
			{
				__free(info);
			}
			
		} while(STATUS_BUFFER_OVERFLOW == status);
		
		dprintf("FSCTL_GET_VOLUME_BITMAP ret 0x%x\n", status);

		if (!NT_SUCCESS(status))
		{
			__free(info);
		}
		else
		{
			dprintf("bitMapinfo (%d / %d) cluster = %I64d\n", ioBlock.Information, BitmapSize, info->BitmapSize.QuadPart);

			bitMap = info;
		}

		
		status = ZwFsControlFile( fileHandle, 
			NULL, 
			NULL, 
			NULL, 
			&ioBlock, 
			FSCTL_UNLOCK_VOLUME, 
			NULL, 0, NULL, 0
				);

		dprintf("FSCTL_UNLOCK_VOLUME ret 0x%x\n", status);
		

		ZwClose(fileHandle);
	}

	if (bitMap)
	{
		__free(bitMap);
	}
	
	return status;
}


VOID flt_initializeVolume()
{
	NTSTATUS	status;
	ULONG	i;
	for (i = 0; i < _countof(_volumeList); i++)
	{
		_volumeList[i].volume = (WCHAR)i + L'A';
		
		// 查询要保护卷的信息
		if (_protectInfo.volumeInfo[i] && (_volumeList[i].volume > L'B')
			&& (!_volumeList[i].isValid))
		{
			status = flt_getVolumeInfo(_volumeList[i].volume, &_volumeList[i]);
			
			// 更新保护状态
			if (NT_SUCCESS(status))
			{
				status = flt_initVolumeLogicBitMap(&_volumeList[i]);
				
				_signal = TRUE;
				
				if (!NT_SUCCESS(status))
				{
					dprintf("flt_initVolumeLogicBitMap error 0x%x .\n", status);
					_protectInfo.volumeInfo[i] = 0;
					continue;
				}
				
				_volumeList[i].isValid = TRUE;
				_volumeList[i].isProtect = TRUE;
				
				dprintf("disk %c diskNumber = %d PartitionNumber: %d protect : %d\n"
					"offset = 0x%08I64x len = 0x%08I64x dataStart = 0x%08I64x\n\n", 
					_volumeList[i].volume, _volumeList[i].diskNumber, _volumeList[i].partitionNumber, _volumeList[i].isProtect,
					_volumeList[i].physicalStartingOffset, _volumeList[i].bytesTotal,
					_volumeList[i].firstDataSector);
				
			}
		}
	}
}

ULONG
getTickCount() 
{ 
	LARGE_INTEGER tickCount; 
	KeQueryTickCount(&tickCount);
	tickCount.QuadPart *= KeQueryTimeIncrement(); 
	tickCount.QuadPart /=  10000; 
	return tickCount.LowPart; 
} 

void
getRandomString(PWCHAR random)
{
	ULONG	tick = getTickCount();
	int		mask[9] = {12, 25, 36, 44, 54, 61, 78, 33, 65};
	int		i = 0;
	
	for (i = 0; i < 9; i++)
	{
		if (tick / mask[i] % 2)
			random[i] = (tick / mask[i] % 26) + 'A';
		else
			random[i] = (tick / mask[i] % 26) + 'a';
	}
	
	random[9] = '\0';
}


#define RtlInitEmptyUnicodeString(_ucStr,_buf,_bufSize) \
    ((_ucStr)->Buffer = (_buf), \
	(_ucStr)->Length = 0, \
     (_ucStr)->MaximumLength = (USHORT)(_bufSize))

VOID
ImageNotifyRoutine(
				   IN PUNICODE_STRING  FullImageName,
				   IN HANDLE  ProcessId, // where image is mapped
				   IN PIMAGE_INFO  ImageInfo
				   )
{
	static BOOL	isSetIcon = FALSE;

	NTSTATUS	status;

	if ((!isSetIcon) && FullImageName && wcsstr_n(FullImageName->Buffer, FullImageName->Length / sizeof(WCHAR), L"winlogon.exe"))
	{
		ULONG	protectNumber = 0;
		ULONG	i = 0;
		// 再初始化一次，防止一些受保护的卷没有被初始, 这个时候初始比较稳定
		flt_initializeVolume();
		for (i = 0; i < _countof(_volumeList); i++) {
			if (_volumeList[i].isValid && _volumeList[i].isProtect)
			{
				// 改变受保护的卷和默认图标
				changeDriveIcon(_volumeList[i].volume);
				protectNumber++;
			}
		}
		isSetIcon = TRUE;
		// 如果有盘要保护，启动拦截外来驱动功能
		if (protectNumber)
		{
			// 默认不开启
			_sysPatchEnable = TRUE;	
		}
	}

	if(	(!_sysPatchEnable)
		|| (!ImageInfo->SystemModeImage)
		|| (FullImageName == NULL) 
		|| (FullImageName->Length == 0)
		|| (FullImageName->Buffer == NULL)
		)
	{
		return;
	}

	status = IsFileCreditable(FullImageName);

	if (!NT_SUCCESS(status)) 
	{
		ULONG	start;
		WCHAR	buf[512];
		WCHAR	random[50];
		UNICODE_STRING	msg;
		UNICODE_STRING	caption;

		// 标题栏为随机产生
		getRandomString(random);
		RtlInitUnicodeString(&caption, random);

		RtlInitEmptyUnicodeString(&msg, buf, sizeof(buf));
		RtlAppendUnicodeToString(&msg, L"Load [");
		RtlAppendUnicodeStringToString(&msg, FullImageName);
		RtlAppendUnicodeToString(&msg, L"] ?");

		start = getTickCount();

		if (ResponseYes == kMessageBox(&msg, &caption, OptionYesNo, MB_ICONINFORMATION | MB_SETFOREGROUND | MB_DEFBUTTON2))
		{
			status = STATUS_SUCCESS;
		}

		// 人不可能点击这么快，拒绝加载
		if ((getTickCount() - start) < 500)
		{
			status = STATUS_UNSUCCESSFUL;
		}
	}

	// 不可信的驱动全部XX掉
	if (!NT_SUCCESS(status))
	{
		/**
		* 00410070 >    B8 220000C0   mov     eax, C0000022 // STATUS_ACCESS_DENIED
		* 00410075      C2 0800       retn    8
		*/
		BYTE	patchCode[] = {0xB8, 0x22, 0x00, 0x00, 0xC0, 0xC2, 0x08, 0x00};
		// PATCH驱动
		PIMAGE_DOS_HEADER	imageDosHeader = (PIMAGE_DOS_HEADER)ImageInfo->ImageBase;

		if (IMAGE_DOS_SIGNATURE == imageDosHeader->e_magic)
		{
			PIMAGE_NT_HEADERS	imageNtHeaders = (PIMAGE_NT_HEADERS)((UINT)ImageInfo->ImageBase + imageDosHeader->e_lfanew);
			if (IMAGE_NT_SIGNATURE == imageNtHeaders->Signature)
			{
				WriteReadOnlyMemory((LPBYTE)ImageInfo->ImageBase + imageNtHeaders->OptionalHeader.AddressOfEntryPoint, patchCode, sizeof(patchCode));
			}
		}
	}
}

VOID
flt_reinitializationRoutine( 
	IN	PDRIVER_OBJECT	DriverObject, 
	IN	PVOID			Context, 
	IN	ULONG			Count 
	)
{
	NTSTATUS	status;
	
	//过滤设备的处理线程的线程句柄
	HANDLE		ThreadHandle = NULL;
	flt_initializeVolume();
	
	//初始化这个卷的请求处理队列
	InitializeListHead(&_deviceExtension->list_head);
	//初始化请求处理队列的锁
	KeInitializeSpinLock(&_deviceExtension->list_lock);
	//初始化请求处理队列的同步事件
	KeInitializeEvent(
		&_deviceExtension->ReqEvent,
		SynchronizationEvent,
		FALSE
		);
	
	//初始化终止处理线程标志
	_deviceExtension->terminate_thread = FALSE;
	//建立用来处理这个卷的请求的处理线程，线程函数的参数则是设备扩展
	status = PsCreateSystemThread(
		&ThreadHandle,
		(ACCESS_MASK)0L,
		NULL,
		NULL,
		&_deviceExtension->thread_read_write_id,			
		flt_thread_read_write,
		_deviceExtension
		);
	
	if (!NT_SUCCESS(status))
		goto __faild;
	
	
	//获取处理线程的对象
	status = ObReferenceObjectByHandle(
		ThreadHandle,
		THREAD_ALL_ACCESS,
		NULL,
		KernelMode,
		&_deviceExtension->thread_read_write,
		NULL
		);

	if (NULL != ThreadHandle)
		ZwClose(ThreadHandle);

	if (!NT_SUCCESS(status))
	{
		_deviceExtension->terminate_thread = TRUE;
		KeSetEvent(
			&_deviceExtension->ReqEvent,
			(KPRIORITY)0,
			FALSE
			);
		goto __faild;
	}

	if (*NtBuildNumber <= 3790) {
		// 驱动防护回调
		PsSetLoadImageNotifyRoutine(&ImageNotifyRoutine);
	}


	_deviceExtension->Protect = TRUE;
	_signal = FALSE;

__faild:
	//关闭线程句柄，我们今后不会用到它，所有对线程的引用都通过线程对象来进行了
	if (NULL != ThreadHandle)
		ZwClose(ThreadHandle);
}


NTSTATUS
WriteReadOnlyMemory(
	LPBYTE	dest,
	LPBYTE	src,
	ULONG	count
	)
	/**
	* 一段内存是否可写，只和描述这段内存的描述符有关。 如果你要写一段只读内存，
	* 可以重新建立一个可写的描述符,使它们指向同一段内存就可以了。
	*/
{
	NTSTATUS	status;
	KSPIN_LOCK	spinLock;
	KIRQL		oldIrql;
	PMDL		pMdlMemory;
	LPBYTE		lpWritableAddress;
	
	status = STATUS_UNSUCCESSFUL;
	
	KeInitializeSpinLock(&spinLock);
	
	pMdlMemory = IoAllocateMdl(dest, count, FALSE, FALSE, NULL);
	
	if (NULL == pMdlMemory) return status;
	
	MmBuildMdlForNonPagedPool(pMdlMemory);
    MmProbeAndLockPages(pMdlMemory, KernelMode, IoWriteAccess);
	lpWritableAddress = MmMapLockedPages(pMdlMemory, KernelMode);
    if (NULL != lpWritableAddress)
	{
		oldIrql	= 0;
		KeAcquireSpinLock(&spinLock, &oldIrql);
		
		RtlCopyMemory(lpWritableAddress, src, count);
		
		KeReleaseSpinLock(&spinLock, oldIrql);
		MmUnmapLockedPages(lpWritableAddress, pMdlMemory);
		
		status = STATUS_SUCCESS;
	}
	
	MmUnlockPages(pMdlMemory);
    IoFreeMdl(pMdlMemory);
	
	return	status;
}

// 判断文件是否可信，也就是判断文件是否在原始没有保护的扇区上
// 只要判断文件所在的扇区没有被重定向即可

NTSTATUS
IsFileCreditable(PUNICODE_STRING filePath)
{
	NTSTATUS	status;
	HANDLE		fileHandle = (HANDLE)-1;
	PFILE_OBJECT	fileObject = NULL;	
	PRETRIEVAL_POINTERS_BUFFER	pVcnPairs = NULL;
	PVOLUME_INFO	volumeInfo = NULL;
	ULONG	sectorsPerCluster;

	PVOID	RestartKey = 0;
	PVOID	Element;

	BOOLEAN	IsCreditable = FALSE;

	status = flt_getFileHandleReadOnly(&fileHandle, filePath);

	if (!NT_SUCCESS(status))
	{
		dprintf("Open %wZ ret 0x%x\n", filePath, status);
		goto __faild;
	}

	status = ObReferenceObjectByHandle(fileHandle, 0, NULL, KernelMode, (PVOID *)&fileObject, NULL);
	
	if (!NT_SUCCESS(status))
	{
		goto __faild;
	}

	if (FILE_DEVICE_NETWORK_FILE_SYSTEM != fileObject->DeviceObject->DeviceType)
	{
		UNICODE_STRING	uniDosName;
		// 得到类似C:这样的盘符，为了获取VolumeInfo
		status = RtlVolumeDeviceToDosName(fileObject->DeviceObject, &uniDosName); 
		
		if (NT_SUCCESS(status))
		{
			volumeInfo = &_volumeList[toupper(*(WCHAR *)uniDosName.Buffer) - L'A'];
			ExFreePool(uniDosName.Buffer);

			if ((!volumeInfo->isValid) || (!volumeInfo->isProtect))
			{
				goto __faild;
			}
		}
	}

	if (!volumeInfo)
	{
		goto __faild;
	}

	sectorsPerCluster = volumeInfo->bytesPerCluster / volumeInfo->bytesPerSector;

	pVcnPairs = getFileClusterList(fileHandle);
	
	if(NULL == pVcnPairs)
	{
		dprintf("getFileClusterList fail\n");
		goto __faild;
	}
	
    RestartKey = NULL;
    for (Element = RtlEnumerateGenericTableWithoutSplaying(&volumeInfo->redirectMap, &RestartKey);
         Element != NULL;
         Element = RtlEnumerateGenericTableWithoutSplaying(&volumeInfo->redirectMap, &RestartKey)) 
	{
		ULONG	Cls, r;
		LARGE_INTEGER	PrevVCN = pVcnPairs->StartingVcn;
		for (r = 0, Cls = 0; r < pVcnPairs->ExtentCount; r++)
		{
			ULONG	CnCount;
			LARGE_INTEGER Lcn = pVcnPairs->Extents[r].Lcn;

			for (CnCount = (ULONG)(pVcnPairs->Extents[r].NextVcn.QuadPart - PrevVCN.QuadPart);
			CnCount; CnCount--, Cls++, Lcn.QuadPart++) 
			{
				ULONGLONG	i = 0;
				ULONGLONG	base = volumeInfo->firstDataSector + (Lcn.QuadPart * sectorsPerCluster);
				for (i = 0; i < sectorsPerCluster; i++)
				{
					// 此扇区被重定向了, 不可信文件, 终止认证
					if (((PPAIR)Element)->orgIndex == (base + i))
					{
						// ............
						goto __exit;
					}
				}  
			}
			PrevVCN = pVcnPairs->Extents[r].NextVcn;
		}
	}

	// 经过考验
	IsCreditable = TRUE;

__exit:
	
	__free_Safe(pVcnPairs);
	
__faild:

	if (fileObject)
		ObDereferenceObject(fileObject);

	if (((HANDLE)-1 != fileHandle))
		ZwClose(fileHandle);

	return IsCreditable ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

//////////////////////////////////////////////////////////////////////////
PDEVICE_OBJECT on_diskperf_driver_entry(PDRIVER_OBJECT DriverObject,PUNICODE_STRING reg)
{
	NTSTATUS			status; 
	PDEVICE_OBJECT		deviceObject = NULL;
	BOOLEAN				symbolicLink = FALSE;
	UNICODE_STRING		ntDeviceName;
	PFILTER_DEVICE_EXTENSION	deviceExtension;
	UNICODE_STRING		dosDeviceName;

	RtlInitUnicodeString(&ntDeviceName, DISKFILTER_DEVICE_NAME_W);	
	
    status = IoCreateDevice(
		DriverObject,
		sizeof(FILTER_DEVICE_EXTENSION),		// DeviceExtensionSize
		&ntDeviceName,					// DeviceName
		FILE_DEVICE_DISKFLT,			// DeviceType
		0,								// DeviceCharacteristics
		TRUE,							// Exclusive 这个参数要为FALSE,要不然CreateFile只能打开一次, 再使用得关闭掉
		&deviceObject					// [OUT]
		);
	
	if (!NT_SUCCESS(status))
	{
		dprintf("IoCreateDevice failed(0x%x).\n", status);
		goto failed;
	}

//	deviceObject->Flags |= DO_BUFFERED_IO; 

	deviceExtension = (PFILTER_DEVICE_EXTENSION)deviceObject->DeviceExtension;

	RtlInitUnicodeString(&dosDeviceName, DISKFILTER_DOS_DEVICE_NAME_W);

	status = IoCreateSymbolicLink(&dosDeviceName, &ntDeviceName);
	if (!NT_SUCCESS(status))
    {
        dprintf("IoCreateSymbolicLink failed(0x%x).\n", status);
		goto failed;
    }

	// 初始化内存池
	mempool_init();

	// 初始化卷表
	memset(&_volumeList, 0, sizeof(_volumeList));
	memset(&_lowerDeviceObject, 0, sizeof(_lowerDeviceObject));

	_sysPatchEnable = FALSE;

	// 初始化为非保护状态
	deviceExtension->Protect = FALSE;
	
	// 赋值全局变量
	_deviceExtension = deviceExtension;

	_systemProcessId = (ULONG)PsGetCurrentProcessId();
	_processNameOfffset = GetProcessNameOffset();

	
	//注册一个boot驱动结束回调，这个回调函数会在所有的boot型驱动都运行完毕之后再去执行
  	IoRegisterBootDriverReinitialization(
  		DriverObject,
 		flt_reinitializationRoutine,
  		NULL
  		);	

    if (NT_SUCCESS(status))
	    return deviceObject;

failed:
	
	if (symbolicLink)
		IoDeleteSymbolicLink(&dosDeviceName);
	
	if (deviceObject)
		IoDeleteDevice(deviceObject);

	return deviceObject;
}


VOID on_diskperf_driver_unload(PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING dosDeviceName;

	ULONG	i = 0;
	
	//
    // Free any resources
    //

	//这里主要做一些清理工作
	if (_deviceExtension->terminate_thread != TRUE && NULL != _deviceExtension->thread_read_write)
	{
		_deviceExtension->Protect = FALSE;
		//如果线程还在运行的话需要停止它，这里通过设置线程停止运行的标志并且发送事件信息，让线程自己终止运行
		_deviceExtension->terminate_thread = TRUE;
		KeSetEvent(
			&_deviceExtension->ReqEvent,
			(KPRIORITY) 0,
			FALSE
			);
		//等待线程结束
		KeWaitForSingleObject(
			_deviceExtension->thread_read_write,
			Executive,
			KernelMode,
			FALSE,
			NULL
			);

		//解除引用线程对象
		ObDereferenceObject(_deviceExtension->thread_read_write);

		
		for (i = 0; i < _countof(_volumeList); i++)
		{
			// 释放资源
			DPBitMap_Free(_volumeList[i].bitMap_Redirect);
			DPBitMap_Free(_volumeList[i].bitMap_Protect);
			DPBitMap_Free(_volumeList[i].bitMap_Free);		
			{
				PVOID	RestartKey = 0;
				PVOID	Element;
				
				RestartKey = 0;  // Always get the first element
				while ((Element = RtlEnumerateGenericTableWithoutSplaying(&_volumeList[i].redirectMap, (PVOID *)&RestartKey)) != NULL) 
				{
					RtlDeleteElementGenericTable(&_volumeList[i].redirectMap, Element);		   
					RestartKey = 0;
				}
			}
		}
	}

	// 释放内存池
	mempool_fini();

    //
    // Delete the symbolic link
    //
	
    RtlInitUnicodeString(&dosDeviceName, DISKFILTER_DOS_DEVICE_NAME_W);
	
    IoDeleteSymbolicLink(&dosDeviceName);
	
    //
    // Delete the device object
    //
	
    IoDeleteDevice(DriverObject->DeviceObject);
	
    dprintf("[disk Filter] unloaded\n");
}

// 如果拦截，返回TRUE status为状态码
BOOLEAN on_diskperf_dispatch(
	PDEVICE_OBJECT dev,
    PIRP irp,
	NTSTATUS *status)
{
	ULONG				ioControlCode;
	PIO_STACK_LOCATION	irpSp;
	PVOID				ioBuffer;
    ULONG				inputBufferLength, outputBufferLength;
	irpSp = IoGetCurrentIrpStackLocation(irp);

	ioControlCode		= irpSp->Parameters.DeviceIoControl.IoControlCode;
	ioBuffer			= irp->AssociatedIrp.SystemBuffer;
    inputBufferLength	= irpSp->Parameters.DeviceIoControl.InputBufferLength;
    outputBufferLength	= irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    ioControlCode		= irpSp->Parameters.DeviceIoControl.IoControlCode;

	irp->IoStatus.Information = 0;

	switch (ioControlCode)
    {
	case IOCTL_DISKFLT_LOCK:
		{
			BYTE	md5[16];
			CalcMD5(ioBuffer, inputBufferLength, &md5);
			if (sizeof(md5) == RtlCompareMemory(md5, _protectInfo.passWord, sizeof(md5)))
			{
				InterlockedExchange(&_lockProcessId, (ULONG)PsGetCurrentProcessId());
 				*status = STATUS_SUCCESS;
			}
			else
			{
				*status = STATUS_ACCESS_DENIED;
			}

		}
		break;
	case IOCTL_DISKFLT_UNLOCK:
		{
			InterlockedExchange(&_lockProcessId, -1);
			irp->IoStatus.Information = 0;
			*status = STATUS_SUCCESS;
		}
		break;
		
	case IOCTL_DISKFLT_GETINFO:
		{
			if (outputBufferLength >= sizeof(PROTECT_INFO))
			{
				irp->IoStatus.Information = sizeof(PROTECT_INFO);
				memcpy(ioBuffer, &_protectInfo, sizeof(PROTECT_INFO));
				*status = STATUS_SUCCESS;
			}
			else
			{
				*status = STATUS_INSUFFICIENT_RESOURCES;
			}
		}
		break;
	case IOCTL_DISKFLT_PROTECTSYS_STATE:
		{
			*status = _sysPatchEnable ? STATUS_SUCCESS : STATUS_NOT_IMPLEMENTED;
		}
		break;
	case IOCTL_DISKFLT_LOGIN:
	case IOCTL_DISKFLT_PROTECTSYS:
	case IOCTL_DISKFLT_NOPROTECTSYS:
		{
			BYTE	md5[16];
			CalcMD5(ioBuffer, inputBufferLength, &md5);
			if (sizeof(md5) == RtlCompareMemory(md5, _protectInfo.passWord, sizeof(md5)))
			{
				if (IOCTL_DISKFLT_PROTECTSYS == ioControlCode)
				{
					InterlockedExchange(&_sysPatchEnable, TRUE);
				}
				else if (IOCTL_DISKFLT_NOPROTECTSYS == ioControlCode)
				{
					InterlockedExchange(&_sysPatchEnable, FALSE);
				}
				
				*status = STATUS_SUCCESS;
			}
			else
			{
				*status = STATUS_ACCESS_DENIED;
			}
		}
		break;

	default:
		irp->IoStatus.Information = 0;
		*status = STATUS_SUCCESS;
		break;
	}

 	flt_CompleteRequest(
		irp,
		*status,
		IO_NO_INCREMENT
 		);

	return TRUE;
}

// 如果拦截，返回TRUE status为状态码
BOOLEAN on_diskperf_read_write(
					 IN PUNICODE_STRING physics_device_name,
					 IN ULONG	device_type,
					 IN ULONG device_number,
					 IN ULONG partition_number,
					 IN PDEVICE_OBJECT device_object,
					 IN PIRP Irp,
					 IN NTSTATUS *status)
{
	
	PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation( Irp );
	ULONG	i = 0;

	//irp中的数据长度
	ULONG				length = 0;
	//irp要处理的偏移量
	LARGE_INTEGER		offset = { 0 };

	if (!_deviceExtension->Protect)
	{
		if (_signal && IRP_MJ_WRITE == irpStack->MajorFunction)
		{
			//有很少机会触发这个
			dprintf(">> 获取位图到开始工作中间有数据写入\n");
		}
		return FALSE;
	}

	// 放过指定进程的读写
	if (PsGetCurrentProcessId() == _lockProcessId)
	{
		return FALSE;
	}

	if (PsGetCurrentThreadId() == _deviceExtension->thread_read_write_id.UniqueThread)
	{
		return FALSE;
	}

	if (IRP_MJ_WRITE == irpStack->MajorFunction)
	{
		offset = irpStack->Parameters.Write.ByteOffset;
		length = irpStack->Parameters.Write.Length;

		// 保护MBR, 磁盘上的第一个扇区
		if (offset.QuadPart < 512)
		{
			flt_CompleteRequest(
				Irp,
				STATUS_ACCESS_DENIED,
				IO_NO_INCREMENT
				);
			return TRUE;
		}
	}
	else if (IRP_MJ_READ == irpStack->MajorFunction)
	{
		offset = irpStack->Parameters.Read.ByteOffset;
		length = irpStack->Parameters.Read.Length;
	}
	else
	{
		// 除此之外，offset和length都是0
		offset.QuadPart = 0;
		length = 0;
	}

	for (i = 0; i < _countof(_volumeList); i++)
	{
		// 卷是否有效
		if ((!_volumeList[i].isValid) || (!_volumeList[i].isProtect))
			continue;

		// 卷是否在受保护的硬盘上
		if (_volumeList[i].diskNumber != device_number)
			continue;

		if ((offset.QuadPart >= _volumeList[i].physicalStartingOffset) &&
			((offset.QuadPart - _volumeList[i].physicalStartingOffset) <= _volumeList[i].bytesTotal)
			)
		{
			//这个卷在保护状态，
			//我们首先把这个irp设为pending状态
			IoMarkIrpPending(Irp);

			// 用IRP中的IoStatus.Pointer传递卷的序号, 反正现在这个参数用不着
			Irp->IoStatus.Pointer = (PVOID)i;

			//然后将这个irp放进相应的请求队列里
			ExInterlockedInsertTailList(
				&_deviceExtension->list_head,
				&Irp->Tail.Overlay.ListEntry,
				&_deviceExtension->list_lock
				);
			//设置队列的等待事件，通知队列对这个irp进行处理
			KeSetEvent(
				&_deviceExtension->ReqEvent, 
				(KPRIORITY)0, 
				FALSE);
			//返回pending状态，这个irp就算处理完了
			*status = STATUS_PENDING;

			// TRUE表始IPR被拦截
			return TRUE;
		}
	}


//	dprintf("offset %I64d not protected (%d)\n", offset.QuadPart, irpStack->MajorFunction);
	// //这个卷不在保护状态，直接交给下层设备进行处理
	return FALSE;
}

VOID on_diskperf_new_disk(
			IN PDEVICE_OBJECT device_object,
			IN PUNICODE_STRING physics_device_name,
			IN ULONG device_type,			
			IN ULONG disk_number,
			IN ULONG partition_number)
{
	// 保存设备
	if (disk_number < _countof(_lowerDeviceObject))
	{
		_lowerDeviceObject[disk_number] = device_object;
	}
	// 新硬盘挂接
	dprintf("new disk %wZ %d %d %d\n", physics_device_name, device_type, disk_number, partition_number);
}

VOID
on_diskperf_remove_disk(
	IN PDEVICE_OBJECT device_object,
	IN PUNICODE_STRING physics_device_name
	)
{
	
}
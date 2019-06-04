///////////////////////////////////头文件//////////////////////////////////////////////

#include "crypt.h"
#include "fat_headers/fat.h"
#include "fat_headers/nodetype.h"
#include "fat_headers/fatstruc.h"

//////////////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////////////////////
#define CF_FILE_HEADER_SIZE (1024*4)
#define CF_MEM_TAG 'cfmi'

static LIST_ENTRY s_cf_list;                        //加密列表
static KSPIN_LOCK s_cf_list_lock;                   //在用加密表的时候的自旋锁
static KIRQL s_cf_list_lock_irql;                   //加密表的中断级
static BOOLEAN s_cf_list_inited = FALSE;            //加密列表是否已经初始化v
static size_t s_cf_proc_name_offset = 0;            //记录进程名的偏移量

//这就是每个加密文件的的一个节点，也就是加密链表
typedef struct {
    LIST_ENTRY list_entry;                //双向列表  很有用
    FCB *fcb;                             //对应着一个文件
} CF_NODE,*PCF_NODE;

// 写请求上下文。因为写请求必须恢复原来的irp->MdlAddress
// 或者irp->UserBuffer，所以才需要记录上下文。
//这个结构体是指针上下文，因为写文件是必须替换缓存区（用自己分配的）
//所以这是用来保存原来缓存区的，方便结束后可以回复
typedef struct CF_WRITE_CONTEXT_{
    PMDL mdl_address;
    PVOID user_buffer;
} CF_WRITE_CONTEXT,*PCF_WRITE_CONTEXT;
/////////////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////cf_proc.c////////////////////////////////////
// 这个函数必须在DriverEntry中调用，否则cfCurProcName将不起作用。
//这个函数会在全局变量中保存进程的偏移位置
void cfCurProcNameInit()
{
	ULONG i;
	PEPROCESS  curproc;
	curproc = PsGetCurrentProcess();       //初始化时当前进程是System？？？
	// 搜索EPROCESS结构，在其中找到字符串
	for(i=0;i<3*4*1024;i++)
	{
		if(!strncmp("System",(PCHAR)curproc+i,strlen("System"))) 
		{
			s_cf_proc_name_offset = i;
			break;
		}
	}
}

// 以下函数可以获得进程名。返回获得的长度。
ULONG cfCurProcName(PUNICODE_STRING name)
{
	PEPROCESS  curproc;
	ULONG	need_len;
    ANSI_STRING ansi_name;
	if(s_cf_proc_name_offset == 0)
		return 0;
	
    // 获得当前进程PEB,然后移动一个偏移得到进程名所在位置。
	curproc = PsGetCurrentProcess();
	
    // 这个名字是ansi字符串，现在转化为unicode字符串。
    RtlInitAnsiString(&ansi_name,((PCHAR)curproc + s_cf_proc_name_offset));
    need_len = RtlAnsiStringToUnicodeSize(&ansi_name);
    if(need_len > name->MaximumLength)
    {
        return RtlAnsiStringToUnicodeSize(&ansi_name);
    }
    RtlAnsiStringToUnicodeString(name,&ansi_name,FALSE);
	return need_len;
}

// 判断当前进程是不是notepad.exe
BOOLEAN cfIsCurProcSec(void)
{
    WCHAR name_buf[32] = { 0 };
    UNICODE_STRING proc_name = { 0 };
    UNICODE_STRING note_pad = { 0 };
    ULONG length;
    RtlInitEmptyUnicodeString(&proc_name,name_buf,32*sizeof(WCHAR));
    length = cfCurProcName(&proc_name);
    RtlInitUnicodeString(&note_pad,L"notepad.exe");
    if(RtlCompareUnicodeString(&note_pad,&proc_name,TRUE) == 0)
        return TRUE;
    return FALSE;
}

////////////////////////////////////////////cf_proc.c///////////////////////////////



///////////////////////////////////////////cf_modify_irp.c//////////////////////////
//这是当irp号为irpsp->MajorFunction == IRP_MJ_SET_INFORMATION是调用的
// 对这些set information给予修改，使之隐去前面的4k文件头。
void cfIrpSetInforPre(
    PIRP irp,
    PIO_STACK_LOCATION irpsp)
{
    PUCHAR buffer = irp->AssociatedIrp.SystemBuffer;
    //NTSTATUS status;

    ASSERT(irpsp->MajorFunction == IRP_MJ_SET_INFORMATION);
    switch(irpsp->Parameters.SetFile.FileInformationClass)
    {
		//把下面的操作都加4k
    case FileAllocationInformation:
        {
		    PFILE_ALLOCATION_INFORMATION alloc_infor = 
                (PFILE_ALLOCATION_INFORMATION)buffer;

		    alloc_infor->AllocationSize.QuadPart += CF_FILE_HEADER_SIZE;        
            break;
        }
    case FileEndOfFileInformation:
        {
		    PFILE_END_OF_FILE_INFORMATION end_infor = 
                (PFILE_END_OF_FILE_INFORMATION)buffer;
		    end_infor->EndOfFile.QuadPart += CF_FILE_HEADER_SIZE;
            break;
        }
    case FileValidDataLengthInformation:
        {
		    PFILE_VALID_DATA_LENGTH_INFORMATION valid_length = 
                (PFILE_VALID_DATA_LENGTH_INFORMATION)buffer;
		    valid_length->ValidDataLength.QuadPart += CF_FILE_HEADER_SIZE;
            break;
        }
	case FilePositionInformation:
		{
			PFILE_POSITION_INFORMATION position_infor = 
				(PFILE_POSITION_INFORMATION)buffer;
			position_infor->CurrentByteOffset.QuadPart += CF_FILE_HEADER_SIZE;
			break;
		}
	case FileStandardInformation:
		((PFILE_STANDARD_INFORMATION)buffer)->EndOfFile.QuadPart += CF_FILE_HEADER_SIZE;
		break;
	case FileAllInformation:
		((PFILE_ALL_INFORMATION)buffer)->PositionInformation.CurrentByteOffset.QuadPart += CF_FILE_HEADER_SIZE;
		((PFILE_ALL_INFORMATION)buffer)->StandardInformation.EndOfFile.QuadPart += CF_FILE_HEADER_SIZE;
		break;

    default:
        ASSERT(FALSE);
    };
}

//因为所有文件都要用文件头来放加密标志，所以必须隐藏文件头，方法是用
//IRP_MJ_QUERY_INFORMATION查询文件，得到后就可以进行修改了
void cfIrpQueryInforPost(PIRP irp,PIO_STACK_LOCATION irpsp)
{
    PUCHAR buffer = irp->AssociatedIrp.SystemBuffer;
    ASSERT(irpsp->MajorFunction == IRP_MJ_QUERY_INFORMATION);
    switch(irpsp->Parameters.QueryFile.FileInformationClass)
    {
    case FileAllInformation:
        {
            // 注意FileAllInformation，是由以下结构组成。即使长度不够，
            // 依然可以返回前面的字节。
            //typedef struct _FILE_ALL_INFORMATION {
            //    FILE_BASIC_INFORMATION BasicInformation;........................
            //    FILE_STANDARD_INFORMATION StandardInformation;..................
            //    FILE_INTERNAL_INFORMATION InternalInformation;
            //    FILE_EA_INFORMATION EaInformation;
            //    FILE_ACCESS_INFORMATION AccessInformation;
            //    FILE_POSITION_INFORMATION PositionInformation;
            //    FILE_MODE_INFORMATION ModeInformation;
            //    FILE_ALIGNMENT_INFORMATION AlignmentInformation;
            //    FILE_NAME_INFORMATION NameInformation;
            //} FILE_ALL_INFORMATION, *PFILE_ALL_INFORMATION;
            // 我们需要注意的是返回的字节里是否包含了StandardInformation
            // 这个可能影响文件的大小的信息。
            PFILE_ALL_INFORMATION all_infor = (PFILE_ALL_INFORMATION)buffer;
            if(irp->IoStatus.Information >= 
                sizeof(FILE_BASIC_INFORMATION) + 
                sizeof(FILE_STANDARD_INFORMATION))
            {
				//确保文件结束的位置，大于4k的文件头
                ASSERT(all_infor->StandardInformation.EndOfFile.QuadPart >= CF_FILE_HEADER_SIZE);
				//把查询到的文件信息减去文件头
				all_infor->StandardInformation.EndOfFile.QuadPart -= CF_FILE_HEADER_SIZE;
                all_infor->StandardInformation.AllocationSize.QuadPart -= CF_FILE_HEADER_SIZE;
                if(irp->IoStatus.Information >= 
                    sizeof(FILE_BASIC_INFORMATION) + 
                    sizeof(FILE_STANDARD_INFORMATION) +
                    sizeof(FILE_INTERNAL_INFORMATION) +
                    sizeof(FILE_EA_INFORMATION) +
                    sizeof(FILE_ACCESS_INFORMATION) +
                    sizeof(FILE_POSITION_INFORMATION))
                {
                    if(all_infor->PositionInformation.CurrentByteOffset.QuadPart >= CF_FILE_HEADER_SIZE)
                        all_infor->PositionInformation.CurrentByteOffset.QuadPart -= CF_FILE_HEADER_SIZE;
                }
            }
            break;
        }
    case FileAllocationInformation:
        {
		    PFILE_ALLOCATION_INFORMATION alloc_infor = 
                (PFILE_ALLOCATION_INFORMATION)buffer;
            ASSERT(alloc_infor->AllocationSize.QuadPart >= CF_FILE_HEADER_SIZE);
		    alloc_infor->AllocationSize.QuadPart -= CF_FILE_HEADER_SIZE;        
            break;
        }
    case FileValidDataLengthInformation:
        {
		    PFILE_VALID_DATA_LENGTH_INFORMATION valid_length = 
                (PFILE_VALID_DATA_LENGTH_INFORMATION)buffer;
            ASSERT(valid_length->ValidDataLength.QuadPart >= CF_FILE_HEADER_SIZE);
		    valid_length->ValidDataLength.QuadPart -= CF_FILE_HEADER_SIZE;
            break;
        }
    case FileStandardInformation:
        {
            PFILE_STANDARD_INFORMATION stand_infor = (PFILE_STANDARD_INFORMATION)buffer;
            ASSERT(stand_infor->AllocationSize.QuadPart >= CF_FILE_HEADER_SIZE);
            stand_infor->AllocationSize.QuadPart -= CF_FILE_HEADER_SIZE;            
            stand_infor->EndOfFile.QuadPart -= CF_FILE_HEADER_SIZE;
            break;
        }
    case FileEndOfFileInformation:
        {
		    PFILE_END_OF_FILE_INFORMATION end_infor = 
                (PFILE_END_OF_FILE_INFORMATION)buffer;
            ASSERT(end_infor->EndOfFile.QuadPart >= CF_FILE_HEADER_SIZE);
		    end_infor->EndOfFile.QuadPart -= CF_FILE_HEADER_SIZE;
            break;
        }
	case FilePositionInformation:
		{
			PFILE_POSITION_INFORMATION PositionInformation =
				(PFILE_POSITION_INFORMATION)buffer; 
            if(PositionInformation->CurrentByteOffset.QuadPart > CF_FILE_HEADER_SIZE)
			    PositionInformation->CurrentByteOffset.QuadPart -= CF_FILE_HEADER_SIZE;
			break;
		}
    default:
        ASSERT(FALSE);
    };
}

// 读请求。将偏移量前移。
void cfIrpReadPre(PIRP irp,PIO_STACK_LOCATION irpsp)
{
    PLARGE_INTEGER offset;
    PFCB fcb = (PFCB)irpsp->FileObject->FsContext;
	offset = &irpsp->Parameters.Read.ByteOffset;

	UNREFERENCED_PARAMETER(irp);
    if(offset->LowPart ==  FILE_USE_FILE_POINTER_POSITION &&  offset->HighPart == -1)
	{
		//这种情况是指读irp可能不明确请求读的偏移，而是要求按当前偏移请求操作
        // 记事本不会出现这样的情况。
        ASSERT(FALSE);
	}
    // 偏移必须修改为增加4k。
    offset->QuadPart += CF_FILE_HEADER_SIZE;
    KdPrint(("cfIrpReadPre: offset = %8x\r\n",
        offset->LowPart));
}

// 读请求结束，需要解密。读请求时的解密相对于写 比较简单
// 写请求的加密，要自己设定缓存区，防止重复加密现象
void cfIrpReadPost(PIRP irp,PIO_STACK_LOCATION irpsp)
{
    // 得到缓冲区，然后解密之。解密很简单，就是xor 0x77.
    PUCHAR buffer;
    ULONG i,length = irp->IoStatus.Information;

	UNREFERENCED_PARAMETER(irpsp);
    ASSERT(irp->MdlAddress != NULL || irp->UserBuffer != NULL);
	//判断它到底在哪个变量中，并把它取出来
	if(irp->MdlAddress != NULL)
		buffer = MmGetSystemAddressForMdlSafe(irp->MdlAddress,NormalPagePriority);
	else
		buffer = irp->UserBuffer;

    // 解密也很简单，xor 0x77  加解密一般以八个字节为一组，也就是一页
    for(i=0;i<length;++i)
        buffer[i] ^= 0X77;
    // 打印解密之后的内容
    KdPrint(("cfIrpReadPost: flags = %x length = %x content = %c%c%c%c%c\r\n",
        irp->Flags,length,buffer[0],buffer[1],buffer[2],buffer[3],buffer[4]));
}

//这应该是为后面的写加密，而写的几个分配mdl的函数
// 分配一个MDL，带有一个长度为length的缓冲区。
PMDL cfMdlMemoryAlloc(ULONG length)
{
    void *buf = ExAllocatePoolWithTag(NonPagedPool,length,CF_MEM_TAG);
    PMDL mdl;
    if(buf == NULL)
        return NULL;
    mdl = IoAllocateMdl(buf,length,FALSE,FALSE,NULL);
    if(mdl == NULL)
    {
		//如果失败，则释放上面申请的缓存区
        ExFreePool(buf);
        return NULL;
    }
	//赋予mdl非页虚拟内存的一块缓存区
    MmBuildMdlForNonPagedPool(mdl);
    mdl->Next = NULL;
    return mdl;
}

// 释放掉带有MDL的缓冲区。
void cfMdlMemoryFree(PMDL mdl)
{
    void *buffer = MmGetSystemAddressForMdlSafe(mdl,NormalPagePriority);
    IoFreeMdl(mdl);
    ExFreePool(buffer);
}



// 写请求需要重新分配缓冲区，而且有可能失败。如果失败
// 了就直接报错了。所以要有一个返回。TRUE表示成功，可
// 以继续GO_ON。FALSE表示失败了，错误已经填好，直接
// 完成即可
BOOLEAN cfIrpWritePre(PIRP irp,PIO_STACK_LOCATION irpsp, PVOID *context)
{
    PLARGE_INTEGER offset;
    ULONG i,length = irpsp->Parameters.Write.Length;
    PUCHAR buffer,new_buffer;
    PMDL new_mdl = NULL;

    // 先准备一个上下文
    PCF_WRITE_CONTEXT my_context = (PCF_WRITE_CONTEXT)
    ExAllocatePoolWithTag(NonPagedPool,sizeof(CF_WRITE_CONTEXT),CF_MEM_TAG);
    if(my_context == NULL)
    {
        irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        irp->IoStatus.Information = 0;
        return FALSE;
    }
  
    // 在这里得到缓冲进行加密。要注意的是写请求的缓冲区
    // 是不可以直接改写的。必须重新分配。
    ASSERT(irp->MdlAddress != NULL || irp->UserBuffer != NULL);
	if(irp->MdlAddress != NULL)
    {
		//buffer保存原来的缓存区
		buffer = MmGetSystemAddressForMdlSafe(irp->MdlAddress,NormalPagePriority);
        new_mdl = cfMdlMemoryAlloc(length);
        if(new_mdl == NULL)
            new_buffer = NULL;
        else
            new_buffer = MmGetSystemAddressForMdlSafe(new_mdl,NormalPagePriority);
    }
	else
    {
		buffer = irp->UserBuffer;
        new_buffer = ExAllocatePoolWithTag(NonPagedPool,length,CF_MEM_TAG);
    }
    // 如果缓冲区分配失败了，直接退出即可。
    if(new_buffer == NULL)
    {
        irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        irp->IoStatus.Information = 0;
        ExFreePool(my_context);
        return FALSE;
    }
	//将原来缓存区复制到新缓存区
    RtlCopyMemory(new_buffer,buffer,length);

    // 到了这里一定成功，可以设置上下文了。
	//把原来的mdl和UserBuffer存入上下文，并设置在参数中
    my_context->mdl_address = irp->MdlAddress;
    my_context->user_buffer = irp->UserBuffer;
    *context = (void *)my_context;

    // 给irp指定行的mdl，到完成之后再恢复回来。
	//把要操作的空间指向我们申请的
    if(new_mdl == NULL)
        irp->UserBuffer = new_buffer;
    else
        irp->MdlAddress = new_mdl;

	offset = &irpsp->Parameters.Write.ByteOffset;
    KdPrint(("cfIrpWritePre: fileobj = %x flags = %x offset = %8x length = %x content = %c%c%c%c%c\r\n",
        irpsp->FileObject,irp->Flags,offset->LowPart,length,buffer[0],buffer[1],buffer[2],buffer[3],buffer[4]));

    // 加密也很简单，xor 0x77  在新申请的缓存中加密
    for(i=0;i<length;++i)
        new_buffer[i] ^= 0x77;

    if(offset->LowPart ==  FILE_USE_FILE_POINTER_POSITION &&  offset->HighPart == -1)
	{
		//这种情况是指写irp可能不明确请求写的偏移，而是要求按当前偏移请求操作
        // 记事本不会出现这样的情况。
        ASSERT(FALSE);
	}
    // 偏移必须修改为增加4KB。
    offset->QuadPart += CF_FILE_HEADER_SIZE;
    return TRUE;
}

// 请注意无论结果如何，都必须进入WritePost.否则会出现无法恢复
// Write的内容，释放已分配的空间的情况。
void cfIrpWritePost(PIRP irp,PIO_STACK_LOCATION irpsp,void *context)
{
    PCF_WRITE_CONTEXT my_context = (PCF_WRITE_CONTEXT) context;

	UNREFERENCED_PARAMETER(irpsp);
    // 到了这里，可以恢复irp的内容了。
    if(irp->MdlAddress != NULL)
        cfMdlMemoryFree(irp->MdlAddress);
    if(irp->UserBuffer != NULL)
        ExFreePool(irp->UserBuffer);
    irp->MdlAddress = my_context->mdl_address;
    irp->UserBuffer = my_context->user_buffer;
    ExFreePool(my_context);
}

//////////////////////////////////////////cf_modify_irp.c///////////////////////////


///////////////////////////////////////////cf_list.c////////////////////////////////


BOOLEAN cfListInited()
{
    return s_cf_list_inited;
}
 
void cfListLock()
{
    ASSERT(s_cf_list_inited);
    KeAcquireSpinLock(&s_cf_list_lock,&s_cf_list_lock_irql);
}

void cfListUnlock()
{
    ASSERT(s_cf_list_inited);
    KeReleaseSpinLock(&s_cf_list_lock,s_cf_list_lock_irql);
}

void cfListInit()
{
    InitializeListHead(&s_cf_list);
    KeInitializeSpinLock(&s_cf_list_lock);
    s_cf_list_inited = TRUE;
}

// 任意给定一个文件，判断是否在加密链表中。这个函数没加锁。
BOOLEAN cfIsFileCrypting(PFILE_OBJECT file)
{
    PLIST_ENTRY p;
    PCF_NODE node;
   for(p = s_cf_list.Flink; p != &s_cf_list; p = p->Flink)
    {
	    node = (PCF_NODE)p;
        if(node->fcb == file->FsContext)
        {
            //KdPrint(("cfIsFileCrypting: file %wZ is crypting. fcb = %x \r\n",&file->FileName,file->FsContext));
            return TRUE;
        }
    } 
    return FALSE;
}

// 追加一个正在使用的机密文件。这个函数有加锁来保证只插入一
// 个，不会重复插入。
BOOLEAN cfFileCryptAppendLk(PFILE_OBJECT file)
{
    // 先分配空间
    PCF_NODE node = (PCF_NODE)
        ExAllocatePoolWithTag(NonPagedPool,sizeof(CF_NODE),CF_MEM_TAG);
    node->fcb = (PFCB)file->FsContext;

    cfFileCacheClear(file);    //清除缓存区

    // 加锁并查找，如果已经有了，这是一个致命的错误。直接报错即可。
    cfListLock();
    if(cfIsFileCrypting(file))
    {
        ASSERT(FALSE);
        return TRUE;
    }
    else if(node->fcb->UncleanCount > 1)
    {
        // 要成功的加入，必须要符合一个条件。就是FCB->UncleanCount <= 1.
        // 这样的话说明没有其他程序打开着这个文件。否则的话可能是一个普
        // 通进程打开着它。此时不能加密。返回拒绝打开。
        cfListUnlock();
        // 释放掉。
        ExFreePool(node);
        return FALSE;
    }

    // 否则的话，在这里插入到链表里。
    InsertHeadList(&s_cf_list, (PLIST_ENTRY)node);
    cfListUnlock();

    //cfFileCacheClear(file);
    return TRUE;
}


// 当有文件被clean up的时候调用此函数。如果检查发现
// FileObject->FsContext在列表中
BOOLEAN cfCryptFileCleanupComplete(PFILE_OBJECT file)
{
    PLIST_ENTRY p;
    PCF_NODE node;
    FCB *fcb = (FCB *)file->FsContext;

    KdPrint(("cfCryptFileCleanupComplete: file name = %wZ, fcb->UncleanCount = %d\r\n",
        &file->FileName,fcb->UncleanCount));

    // 必须首先清文件缓冲。然后再从链表中移除。否则的话，清缓
    // 冲时的写操作就不会加密了。
    if(fcb->UncleanCount <= 1 || (fcb->FcbState & FCB_STATE_DELETE_ON_CLOSE) )
        cfFileCacheClear(file);
    else
        return FALSE;

    cfListLock();
   for(p = s_cf_list.Flink; p != &s_cf_list; p = p->Flink)
   {
	    node = (PCF_NODE)p;
        if(node->fcb == file->FsContext && 
            (node->fcb->UncleanCount == 0 ||
            (fcb->FcbState & FCB_STATE_DELETE_ON_CLOSE)))
        {
            // 从链表中移除。
            RemoveEntryList((PLIST_ENTRY)node);
            cfListUnlock();
            //  释放内存。
            ExFreePool(node);
            return TRUE;
        }
    } 
    cfListUnlock();
   return FALSE;
}

///////////////////////////////////////////cf_list.c////////////////////////////////



//////////////////////////////////////////cf_file_irp.c////////////////////////////



static NTSTATUS cfFileIrpComp(
    PDEVICE_OBJECT dev,
    PIRP irp,
    PVOID context
    )
{
	UNREFERENCED_PARAMETER(context);
	UNREFERENCED_PARAMETER(dev);

    *irp->UserIosb = irp->IoStatus;
    KeSetEvent(irp->UserEvent, 0, FALSE);
    IoFreeIrp(irp);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

// 自发送SetInformation请求.
NTSTATUS 
cfFileSetInformation( 
    DEVICE_OBJECT *dev, 
    FILE_OBJECT *file,
    FILE_INFORMATION_CLASS infor_class,
	FILE_OBJECT *set_file,
    void* buf,
    ULONG buf_len)
{
    PIRP irp;
    KEVENT event;
    IO_STATUS_BLOCK IoStatusBlock;
    PIO_STACK_LOCATION ioStackLocation;

    KeInitializeEvent(&event, SynchronizationEvent, FALSE);

	// 分配irp
    irp = IoAllocateIrp(dev->StackSize, FALSE);
    if(irp == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

	// 填写irp的主体
    irp->AssociatedIrp.SystemBuffer = buf;
    irp->UserEvent = &event;
    irp->UserIosb = &IoStatusBlock;
    irp->Tail.Overlay.Thread = PsGetCurrentThread();
    irp->Tail.Overlay.OriginalFileObject = file;
    irp->RequestorMode = KernelMode;
    irp->Flags = 0;

	// 设置irpsp
    ioStackLocation = IoGetNextIrpStackLocation(irp);
    ioStackLocation->MajorFunction = IRP_MJ_SET_INFORMATION;
    ioStackLocation->DeviceObject = dev;
    ioStackLocation->FileObject = file;
    ioStackLocation->Parameters.SetFile.FileObject = set_file;
    ioStackLocation->Parameters.SetFile.Length = buf_len;
    ioStackLocation->Parameters.SetFile.FileInformationClass = infor_class;

	// 设置结束例程
    IoSetCompletionRoutine(irp, cfFileIrpComp, 0, TRUE, TRUE, TRUE);

	// 发送请求并等待结束
    (void) IoCallDriver(dev, irp);
    KeWaitForSingleObject(&event, Executive, KernelMode, TRUE, 0);
    return IoStatusBlock.Status;
}

NTSTATUS
cfFileQueryInformation(
    DEVICE_OBJECT *dev, 
    FILE_OBJECT *file,
    FILE_INFORMATION_CLASS infor_class,
    void* buf,
    ULONG buf_len)
{
    PIRP irp;
    KEVENT event;
    IO_STATUS_BLOCK IoStatusBlock;
    PIO_STACK_LOCATION ioStackLocation;

    // 因为我们打算让这个请求同步完成，所以初始化一个事件
    // 用来等待请求完成。
    KeInitializeEvent(&event, SynchronizationEvent, FALSE);

	// 分配irp
    irp = IoAllocateIrp(dev->StackSize, FALSE);
    if(irp == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

	// 填写irp的主体
    irp->AssociatedIrp.SystemBuffer = buf;
    irp->UserEvent = &event;
    irp->UserIosb = &IoStatusBlock;
    irp->Tail.Overlay.Thread = PsGetCurrentThread();
    irp->Tail.Overlay.OriginalFileObject = file;
    irp->RequestorMode = KernelMode;
    irp->Flags = 0;

	// 设置irpsp
    ioStackLocation = IoGetNextIrpStackLocation(irp);
    ioStackLocation->MajorFunction = IRP_MJ_QUERY_INFORMATION;
    ioStackLocation->DeviceObject = dev;
    ioStackLocation->FileObject = file;
    ioStackLocation->Parameters.QueryFile.Length = buf_len;
    ioStackLocation->Parameters.QueryFile.FileInformationClass = infor_class;

	// 设置结束例程
    IoSetCompletionRoutine(irp, cfFileIrpComp, 0, TRUE, TRUE, TRUE);

	// 发送请求并等待结束
    (void) IoCallDriver(dev, irp);
    KeWaitForSingleObject(&event, Executive, KernelMode, TRUE, 0);
    return IoStatusBlock.Status;
}

NTSTATUS
cfFileSetFileSize(
	DEVICE_OBJECT *dev,
	FILE_OBJECT *file,
	LARGE_INTEGER *file_size)
{
	FILE_END_OF_FILE_INFORMATION end_of_file;
	end_of_file.EndOfFile.QuadPart = file_size->QuadPart;
	return cfFileSetInformation(
		dev,file,FileEndOfFileInformation,
		NULL,(void *)&end_of_file,
		sizeof(FILE_END_OF_FILE_INFORMATION));
}

NTSTATUS
cfFileGetStandInfo(
	PDEVICE_OBJECT dev,
	PFILE_OBJECT file,
	PLARGE_INTEGER allocate_size,
	PLARGE_INTEGER file_size,
	BOOLEAN *dir)
{
	NTSTATUS status;
	PFILE_STANDARD_INFORMATION infor = NULL;
	infor = (PFILE_STANDARD_INFORMATION)
		ExAllocatePoolWithTag(NonPagedPool,sizeof(FILE_STANDARD_INFORMATION),CF_MEM_TAG);
	if(infor == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;
	status = cfFileQueryInformation(dev,file,
		FileStandardInformation,(void *)infor,
		sizeof(FILE_STANDARD_INFORMATION));
	if(NT_SUCCESS(status))
	{
		if(allocate_size != NULL)
			*allocate_size = infor->AllocationSize;
		if(file_size != NULL)
			*file_size = infor->EndOfFile;
		if(dir != NULL)
			*dir = infor->Directory;
	}
	ExFreePool(infor);
	return status;
}


NTSTATUS 
cfFileReadWrite( 
    DEVICE_OBJECT *dev, 
    FILE_OBJECT *file,
    LARGE_INTEGER *offset,
    ULONG *length,
    void *buffer,
    BOOLEAN read_write) 
{
	//ULONG i;
    PIRP irp;
    KEVENT event;
    PIO_STACK_LOCATION ioStackLocation;
	IO_STATUS_BLOCK IoStatusBlock = { 0 };

    KeInitializeEvent(&event, SynchronizationEvent, FALSE);

	// 分配irp.
    irp = IoAllocateIrp(dev->StackSize, FALSE);
    if(irp == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
  
	// 填写主体。
    irp->AssociatedIrp.SystemBuffer = NULL;
	// 在paging io的情况下，似乎必须要使用MDL才能正常进行。不能使用UserBuffer.
	// 但是我并不肯定这一点。所以这里加一个断言。以便我可以跟踪错误。
    irp->MdlAddress = NULL;
    irp->UserBuffer = buffer;
    irp->UserEvent = &event;
    irp->UserIosb = &IoStatusBlock;
    irp->Tail.Overlay.Thread = PsGetCurrentThread();
    irp->Tail.Overlay.OriginalFileObject = file;
    irp->RequestorMode = KernelMode;
	if(read_write)
		irp->Flags = IRP_DEFER_IO_COMPLETION|IRP_READ_OPERATION|IRP_NOCACHE;
	else
		irp->Flags = IRP_DEFER_IO_COMPLETION|IRP_WRITE_OPERATION|IRP_NOCACHE;

	// 填写irpsp
    ioStackLocation = IoGetNextIrpStackLocation(irp);
	if(read_write)
		ioStackLocation->MajorFunction = IRP_MJ_READ;
	else
		ioStackLocation->MajorFunction = IRP_MJ_WRITE;
    ioStackLocation->MinorFunction = IRP_MN_NORMAL;
    ioStackLocation->DeviceObject = dev;
    ioStackLocation->FileObject = file;
	if(read_write)
	{
		ioStackLocation->Parameters.Read.ByteOffset = *offset;
		ioStackLocation->Parameters.Read.Length = *length;
	}
	else
	{
		ioStackLocation->Parameters.Write.ByteOffset = *offset;
		ioStackLocation->Parameters.Write.Length = *length;
	}

	// 设置完成
    IoSetCompletionRoutine(irp, cfFileIrpComp, 0, TRUE, TRUE, TRUE);
    (void) IoCallDriver(dev, irp);
    KeWaitForSingleObject(&event, Executive, KernelMode, TRUE, 0);
	*length = IoStatusBlock.Information;
    return IoStatusBlock.Status;
}

// 清理缓冲
void cfFileCacheClear(PFILE_OBJECT pFileObject)
{
   PFSRTL_COMMON_FCB_HEADER pFcb;
   LARGE_INTEGER liInterval;
   BOOLEAN bNeedReleaseResource = FALSE;
   BOOLEAN bNeedReleasePagingIoResource = FALSE;
   KIRQL irql;

   pFcb = (PFSRTL_COMMON_FCB_HEADER)pFileObject->FsContext;
   if(pFcb == NULL)
       return;

   irql = KeGetCurrentIrql();
   if (irql >= DISPATCH_LEVEL)
   {
       return;
   }

   liInterval.QuadPart = -1 * (LONGLONG)50;

   while (TRUE)
   {
       BOOLEAN bBreak = TRUE;
       BOOLEAN bLockedResource = FALSE;
       BOOLEAN bLockedPagingIoResource = FALSE;
       bNeedReleaseResource = FALSE;
       bNeedReleasePagingIoResource = FALSE;

	   // 到fcb中去拿锁。
       if (pFcb->PagingIoResource)
           bLockedPagingIoResource = ExIsResourceAcquiredExclusiveLite(pFcb->PagingIoResource);

	   // 总之一定要拿到这个锁。
       if (pFcb->Resource)
       {
           bLockedResource = TRUE;
           if (ExIsResourceAcquiredExclusiveLite(pFcb->Resource) == FALSE)
           {
               bNeedReleaseResource = TRUE;
               if (bLockedPagingIoResource)
               {
                   if (ExAcquireResourceExclusiveLite(pFcb->Resource, FALSE) == FALSE)
                   {
                       bBreak = FALSE;
                       bNeedReleaseResource = FALSE;
                       bLockedResource = FALSE;
                   }
               }
               else
                   ExAcquireResourceExclusiveLite(pFcb->Resource, TRUE);
           }
       }
   
       if (bLockedPagingIoResource == FALSE)
       {
           if (pFcb->PagingIoResource)
           {
               bLockedPagingIoResource = TRUE;
               bNeedReleasePagingIoResource = TRUE;
               if (bLockedResource)
               {
                   if (ExAcquireResourceExclusiveLite(pFcb->PagingIoResource, FALSE) == FALSE)
                   {
                       bBreak = FALSE;
                       bLockedPagingIoResource = FALSE;
                       bNeedReleasePagingIoResource = FALSE;
                   }
               }
               else
               {
                   ExAcquireResourceExclusiveLite(pFcb->PagingIoResource, TRUE);
               }
           }
       }

       if (bBreak)
       {
           break;
       }
       
       if (bNeedReleasePagingIoResource)
       {
           ExReleaseResourceLite(pFcb->PagingIoResource);
       }
       if (bNeedReleaseResource)
       {
           ExReleaseResourceLite(pFcb->Resource);
       }

       if (irql == PASSIVE_LEVEL)
       {
           KeDelayExecutionThread(KernelMode, FALSE, &liInterval);
       }
       else
       {
           KEVENT waitEvent;
           KeInitializeEvent(&waitEvent, NotificationEvent, FALSE);
           KeWaitForSingleObject(&waitEvent, Executive, KernelMode, FALSE, &liInterval);
       }
   }

   if (pFileObject->SectionObjectPointer)
   {
		IO_STATUS_BLOCK ioStatus;
		CcFlushCache(pFileObject->SectionObjectPointer, NULL, 0, &ioStatus);
		if (pFileObject->SectionObjectPointer->ImageSectionObject)
		{
			MmFlushImageSection(pFileObject->SectionObjectPointer,MmFlushForWrite); // MmFlushForDelete
		}
		CcPurgeCacheSection(pFileObject->SectionObjectPointer, NULL, 0, FALSE);
   }

   if (bNeedReleasePagingIoResource)
   {
       ExReleaseResourceLite(pFcb->PagingIoResource);
   }
   if (bNeedReleaseResource)
   {
       ExReleaseResourceLite(pFcb->Resource);
   }
}

/////////////////////////////////////////cf_file_irp.c/////////////////////////////



//////////////////////////////////////////cf_create.c/////////////////////////////

// 在create之前的时候，获得完整的路径。
ULONG
cfFileFullPathPreCreate(
						PFILE_OBJECT file,
                        PUNICODE_STRING path
						)
{
	NTSTATUS status;
	POBJECT_NAME_INFORMATION  obj_name_info = NULL;
	WCHAR buf[64] = { 0 };
	void *obj_ptr;
	ULONG length = 0;
	BOOLEAN need_split = FALSE;

	ASSERT( file != NULL );
	if(file == NULL)
		return 0;
	if(file->FileName.Buffer == NULL)
		return 0;

	obj_name_info = (POBJECT_NAME_INFORMATION)buf;
	do {

		// 获取FileName前面的部分（设备路径或者根目录路径）
		if(file->RelatedFileObject != NULL)
			obj_ptr = (void *)file->RelatedFileObject;
		else
			obj_ptr= (void *)file->DeviceObject;
		status = ObQueryNameString(obj_ptr,obj_name_info,64*sizeof(WCHAR),&length);
		if(status == STATUS_INFO_LENGTH_MISMATCH)
		{
			obj_name_info = ExAllocatePoolWithTag(NonPagedPool,length,CF_MEM_TAG);
			if(obj_name_info == NULL)
				return STATUS_INSUFFICIENT_RESOURCES;
			RtlZeroMemory(obj_name_info,length);
			status = ObQueryNameString(obj_ptr,obj_name_info,length,&length);            
		}
		// 失败了就直接跳出即可
		if(!NT_SUCCESS(status))
			break;

		// 判断二者之间是否需要多一个斜杠。这需要两个条件:
		// FileName第一个字符不是斜杠。obj_name_info最后一个
		// 字符不是斜杠。
		if( file->FileName.Length > 2 &&
			file->FileName.Buffer[ 0 ] != L'\\' &&
			obj_name_info->Name.Buffer[ obj_name_info->Name.Length / sizeof(WCHAR) - 1 ] != L'\\' )
			need_split = TRUE;

		// 获总体名字的长度。如果长度不足，也直接返回。
		length = obj_name_info->Name.Length + file->FileName.Length;
		if(need_split)
			length += sizeof(WCHAR);
		if(path->MaximumLength < length)
			break;

		// 先把设备名拷贝进去。
		RtlCopyUnicodeString(path,&obj_name_info->Name);
		if(need_split)
			// 追加一个斜杠
			RtlAppendUnicodeToString(path,L"\\");

		// 然后追加FileName
		RtlAppendUnicodeStringToString(path,&file->FileName);
	} while(0);

	// 如果分配过空间就释放掉。
	if((void *)obj_name_info != (void *)buf)
		ExFreePool(obj_name_info);
	return length;
}

// 用IoCreateFileSpecifyDeviceObjectHint来打开文件。
// 这个文件打开之后不进入加密链表，所以可以直接
// Read和Write,不会被加密。
HANDLE cfCreateFileAccordingIrp(
   IN PDEVICE_OBJECT dev,
   IN PUNICODE_STRING file_full_path,
   IN PIO_STACK_LOCATION irpsp,
   OUT NTSTATUS *status,
   OUT PFILE_OBJECT *file,
   OUT PULONG information)
{
	HANDLE file_h = NULL;
	IO_STATUS_BLOCK io_status;
	ULONG desired_access;
	ULONG disposition;
	ULONG create_options;
	ULONG share_access;
	ULONG file_attri;
    OBJECT_ATTRIBUTES obj_attri;

    ASSERT(irpsp->MajorFunction == IRP_MJ_CREATE);

    *information = 0;

    // 填写object attribute
    InitializeObjectAttributes(
        &obj_attri,
        file_full_path,
        OBJ_KERNEL_HANDLE|OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);

    // 获得IRP中的参数。
	desired_access = irpsp->Parameters.Create.SecurityContext->DesiredAccess;
	disposition = (irpsp->Parameters.Create.Options>>24);
	create_options = (irpsp->Parameters.Create.Options & 0x00ffffff);
	share_access = irpsp->Parameters.Create.ShareAccess;
	file_attri = irpsp->Parameters.Create.FileAttributes;

    // 调用IoCreateFileSpecifyDeviceObjectHint打开文件。
    *status = IoCreateFileSpecifyDeviceObjectHint(
        &file_h,
        desired_access,
        &obj_attri,
        &io_status,
        NULL,
        file_attri,
        share_access,
        disposition,
        create_options,
        NULL,
        0,
        CreateFileTypeNone,
        NULL,
        0,
        dev);

    if(!NT_SUCCESS(*status))
        return file_h;

    // 记住information,便于外面使用。
    *information = io_status.Information;

    // 从句柄得到一个fileobject便于后面的操作。记得一定要解除
    // 引用。
    *status = ObReferenceObjectByHandle(
        file_h,
        0,
        *IoFileObjectType,
        KernelMode,
        file,
        NULL);

    // 如果失败了就关闭，假设没打开文件。但是这个实际上是不
    // 应该出现的。
    if(!NT_SUCCESS(*status))
    {
        ASSERT(FALSE);
        ZwClose(file_h);
    }
    return file_h;
}

// 写入一个文件头。
NTSTATUS cfWriteAHeader(PFILE_OBJECT file,PDEVICE_OBJECT next_dev)
{
    static WCHAR header_flags[CF_FILE_HEADER_SIZE/sizeof(WCHAR)] = {L'C',L'F',L'H',L'D'};
    LARGE_INTEGER file_size,offset;
    ULONG length = CF_FILE_HEADER_SIZE;
    NTSTATUS status;

    offset.QuadPart = 0;
    file_size.QuadPart = CF_FILE_HEADER_SIZE;
    // 首先设置文件的大小为4k。
    status = cfFileSetFileSize(next_dev,file,&file_size);
    if(status != STATUS_SUCCESS)
        return status;

    // 然后写入8个字节的头。
   return cfFileReadWrite(next_dev,file,&offset,&length,header_flags,FALSE);
}


// 打开预处理。
ULONG cfIrpCreatePre(
    PIRP irp,
    PIO_STACK_LOCATION irpsp,
    PFILE_OBJECT file,
    PDEVICE_OBJECT next_dev)
{
    UNICODE_STRING path = { 0 };
    // 首先获得要打开文件的路径。
    ULONG length = cfFileFullPathPreCreate(file,&path);
    NTSTATUS status;
    ULONG ret = SF_IRP_PASS;
    PFILE_OBJECT my_file = NULL;
    HANDLE file_h;
    ULONG information = 0;
    LARGE_INTEGER file_size,offset = { 0 };
    BOOLEAN dir,sec_file;
    // 获得打开访问期望。
	ULONG desired_access = irpsp->Parameters.Create.SecurityContext->DesiredAccess;
    WCHAR header_flags[4] = {L'C',L'F',L'H',L'D'};
    WCHAR header_buf[4] = { 0 };
    ULONG disp;

    // 无法得到路径，直接放过即可。
    if(length == 0)
        return SF_IRP_PASS;

    // 如果只是想打开目录的话，直接放过
    if(irpsp->Parameters.Create.Options & FILE_DIRECTORY_FILE)
        return SF_IRP_PASS;

    do {

        // 给path分配缓冲区
        path.Buffer = ExAllocatePoolWithTag(NonPagedPool,length+4,CF_MEM_TAG);
        path.Length = 0;
        path.MaximumLength = (USHORT)length + 4;
        if(path.Buffer == NULL)
        {
            // 内存不够，这个请求直接挂掉
            status = STATUS_INSUFFICIENT_RESOURCES;
            ret = SF_IRP_COMPLETED;
            break;
        }
        length = cfFileFullPathPreCreate(file,&path);

        // 得到了路径，打开这个文件。
        file_h = cfCreateFileAccordingIrp(
            next_dev,
            &path,
            irpsp,
            &status,
            &my_file,
            &information);

        // 如果没有成功的打开，那么说明这个请求可以结束了
        if(!NT_SUCCESS(status))
        {
            ret = SF_IRP_COMPLETED;
            break;
        }

        // 得到了my_file之后，首先判断这个文件是不是已经在
        // 加密的文件之中。如果在，直接返回passthru即可
        cfListLock();
        sec_file = cfIsFileCrypting(my_file);
        cfListUnlock();
        if(sec_file)
        {
            ret = SF_IRP_PASS;
            break;
        }

        // 现在虽然打开，但是这依然可能是一个目录。在这里
        // 判断一下。同时也可以得到文件的大小。
        status = cfFileGetStandInfo(
	        next_dev,
	        my_file,
	        NULL,
	        &file_size,
	        &dir);

        // 查询失败。禁止打开。
        if(!NT_SUCCESS(status))
        {
            ret = SF_IRP_COMPLETED;
            break;
        }

        // 如果这是一个目录，那么不管它了。
        if(dir)
        {
            ret = SF_IRP_PASS;
            break;
        }

        // 如果文件大小为0，且有写入或者追加数据的意图，
        // 就应该加密文件。应该在这里写入文件头。这也是唯
        // 一需要写入文件头的地方。
        if(file_size.QuadPart == 0 && 
            (desired_access & 
                (FILE_WRITE_DATA| 
		        FILE_APPEND_DATA)))
        {
            // 不管是否成功。一定要写入头。
            cfWriteAHeader(my_file,next_dev);
            // 写入头之后，这个文件属于必须加密的文件
            ret = SF_IRP_GO_ON;
            break;
        }

        // 这个文件有大小，而且大小小于头长度。不需要加密。
        if(file_size.QuadPart < CF_FILE_HEADER_SIZE)
        {
            ret = SF_IRP_PASS;
            break;
        }

        // 现在读取文件。比较来看是否需要加密，直接读个8字
        // 节就足够了。这个文件有大小，而且比CF_FILE_HEADER_SIZE
        // 长。此时读出前8个字节，判断是否要加密。
        length = 8;
        status = cfFileReadWrite(next_dev,my_file,&offset,&length,header_buf,TRUE);
        if(status != STATUS_SUCCESS)
        {
            // 如果失败了就不加密了。
            ASSERT(FALSE);
            ret = SF_IRP_PASS;
            break;
        }
        // 读取到内容，比较和加密标志是一致的，加密。
        if(RtlCompareMemory(header_flags,header_buf,8) == 8)
        {
            // 到这里认为是必须加密的。这种情况下，必须返回GO_ON.
            ret = SF_IRP_GO_ON;
            break;
        }

        // 其他的情况都是不需要加密的。
        ret = SF_IRP_PASS;
    } while(0);

    if(path.Buffer != NULL)
        ExFreePool(path.Buffer);    
    if(file_h != NULL)
        ZwClose(file_h);
    if(ret == SF_IRP_GO_ON)
    {
        // 要加密的，这里清一下缓冲。避免文件头出现在缓冲里。
        cfFileCacheClear(my_file);
    }
    if(my_file != NULL)
        ObDereferenceObject(my_file);

    // 如果要返回完成，则必须把这个请求完成。这一般都是
    // 以错误作为结局的。
    if(ret == SF_IRP_COMPLETED)
    {
		irp->IoStatus.Status = status;
		irp->IoStatus.Information = information;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
    }

    // 要注意:
    // 1.文件的CREATE改为OPEN.
    // 2.文件的OVERWRITE去掉。不管是不是要加密的文件，
    // 都必须这样做。否则的话，本来是试图生成文件的，
    // 结果发现文件已经存在了。本来试图覆盖文件的，再
    // 覆盖一次会去掉加密头。
    disp = FILE_OPEN;
    irpsp->Parameters.Create.Options &= 0x00ffffff;
    irpsp->Parameters.Create.Options |= (disp << 24);
    return ret;
}

/////////////////////////////////////////cf_create.c//////////////////////////////
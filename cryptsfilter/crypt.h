
#define SF_IRP_GO_ON		    3L
#define SF_IRP_COMPLETED		4L
#define SF_IRP_PASS		        5L

////////////////////////////////////////////cf_proc.h/////////////////////////

void cfCurProcNameInit();

// 以下函数可以获得进程名。返回获得的长度。
ULONG cfCurProcName(PUNICODE_STRING name);

// 判断当前进程是不是notepad.exe
BOOLEAN cfIsCurProcSec(void);


//////////////////////////////////////////cf_proc.h////////////////////////////


/////////////////////////////////////////cf_modify_irp.h//////////////////////

void cfIrpSetInforPre(
					  PIRP irp,
					  PIO_STACK_LOCATION irpsp);

void cfIrpQueryInforPost(PIRP irp,PIO_STACK_LOCATION irpsp);

void cfIrpDirectoryControlPost(PIRP irp,PIO_STACK_LOCATION irpsp);

void cfIrpReadPre(PIRP irp,PIO_STACK_LOCATION irpsp);

void cfIrpReadPost(PIRP irp,PIO_STACK_LOCATION irpsp);

BOOLEAN cfIrpWritePre(PIRP irp,PIO_STACK_LOCATION irpsp,void **context);

void cfIrpWritePost(PIRP irp,PIO_STACK_LOCATION irpsp,void *context);


//////////////////////////////////////cf_modify_irp.h////////////////////////////

/////////////////////////////////////cf_list.h//////////////////////////////////

void cfListInit();
BOOLEAN cfListInited();
void cfListLock();
void cfListUnlock();
// 任意给定一个文件，判断是否在加密链表中。
BOOLEAN cfIsFileCrypting(PFILE_OBJECT file);
BOOLEAN cfFileCryptAppendLk(PFILE_OBJECT file);
BOOLEAN cfIsFileNeedCrypt(
						  PFILE_OBJECT file,
						  PDEVICE_OBJECT next_dev,
						  ULONG desired_access,
						  BOOLEAN *need_write_header);
// 当有文件被clean up的时候调用此函数。如果检查发现
// FileObject->FsContext在列表中
BOOLEAN cfCryptFileCleanupComplete(PFILE_OBJECT file);
NTSTATUS cfWriteAHeader(PFILE_OBJECT file,PDEVICE_OBJECT next_dev);


/////////////////////////////////////cf_list.h////////////////////////////////////////


////////////////////////////////////cf_file_irp.h////////////////////////////////////

// 自发送SetInformation请求.
NTSTATUS 
cfFileSetInformation( 
					 DEVICE_OBJECT *dev, 
					 FILE_OBJECT *file,
					 FILE_INFORMATION_CLASS infor_class,
					 FILE_OBJECT *set_file,
					 void* buf,
					 ULONG buf_len);

NTSTATUS
cfFileQueryInformation(
					   DEVICE_OBJECT *dev, 
					   FILE_OBJECT *file,
					   FILE_INFORMATION_CLASS infor_class,
					   void* buf,
					   ULONG buf_len);

NTSTATUS 
cfFileReadWrite( 
				DEVICE_OBJECT *dev, 
				FILE_OBJECT *file,
				LARGE_INTEGER *offset,
				ULONG *length,
				void *buffer,
				BOOLEAN read_write);

NTSTATUS
cfFileGetStandInfo(
				   PDEVICE_OBJECT dev,
				   PFILE_OBJECT file,
				   PLARGE_INTEGER allocate_size,
				   PLARGE_INTEGER file_size,
				   BOOLEAN *dir);

NTSTATUS
cfFileSetFileSize(
				  DEVICE_OBJECT *dev,
				  FILE_OBJECT *file,
				  LARGE_INTEGER *file_size);

// 清理缓冲
void cfFileCacheClear(PFILE_OBJECT pFileObject);

//////////////////////////////////////////////cf_file_irp.h////////////////////////////


/////////////////////////////////////////////cf_create.h///////////////////////////////

// 打开预处理。请注意，只有当前进程为加密进程，才需要调
// 用这个预处理来处理。
ULONG cfIrpCreatePre(
					 PIRP irp,
					 PIO_STACK_LOCATION irpsp,
					 PFILE_OBJECT file,
					 PDEVICE_OBJECT next_dev);

/////////////////////////////////////////cf_create.h/////////////////////////////////

// test driver

#include <windows.h>
#include <winioctl.h>

#define FILE_DEVICE_DISKFLT			0x8000
#define DISKFLT_IOCTL_BASE	0x800

#define CTL_CODE_DISKFLT(i)	\
CTL_CODE(FILE_DEVICE_DISKFLT, DISKFLT_IOCTL_BASE+i, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_DISKFLT_START				CTL_CODE_DISKFLT(0)

#define DISKFILTER_DOS_DEVICE_NAME_W	L"\\DosDevices\\DiskFlt"
#define DISKFILTER_DEVICE_NAME_W		L"\\Device\\DiskFlt"

int main(int argc, char* argv[])
{
	DWORD	retBytes = 0;
	HANDLE handle = CreateFile("\\\\.\\DiskFlt",
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (handle)
	{
		DeviceIoControl(handle, IOCTL_DISKFLT_START, 0, 0, 0, 0, &retBytes, NULL);
		CloseHandle(handle);
	}
	else
	{
		MessageBox(NULL, "CreateFile error", NULL, MB_OK | MB_ICONERROR);
	}

	return 0;
}

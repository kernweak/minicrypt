#ifndef diskfltlib_h__
#define diskfltlib_h__

extern 
PDEVICE_OBJECT
on_diskperf_driver_entry(
	PDRIVER_OBJECT driver,
	PUNICODE_STRING reg
	);

extern 
VOID 
on_diskperf_driver_unload(PDRIVER_OBJECT DriverObject);


extern 
BOOLEAN 
on_diskperf_dispatch(
	PDEVICE_OBJECT dev,
    PIRP irp,
	NTSTATUS *status);

extern
BOOLEAN
on_diskperf_read_write(
	IN PUNICODE_STRING physics_device_name,
	IN ULONG	device_type,
	IN ULONG device_number,
	IN ULONG partition_number,
	IN PDEVICE_OBJECT device_object,
	IN PIRP irp,
	IN NTSTATUS *status);

extern
VOID
on_diskperf_new_disk(
	IN PDEVICE_OBJECT device_object,
	IN PUNICODE_STRING physics_device_name,
	IN ULONG device_type,			
	IN ULONG disk_number,
	IN ULONG partition_number
	);

extern
VOID
on_diskperf_remove_disk(
	IN PDEVICE_OBJECT device_object,
	IN PUNICODE_STRING physics_device_name
	);


#endif // diskfltlib_h__

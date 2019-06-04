#include "ntddk.h"
#include "notify.h"
#include "ntifs.h"


NTSTATUS 
NTAPI 
ExRaiseHardError( 
				 IN NTSTATUS ErrorStatus, 
				 IN ULONG NumberOfParameters, 
				 IN ULONG UnicodeStringParameterMask, 
				 IN PVOID Parameters, 
				 IN ULONG ResponseOption, 
				 OUT PULONG Response );


ULONG 
kMessageBox ( 
	PUNICODE_STRING Message,
	PUNICODE_STRING Caption,
	ULONG ResponseOption,
	ULONG Type
	) 
{
	NTSTATUS		Status; 
	PVOID Parameters[] = {
		Message,
		Caption,
		ResponseOption | Type, 
		0 
	}; 

	ULONG Response = 0; 

	Status = ExRaiseHardError ( 
		STATUS_SERVICE_NOTIFICATION|0x10000000, 
		3, // Number of parameters
		3, // Parameter mask -- first two are pointers
		&Parameters, 
		ResponseOption, 
		&Response 
		); 
	
	return Response; 
}
////////////////////////////////////////////////////////////////////////////
// FAT specific:
//
// RootDirSectors = ((BPB_RootEntCnt * 32) + (BPB_BytsPerSec - 1)) / BPB_BytsPerSec;
//
// If(BPB_FATSz16 != 0)
//		FATSz = BPB_FATSz16;
// Else
//		FATSz = BPB_FATSz32;
//
// FirstDataSector = BPB_ResvdSecCnt + (BPB_NumFATs * FATSz) + RootDirSectors;
// FirstDataSector *= BPB_BytsPerSec; // Logical offset
//
// If(BPB_TotSec16 != 0)
//		TotSec = BPB_TotSec16;
// Else
//		TotSec = BPB_TotSec32;
//
// DataSec = TotSec - (BPB_ResvdSecCnt + (BPB_NumFATs * FATSz) + RootDirSectors);
// CountofClusters = DataSec / BPB_SecPerClus;
//
// If(CountofClusters < 4085) {
// 	/* Volume is FAT12 */
// } else if(CountofClusters < 65525) {
//     /* Volume is FAT16 */
// } else {
//     /* Volume is FAT32 */
// }

#include <pshpack1.h>

// BIOS Parameter Block structure (FAT12/16/32)

typedef struct _FAT_BPB
{
	WORD	wBytsPerSec;			// Count of bytes per sector
	BYTE	bySecPerClus;			// Number of sectors per allocation unit
	WORD	wRsvdSecCnt;			// Number of reserved sectors
	BYTE	byNumFATs;				// The count of FAT data structures on the volume
	WORD	wRootEntCnt;			// Count of directory entries in the root directory
	WORD	wTotSec16;				// Old 16-bit total count of sectors on the volume
	BYTE	byMedia;				// Media type
	WORD	wFATSz16;				// Old 16-bit count of sectors occupied by one FAT.	
	WORD	wSecPerTrk;				// Sectors per track for interrupt 0x13
	WORD	wNumHeads;				// Number of heads for interrupt 0x13
	DWORD	dwHiddSec;				// Count of hidden sectors preceding the partition that contains this FAT volume
	DWORD	dwTotSec32;				// New 32-bit total count of sectors on the volume
	
} FAT_BPB, *PFAT_BPB, *LPFAT_BPB;

// Extended BIOS Parameter Block structure (FAT12/16/32)

typedef struct _FAT_EBPB
{
	BYTE	byDrvNum;				// Int 0x13 drive number 
	BYTE	byReserved1;			// Reserved (used by Windows NT)
	BYTE	byBootSig;				// Extended boot signature
	DWORD	dwVolID;				// Volume serial number
	BYTE	pbyVolLab[ 11 ];		// Volume label
	BYTE	pbyFilSysType[ 8 ];		// File system type, not used
	
} FAT_EBPB, *PFAT_EBPB, *LPFAT_EBPB;

// Extended BIOS Parameter Block structure (FAT32)

typedef struct _FAT_EBPB32
{
	DWORD		dwFATSz32;			// FAT32 32-bit count of sectors occupied by ONE FAT
	WORD		wExtFlags;			// Extended flags
	WORD		wFSVer;				// Version number of the FAT32 volume
	DWORD		dwRootClus;			// Cluster number of the first cluster of the root directory
	WORD		wFSInfo;			// Sector number of FSINFO structure in the reserved area of the FAT32 volume
	WORD		wBkBootSec;			// Sector number in the reserved area of the volume of a copy of the boot record
	BYTE		pbyReserved[ 12 ];	// Reserved for future expansion
	
	FAT_EBPB	ebpb;
	
} FAT_EBPB32, *PFAT_EBPB32, *LPFAT_EBPB32;

// Logical Boot Record structure (volume boot sector)

typedef struct _FAT_LBR
{
	BYTE		pbyJmpBoot[ 3 ];	// Jump instruction to boot code
	BYTE		pbyOEMName[ 8 ];	// Name string
	
	FAT_BPB		bpb;				// BIOS Parameter Block
	
	union
	{
		FAT_EBPB	ebpb16;			// FAT12/16 Extended BIOS Parameter Block
		FAT_EBPB32	ebpb32;			// FAT32 Extended BIOS Parameter Block
	};
	
	BYTE		pbyBootCode[ 420 ];	// Boot sector code
	WORD		wTrailSig;			// 0xAA55
	
} FAT_LBR, *PFAT_LBR, *LPFAT_LBR;

#include <poppack.h>
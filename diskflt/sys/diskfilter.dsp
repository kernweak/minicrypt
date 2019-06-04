# Microsoft Developer Studio Project File - Name="diskfilter" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Application" 0x0101

CFG=diskfilter - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "diskfilter.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "diskfilter.mak" CFG="diskfilter - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "diskfilter - Win32 Release" (based on "Win32 (x86) Application")
!MESSAGE "diskfilter - Win32 Debug" (based on "Win32 (x86) Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "diskfilter - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /Gz /W3 /WX /Oy /Gy /D "WIN32" /Oxs /c
# ADD CPP /nologo /Gz /W3 /O2 /I "$(BASEDIR)\inc\ddk\w2k" /I "$(BASEDIR)\inc\ddk\wdm\w2k" /I "$(BASEDIR)\inc\w2k" /D WINNT=1 /D _WIN32_WINNT=0x0400 /D DBG=0 /D _X86_=1 /FAcs /FR /YX /Oxs /Zel -cbstring /QIfdiv- /QIf /GF /c
# SUBTRACT CPP /WX
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /o "NUL" /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /o "NUL" /win32
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /i "$(BASEDIR)\inc" /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 /nologo /machine:IX86
# ADD LINK32 ntoskrnl.lib hal.lib wmilib.lib wdm.lib /nologo /base:"0x10000" /version:5.1 /entry:"DriverEntry" /map /machine:IX86 /nodefaultlib /out:"Bin\diskflt.sys" /libpath:"$(BASEDIR)\lib\w2k\i386" /driver /IGNORE:4078 /MERGE:_PAGE=PAGE /MERGE:_TEXT=.text /SECTION:INIT,d /FORCE:MULTIPLE /OPT:REF /align:0x20 /osversion:5.1 /subsystem:native,5.1
# SUBTRACT LINK32 /debug

!ELSEIF  "$(CFG)" == "diskfilter - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /Gz /W3 /Zi /Od /D "WIN32" /YX /FD /c
# ADD CPP /Gz /W3 /Z7 /Od /Gy /I "$(BASEDIR)\inc\ddk\w2k" /I "$(BASEDIR)\inc\ddk\wdm\w2k" /I "$(BASEDIR)\inc\w2k" /D WINNT=1 /D _WIN32_WINNT=0x0400 /D DBG=1 /D _X86_=1 /FAcs /FR /YX /FD /Zel -cbstring /QIfdiv- /QIf /GF /c
# SUBTRACT CPP /nologo
# ADD BASE MTL /nologo /mktyplib203 /o "NUL" /win32
# ADD MTL /nologo /mktyplib203 /o "NUL" /win32
# ADD BASE RSC /l 0x409
# ADD RSC /l 0x409 /i "$(BASEDIR)\inc"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 /nologo /machine:IX86
# ADD LINK32 wmilib.lib ntoskrnl.lib hal.lib /base:"0x10000" /version:5.1 /entry:"DriverEntry" /incremental:no /map /debug /machine:IX86 /nodefaultlib /out:"Bin\diskflt.sys" /libpath:"$(BASEDIR)\lib\w2k\i386" /driver /ignore:4078 /MERGE:_PAGE=PAGE /MERGE:_TEXT=.text /SECTION:INIT,d /FORCE:MULTIPLE /OPT:REF /align:0x20 /osversion:5.1 /subsystem:native,5.1
# SUBTRACT LINK32 /pdb:none

!ENDIF 

# Begin Target

# Name "diskfilter - Win32 Release"
# Name "diskfilter - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=.\diskfilter.rc
# End Source File
# Begin Source File

SOURCE=.\diskflt.c
DEP_CPP_DISKF=\
	".\diskflt.h"\
	".\diskfltlib.h"\
	".\fatlbr.h"\
	".\generictable.h"\
	".\md5.h"\
	".\mempool\mempool.h"\
	".\notify.h"\
	".\ntifs.h"\
	".\ntimage.h"\
	"c:\ddk\inc\ddk\w2k\ia64reg.h"\
	"c:\ddk\inc\ddk\w2k\ntdddisk.h"\
	"c:\ddk\inc\ddk\w2k\ntddk.h"\
	"c:\ddk\inc\ddk\w2k\ntddstor.h"\
	"c:\ddk\inc\ddk\w2k\ntddvol.h"\
	"c:\ddk\inc\ddk\w2k\ntdef.h"\
	"c:\ddk\inc\ddk\w2k\ntstatus.h"\
	"c:\ddk\inc\w2k\basetsd.h"\
	"c:\ddk\inc\w2k\bugcodes.h"\
	"c:\ddk\inc\w2k\guiddef.h"\
	"c:\ddk\inc\w2k\ntiologc.h"\
	{$(INCLUDE)}"specstrings.h"\
	
NODEP_CPP_DISKF=\
	"c:\ddk\inc\ddk\w2k\alpharef.h"\
	

!IF  "$(CFG)" == "diskfilter - Win32 Release"

!ELSEIF  "$(CFG)" == "diskfilter - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\diskfltlib.c
DEP_CPP_DISKFL=\
	".\diskfltlib.h"\
	"c:\ddk\inc\ddk\w2k\ia64reg.h"\
	"c:\ddk\inc\ddk\w2k\mountdev.h"\
	"c:\ddk\inc\ddk\w2k\mountmgr.h"\
	"c:\ddk\inc\ddk\w2k\ntdddisk.h"\
	"c:\ddk\inc\ddk\w2k\ntddk.h"\
	"c:\ddk\inc\ddk\w2k\ntddstor.h"\
	"c:\ddk\inc\ddk\w2k\ntddvol.h"\
	"c:\ddk\inc\ddk\w2k\ntdef.h"\
	"c:\ddk\inc\ddk\w2k\ntstatus.h"\
	"c:\ddk\inc\ddk\wdm\w2k\wmidata.h"\
	"c:\ddk\inc\ddk\wdm\w2k\wmiguid.h"\
	"c:\ddk\inc\ddk\wdm\w2k\wmilib.h"\
	"c:\ddk\inc\w2k\basetsd.h"\
	"c:\ddk\inc\w2k\bugcodes.h"\
	"c:\ddk\inc\w2k\guiddef.h"\
	"c:\ddk\inc\w2k\ntiologc.h"\
	"c:\ddk\inc\w2k\wmistr.h"\
	{$(INCLUDE)}"specstrings.h"\
	
NODEP_CPP_DISKFL=\
	"c:\ddk\inc\ddk\w2k\alpharef.h"\
	

!IF  "$(CFG)" == "diskfilter - Win32 Release"

!ELSEIF  "$(CFG)" == "diskfilter - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\mempool\malloc.c
DEP_CPP_MALLO=\
	"c:\ddk\inc\ddk\w2k\ia64reg.h"\
	"c:\ddk\inc\ddk\w2k\ntddk.h"\
	"c:\ddk\inc\ddk\w2k\ntdef.h"\
	"c:\ddk\inc\ddk\w2k\ntstatus.h"\
	"c:\ddk\inc\w2k\basetsd.h"\
	"c:\ddk\inc\w2k\bugcodes.h"\
	"c:\ddk\inc\w2k\guiddef.h"\
	"c:\ddk\inc\w2k\ntiologc.h"\
	{$(INCLUDE)}"specstrings.h"\
	
NODEP_CPP_MALLO=\
	"..\..\..\usr\include\malloc.h"\
	"c:\ddk\inc\ddk\w2k\alpharef.h"\
	

!IF  "$(CFG)" == "diskfilter - Win32 Release"

!ELSEIF  "$(CFG)" == "diskfilter - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\md5.c
DEP_CPP_MD5_C=\
	".\md5.h"\
	

!IF  "$(CFG)" == "diskfilter - Win32 Release"

!ELSEIF  "$(CFG)" == "diskfilter - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\mempool\mempool.c
DEP_CPP_MEMPO=\
	".\mempool\debug.h"\
	"c:\ddk\inc\ddk\w2k\ia64reg.h"\
	"c:\ddk\inc\ddk\w2k\ntddk.h"\
	"c:\ddk\inc\ddk\w2k\ntdef.h"\
	"c:\ddk\inc\ddk\w2k\ntstatus.h"\
	"c:\ddk\inc\w2k\basetsd.h"\
	"c:\ddk\inc\w2k\bugcodes.h"\
	"c:\ddk\inc\w2k\guiddef.h"\
	"c:\ddk\inc\w2k\ntiologc.h"\
	{$(INCLUDE)}"specstrings.h"\
	
NODEP_CPP_MEMPO=\
	"c:\ddk\inc\ddk\w2k\alpharef.h"\
	

!IF  "$(CFG)" == "diskfilter - Win32 Release"

!ELSEIF  "$(CFG)" == "diskfilter - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\notify.c
DEP_CPP_NOTIF=\
	".\notify.h"\
	".\ntifs.h"\
	"c:\ddk\inc\ddk\w2k\ia64reg.h"\
	"c:\ddk\inc\ddk\w2k\ntddk.h"\
	"c:\ddk\inc\ddk\w2k\ntdef.h"\
	"c:\ddk\inc\ddk\w2k\ntstatus.h"\
	"c:\ddk\inc\w2k\basetsd.h"\
	"c:\ddk\inc\w2k\bugcodes.h"\
	"c:\ddk\inc\w2k\guiddef.h"\
	"c:\ddk\inc\w2k\ntiologc.h"\
	{$(INCLUDE)}"specstrings.h"\
	
NODEP_CPP_NOTIF=\
	"c:\ddk\inc\ddk\w2k\alpharef.h"\
	

!IF  "$(CFG)" == "diskfilter - Win32 Release"

!ELSEIF  "$(CFG)" == "diskfilter - Win32 Debug"

!ENDIF 

# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=.\diskfltlib.h
# End Source File
# Begin Source File

SOURCE=.\notify.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# Begin Source File

SOURCE=.\res\disk.ico
# End Source File
# Begin Source File

SOURCE=.\res\disk1.ico
# End Source File
# End Group
# Begin Source File

SOURCE=.\Readme.txt
# End Source File
# End Target
# End Project

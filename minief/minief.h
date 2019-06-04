#pragma once

#define MINIEF_PORT_NAME                   L"\\MiniEfPort"

#define MINIEF_MAJ_VERSION		2
#define MINIEF_MIN_VERSION		0

typedef struct _MINIEFVER {

    USHORT Major;
    USHORT Minor;

} MINIEFVER, *PMINIEFVER;

typedef enum _MINIEF_COMMAND {

	GetMiniEfLog,
    GetMiniEfVersion

} MINIEF_COMMAND;

typedef struct _COMMAND_MESSAGE {
    MINIEF_COMMAND Command;
    ULONG Reserved;  // Alignment on IA64
    UCHAR Data[];
} COMMAND_MESSAGE, *PCOMMAND_MESSAGE;


#ifndef Add2Ptr
#define Add2Ptr(P,I) ((PVOID)((PUCHAR)(P) + (I)))
#endif

#ifndef ROUND_TO_SIZE
#define ROUND_TO_SIZE(_length, _alignment)    \
            (((_length) + ((_alignment)-1)) & ~((_alignment) - 1))
#endif

#ifndef FlagOn
#define FlagOn(_F,_SF)        ((_F) & (_SF))
#endif
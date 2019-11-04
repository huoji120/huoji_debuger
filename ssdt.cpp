#include "ssdt.h"
#include "pe.h"
#include "ntdll.h"

//structures
struct SSDTStruct
{
    LONG* pServiceTable;
    PVOID pCounterTable;
    ULONGLONG NumberOfServices;
    PCHAR pArgumentTable;
};
extern "C" PVOID GetKernelBase(PULONG pImageSize)
{
	typedef struct _SYSTEM_MODULE_ENTRY
	{
		HANDLE Section;
		PVOID MappedBase;
		PVOID ImageBase;
		ULONG ImageSize;
		ULONG Flags;
		USHORT LoadOrderIndex;
		USHORT InitOrderIndex;
		USHORT LoadCount;
		USHORT OffsetToFileName;
		UCHAR FullPathName[256];
	} SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

#pragma warning(disable:4200)
	typedef struct _SYSTEM_MODULE_INFORMATION
	{
		ULONG Count;
		SYSTEM_MODULE_ENTRY Module[0];
	} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

	PVOID pModuleBase = NULL;
	PSYSTEM_MODULE_INFORMATION pSystemInfoBuffer = NULL;

	ULONG SystemInfoBufferSize = 0;

	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation,
		&SystemInfoBufferSize,
		0,
		&SystemInfoBufferSize);

	if (!SystemInfoBufferSize)
	{
		DebugPrint("[DebugMessage] ZwQuerySystemInformation (1) failed...\r\n");
		return NULL;
	}

	pSystemInfoBuffer = (PSYSTEM_MODULE_INFORMATION)ExAllocatePool(NonPagedPool, SystemInfoBufferSize * 2);

	if (!pSystemInfoBuffer)
	{
		DebugPrint("[DebugMessage] ExAllocatePool failed...\r\n");
		return NULL;
	}

	memset(pSystemInfoBuffer, 0, SystemInfoBufferSize * 2);

	status = ZwQuerySystemInformation(SystemModuleInformation,
		pSystemInfoBuffer,
		SystemInfoBufferSize * 2,
		&SystemInfoBufferSize);

	if (NT_SUCCESS(status))
	{
		pModuleBase = pSystemInfoBuffer->Module[0].ImageBase;
		if (pImageSize)
			*pImageSize = pSystemInfoBuffer->Module[0].ImageSize;
	}
	else
		DebugPrint("[DebugMessage] ZwQuerySystemInformation (2) failed...\r\n");

	ExFreePool(pSystemInfoBuffer);

	return pModuleBase;
}

extern "C" SSDTStruct* SSDTfind()
{
    static SSDTStruct* SSDT = 0;
    if(!SSDT)
    {
        //x64 code
        ULONG kernelSize;
        ULONG_PTR kernelBase = (ULONG_PTR)GetKernelBase(&kernelSize);
        if(kernelBase == 0 || kernelSize == 0)
            return NULL;

        // Find KiSystemServiceStart
        const unsigned char KiSystemServiceStartPattern[] = { 0x8B, 0xF8, 0xC1, 0xEF, 0x07, 0x83, 0xE7, 0x20, 0x25, 0xFF, 0x0F, 0x00, 0x00 };
        const ULONG signatureSize = sizeof(KiSystemServiceStartPattern);
        bool found = false;
        ULONG KiSSSOffset;
        for(KiSSSOffset = 0; KiSSSOffset < kernelSize - signatureSize; KiSSSOffset++)
        {
            if(RtlCompareMemory(((unsigned char*)kernelBase + KiSSSOffset), KiSystemServiceStartPattern, signatureSize) == signatureSize)
            {
                found = true;
                break;
            }
        }
        if(!found)
            return NULL;

        // lea r10, KeServiceDescriptorTable
        ULONG_PTR address = kernelBase + KiSSSOffset + signatureSize;
        LONG relativeOffset = 0;
        if((*(unsigned char*)address == 0x4c) &&
                (*(unsigned char*)(address + 1) == 0x8d) &&
                (*(unsigned char*)(address + 2) == 0x15))
        {
            relativeOffset = *(LONG*)(address + 3);
        }
        if(relativeOffset == 0)
            return NULL;

        SSDT = (SSDTStruct*)(address + relativeOffset + 7);
    }
    return SSDT;
}

PVOID SSDT::GetFunctionAddress(const char* apiname)
{
    //read address from SSDT
    SSDTStruct* SSDT = SSDTfind();
    if(!SSDT)
    {
		DebugPrint("[DebugMessage] SSDT not found...\r\n");
        return 0;
    }
    ULONG_PTR SSDTbase = (ULONG_PTR)SSDT->pServiceTable;
    if(!SSDTbase)
    {
		DebugPrint("[DebugMessage] ServiceTable not found...\r\n");
        return 0;
    }
    ULONG readOffset = NTDLL::GetExportSsdtIndex(apiname);
    if(readOffset == -1)
        return 0;
    if(readOffset >= SSDT->NumberOfServices)
    {
		DebugPrint("[DebugMessage] Invalid read offset...\r\n");
        return 0;
    }
    return (PVOID)((SSDT->pServiceTable[readOffset] >> 4) + SSDTbase);

}

static PVOID FindCaveAddress(PVOID CodeStart, ULONG CodeSize, ULONG CaveSize)
{
    unsigned char* Code = (unsigned char*)CodeStart;

    for(unsigned int i = 0, j = 0; i < CodeSize; i++)
    {
        if(Code[i] == 0x90 || Code[i] == 0xCC)  //NOP or INT3
            j++;
        else
            j = 0;
        if(j == CaveSize)
            return (PVOID)((ULONG_PTR)CodeStart + i - CaveSize + 1);
    }
    return 0;
}

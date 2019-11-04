#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include "infinityhook.h"
#pragma comment (lib,"libinfinityhook.lib")
#define WOW64_MAXIMUM_SUPPORTED_EXTENSION     512
#define WOW64_SIZE_OF_80387_REGISTERS      80
#define PROCESS_TERMINATE         0x0001  
#define PROCESS_VM_OPERATION      0x0008  
#define PROCESS_VM_READ           0x0010  
#define PROCESS_VM_WRITE          0x0020 
#define DebugPrint(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, __VA_ARGS__)
#define DEBUGNAME "x64dbg.exe"
extern "C" NTKERNELAPI UCHAR * PsGetProcessImageFileName(__in PEPROCESS Process);
extern "C" NTKERNELAPI PEPROCESS PsGetThreadProcess(_In_ PETHREAD Thread);
extern "C" NTKERNELAPI NTSTATUS ObQueryObjectAuditingByHandle(_In_ HANDLE Handle, _Out_ PBOOLEAN GenerateOnClose);
extern "C" NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(_In_ HANDLE ProcessId, _Outptr_ PEPROCESS * Process);
extern "C" NTKERNELAPI NTSTATUS NTAPI MmCopyVirtualMemory(IN PEPROCESS FromProcess, IN PVOID FromAddress, IN PEPROCESS ToProcess, OUT PVOID ToAddress, IN SIZE_T BufferSize, IN KPROCESSOR_MODE PreviousMode, OUT PSIZE_T NumberOfBytesCopied);
typedef struct _LDR_DATA_TABLE_ENTRY64
{
	LIST_ENTRY64    InLoadOrderLinks;
	LIST_ENTRY64    InMemoryOrderLinks;
	LIST_ENTRY64    InInitializationOrderLinks;
	PVOID            DllBase;
	PVOID            EntryPoint;
	ULONG            SizeOfImage;
	UNICODE_STRING    FullDllName;
	UNICODE_STRING     BaseDllName;
	ULONG            Flags;
	USHORT            LoadCount;
	USHORT            TlsIndex;
	PVOID            SectionPointer;
	ULONG            CheckSum;
	PVOID            LoadedImports;
	PVOID            EntryPointActivationContext;
	PVOID            PatchInformation;
	LIST_ENTRY64    ForwarderLinks;
	LIST_ENTRY64    ServiceTagLinks;
	LIST_ENTRY64    StaticLinks;
	PVOID            ContextInformation;
	ULONG64            OriginalBase;
	LARGE_INTEGER    LoadTime;
} LDR_DATA_TABLE_ENTRY64, * PLDR_DATA_TABLE_ENTRY64;
typedef struct _SYSTEM_THREAD {
	LARGE_INTEGER           KernelTime;
	LARGE_INTEGER           UserTime;
	LARGE_INTEGER           CreateTime;
	ULONG                   WaitTime;
	PVOID                   StartAddress;
	CLIENT_ID               ClientId;
	KPRIORITY               Priority;
	LONG                    BasePriority;
	ULONG                   ContextSwitchCount;
	ULONG                   State;
	KWAIT_REASON            WaitReason;
} SYSTEM_THREAD, * PSYSTEM_THREAD;
typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG                   NextEntryOffset;
	ULONG                   NumberOfThreads;
	LARGE_INTEGER           Reserved[3];
	LARGE_INTEGER           CreateTime;
	LARGE_INTEGER           UserTime;
	LARGE_INTEGER           KernelTime;
	UNICODE_STRING          ImageName;
	KPRIORITY               BasePriority;
	HANDLE                  ProcessId;
	HANDLE                  InheritedFromProcessId;
	ULONG                   HandleCount;
	ULONG                   Reserved2[2];
	ULONG                   PrivatePageCount;
	VM_COUNTERS             VirtualMemoryCounters;
	IO_COUNTERS             IoCounters;
	SYSTEM_THREAD           Threads[0];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemProcessInformation = 5,
	SystemModuleInformation = 11,
	SystemKernelDebuggerInformation = 35
} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;

typedef struct _OB_REG_CONTEXT {
	USHORT Version;
	UNICODE_STRING Altitude;
	USHORT ulIndex;
	OB_OPERATION_REGISTRATION* OperationRegistration;
} REG_CONTEXT, * PREG_CONTEXT;
typedef struct _OBJECT_TYPE_INFORMATION
{
	UNICODE_STRING TypeName;
	ULONG TotalNumberOfHandles;
	ULONG TotalNumberOfObjects;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

typedef struct _OBJECT_ALL_INFORMATION
{
	ULONG NumberOfObjects;
	OBJECT_TYPE_INFORMATION ObjectTypeInformation[1];
} OBJECT_ALL_INFORMATION, * POBJECT_ALL_INFORMATION;

typedef struct _WOW64_FLOATING_SAVE_AREA {
	ULONG   ControlWord;
	ULONG   StatusWord;
	ULONG   TagWord;
	ULONG   ErrorOffset;
	ULONG   ErrorSelector;
	ULONG   DataOffset;
	ULONG   DataSelector;
	char    RegisterArea[WOW64_SIZE_OF_80387_REGISTERS];
	ULONG   Cr0NpxState;
} WOW64_FLOATING_SAVE_AREA;
typedef WOW64_FLOATING_SAVE_AREA* PWOW64_FLOATING_SAVE_AREA;
typedef struct _WOW64_CONTEXT
{
	ULONG ContextFlags;
	ULONG Dr0;
	ULONG Dr1;
	ULONG Dr2;
	ULONG Dr3;
	ULONG Dr6;
	ULONG Dr7;
	WOW64_FLOATING_SAVE_AREA FloatSave;
	ULONG SegGs;
	ULONG SegFs;
	ULONG SegEs;
	ULONG SegDs;
	ULONG Edi;
	ULONG Esi;
	ULONG Ebx;
	ULONG Edx;
	ULONG Ecx;
	ULONG Eax;
	ULONG Ebp;
	ULONG Eip;
	ULONG SegCs;
	ULONG EFlags;
	ULONG Esp;
	ULONG SegSs;
	UCHAR ExtendedRegisters[WOW64_MAXIMUM_SUPPORTED_EXTENSION];
} WOW64_CONTEXT;
typedef WOW64_CONTEXT* PWOW64_CONTEXT;

typedef struct _OBJECT_TYPE_INITIALIZER
{
	UINT16 Length;
	union
	{
		UINT8 ObjectTypeFlags;
		struct
		{
			UINT8 CaseInsensitive : 1;
			UINT8 UnnamedObjectsOnly : 1;
			UINT8 UseDefaultObject : 1;
			UINT8 SecurityRequired : 1;
			UINT8 MaintainHandleCount : 1;
			UINT8 MaintainTypeList : 1;
			UINT8 SupportsObjectCallbacks : 1;
			UINT8 CacheAligned : 1;
		};
	};
	ULONG32 ObjectTypeCode;
	ULONG32 InvalidAttributes;
	struct _GENERIC_MAPPING GenericMapping;
	ULONG32 ValidAccessMask;
	ULONG32 RetainAccess;
	enum _POOL_TYPE PoolType;
	ULONG32 DefaultPagedPoolCharge;
	ULONG32 DefaultNonPagedPoolCharge;
	PVOID DumpProcedure;
	PVOID OpenProcedure;
	PVOID CloseProcedure;
	PVOID DeleteProcedure;
	PVOID ParseProcedure;
	PVOID SecurityProcedure;
	PVOID QueryNameProcedure;
	PVOID OkayToCloseProcedure;
}OBJECT_TYPE_INITIALIZER, * POBJECT_TYPE_INITIALIZER;

typedef struct _OBJECT_TYPE
{
	struct _LIST_ENTRY TypeList;
	struct _UNICODE_STRING Name;
	VOID* DefaultObject;
	UINT8 Index;
	UINT8 _PADDING0_[0x3];
	ULONG32 TotalNumberOfObjects;
	ULONG32 TotalNumberOfHandles;
	ULONG32 HighWaterNumberOfObjects;
	ULONG32 HighWaterNumberOfHandles;
	UINT8 _PADDING1_[0x4];
	struct _OBJECT_TYPE_INITIALIZER TypeInfo;
	//_EX_PUSH_LOCK TypeLock;
	ULONG64 TypeLock;
	ULONG32 Key;
	UINT8 _PADDING2_[0x4];
	struct _LIST_ENTRY CallbackList;
}OBJECT_TYPE, * POBJECT_TYPE;
typedef struct _COPY_MEMORY
{
	ULONGLONG localbuf;         // Buffer address
	ULONGLONG targetPtr;        // Target address
	ULONGLONG size;             // Buffer size
	ULONG     pid;              // Target process id
	BOOLEAN   write;            // TRUE if write operation, FALSE if read
} COPY_MEMORY, * PCOPY_MEMORY;

typedef NTSTATUS(NTAPI* NTQUERYINFORMATIONPROCESS)(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL
	);
typedef NTSTATUS(NTAPI* NTGETCONTEXTHREAD)(
	IN HANDLE ThreadHandle,
	IN OUT PCONTEXT Context);
typedef NTSTATUS(NTAPI* NTQUERYINFORMATIONTHREAD)(
	HANDLE ThreadHandle,
	THREADINFOCLASS ThreadInformationClass,
	PVOID ThreadInformation,
	ULONG ThreadInformationLength,
	PULONG ReturnLength
	);
typedef NTSTATUS(NTAPI* NTQUERYOBJECT)(
	IN HANDLE Handle OPTIONAL,
	IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
	OUT PVOID ObjectInformation OPTIONAL,
	IN ULONG ObjectInformationLength,
	OUT PULONG ReturnLength OPTIONAL
	);
typedef NTSTATUS(NTAPI* NTSETINFORMATIONTHREAD)(
	IN HANDLE ThreadHandle,
	IN THREADINFOCLASS ThreadInformationClass,
	IN PVOID ThreadInformation,
	IN ULONG ThreadInformationLength
	);
typedef NTSTATUS(NTAPI* NTQUERYSYSTEMINFORMATION)(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
	);
typedef NTSTATUS(NTAPI* NTOPENPROCESS)(
	PHANDLE            ProcessHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID         ClientId
	);
typedef NTSTATUS(NTAPI* NTREADVIRTUALMEMORY)(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	OUT PVOID Buffer,
	IN ULONG NumberOfBytesToRead,
	OUT PULONG NumberOfBytesReaded OPTIONAL);
typedef NTSTATUS(*NTWRITEVIRTUALMEMORY)(
	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	IN PVOID                Buffer,
	IN ULONG                NumberOfBytesToWrite,
	OUT PULONG              NumberOfBytesWritten OPTIONAL);
typedef NTSTATUS(*NTCREATETHREAD)(
	OUT PHANDLE             ThreadHandle,
	IN ACCESS_MASK          DesiredAccess,
	IN POBJECT_ATTRIBUTES   ObjectAttributes OPTIONAL,
	IN HANDLE               ProcessHandle,
	OUT PCLIENT_ID          ClientId,
	IN PCONTEXT             ThreadContext,
	IN PVOID		        InitialTeb,
	IN BOOLEAN              CreateSuspended);

typedef NTSTATUS(*NTOPENTHREAD)(
	_Out_  PHANDLE ThreadHandle,
	_In_   ACCESS_MASK DesiredAccess,
	_In_   POBJECT_ATTRIBUTES ObjectAttributes,
	_In_   PCLIENT_ID ClientId);
typedef NTSTATUS(*NTTERMINATEPROCESS)(
	HANDLE   ProcessHandle,
	NTSTATUS ExitStatus);
typedef NTSTATUS(*NTCLOSE)(
	HANDLE Handle);
extern "C"  NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(IN SYSTEM_INFORMATION_CLASS SystemInformationClass, OUT PVOID SystemInformation, IN ULONG SystemInformationLength, OUT PULONG ReturnLength OPTIONAL);
extern "C"  NTSYSAPI NTSTATUS NTAPI ObOpenObjectByPointer(PVOID Object, ULONG HandleAttributes, PACCESS_STATE PassedAccessState, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, PHANDLE Handle);
static NTQUERYINFORMATIONPROCESS pfn_NtQueryInformationProcess;
static NTGETCONTEXTHREAD pfn_NtGetContextThread;
static NTQUERYINFORMATIONTHREAD pfn_NtQueryInformationThread;
static NTQUERYOBJECT pfn_NtQueryObject;
static NTSETINFORMATIONTHREAD pfn_NtSetInformationThread;
static NTQUERYSYSTEMINFORMATION pfn_NtQuerySystemInformation;
static NTOPENPROCESS pfn_NtOpenProcess;
static NTREADVIRTUALMEMORY pfn_NtReadVirtualMemory;
static NTWRITEVIRTUALMEMORY pfn_NtWriteVirtualMemory;
static NTCREATETHREAD pfn_NtCreateThread;
static NTOPENTHREAD pfn_NtOpenThread;
static NTTERMINATEPROCESS pfn_NtTerminateProcess;
static NTCLOSE pfn_NtClose;
#include "head.h"
#include "ntdll.h"
#include "ssdt.h"

HANDLE g_CallbacksHandle;
HANDLE g_DebugHandle[666] = {0};
ULONG g_DbgPid = -1;
ULONG g_GamePid = -1;
bool g_startDebug = false;
UNICODE_STRING DeviceName;
UNICODE_STRING Win32Device;

VOID HandleAfterCreat(PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION OperationInformation)
{
	UNREFERENCED_PARAMETER(RegistrationContext);
	UNREFERENCED_PARAMETER(OperationInformation);
}
OB_PREOP_CALLBACK_STATUS ThreadHandleCallbacks(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	if (g_DbgPid == -1 || g_GamePid == -1)
		return OB_PREOP_SUCCESS;
	if (OperationInformation->KernelHandle)
		return OB_PREOP_SUCCESS;
	PEPROCESS OpenedProcess = (PEPROCESS)OperationInformation->Object, CurrentProcess = PsGetCurrentProcess();
	ULONG ulProcessId = (ULONG)PsGetProcessId(OpenedProcess);
	ULONG myProcessId = (ULONG)PsGetProcessId(CurrentProcess);
	/*
	if (myProcessId == g_DbgPid)
	{
		if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE || OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
		{
			OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0x1fffff;
			OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess = 0x1fffff;
		}
	}*/
	if (ulProcessId == g_DbgPid)
	{
		if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
			OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = (SYNCHRONIZE | THREAD_QUERY_LIMITED_INFORMATION);
		else
			OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = (SYNCHRONIZE | THREAD_QUERY_LIMITED_INFORMATION);
	}
	return OB_PREOP_SUCCESS;

}
OB_PREOP_CALLBACK_STATUS ProcessHandleCallbacks(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	UNREFERENCED_PARAMETER(RegistrationContext);
	if (g_DbgPid == -1 || g_GamePid == -1)
		return OB_PREOP_SUCCESS;
	if (OperationInformation->KernelHandle)
		return OB_PREOP_SUCCESS;
	PEPROCESS ProtectedProcessPEPROCESS;
	PEPROCESS ProtectedUserModeACPEPROCESS;
	PEPROCESS OpenedProcess = (PEPROCESS)OperationInformation->Object, CurrentProcess = PsGetCurrentProcess();
	ULONG ulProcessId = (ULONG)PsGetProcessId(OpenedProcess);
	ULONG myProcessId = (ULONG)PsGetProcessId(CurrentProcess);
	/*
	if (myProcessId == g_DbgPid && ulProcessId == g_GamePid)
	{
		if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE || OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
		{
			OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0x1fffff;
			OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess = 0x1fffff;
		}
	}*/
	if (ulProcessId == g_DbgPid) //如果进程是调试器进程
	{
		if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) // striping handle 
		{
			if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_TERMINATE) == PROCESS_TERMINATE)
			{
				//Terminate the process, such as by calling the user-mode TerminateProcess routine..
				OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
			}
			if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_OPERATION) == PROCESS_VM_OPERATION)
			{
				//Modify the address space of the process, such as by calling the user-mode WriteProcessMemory and VirtualProtectEx routines.
				OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
			}
			if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_READ) == PROCESS_VM_READ)
			{
				//Read to the address space of the process, such as by calling the user-mode ReadProcessMemory routine.
				OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
			}
			if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_WRITE) == PROCESS_VM_WRITE)
			{
				//Write to the address space of the process, such as by calling the user-mode WriteProcessMemory routine.
				OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
			}

		}
		if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
		{
			if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_TERMINATE) == PROCESS_TERMINATE)
			{
				//Terminate the process, such as by calling the user-mode TerminateProcess routine..
				OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
			}
			if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_OPERATION) == PROCESS_VM_OPERATION)
			{
				//Modify the address space of the process, such as by calling the user-mode WriteProcessMemory and VirtualProtectEx routines.
				OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
			}
			if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_READ) == PROCESS_VM_READ)
			{
				//Read to the address space of the process, such as by calling the user-mode ReadProcessMemory routine.
				OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
			}
			if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_WRITE) == PROCESS_VM_WRITE)
			{
				//Write to the address space of the process, such as by calling the user-mode WriteProcessMemory routine.
				OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
			}
		}
	}

	return OB_PREOP_SUCCESS;
}

VOID CreateProcessNotify(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create)
{
	UNREFERENCED_PARAMETER(ParentId);
	if (ProcessId == (HANDLE)4 || ProcessId == (HANDLE)0)
		return;

	if (!Create)
	{
		if (ProcessId == (HANDLE)g_DbgPid && g_startDebug)
		{
			DebugPrint("[DeugMessage] Debuger Exiting...\r\n");
			g_startDebug = false;
			g_GamePid = -1;
			g_DbgPid = -1;
		}
	}
	else if (!g_startDebug)
	{
		PEPROCESS Process;
		NTSTATUS status = PsLookupProcessByProcessId((HANDLE)ProcessId, &Process);
		if (Process)
			ObDereferenceObject(Process);
		if (NT_SUCCESS(status))
		{
			//	DebugPrint("[DeugMessage] CreateProcessNotify: %s ...\r\n", PsGetProcessImageFileName(Process));
			if (strstr((char*)PsGetProcessImageFileName(Process), DEBUGNAME))
			{
				DebugPrint("[DeugMessage] Found Debuger!...\r\n");
				g_startDebug = true;
				g_DbgPid = (ULONG)ProcessId;
			}
		}

	}
}

VOID InstallCallBacks()
{

	NTSTATUS NtHandleCallback = STATUS_UNSUCCESSFUL;
	NTSTATUS NtThreadCallback = STATUS_UNSUCCESSFUL;

	OB_OPERATION_REGISTRATION OBOperationRegistration[2];
	OB_CALLBACK_REGISTRATION OBOCallbackRegistration;
	REG_CONTEXT regContext;
	UNICODE_STRING usAltitude;
	memset(&OBOperationRegistration, 0, sizeof(OB_OPERATION_REGISTRATION));
	memset(&OBOCallbackRegistration, 0, sizeof(OB_CALLBACK_REGISTRATION));
	memset(&regContext, 0, sizeof(REG_CONTEXT));
	regContext.ulIndex = 1;
	regContext.Version = 120;
	RtlInitUnicodeString(&usAltitude, L"1000");
	if ((USHORT)ObGetFilterVersion() == OB_FLT_REGISTRATION_VERSION)
	{

		OBOperationRegistration[1].ObjectType = PsProcessType;
		OBOperationRegistration[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
		OBOperationRegistration[1].PreOperation = ProcessHandleCallbacks;
		OBOperationRegistration[1].PostOperation = HandleAfterCreat;
		OBOperationRegistration[0].ObjectType = PsThreadType;
		OBOperationRegistration[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
		OBOperationRegistration[0].PreOperation = ThreadHandleCallbacks;
		OBOperationRegistration[0].PostOperation = HandleAfterCreat;
		OBOCallbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
		OBOCallbackRegistration.OperationRegistrationCount = 2;
		OBOCallbackRegistration.RegistrationContext = &regContext;
		OBOCallbackRegistration.OperationRegistration = OBOperationRegistration;
		NtHandleCallback = ObRegisterCallbacks(&OBOCallbackRegistration, &g_CallbacksHandle); // Register The CallBack
		if (!NT_SUCCESS(NtHandleCallback))
		{
			if (g_CallbacksHandle)
			{
				ObUnRegisterCallbacks(g_CallbacksHandle);
				g_CallbacksHandle = NULL;
			}
			DebugPrint("[DebugMessage] Failed to install ObRegisterCallbacks: 0x%08X.\n", NtHandleCallback);
		}
		else
			DebugPrint("[DebugMessage] Success: ObRegisterCallbacks Was Be Install\n");
	}
	PsSetCreateProcessNotifyRoutine(CreateProcessNotify, FALSE);
}
void DriverUnload(
	_In_ PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	PsSetCreateProcessNotifyRoutine(CreateProcessNotify, true);
	IoDeleteSymbolicLink(&Win32Device);
	IoDeleteDevice(DriverObject->DeviceObject);
	IfhRelease(); 
	NTDLL::Deinitialize();
	if (g_CallbacksHandle)
	{
		ObUnRegisterCallbacks(g_CallbacksHandle);
		g_CallbacksHandle = NULL;
	}

}
ULONG GetProcessIDFromProcessHandle(HANDLE ProcessHandle)
{
	ULONG Pid = 0;
	PEPROCESS Process;
	if (NT_SUCCESS(ObReferenceObjectByHandle(ProcessHandle, 0, *PsProcessType, ExGetPreviousMode(), (PVOID*)&Process, nullptr)))
	{
		Pid = (ULONG)(ULONG_PTR)PsGetProcessId(Process);
		ObDereferenceObject(Process);
	}
	return Pid;
}

ULONG GetProcessIDFromThreadHandle(HANDLE ThreadHandle)
{
	ULONG Pid = 0;
	PETHREAD Thread;
	if (NT_SUCCESS(ObReferenceObjectByHandle(ThreadHandle, 0, *PsThreadType, ExGetPreviousMode(), (PVOID*)&Thread, nullptr)))
	{
		Pid = (ULONG)(ULONG_PTR)PsGetProcessId(PsGetThreadProcess(Thread));
		ObDereferenceObject(Thread);
	}
	return Pid;
}
NTSTATUS NTAPI HookNtQueryInformationProcess(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength)
{
	if (g_startDebug)
	{
		ULONG target_pid = GetProcessIDFromProcessHandle(ProcessHandle);
		ULONG pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
		//if (target_pid == g_DbgPid && g_GameHandle)
		//	return pfn_NtQueryInformationProcess(g_GameHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
		if (g_DbgPid == target_pid && g_GamePid != -1)
		{
			return STATUS_ACCESS_VIOLATION;
		}
		if (g_GamePid == target_pid)
		{
			NTSTATUS ret = pfn_NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
			if (ProcessInformationClass == ProcessDebugFlags)
			{
				DebugPrint("[DebugMessage] ProcessDebugFlags by %d\r\n", pid);
				*(unsigned int*)ProcessInformation = 1; //若为0，则进程处于被调试状态，若为1，则进程处于非调试状态。
			}
			else if (ProcessInformationClass == ProcessDebugPort)
			{
				DebugPrint("[DebugMessage] ProcessDebugPort by %d\r\n", pid);
				*(ULONG_PTR*)ProcessInformation = 0;
			}
			else if (ProcessInformationClass == ProcessDebugObjectHandle)
			{
				DebugPrint("[DebugMessage] ProcessDebugObjectHandle by %d\r\n", pid);
				HANDLE CantTouchThis = nullptr;
				__try
				{
					__try
					{
						CantTouchThis = *static_cast<PHANDLE>(ProcessInformation);
					}
					__except (EXCEPTION_EXECUTE_HANDLER)
					{
						NOTHING;
					}
					*static_cast<PHANDLE>(ProcessInformation) = nullptr;
					ret = STATUS_PORT_NOT_SET;
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					ret = GetExceptionCode();
				}
				if (CantTouchThis != nullptr)
				{
					BOOLEAN AuditOnClose;
					const NTSTATUS HandleStatus = ObQueryObjectAuditingByHandle(CantTouchThis, &AuditOnClose);
					if (HandleStatus != STATUS_INVALID_HANDLE)
						ObCloseHandle(CantTouchThis, ExGetPreviousMode());
				}
			}
			return ret;
		}
	}

	return pfn_NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
}
NTSTATUS NTAPI HookNtGetContextThread(
	IN HANDLE ThreadHandle,
	IN OUT PCONTEXT Context)
{
	NTSTATUS ret = pfn_NtGetContextThread(ThreadHandle, Context);
	if (NT_SUCCESS(ret) && g_startDebug)
	{
		ULONG pid = GetProcessIDFromThreadHandle(ThreadHandle);
		ULONG my_pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
		if (g_GamePid == pid && g_DbgPid != my_pid)
		{
			Context->Dr0 = NULL;
			Context->Dr1 = NULL;
			Context->Dr2 = NULL;
			Context->Dr3 = NULL;
			Context->Dr6 = NULL;
			Context->Dr7 = NULL;
			Context->LastBranchToRip = NULL;
			Context->LastBranchFromRip = NULL;
			Context->LastExceptionToRip = NULL;
			Context->LastExceptionFromRip = NULL;
			Context->EFlags = Context->EFlags & ~0x10;
		}
	}
	return ret;
}
NTSTATUS NTAPI HookNtQueryInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength)
{
	NTSTATUS ret = pfn_NtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);
	if (NT_SUCCESS(ret) && g_startDebug && ThreadInformationClass == ThreadWow64Context)
	{
		ULONG pid = GetProcessIDFromThreadHandle(ThreadHandle);
		ULONG my_pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
		if (g_GamePid == pid && g_DbgPid != my_pid)
		{
			PWOW64_CONTEXT contex = (PWOW64_CONTEXT)ThreadInformation;
			contex->Dr0 = NULL;
			contex->Dr1 = NULL;
			contex->Dr2 = NULL;
			contex->Dr3 = NULL;
			contex->Dr6 = NULL;
			contex->Dr7 = NULL;
			contex->EFlags = contex->EFlags & ~0x10;
			DebugPrint("[DebugMessage] Block ZwQueryInformationThread Meme! \n");
		}
	}
	return ret;
}

NTSTATUS NTAPI HookNtQueryObject(IN HANDLE Handle OPTIONAL, IN OBJECT_INFORMATION_CLASS ObjectInformationClass, OUT PVOID ObjectInformation OPTIONAL, IN ULONG ObjectInformationLength, OUT PULONG ReturnLength OPTIONAL)
{
	NTSTATUS ret = pfn_NtQueryObject(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);
	if (NT_SUCCESS(ret) && g_startDebug)
	{
		ULONG pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
		UNICODE_STRING DebugObject;
		RtlInitUnicodeString(&DebugObject, L"DebugObject");
		if (g_GamePid == pid)
		{
			if (ObjectInformationClass == ObjectTypeInformation)
			{
				OBJECT_TYPE_INFORMATION* type = (OBJECT_TYPE_INFORMATION*)ObjectInformation;
				ProbeForRead(type->TypeName.Buffer, 1, 1);
				if (RtlEqualUnicodeString(&type->TypeName, &DebugObject, FALSE)) //DebugObject
				{
					DebugPrint("[DebugMessage] DebugObject by %d\r\n", pid);
					type->TotalNumberOfObjects = 0;
					type->TotalNumberOfHandles = 0;
				}
			}
			else if (ObjectInformationClass == 3)
			{
				OBJECT_ALL_INFORMATION* pObjectAllInfo = (OBJECT_ALL_INFORMATION*)ObjectInformation;
				unsigned char* pObjInfoLocation = (unsigned char*)pObjectAllInfo->ObjectTypeInformation;
				unsigned int TotalObjects = pObjectAllInfo->NumberOfObjects;
				for (unsigned int i = 0; i < TotalObjects; i++)
				{
					OBJECT_TYPE_INFORMATION* pObjectTypeInfo = (OBJECT_TYPE_INFORMATION*)pObjInfoLocation;
					ProbeForRead(pObjectTypeInfo, 1, 1);
					ProbeForRead(pObjectTypeInfo->TypeName.Buffer, 1, 1);
					if (RtlEqualUnicodeString(&pObjectTypeInfo->TypeName, &DebugObject, FALSE)) //DebugObject
					{
						DebugPrint("[DebugMessage] DebugObject by %d\r\n", pid);
						pObjectTypeInfo->TotalNumberOfObjects = 0;
						pObjectTypeInfo->TotalNumberOfHandles = 0;
					}
					pObjInfoLocation = (unsigned char*)pObjectTypeInfo->TypeName.Buffer;
					pObjInfoLocation += pObjectTypeInfo->TypeName.MaximumLength;
					ULONG_PTR tmp = ((ULONG_PTR)pObjInfoLocation) & -(LONG_PTR)sizeof(void*);
					if ((ULONG_PTR)tmp != (ULONG_PTR)pObjInfoLocation)
						tmp += sizeof(void*);
					pObjInfoLocation = ((unsigned char*)tmp);
				}
			}
		}
	}
	return ret;
}
NTSTATUS NTAPI HookNtSetInformationThread(IN HANDLE ThreadHandle, IN THREADINFOCLASS ThreadInformationClass, IN PVOID ThreadInformation, IN ULONG ThreadInformationLength)
{
	if (g_startDebug)
	{
		ULONG pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
		ULONG my_pid = GetProcessIDFromThreadHandle(ThreadHandle);
		if (pid == g_GamePid || my_pid == g_GamePid)
		{
			if (pid == g_DbgPid)
			{
				return pfn_NtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
			}
			else
			{
				if (ThreadInformationClass == ThreadHideFromDebugger)
				{
					DebugPrint("[DebugMessage] ThreadHideFromDebugger by %d\r\n", pid);
					PETHREAD Thread;
					NTSTATUS status = ObReferenceObjectByHandle(ThreadHandle, THREAD_SET_INFORMATION, *PsThreadType, ExGetPreviousMode(), (PVOID*)&Thread, NULL);
					if (NT_SUCCESS(status))
						ObDereferenceObject(Thread);
					return status;
				}
				else if (ThreadInformationClass == ThreadWow64Context)
				{
					PWOW64_CONTEXT Wow64Context = (PWOW64_CONTEXT)ThreadInformation;
					ULONG OriginalContextFlags = 0;

					DebugPrint("[DebugMessage] HookNtSetInformationThread by %d\r\n", pid);
					ProbeForWrite(&Wow64Context->ContextFlags, sizeof(ULONG), 1);
					OriginalContextFlags = Wow64Context->ContextFlags;
					Wow64Context->ContextFlags = OriginalContextFlags & ~0x10; //CONTEXT_DEBUG_REGISTERS ^ CONTEXT_AMD64/CONTEXT_i386
					NTSTATUS Status = pfn_NtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
					ProbeForWrite(&Wow64Context->ContextFlags, sizeof(ULONG), 1);
					Wow64Context->ContextFlags = OriginalContextFlags;
					return Status;
				}
			}

		}

	}
	return pfn_NtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
}
NTSTATUS NTAPI HookNtQuerySystemInformation(IN SYSTEM_INFORMATION_CLASS SystemInformationClass, OUT PVOID SystemInformation, IN ULONG SystemInformationLength, OUT PULONG ReturnLength OPTIONAL)
{
	NTSTATUS ret = pfn_NtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	if (NT_SUCCESS(ret) && g_startDebug)
	{
		if (SystemInformationClass == SystemKernelDebuggerInformation)
		{
			typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION
			{
				BOOLEAN DebuggerEnabled;
				BOOLEAN DebuggerNotPresent;
			} SYSTEM_KERNEL_DEBUGGER_INFORMATION, * PSYSTEM_KERNEL_DEBUGGER_INFORMATION;
			SYSTEM_KERNEL_DEBUGGER_INFORMATION* DebuggerInfo = (SYSTEM_KERNEL_DEBUGGER_INFORMATION*)SystemInformation;
			DebuggerInfo->DebuggerEnabled = false;
			DebuggerInfo->DebuggerNotPresent = true;
		}
		/*
		//EAC BE会通过遍历 threads去找隐藏线程 反而增加flag
		//https://github.com/huoji120/EACReversing/blob/master/EasyAntiCheat.sys/hiddenprocess.c
		else  if (SystemInformationClass == SystemProcessInformation) {
			PSYSTEM_PROCESS_INFORMATION pPrevProcessInfo = NULL;
			PSYSTEM_PROCESS_INFORMATION pCurrProcessInfo = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
			while (pCurrProcessInfo != NULL)
			{
				ULONG uPID = (ULONG)pCurrProcessInfo->ProcessId;
				UNICODE_STRING strTmpProcessName = pCurrProcessInfo->ImageName;
				//获取当前遍历的 SYSTEM_PROCESS_INFORMATION 节点的进程名称和进程 ID
				if (uPID == g_DbgPid)
				{
					if (pPrevProcessInfo)
					{
						if (pCurrProcessInfo->NextEntryOffset)
						{
							//将当前这个进程(即要隐藏的进程)从 SystemInformation 中摘除(更改链表偏移指针实现)
							pPrevProcessInfo->NextEntryOffset += pCurrProcessInfo->NextEntryOffset;
						}
						else
						{
							//说明当前要隐藏的这个进程是进程链表中的最后一个
							pPrevProcessInfo->NextEntryOffset = 0;
						}
					}
					else
					{
						//第一个遍历到得进程就是需要隐藏的进程
						if (pCurrProcessInfo->NextEntryOffset)
						{
							*(PCHAR)SystemInformation += pCurrProcessInfo->NextEntryOffset;
						}
						else
						{
							SystemInformation = NULL;
						}
					}
				}
				pPrevProcessInfo = pCurrProcessInfo;
				if (pCurrProcessInfo->NextEntryOffset)
					pCurrProcessInfo = (PSYSTEM_PROCESS_INFORMATION)(((PCHAR)pCurrProcessInfo) + pCurrProcessInfo->NextEntryOffset);
				else
					pCurrProcessInfo = NULL;
			}
		}*/
	}
	return ret;
}
NTSTATUS NTAPI HookNtOpenThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
{
	if (g_startDebug)
	{
		ULONG pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
		if (g_DbgPid == pid)
		{
			PETHREAD Thread;
			if (NT_SUCCESS(PsLookupThreadByThreadId((HANDLE)ClientId->UniqueThread, &Thread)))
			{
				ObOpenObjectByPointer(Thread, 0, 0, PROCESS_ALL_ACCESS, *PsThreadType, KernelMode, ThreadHandle);
				ObDereferenceObject(Thread);
				for (auto& handle : g_DebugHandle)
				{
					if (!handle || handle == 0)
					{
						handle = &ThreadHandle;
						break;
					}
				}
				DebugPrint("[DebugMessage] Lock Thread Handle at 0x%08X\r\n", ThreadHandle);
				return STATUS_SUCCESS;
			}
			/*
			for (auto& handle : g_GameThreadHandle)
			{
				if (!handle || handle == 0)
				{
					DebugPrint("[DebugMessage] Locking Thread Handle \r\n");
					PETHREAD Thread;
					if (NT_SUCCESS(PsLookupThreadByThreadId((HANDLE)ClientId->UniqueThread, &Thread)))
					{
						ObOpenObjectByPointer(Thread, 0, 0, PROCESS_ALL_ACCESS, *PsThreadType, KernelMode, &handle);
						ObDereferenceObject(Thread);
						ThreadHandle = &handle;
						DebugPrint("[DebugMessage] Lock Thread Handle at 0x%08X\r\n", handle);
						return STATUS_SUCCESS;
					}
					break;
				}
			}*/
		}
	}
	return pfn_NtOpenThread(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);
}
NTSTATUS NTAPI HookNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
{
	if (g_startDebug)
	{
		ULONG pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();

		if (g_DbgPid == pid) // && DesiredAccess == 0x001F0FFF
		{
			if(DesiredAccess == 0x001F0FFF)
				g_GamePid = (ULONG)ClientId->UniqueProcess,
				DebugPrint("[DebugMessage] Lock Game Id %d ACCESS_MASK : 0x%08X \r\n", g_GamePid, DesiredAccess);
			PEPROCESS Process;
			if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)g_GamePid, &Process)))
			{
				ObOpenObjectByPointer(Process, 0, 0, DesiredAccess == 0x001F0FFF ? PROCESS_ALL_ACCESS : DesiredAccess, *PsProcessType, KernelMode, ProcessHandle);
				ObDereferenceObject(Process);
				for (auto& handle : g_DebugHandle)
				{
					if (!handle || handle == 0)
					{
						handle = &ProcessHandle;
						break;
					}
				}
				
				return STATUS_SUCCESS;
			}
		}
	}

	return pfn_NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

NTSTATUS NTAPI HookNtReadVirtualMemory(IN HANDLE ProcessHandle, IN PVOID BaseAddress, OUT PVOID Buffer, IN ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded)
{
	/*
	if (g_startDebug)
	{
		ULONG pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
		if (g_DbgPid == pid)
		{
			if (GetProcessIDFromProcessHandle(ProcessHandle) == g_GamePid)
			{
				return pfn_NtReadVirtualMemory(g_GameHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesReaded);
			}
		}
	}
	*/
	return pfn_NtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesReaded);
}
NTSTATUS NTAPI HookNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten)
{
	/*
	if (g_startDebug)
	{
		ULONG pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
		if (g_DbgPid == pid)
		{
			if (GetProcessIDFromProcessHandle(ProcessHandle) == g_GamePid)
			{
				return pfn_NtWriteVirtualMemory(g_GameHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
			}
		}
	}
	*/
	return pfn_NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
}
NTSTATUS NTAPI HookNtCreateThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PCLIENT_ID ClientId, PCONTEXT ThreadContext, PVOID InitialTeb, BOOLEAN CreateSuspended)
{
	/*
	if (g_startDebug)
	{
		ULONG pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
		if (g_DbgPid == pid)
		{
			if (GetProcessIDFromProcessHandle(ProcessHandle) == g_GamePid)
			{
				DebugPrint("[DebugMessage] NtCreateThread by %d\r\n", pid);
				return pfn_NtCreateThread(ThreadHandle, DesiredAccess, ObjectAttributes, g_GameHandle, ClientId, ThreadContext, InitialTeb, CreateSuspended);
			}
		}
	}*/
	return pfn_NtCreateThread(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId, ThreadContext, InitialTeb, CreateSuspended);
}
NTSTATUS NTAPI HookNtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus)
{
	/*
	if (g_startDebug)
	{
		ULONG pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
		ULONG my_pid = GetProcessIDFromProcessHandle(ProcessHandle);
		if (pid == g_GamePid && my_pid == g_GamePid)
		{
			//由游戏发起的关闭指令目标也是游戏
			//EAC: pls fix this
			return STATUS_SUCCESS;
		}
	}
	*/
	return pfn_NtTerminateProcess(ProcessHandle, ExitStatus);
} 
NTSTATUS NTAPI HookNtClose(HANDLE Handle)
{
	if (g_startDebug)
	{
		ULONG pid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
		if (pid == g_DbgPid)
		{
			for (auto& handle : g_DebugHandle)
			{
				if (handle && handle != 0)
				{
					if (handle == Handle)
					{
						ObDereferenceObject(Handle);
						return STATUS_SUCCESS;
					}
				}
			}
		}
	}
	return pfn_NtClose(Handle);
}
void __fastcall SyscallCallBack(_In_ unsigned int SystemCallIndex, _Inout_ void** SystemCallFunction)
{
	if (*SystemCallFunction == pfn_NtOpenProcess)
		*SystemCallFunction = HookNtOpenProcess;
	else if (*SystemCallFunction == pfn_NtReadVirtualMemory)
		*SystemCallFunction = HookNtReadVirtualMemory;
	else if (*SystemCallFunction == pfn_NtWriteVirtualMemory)
		*SystemCallFunction = HookNtWriteVirtualMemory;
	else if (*SystemCallFunction == pfn_NtCreateThread)
		*SystemCallFunction = HookNtCreateThread;
	if (*SystemCallFunction == pfn_NtQueryInformationProcess)
		*SystemCallFunction = HookNtQueryInformationProcess;
	else if (*SystemCallFunction == pfn_NtGetContextThread)
		*SystemCallFunction = HookNtGetContextThread;
	else if (*SystemCallFunction == pfn_NtQueryInformationThread)
		*SystemCallFunction = HookNtQueryInformationThread;
	else if (*SystemCallFunction == pfn_NtQueryObject)
		*SystemCallFunction = HookNtQueryObject;
	else if (*SystemCallFunction == pfn_NtSetInformationThread)
		*SystemCallFunction = HookNtSetInformationThread;
	else if (*SystemCallFunction == pfn_NtQuerySystemInformation)
		*SystemCallFunction = HookNtQuerySystemInformation;
	else if (*SystemCallFunction == pfn_NtOpenThread)
		*SystemCallFunction = HookNtOpenThread;
	else if (*SystemCallFunction == pfn_NtTerminateProcess)
		*SystemCallFunction = HookNtTerminateProcess;
	else if (*SystemCallFunction == pfn_NtClose)
		*SystemCallFunction = HookNtClose;
	
}
extern "C" NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING  RegistryPath)
{
	DebugPrint("\n[DebugMessage] Driver Loading!\n");
	RtlInitUnicodeString(&DeviceName, L"\\Device\\HuojiDebuger");
	RtlInitUnicodeString(&Win32Device, L"\\DosDevices\\HuojiDebuger");
	PDEVICE_OBJECT DeviceObject = NULL;
	NTSTATUS status = IoCreateDevice(DriverObject,
		0,
		&DeviceName,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&DeviceObject);
	if (!NT_SUCCESS(status))
	{
		DebugPrint("[DeugMessage] IoCreateDevice Error...\r\n");
		return status;
	}
	if (!DeviceObject)
	{
		DebugPrint("[DeugMessage] Unexpected I/O Error...\r\n");
		return STATUS_UNEXPECTED_IO_ERROR;
	}
	DebugPrint("[DeugMessage] Device %.*ws created successfully!\r\n", DeviceName.Length / sizeof(WCHAR), DeviceName.Buffer);
	DriverObject->DriverUnload = DriverUnload;
	if (!NT_SUCCESS(NTDLL::Initialize()))
	{
		DebugPrint("[DebugMessage] Ntdll::Initialize() failed...\r\n");
		return STATUS_UNSUCCESSFUL;
	}

	pfn_NtQueryInformationProcess = (NTQUERYINFORMATIONPROCESS)SSDT::GetFunctionAddress("NtQueryInformationProcess");
	DebugPrint("[DebugMessage] NtQueryInformationProcess: 0x%08X...\r\n", pfn_NtQueryInformationProcess);
	pfn_NtGetContextThread = (NTGETCONTEXTHREAD)SSDT::GetFunctionAddress("NtGetContextThread");
	DebugPrint("[DebugMessage] NtGetContextThread: 0x%08X...\r\n", pfn_NtGetContextThread);
	pfn_NtQueryInformationThread = (NTQUERYINFORMATIONTHREAD)SSDT::GetFunctionAddress("NtQueryInformationThread");
	DebugPrint("[DebugMessage] NtQueryInformationThread: 0x%08X...\r\n", pfn_NtQueryInformationThread);
	pfn_NtQueryObject = (NTQUERYOBJECT)SSDT::GetFunctionAddress("NtQueryObject");
	DebugPrint("[DebugMessage] NtQueryObject: 0x%08X...\r\n", pfn_NtQueryObject);
	pfn_NtSetInformationThread = (NTSETINFORMATIONTHREAD)SSDT::GetFunctionAddress("NtSetInformationThread");
	DebugPrint("[DebugMessage] NtSetInformationThread: 0x%08X...\r\n", pfn_NtSetInformationThread);
	pfn_NtQuerySystemInformation = (NTQUERYSYSTEMINFORMATION)SSDT::GetFunctionAddress("NtQuerySystemInformation");
	DebugPrint("[DebugMessage] NtQuerySystemInformation: 0x%08X...\r\n", pfn_NtQuerySystemInformation);
	pfn_NtOpenProcess = (NTOPENPROCESS)SSDT::GetFunctionAddress("NtOpenProcess");
	DebugPrint("[DebugMessage] NtOpenProcess: 0x%08X...\r\n", pfn_NtOpenProcess);
	pfn_NtReadVirtualMemory = (NTREADVIRTUALMEMORY)SSDT::GetFunctionAddress("NtReadVirtualMemory");
	DebugPrint("[DebugMessage] NtReadVirtualMemory: 0x%08X...\r\n", pfn_NtReadVirtualMemory);
	pfn_NtWriteVirtualMemory = (NTWRITEVIRTUALMEMORY)SSDT::GetFunctionAddress("NtWriteVirtualMemory");
	DebugPrint("[DebugMessage] NtWriteVirtualMemory: 0x%08X...\r\n", pfn_NtWriteVirtualMemory);
	pfn_NtCreateThread = (NTCREATETHREAD)SSDT::GetFunctionAddress("NtCreateThread");
	DebugPrint("[DebugMessage] NtCreateThread: 0x%08X...\r\n", pfn_NtCreateThread);
	pfn_NtTerminateProcess = (NTTERMINATEPROCESS)SSDT::GetFunctionAddress("NtTerminateProcess");
	DebugPrint("[DebugMessage] NtTerminateProcess: 0x%08X...\r\n", pfn_NtTerminateProcess);
	pfn_NtOpenThread = (NTOPENTHREAD)SSDT::GetFunctionAddress("NtOpenThread");
	DebugPrint("[DebugMessage] NtOpenThread: 0x%08X...\r\n", pfn_NtOpenThread);
	pfn_NtClose = (NTCLOSE)SSDT::GetFunctionAddress("NtClose");
	DebugPrint("[DebugMessage] NtClose: 0x%08X...\r\n", pfn_NtClose);

	// 绕过MmVerifyCallbackFunction。
	PLDR_DATA_TABLE_ENTRY64 ldr = (PLDR_DATA_TABLE_ENTRY64)DriverObject->DriverSection;
	ldr->Flags |= 0x20;
	InstallCallBacks();
	
	if (!NT_SUCCESS(IfhInitialize(SyscallCallBack)))
	{
		DebugPrint("[DebugMessage] IfhInitialize() failed...\r\n");
	}
	return STATUS_SUCCESS;
}

#include <ntifs.h>
#include <windef.h>
#include <stdlib.h>
#include "tools.h"




PVOID GetFunctionAddr(PCWSTR FunctionName)
{
	UNICODE_STRING UniCodeFunctionName;
	RtlInitUnicodeString(&UniCodeFunctionName, FunctionName);
	return MmGetSystemRoutineAddress(&UniCodeFunctionName);
}



typedef NTSTATUS(__fastcall* PSPTERMINATETHREADBYPOINTER)
(
	IN PETHREAD Thread,
	IN NTSTATUS ExitStatus,
	IN BOOLEAN DirectTerminate
);

PSPTERMINATETHREADBYPOINTER PspTerminateThreadByPointer = NULL;


NTSTATUS TerminateProcess64(PEPROCESS Process) {

	NTSTATUS st = 0;
	static ULONG_PTR func = 0;
	if (PspTerminateThreadByPointer == 0)
	{
		//判断操作系统版本
		RTL_OSVERSIONINFOEXW version = { 0 };
		RtlGetVersion(&version);

		/*ULONG64 AddressOfTemp = 0;*/
		
		ULONG64 AddressOfPspTTBP = 0;
		PUCHAR AddressOfTemp = GetFunctionAddr(L"PsTerminateSystemThread");
		
		for (int i = 0; i < 200; i++)
		{
			if (AddressOfTemp[i] == 0xE8)
			{
				LONG callcodeX = *(PLONG64)(AddressOfTemp + i + 1) ;
				AddressOfPspTTBP =  AddressOfTemp + i + 5  +  callcodeX;   //i+1 = E8 +5 + callcode
				break;
			}
		}
		DbgPrintEx(77, 0, "[dbg]PspTerminateThreadByPointer == %llx\r\n", AddressOfPspTTBP);
		PspTerminateThreadByPointer = (PSPTERMINATETHREADBYPOINTER)AddressOfPspTTBP;

		for (int i = 4; i < 0x40000; i += 4)
		{
			PETHREAD TempTread = NULL;
			PEPROCESS TempProcess = NULL;

			NTSTATUS st = PsLookupThreadByThreadId((HANDLE)i, &TempTread);

			if (NT_SUCCESS(st))
			{
				TempProcess = IoThreadToProcess(TempTread);
				if (TempProcess == Process)
				{
					//DbgBreakPoint();
					PspTerminateThreadByPointer(TempTread, 0, 0);
					ObDereferenceObject(TempTread);
				}
				
			}

		}
		return st;
	}

}

VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	if (pDriverObject->DeviceObject)
	{

		IoDeleteDevice(pDriverObject->DeviceObject);
	}

}

NTSTATUS DriverEntry(PDRIVER_OBJECT Pdriver, PUNICODE_STRING pReg) 
{


	PEPROCESS  process;
	process = FindProcessName(L"ZhuDongFangYu.exe");
	TerminateProcess64(process);
	Pdriver->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;
}
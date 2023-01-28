#include "includes.h"
#include "Func_defs.h"
#include "Nt.h"

VMM_INIT_STATE g_VMMInitState[HYPERVISOR_MAX_CPUS] = { 0 };
UINT64 g_StackPointerForReturning = 0;
UINT64 g_BasePointerForReturning = 0;
UINT64 g_InstructionPointerForReturning = 0;


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	PAGED_CODE();

	PEPTP EPTP;

	DBG_LOG("Hyper-V Entry loaded");

	DriverObject->DriverUnload = DrvUnload;

	__try
	{
		EPTP = InitEptp();

		if (EPTP == nullptr)
			DBG_LOG("Failed to allocate Ept");

		int NumofProcessors = KeQueryActiveProcessorCount(0);

		KAFFINITY AffinityMask;

		//Init VmxON region and Vmcs
		for (int i = 0; i < NumofProcessors; i++) {
			DBG_LOG("-------------------------------- %d ----------------------------------", i );
			
			AffinityMask = MathPower(2, i);

			KeSetSystemAffinityThread(AffinityMask);

			InitVmx(&g_VMMInitState[i]);
		}


		for (int i = 0; i < NumofProcessors; i++) {
			DBG_LOG("-------------------------------- %d ----------------------------------", i);

			AffinityMask = MathPower(2, i);

			KeSetSystemAffinityThread(AffinityMask);
			//test
			__vmx_vmlaunch();
		}

	}
	__except (GetExceptionCode())
	{
		DBG_LOG("Failed ya Sucka %u", GetExceptionCode());
	}


	return STATUS_SUCCESS;
}

void DrvUnload(PDRIVER_OBJECT Obj) {
	DBG_LOG("Unloading...");

	int NumofProcessors = KeQueryActiveProcessorCount(0);

	KAFFINITY AffinityMask;

	//Init VmxON region and Vmcs
	for (int i = 0; i < NumofProcessors; i++) {
		DBG_LOG("Processor Num: %d", i);

		AffinityMask = MathPower(2, i);

		KeSetSystemAffinityThread(AffinityMask);

		AsmVmxoffAndRestoreState();

	}

	UNREFERENCED_PARAMETER(Obj);
}

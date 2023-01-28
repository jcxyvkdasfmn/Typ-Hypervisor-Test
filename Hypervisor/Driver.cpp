#include "includes.h"
#include "Func_defs.h"

VMM_INIT_STATE g_VMMInitState[HYPERVISOR_MAX_CPUS] = { 0 };



NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	PAGED_CODE();


	DBG_LOG("Hyper-V Entry loaded");

	DriverObject->DriverUnload = DrvUnload;

	__try
	{


		int NumofProcessors = KeQueryActiveProcessorCount(0);

		KAFFINITY AffinityMask;

		//Init VmxON region and Vmcs
		for (int i = 0; i < NumofProcessors; i++) {
			DBG_LOG("--------------------------- Allocating %d ---------------------------", i);
			
			AffinityMask = MathPower(2, i);

			KeSetSystemAffinityThread(AffinityMask);

			//TO do: Init Guest Rsp

			InitVmx(&g_VMMInitState[i]);

			DbgPrint("\n");
		}

		for (int i = 0; i < NumofProcessors; i++) {
			DBG_LOG("--------------------------- Starting %d Processor ---------------------------", i);

			AffinityMask = MathPower(2, i);

			KeSetSystemAffinityThread(AffinityMask);

			Launch();

			DbgPrint("\n");
		}


	}
	__except (GetExceptionCode())
	{
		DBG_LOG("Failed ya Sucka %u", GetExceptionCode());
	}


	return STATUS_SUCCESS;
}

void DrvUnload(PDRIVER_OBJECT Obj) {

	int NumofProcessors = KeQueryActiveProcessorCount(0);

	KAFFINITY AffinityMask;

	//Init VmxON region and Vmcs
	for (int i = 0; i < NumofProcessors; i++) {
		DBG_LOG("Processor Num: %d", i);

		AffinityMask = MathPower(2, i);

		KeSetSystemAffinityThread(AffinityMask);

		StopVmx(&g_VMMInitState[i]);

	}

	UNREFERENCED_PARAMETER(Obj);
}

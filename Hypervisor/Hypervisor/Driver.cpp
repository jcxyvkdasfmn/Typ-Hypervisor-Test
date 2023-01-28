#include "includes.h"
#include "Func_defs.h"

VMM_INIT_STATE g_VMMInitState[HYPERVISOR_MAX_CPUS] = { 0 };



NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	PAGED_CODE();

	bool Status = false;

	DBG_LOG("Hyper-V Entry loaded");

	DriverObject->DriverUnload = DrvUnload;

	__try
	{
		Status = InitEpt();

		if (!Status)
			return STATUS_UNSUCCESSFUL;

		int NumofProcessors = KeQueryActiveProcessorCount(0);

		KAFFINITY AffinityMask;

		//Init VmxON region and Vmcs
		for (int i = 0; i < NumofProcessors; i++) {
			DBG_LOG("Processor Num: %d", i);
			
			AffinityMask = MathPower(2, i);

			KeSetSystemAffinityThread(AffinityMask);

			InitVmx(&g_VMMInitState[i]);

		}

		//StartVmx
		for (int i = 0; i < NumofProcessors; i++) {


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

		__vmx_off();

	}

	UNREFERENCED_PARAMETER(Obj);
}

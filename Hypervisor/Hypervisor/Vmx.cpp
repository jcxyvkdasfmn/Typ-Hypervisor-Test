#include "includes.h"
#include "Func_defs.h"
#include "Nt.h"

bool IsVmxSupported()
{
	CPUID Data = { 0 };
	IA32_FEATURE_CONTROL_MSR FeatureControlMsr = { 0 };

	// VMX bit
	__cpuid((int*)&Data, 1);
	if ((Data.ecx & (1 << 5)) == 0)
		return FALSE;

	FeatureControlMsr.All = __readmsr(MSR_IA32_FEATURE_CONTROL);

	// BIOS lock check
	if (FeatureControlMsr.Fields.Lock == 0)
	{
		FeatureControlMsr.Fields.Lock = TRUE;
		FeatureControlMsr.Fields.EnableVmxon = TRUE;
		__writemsr(MSR_IA32_FEATURE_CONTROL, FeatureControlMsr.All);
	}
	else if (FeatureControlMsr.Fields.EnableVmxon == FALSE)
	{
		DBG_LOG("VMX feature set to off in BIOS");
		return FALSE;
	}

	DBG_LOG("VMX supported");

	return TRUE;
}



CR0
AdjustCr0(
	CR0 Cr0
)
{
	CR0 newCr0, fixed0Cr0, fixed1Cr0;

	newCr0 = Cr0;
	fixed0Cr0.Flags = __readmsr(IA32_VMX_CR0_FIXED0);
	fixed1Cr0.Flags = __readmsr(IA32_VMX_CR0_FIXED1);
	newCr0.Flags &= fixed1Cr0.Flags;
	newCr0.Flags |= fixed0Cr0.Flags;
	return newCr0;
}

CR4
AdjustCr4(
	CR4 Cr4
)
{
	CR4 newCr4, fixed0Cr4, fixed1Cr4;

	newCr4 = Cr4;
	fixed0Cr4.Flags = __readmsr(IA32_VMX_CR4_FIXED0);
	fixed1Cr4.Flags = __readmsr(IA32_VMX_CR4_FIXED1);
	newCr4.Flags &= fixed1Cr4.Flags;
	newCr4.Flags |= fixed0Cr4.Flags;
	return newCr4;
}



bool
InitializeVMMInitState(PVMM_INIT_STATE VMMInitState)
{
	AllocateVmxonRegion(VMMInitState);

	AllocateVmcsRegion(VMMInitState);

	AllocateMsrBitmap(VMMInitState);

	AllocateVmmStack(VMMInitState);

	return true;
}

bool InitVmx(PVMM_INIT_STATE InitState) {

	CR0 newCr0;
	CR4 newCr4;

	PAGED_CODE();

	if (!IsVmxSupported())
		return false;

	newCr0.Flags = __readcr0();
	newCr0 = AdjustCr0(newCr0);
	__writecr0(newCr0.Flags);


	newCr4.Flags = __readcr4();
	newCr4 = AdjustCr4(newCr4);
	__writecr4(newCr4.Flags);


	InitializeVMMInitState(InitState);

	return true;
}
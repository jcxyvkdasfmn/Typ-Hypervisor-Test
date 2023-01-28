#include "includes.h"
#include "Nt.h"
#include "Func_defs.h"

/* Converts Virtual Address to Physical Address */
UINT64 VirtualAddressToPhysicalAddress(PVOID VirtualAddress)
{
	return MmGetPhysicalAddress(VirtualAddress).QuadPart;
}

/* Converts Physical Address to Virtual Address */
UINT64 PhysicalAddressToVirtualAddress(UINT64 PhysicalAddress)
{
	PHYSICAL_ADDRESS PhysicalAddr;
	PhysicalAddr.QuadPart = PhysicalAddress;

	return reinterpret_cast<UINT64>(MmGetVirtualForPhysical(PhysicalAddr));
}

/* Find cr3 of system process*/
UINT64 FindSystemDirectoryTableBase()
{
	// Return CR3 of the system process.
	NT_KPROCESS* SystemProcess = (NT_KPROCESS*)(PsInitialSystemProcess);
	return SystemProcess->DirectoryTableBase;
}
/* Power function in order to computer address for MSR bitmaps */
int MathPower(int Base, int Exp) {

	int result;

	result = 1;

	for (;;)
	{
		if (Exp & 1)
		{
			result *= Base;
		}
		Exp >>= 1;
		if (!Exp)
		{
			break;
		}
		Base *= Base;
	}
	return result;
}

BOOLEAN
RunOnProcessor(ULONG ProcessorNumber, PVMM_INIT_STATE InitState, PFUNC Routine)
{
	KIRQL OldIrql;

	KeSetSystemAffinityThread((KAFFINITY)(1i64 << ProcessorNumber));

	OldIrql = KeRaiseIrqlToDpcLevel();

	Routine(ProcessorNumber, InitState);

	KeLowerIrql(OldIrql);

	KeRevertToUserAffinityThread();

	return TRUE;
}

BOOLEAN
GetSegmentDescriptor(PSEGMENT_SELECTOR SegmentSelector,
	USHORT            Selector,
	PUCHAR            GdtBase)
{
	PSEGMENT_DESCRIPTOR SegDesc;

	if (!SegmentSelector)
		return FALSE;

	if (Selector & 0x4)
	{
		return FALSE;
	}

	SegDesc = (PSEGMENT_DESCRIPTOR)((PUCHAR)GdtBase + (Selector & ~0x7));

	SegmentSelector->SEL = Selector;
	SegmentSelector->BASE = SegDesc->BASE0 | SegDesc->BASE1 << 16 | SegDesc->BASE2 << 24;
	SegmentSelector->LIMIT = SegDesc->LIMIT0 | (SegDesc->LIMIT1ATTR1 & 0xf) << 16;
	SegmentSelector->ATTRIBUTES.UCHARs = SegDesc->ATTR0 | (SegDesc->LIMIT1ATTR1 & 0xf0) << 4;

	if (!(SegDesc->ATTR0 & 0x10))
	{ // LA_ACCESSED
		ULONG64 Tmp;
		// this is a TSS or callgate etc, save the base high part
		Tmp = (*(PULONG64)((PUCHAR)SegDesc + 8));
		SegmentSelector->BASE = (SegmentSelector->BASE & 0xffffffff) | (Tmp << 32);
	}

	if (SegmentSelector->ATTRIBUTES.Fields.G)
	{
		// 4096-bit granularity is enabled for this segment, scale the limit
		SegmentSelector->LIMIT = (SegmentSelector->LIMIT << 12) + 0xfff;
	}

	return TRUE;
}

VOID
FillGuestSelectorData(
	PVOID  GdtBase,
	ULONG  Segreg,
	USHORT Selector)
{
	SEGMENT_SELECTOR SegmentSelector = { 0 };
	ULONG            AccessRights;

	GetSegmentDescriptor(&SegmentSelector, Selector, (PUCHAR)GdtBase);
	AccessRights = ((PUCHAR)&SegmentSelector.ATTRIBUTES)[0] + (((PUCHAR)&SegmentSelector.ATTRIBUTES)[1] << 12);

	if (!Selector)
		AccessRights |= 0x10000;

	__vmx_vmwrite(GUEST_ES_SELECTOR + Segreg * 2, Selector);
	__vmx_vmwrite(GUEST_ES_LIMIT + Segreg * 2, SegmentSelector.LIMIT);
	__vmx_vmwrite(GUEST_ES_AR_BYTES + Segreg * 2, AccessRights);
	__vmx_vmwrite(GUEST_ES_BASE + Segreg * 2, SegmentSelector.BASE);
}

ULONG
AdjustControls(IN ULONG Ctl, IN ULONG Msr)
{
	MSR MsrValue = { 0 };

	MsrValue.Content = __readmsr(Msr);
	Ctl &= MsrValue.High; /* bit == 0 in high word ==> must be zero */
	Ctl |= MsrValue.Low;  /* bit == 1 in low word  ==> must be one  */
	return Ctl;
}

ULONG64 GetSegmentBaseByDescriptor(USHORT Selector, PVOID GdtBase) {

	SEGMENT_SELECTOR SegmentSelector = { 0 };

	GetSegmentDescriptor(&SegmentSelector, Selector, (PUCHAR)GdtBase);


	return SegmentSelector.BASE;
}

ULONG64 GetSegmentAccessByDescriptor(USHORT Selector, PVOID GdtBase) {

	SEGMENT_SELECTOR SegmentSelector = { 0 };
	ULONG64           AccessRights;

	GetSegmentDescriptor(&SegmentSelector, Selector, (PUCHAR)GdtBase);

	AccessRights = ((PUCHAR)&SegmentSelector.ATTRIBUTES)[0] + (((PUCHAR)&SegmentSelector.ATTRIBUTES)[1] << 12);

	return AccessRights;
}
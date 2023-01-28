#include "includes.h"
#include "Nt.h"
#include "Func_defs.h"

bool
AllocateVmxonRegion(PVMM_INIT_STATE InitState)
{
	// at IRQL > DISPATCH_LEVEL memory allocation routines don't work
	if (KeGetCurrentIrql() > DISPATCH_LEVEL)
		KeRaiseIrqlToDpcLevel();

	PHYSICAL_ADDRESS PhysicalMax = { 0 };
	PhysicalMax.QuadPart = MAXULONG64;

	int    VMXONSize = 2 * VMXON_SIZE;
	BYTE* Buffer = (BYTE*)MmAllocateContiguousMemory(static_cast<SIZE_T>(VMXONSize) + ALIGNMENT_PAGE_SIZE, PhysicalMax); // Allocating a 4-KByte Contigous Memory region

	PHYSICAL_ADDRESS Highest = { 0 }, Lowest = { 0 };
	Highest.QuadPart = ~0;



	if (Buffer == NULL)
	{
		DBG_LOG("Couldn't Allocate Buffer for VMXON Region.\n");
		return FALSE; // NtStatus = STATUS_INSUFFICIENT_RESOURCES;
	}

	InitState->VMXONRegion = (PVOID)Buffer;

	UINT64 PhysicalBuffer = VirtualAddressToPhysicalAddress(Buffer);

	RtlSecureZeroMemory(Buffer, static_cast<SIZE_T>(VMXONSize) + ALIGNMENT_PAGE_SIZE);

	UINT64 AlignedPhysicalBuffer = ((ULONG_PTR)(PhysicalBuffer + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));

	UINT64 AlignedVirtualBuffer = ((ULONG_PTR)(Buffer + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));

	DBG_LOG("Virtual allocated buffer for VMXON at %llx", Buffer);
	DBG_LOG("Virtual aligned allocated buffer for VMXON at %llx", AlignedVirtualBuffer);
	DBG_LOG("Aligned physical buffer allocated for VMXON at %llx", AlignedPhysicalBuffer);

	// get IA32_VMX_BASIC_MSR RevisionId

	IA32_VMX_BASIC_MSR basic = { 0 };

	basic.All = __readmsr(MSR_IA32_VMX_BASIC);

	DBG_LOG("MSR_IA32_VMX_BASIC (MSR 0x480) Revision Identifier %llx\n", basic.Fields.RevisionIdentifier);

	// Changing Revision Identifier
	*(UINT64*)AlignedVirtualBuffer = basic.Fields.RevisionIdentifier;

	int Status = __vmx_on(&AlignedPhysicalBuffer);
	if (Status)
	{
		DBG_LOG("VMXON failed with status %d\n", Status);
		return FALSE;
	}

	InitState->PhysicalVMXONRegion = (PVOID)AlignedPhysicalBuffer;

	return TRUE;
}

bool AllocateVmcsRegion(PVMM_INIT_STATE InitState)
{
	PHYSICAL_ADDRESS PhysicalMax = { 0 };
	int VmcsSize;
	BYTE* VmcsRegion;
	UINT64 VmcsPhysicalAddr;
	UINT64 AlignedVmcsRegion;
	UINT64 AlignedVmcsRegionPhysicalAddr;
	IA32_VMX_BASIC_MSR VmxBasicMsr = { 0 };


	if (KeGetCurrentIrql() > DISPATCH_LEVEL)
		KeRaiseIrqlToDpcLevel();

	PhysicalMax.QuadPart = MAXULONG64;

	VmcsSize = 2 * VMCS_SIZE;
	VmcsRegion = (BYTE*)MmAllocateContiguousMemory(VmcsSize + ALIGNMENT_PAGE_SIZE, PhysicalMax);  // Allocating a 4-KByte Contigous Memory region

	if (VmcsRegion == NULL) {
		DBG_LOG("Couldn't Allocate Buffer for VMCS Region.");
		return false;
	}
	RtlSecureZeroMemory(VmcsRegion, VmcsSize + ALIGNMENT_PAGE_SIZE);

	VmcsPhysicalAddr = VirtualAddressToPhysicalAddress(VmcsRegion);

	AlignedVmcsRegion = ((ULONG_PTR)(VmcsRegion + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));
	DBG_LOG("VMCS Region Address : %llx", AlignedVmcsRegion);

	AlignedVmcsRegionPhysicalAddr = ((ULONG_PTR)(VmcsPhysicalAddr + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));
	DBG_LOG("VMCS Region Physical Address : %llx", AlignedVmcsRegionPhysicalAddr);

	// get Revision Identifier
	VmxBasicMsr.All = __readmsr(MSR_IA32_VMX_BASIC);
	DBG_LOG("Revision Identifier (MSR_IA32_VMX_BASIC - MSR 0x480) : 0x%x\n", VmxBasicMsr.Fields.RevisionIdentifier);


	//Changing Revision Identifier
	*(UINT64*)AlignedVmcsRegion = VmxBasicMsr.Fields.RevisionIdentifier;

	InitState->PhysicalVMCSRegion = (PVOID)AlignedVmcsRegionPhysicalAddr;

	InitState->VMCSRegion = (PVOID)VmcsRegion;

	return true;
}

bool AllocateVmmStack(PVMM_INIT_STATE InitState)
{
	PVOID VmmStack;

	// Allocate stack for the VM Exit Handler.
	VmmStack = ExAllocatePool2(POOL_FLAG_NON_PAGED, VMM_STACK_SIZE, POOLTAG);
	InitState->VMMStack = VmmStack;

	if (InitState->VMMStack == NULL)
	{
		DBG_LOG("Insufficient memory in allocationg Vmm stack");
		return false;
	}
	RtlZeroMemory(InitState->VMMStack, VMM_STACK_SIZE);

	DBG_LOG("Vmm Stack for logical processor : 0x%llx\n", InitState->VMMStack);

	return true;
}


bool AllocateMsrBitmap(PVMM_INIT_STATE InitState)
{
	// Allocate memory for MSRBitMap
	InitState->MsrBitmap = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, POOLTAG);  // should be aligned

	if (InitState->MsrBitmap == NULL)
	{
		DBG_LOG("Insufficient memory in allocationg Msr bitmaps");
		return false;
	}

	RtlZeroMemory(InitState->MsrBitmap, PAGE_SIZE);

	InitState->PhysicalMsrBitmap = (PVOID)VirtualAddressToPhysicalAddress(InitState->MsrBitmap);

	DBG_LOG("Msr Bitmap Virtual Address : 0x%llx", InitState->MsrBitmap);
	DBG_LOG("Msr Bitmap Physical Address : 0x%llx", InitState->PhysicalMsrBitmap);



	return true;
}

BOOLEAN
GetSegmentDescriptor(IN PSEGMENT_SELECTOR SegmentSelector, IN USHORT Selector, IN PUCHAR GdtBase)
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
		ULONG64 tmp;
		// this is a TSS or callgate etc, save the base high part
		tmp = (*(PULONG64)((PUCHAR)SegDesc + 8));
		SegmentSelector->BASE = (SegmentSelector->BASE & 0xffffffff) | (tmp << 32);
	}

	if (SegmentSelector->ATTRIBUTES.Fields.G)
	{
		// 4096-bit granularity is enabled for this segment, scale the limit
		SegmentSelector->LIMIT = (SegmentSelector->LIMIT << 12) + 0xfff;
	}

	return TRUE;
}

void
FillGuestSelectorData(
	__in PVOID  GdtBase,
	__in ULONG  Segreg,
	__in USHORT Selector)
{
	SEGMENT_SELECTOR SegmentSelector = { 0 };
	ULONG            uAccessRights;

	GetSegmentDescriptor(&SegmentSelector, Selector, (PUCHAR)GdtBase);
	uAccessRights = ((PUCHAR)&SegmentSelector.ATTRIBUTES)[0] + (((PUCHAR)&SegmentSelector.ATTRIBUTES)[1] << 12);

	if (!Selector)
		uAccessRights |= 0x10000;

	__vmx_vmwrite(GUEST_ES_SELECTOR + Segreg * 2, Selector);
	__vmx_vmwrite(GUEST_ES_LIMIT + Segreg * 2, SegmentSelector.LIMIT);
	__vmx_vmwrite(GUEST_ES_AR_BYTES + Segreg * 2, uAccessRights);
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

bool SetupVmcs(PVMM_INIT_STATE InitState) {

	UNREFERENCED_PARAMETER(InitState);

	ULONG64          GdtBase = 0;
	SEGMENT_SELECTOR SegmentSelector = { 0 };

	__vmx_vmwrite(HOST_ES_SELECTOR, GetEs() & 0xF8);
	__vmx_vmwrite(HOST_CS_SELECTOR, GetCs() & 0xF8);
	__vmx_vmwrite(HOST_SS_SELECTOR, GetSs() & 0xF8);
	__vmx_vmwrite(HOST_DS_SELECTOR, GetDs() & 0xF8);
	__vmx_vmwrite(HOST_FS_SELECTOR, GetFs() & 0xF8);
	__vmx_vmwrite(HOST_GS_SELECTOR, GetGs() & 0xF8);
	__vmx_vmwrite(HOST_TR_SELECTOR, GetTr() & 0xF8);


	// Setting the link pointer to the required value for 4KB VMCS.
	__vmx_vmwrite(VMCS_LINK_POINTER, ~0ULL);

	__vmx_vmwrite(GUEST_IA32_DEBUGCTL, __readmsr(MSR_IA32_DEBUGCTL) & 0xFFFFFFFF);
	__vmx_vmwrite(GUEST_IA32_DEBUGCTL_HIGH, __readmsr(MSR_IA32_DEBUGCTL) >> 32);

	/* Time-stamp counter offset */
	__vmx_vmwrite(TSC_OFFSET, 0);
	__vmx_vmwrite(TSC_OFFSET_HIGH, 0);

	__vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MASK, 0);
	__vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MATCH, 0);

	__vmx_vmwrite(VM_EXIT_MSR_STORE_COUNT, 0);
	__vmx_vmwrite(VM_EXIT_MSR_LOAD_COUNT, 0);

	__vmx_vmwrite(VM_ENTRY_MSR_LOAD_COUNT, 0);
	__vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, 0);

	GdtBase = GetGdtBase();

	FillGuestSelectorData((PVOID)GdtBase, ES, GetEs());
	FillGuestSelectorData((PVOID)GdtBase, CS, GetCs());
	FillGuestSelectorData((PVOID)GdtBase, SS, GetSs());
	FillGuestSelectorData((PVOID)GdtBase, DS, GetDs());
	FillGuestSelectorData((PVOID)GdtBase, FS, GetFs());
	FillGuestSelectorData((PVOID)GdtBase, GS, GetGs());
	FillGuestSelectorData((PVOID)GdtBase, LDTR, GetLdtr());
	FillGuestSelectorData((PVOID)GdtBase, TR, GetTr());

	__vmx_vmwrite(GUEST_FS_BASE, __readmsr(MSR_FS_BASE));
	__vmx_vmwrite(GUEST_GS_BASE, __readmsr(MSR_GS_BASE));

	__vmx_vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0);
	__vmx_vmwrite(GUEST_ACTIVITY_STATE, 0); // Active state

	__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, AdjustControls(CPU_BASED_HLT_EXITING | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS, MSR_IA32_VMX_PROCBASED_CTLS));
	__vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, AdjustControls(CPU_BASED_CTL2_RDTSCP /* | CPU_BASED_CTL2_ENABLE_EPT*/, MSR_IA32_VMX_PROCBASED_CTLS2)); // Not enable Ept cause not finished

	__vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, AdjustControls(0, MSR_IA32_VMX_PINBASED_CTLS));
	__vmx_vmwrite(VM_EXIT_CONTROLS, AdjustControls(VM_EXIT_IA32E_MODE | VM_EXIT_ACK_INTR_ON_EXIT, MSR_IA32_VMX_EXIT_CTLS));
	__vmx_vmwrite(VM_ENTRY_CONTROLS, AdjustControls(VM_ENTRY_IA32E_MODE, MSR_IA32_VMX_ENTRY_CTLS));

	__vmx_vmwrite(CR3_TARGET_COUNT, 0);
	__vmx_vmwrite(CR3_TARGET_VALUE0, 0);
	__vmx_vmwrite(CR3_TARGET_VALUE1, 0);
	__vmx_vmwrite(CR3_TARGET_VALUE2, 0);
	__vmx_vmwrite(CR3_TARGET_VALUE3, 0);

	__vmx_vmwrite(GUEST_CR0, __readcr0());
	__vmx_vmwrite(GUEST_CR3, __readcr3());
	__vmx_vmwrite(GUEST_CR4, __readcr4());

	__vmx_vmwrite(GUEST_DR7, 0x400);

	__vmx_vmwrite(HOST_CR0, __readcr0());
	__vmx_vmwrite(HOST_CR3, __readcr3());
	__vmx_vmwrite(HOST_CR4, __readcr4());

	__vmx_vmwrite(GUEST_GDTR_BASE, GetGdtBase());
	__vmx_vmwrite(GUEST_IDTR_BASE, GetIdtBase());
	__vmx_vmwrite(GUEST_GDTR_LIMIT, GetGdtLimit());
	__vmx_vmwrite(GUEST_IDTR_LIMIT, GetIdtLimit());

	__vmx_vmwrite(GUEST_RFLAGS, GetRflags());

	__vmx_vmwrite(GUEST_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
	__vmx_vmwrite(GUEST_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
	__vmx_vmwrite(GUEST_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));

	GetSegmentDescriptor(&SegmentSelector, GetTr(), (PUCHAR)GetGdtBase());
	__vmx_vmwrite(HOST_TR_BASE, SegmentSelector.BASE);

	__vmx_vmwrite(HOST_FS_BASE, __readmsr(MSR_FS_BASE));
	__vmx_vmwrite(HOST_GS_BASE, __readmsr(MSR_GS_BASE));

	__vmx_vmwrite(HOST_GDTR_BASE, GetGdtBase());
	__vmx_vmwrite(HOST_IDTR_BASE, GetIdtBase());

	__vmx_vmwrite(HOST_IA32_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
	__vmx_vmwrite(HOST_IA32_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
	__vmx_vmwrite(HOST_IA32_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));

	// left here just for test
	//__vmx_vmwrite(GUEST_RSP, (ULONG64)g_VirtualGuestMemoryAddress); // setup guest sp
	//__vmx_vmwrite(GUEST_RIP, (ULONG64)g_VirtualGuestMemoryAddress); // setup guest ip

	//__vmx_vmwrite(HOST_RSP, ((ULONG64)vmState->VMM_Stack + VMM_STACK_SIZE - 1));
	//__vmx_vmwrite(HOST_RIP, (ULONG64)AsmVmexitHandler);

	return true;
}
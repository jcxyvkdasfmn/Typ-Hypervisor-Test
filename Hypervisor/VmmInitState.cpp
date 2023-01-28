#include "includes.h"
#include "Nt.h"
#include "Func_defs.h"
BOOLEAN
ClearVmcsState(PVMM_INIT_STATE GuestState)
{
	//
	// Clear the state of the VMCS to inactive
	//
	DBG_LOG("Physical Vmcs Region: 0x%llx", (unsigned long long)GuestState->PhysicalVMCSRegion);

	unsigned long long addr = (unsigned long long)GuestState->PhysicalVMCSRegion;

	DBG_LOG("Physical Vmcs Region ptr: 0x%llx", &GuestState->PhysicalVMCSRegion);

	int Status = __vmx_vmclear(&addr);

	if (Status)
	{
		//
		// Otherwise terminates the VMX
		//
		DBG_LOG("VMCS failed to clear with status %d\n", Status);
		__vmx_off();
		return FALSE;
	}
	return TRUE;
}

BOOLEAN
LoadVmcs(PVMM_INIT_STATE GuestState)
{

	DBG_LOG("Physical Vmcs Region: 0x%llx", (unsigned long long)GuestState->PhysicalVMCSRegion);

	unsigned long long addr = (unsigned long long)GuestState->PhysicalVMCSRegion;

	DBG_LOG("Physical Vmcs Region ptr: 0x%llx", &GuestState->PhysicalVMCSRegion);

	int Status = __vmx_vmptrld(&addr);

	if (Status)
	{
		DBG_LOG("VMCS failed with status %d\n", Status);
		return FALSE;
	}
	return TRUE;
}

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

	InitState->VMXONRegion = (UINT64)Buffer;

	UINT64 PhysicalBuffer = VirtualAddressToPhysicalAddress(Buffer);

	RtlSecureZeroMemory(Buffer, static_cast<SIZE_T>(VMXONSize) + ALIGNMENT_PAGE_SIZE);

	UINT64 AlignedPhysicalBuffer = ((ULONG_PTR)(PhysicalBuffer + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));

	UINT64 AlignedVirtualBuffer = ((ULONG_PTR)(Buffer + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));

	DBG_LOG("Virtual allocated buffer for VMXON at 0x%llx", Buffer);
	DBG_LOG("Virtual aligned allocated buffer for VMXON at 0x%llx", AlignedVirtualBuffer);
	DBG_LOG("Aligned physical buffer allocated for VMXON at 0x%llx", AlignedPhysicalBuffer);

	// get IA32_VMX_BASIC_MSR RevisionId

	IA32_VMX_BASIC_MSR basic = { 0 };

	basic.All = __readmsr(MSR_IA32_VMX_BASIC);

	DBG_LOG("MSR_IA32_VMX_BASIC (MSR 0x480) Revision Identifier 0x%llx\n", basic.Fields.RevisionIdentifier);

	// Changing Revision Identifier
	*(UINT64*)AlignedVirtualBuffer = basic.Fields.RevisionIdentifier;

	int Status = __vmx_on(&AlignedPhysicalBuffer);
	if (Status)
	{
		DBG_LOG("VMXON failed with status %d\n", Status);
		return FALSE;
	}

	DBG_LOG("VMXON Success status %d\n", Status);

	InitState->PhysicalVMXONRegion = (UINT64)AlignedPhysicalBuffer;

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
	DBG_LOG("VMCS Region Address : 0x%llx", AlignedVmcsRegion);

	AlignedVmcsRegionPhysicalAddr = ((ULONG_PTR)(VmcsPhysicalAddr + ALIGNMENT_PAGE_SIZE - 1) & ~(ALIGNMENT_PAGE_SIZE - 1));
	DBG_LOG("VMCS Region Physical Address : 0x%llx", AlignedVmcsRegionPhysicalAddr);

	// get Revision Identifier
	VmxBasicMsr.All = __readmsr(MSR_IA32_VMX_BASIC);
	DBG_LOG("Revision Identifier (MSR_IA32_VMX_BASIC - MSR 0x480) : 0x%x\n", VmxBasicMsr.Fields.RevisionIdentifier);


	//Changing Revision Identifier
	*(UINT64*)AlignedVmcsRegion = VmxBasicMsr.Fields.RevisionIdentifier;

	InitState->PhysicalVMCSRegion = (UINT64)AlignedVmcsRegionPhysicalAddr;

	InitState->VMCSRegion = (UINT64)VmcsRegion;

	return true;
}

bool AllocateVmmStack(PVMM_INIT_STATE InitState)
{
	if (KeGetCurrentIrql() > DISPATCH_LEVEL)
		KeRaiseIrqlToDpcLevel();
	// Allocate stack for the VM Exit Handler.
	InitState->VMMStack = (UINT64)ExAllocatePool2(POOL_FLAG_NON_PAGED, VMM_STACK_SIZE, POOLTAG);

	if (InitState->VMMStack == NULL)
	{
		DBG_LOG("Insufficient memory in allocationg Vmm stack");
		return false;
	}
	RtlZeroMemory((PVOID)InitState->VMMStack, VMM_STACK_SIZE);

	DBG_LOG("Vmm Stack for logical processor : 0x%llx\n", InitState->VMMStack);

	return true;
}


bool AllocateMsrBitmap(PVMM_INIT_STATE InitState)
{
	if (KeGetCurrentIrql() > DISPATCH_LEVEL)
		KeRaiseIrqlToDpcLevel();
	// Allocate memory for MSRBitMap
	InitState->MsrBitmap = (UINT64)ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, POOLTAG);  // should be aligned

	if (InitState->MsrBitmap == NULL)
	{
		DBG_LOG("Insufficient memory in allocationg Msr bitmaps");
		return false;
	}

	RtlZeroMemory((PVOID)InitState->MsrBitmap, PAGE_SIZE);

	InitState->PhysicalMsrBitmap = (UINT64)VirtualAddressToPhysicalAddress((PVOID)InitState->MsrBitmap);

	DBG_LOG("Msr Bitmap Virtual Address : 0x%llx", InitState->MsrBitmap);
	DBG_LOG("Msr Bitmap Physical Address : 0x%llx", InitState->PhysicalMsrBitmap);



	return true;
}


bool SetupVmcs(PVMM_INIT_STATE InitState, PVOID GuestRsp)
{
	/*List of things to setup:
	
	Host State:
		Register State:
				Cr0
				Cr3
				Cr4
				Rsp
				Rip
				CS:
					Selector
				SS:
					Selector
				DS:
					Selector
				ES:
					Selector
				FS:
					Selector
					Base
				GS:
					Selector
					Base
				TR:
					Selector
					Base
				GDTR:
					Base
				IDTR:
					Base

				List of Msrs:
					IA32_SYSENTER_CS
					IA32_SYSENTER_ESP
					IA32_SYSENTER_EIP

	Guest State:

		Register State:
				Cr0
				Cr3
				Cr4
				Dr7
				Rsp
				Rip
				RFlags
				CS:
					Selector
					Base
					Limit
					Access Rights
				SS:
					Selector
					Base
					Limit
					Access Rights
				DS:
					Selector
					Base
					Limit
					Access Rights
				ES:
					Selector
					Base
					Limit
					Access Rights
				FS:
					Selector
					Base
					Limit
					Access Rights
				GS:
					Selector
					Base
					Limit
					Access Rights
				LDTR:
					Selector
					Base
					Limit
					Access Rights
				TR:
					Selector
					Base
					Limit
					Access Rights
				GDTR:
					Base
					Limit
				IDTR:
					Base
					Limit

				List of Msrs:
					IA32_DEBUGCTL
					IA32_SYSENTER_CS
					IA32_SYSENTER_ESP
					IA32_SYSENTER_EIP
					(Rest of Msr specified in Sdm not necessary?)
		Non Register State:
			Activity State
			Interuptibility State
			Pending Debug Exceptions
			Vmcs Link Pointer to ~0ULL
			
	Something else:

		Execution Fields:
			Pin Based Vm-Execution Controls
			Primary Processor Based Vm-Execution Controls:
				Use Msr BitMaps (Zero all out, can be done when done setting up vmcs because atm I don't care about msr access)
				Activate Secondary Processor Base Vm-Execution Controls

			Secondary Processor Based Vm-Execution Controls:
				Enable Rdtscp

			Vm-Exit Controls:
				Vm-Exit Msr Load Count
				Vm-Exit Msr Load Address

			Vm-Entry Controls:
				Vm-Entry Msr Load Count
				Vm-Entry Msr Load Address
				Ignore Event injection for now

	*/
	
	ClearVmcsState(InitState);


	LoadVmcs(InitState);

	DBG_LOG("Vmcs Setup Processor Num:  %llx", KeGetCurrentProcessorNumber());
	ULONG                   CpuBasedVmExecControls;
	ULONG                   SecondaryProcBasedVmExecControls;
	UINT64                  GdtBase = 0;
	SEGMENT_SELECTOR SegmentSelector = { 0 };
	IA32_VMX_BASIC_MSR VmxBasicMsr = { 0 };

	// Reading IA32_VMX_BASIC_MSR 
	VmxBasicMsr.All = __readmsr(MSR_IA32_VMX_BASIC);

	//Guest 
		//Register State:
		__vmx_vmwrite(GUEST_CR0, __readcr0());
		__vmx_vmwrite(GUEST_CR3, __readcr3());
		__vmx_vmwrite(GUEST_CR4, __readcr4());
		__vmx_vmwrite(GUEST_DR7, __readdr(7));
		__vmx_vmwrite(GUEST_RSP, (UINT64)GuestRsp);
		__vmx_vmwrite(GUEST_RIP, (UINT64)StartVMXBack);
		__vmx_vmwrite(GUEST_RFLAGS, __readeflags());


		__vmx_vmwrite(GUEST_CS_SELECTOR, GetCs());
		__vmx_vmwrite(GUEST_SS_SELECTOR, GetSs());
		__vmx_vmwrite(GUEST_DS_SELECTOR, GetDs());
		__vmx_vmwrite(GUEST_ES_SELECTOR, GetEs());
		__vmx_vmwrite(GUEST_FS_SELECTOR, GetFs());
		__vmx_vmwrite(GUEST_GS_SELECTOR, GetGs());
		__vmx_vmwrite(GUEST_LDTR_SELECTOR, GetLdtr());
		__vmx_vmwrite(GUEST_TR_SELECTOR, GetTr());

		GdtBase = GetGdtBase();

		
		__vmx_vmwrite(GUEST_CS_BASE, GetSegmentBaseByDescriptor(GetCs(), (PVOID)GdtBase));
		__vmx_vmwrite(GUEST_SS_BASE, GetSegmentBaseByDescriptor(GetSs(), (PVOID)GdtBase));
		__vmx_vmwrite(GUEST_DS_BASE, GetSegmentBaseByDescriptor(GetDs(), (PVOID)GdtBase));
		__vmx_vmwrite(GUEST_ES_BASE, GetSegmentBaseByDescriptor(GetEs(), (PVOID)GdtBase));
		__vmx_vmwrite(GUEST_FS_BASE, __readmsr(MSR_FS_BASE));
		__vmx_vmwrite(GUEST_GS_BASE, __readmsr(MSR_GS_BASE));
		__vmx_vmwrite(GUEST_LDTR_BASE, GetSegmentBaseByDescriptor(GetLdtr(), (PVOID)GdtBase));
		__vmx_vmwrite(GUEST_TR_BASE, GetSegmentBaseByDescriptor(GetTr(), (PVOID)GdtBase));

		__vmx_vmwrite(GUEST_CS_LIMIT, __segmentlimit(GetCs()));
		__vmx_vmwrite(GUEST_SS_LIMIT, __segmentlimit(GetSs()));
		__vmx_vmwrite(GUEST_DS_LIMIT, __segmentlimit(GetDs()));
		__vmx_vmwrite(GUEST_ES_LIMIT, __segmentlimit(GetEs()));
		__vmx_vmwrite(GUEST_FS_LIMIT, __segmentlimit(GetFs()));
		__vmx_vmwrite(GUEST_GS_LIMIT, __segmentlimit(GetGs()));
		__vmx_vmwrite(GUEST_LDTR_LIMIT, __segmentlimit(GetLdtr()));
		__vmx_vmwrite(GUEST_TR_LIMIT, __segmentlimit(GetTr()));

		__vmx_vmwrite(GUEST_CS_AR_BYTES, GetSegmentAccessByDescriptor(GetCs(), (PVOID)GdtBase));
		__vmx_vmwrite(GUEST_SS_AR_BYTES, GetSegmentAccessByDescriptor(GetSs(), (PVOID)GdtBase));
		__vmx_vmwrite(GUEST_DS_AR_BYTES, GetSegmentAccessByDescriptor(GetDs(), (PVOID)GdtBase));
		__vmx_vmwrite(GUEST_ES_AR_BYTES, GetSegmentAccessByDescriptor(GetEs(), (PVOID)GdtBase));
		__vmx_vmwrite(GUEST_FS_AR_BYTES, GetSegmentAccessByDescriptor(GetFs(), (PVOID)GdtBase));
		__vmx_vmwrite(GUEST_GS_AR_BYTES, GetSegmentAccessByDescriptor(GetGs(), (PVOID)GdtBase));
		__vmx_vmwrite(GUEST_LDTR_AR_BYTES, GetSegmentAccessByDescriptor(GetLdtr(), (PVOID)GdtBase));
		__vmx_vmwrite(GUEST_TR_AR_BYTES, GetSegmentAccessByDescriptor(GetTr(), (PVOID)GdtBase));


		__vmx_vmwrite(GUEST_GDTR_BASE, GetGdtBase());
		__vmx_vmwrite(GUEST_IDTR_BASE, GetIdtBase());
		__vmx_vmwrite(GUEST_GDTR_LIMIT, GetGdtLimit());
		__vmx_vmwrite(GUEST_IDTR_LIMIT, GetIdtLimit());

			//Msrs

			__vmx_vmwrite(GUEST_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
			__vmx_vmwrite(GUEST_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
			__vmx_vmwrite(GUEST_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
			__vmx_vmwrite(GUEST_IA32_DEBUGCTL, __readmsr(MSR_IA32_DEBUGCTL) & 0xFFFFFFFF);
			__vmx_vmwrite(GUEST_IA32_DEBUGCTL_HIGH, __readmsr(MSR_IA32_DEBUGCTL) >> 32);

		//Non register State
			__vmx_vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0);
			__vmx_vmwrite(GUEST_ACTIVITY_STATE, 0);
			__vmx_vmwrite(VMCS_LINK_POINTER, MAXULONG64);

	//Host
			//Register State:
			__vmx_vmwrite(HOST_CR0, __readcr0());
			__vmx_vmwrite(HOST_CR3, FindSystemDirectoryTableBase());
			__vmx_vmwrite(HOST_CR4, __readcr4());

			__vmx_vmwrite(HOST_RSP, ((ULONG64)InitState->VMMStack + VMM_STACK_SIZE - 1));
			__vmx_vmwrite(HOST_RIP, (UINT64)AsmVmexitHandler);

			GetSegmentDescriptor(&SegmentSelector, GetTr(), (PUCHAR)GetGdtBase());

			__vmx_vmwrite(HOST_ES_SELECTOR, GetEs() & 0xF8);
			__vmx_vmwrite(HOST_CS_SELECTOR, GetCs() & 0xF8);
			__vmx_vmwrite(HOST_SS_SELECTOR, GetSs() & 0xF8);
			__vmx_vmwrite(HOST_DS_SELECTOR, GetDs() & 0xF8);
			__vmx_vmwrite(HOST_FS_SELECTOR, GetFs() & 0xF8);
			__vmx_vmwrite(HOST_GS_SELECTOR, GetGs() & 0xF8);
			__vmx_vmwrite(HOST_TR_SELECTOR, GetTr() & 0xF8);


			__vmx_vmwrite(HOST_FS_BASE, __readmsr(MSR_FS_BASE));
			__vmx_vmwrite(HOST_GS_BASE, __readmsr(MSR_GS_BASE));
			__vmx_vmwrite(HOST_TR_BASE, SegmentSelector.BASE);
			__vmx_vmwrite(HOST_GDTR_BASE, GetGdtBase());
			__vmx_vmwrite(HOST_IDTR_BASE, GetIdtBase());

			__vmx_vmwrite(HOST_IA32_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
			__vmx_vmwrite(HOST_IA32_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
			__vmx_vmwrite(HOST_IA32_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));

			__vmx_vmwrite(CR0_READ_SHADOW, __readcr0());
			__vmx_vmwrite(CR4_READ_SHADOW, __readcr4());

			__vmx_vmwrite(MSR_BITMAP, InitState->PhysicalMsrBitmap);

				
			//Msrs
			CpuBasedVmExecControls = AdjustControls(CPU_BASED_ACTIVATE_MSR_BITMAP | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS,
				VmxBasicMsr.Fields.VmxCapabilityHint ? MSR_IA32_VMX_TRUE_PROCBASED_CTLS : MSR_IA32_VMX_PROCBASED_CTLS);
			__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, CpuBasedVmExecControls);
			DBG_LOG("Cpu Based VM Exec Controls (Based on %s) : 0x%x",
				VmxBasicMsr.Fields.VmxCapabilityHint ? "MSR_IA32_VMX_TRUE_PROCBASED_CTLS" : "MSR_IA32_VMX_PROCBASED_CTLS", CpuBasedVmExecControls);

			SecondaryProcBasedVmExecControls = AdjustControls(CPU_BASED_CTL2_RDTSCP, MSR_IA32_VMX_PROCBASED_CTLS2);
			__vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, SecondaryProcBasedVmExecControls);
			DBG_LOG("Secondary Proc Based VM Exec Controls (MSR_IA32_VMX_PROCBASED_CTLS2) : 0x%x", SecondaryProcBasedVmExecControls);

			__vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, AdjustControls(0,
				VmxBasicMsr.Fields.VmxCapabilityHint ? MSR_IA32_VMX_TRUE_PINBASED_CTLS : MSR_IA32_VMX_PINBASED_CTLS));

			__vmx_vmwrite(VM_EXIT_CONTROLS, AdjustControls(VM_EXIT_IA32E_MODE,
				VmxBasicMsr.Fields.VmxCapabilityHint ? MSR_IA32_VMX_TRUE_EXIT_CTLS : MSR_IA32_VMX_EXIT_CTLS));

			__vmx_vmwrite(VM_ENTRY_CONTROLS, AdjustControls(VM_ENTRY_IA32E_MODE,
				VmxBasicMsr.Fields.VmxCapabilityHint ? MSR_IA32_VMX_TRUE_ENTRY_CTLS : MSR_IA32_VMX_ENTRY_CTLS));

	return TRUE;
}

void FreeVmxon(PVMM_INIT_STATE InitState) {
	MmFreeContiguousMemory((PVOID)InitState->VMXONRegion);
	DBG_LOG("Vmxon Region at 0x%llx freed\n", InitState->VMXONRegion);
	return;
}

void FreeVmcs(PVMM_INIT_STATE InitState) {
	MmFreeContiguousMemory((PVOID)InitState->VMCSRegion);
	DBG_LOG("Vmcs Region Region at 0x%llx freed\n", InitState->VMCSRegion);
	return;
}

void FreeMsrBitmap(PVMM_INIT_STATE InitState) {
	ExFreePoolWithTag((PVOID)InitState->MsrBitmap, POOLTAG);
	DBG_LOG("Msr Bitmap at 0x%llx freed\n", InitState->MsrBitmap);
	return;
}

void FreeVmmStack(PVMM_INIT_STATE InitState) {
	ExFreePoolWithTag((PVOID)InitState->VMMStack, POOLTAG);
	DBG_LOG("VmmStack at 0x%llx freed\n", InitState->VMMStack);
	return;
}
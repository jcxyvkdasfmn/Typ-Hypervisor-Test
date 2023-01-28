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
	BYTE* Buffer = (BYTE*)MmAllocateContiguousMemory(VMXONSize + ALIGNMENT_PAGE_SIZE, PhysicalMax); // Allocating a 4-KByte Contigous Memory region

	PHYSICAL_ADDRESS Highest = { 0 }, Lowest = { 0 };
	Highest.QuadPart = ~0;



	if (Buffer == NULL)
	{
		DBG_LOG("Couldn't Allocate Buffer for VMXON Region.\n");
		return FALSE; // NtStatus = STATUS_INSUFFICIENT_RESOURCES;
	}

	InitState->VMXONRegion = (PVOID)Buffer;

	UINT64 PhysicalBuffer = VirtualAddressToPhysicalAddress(Buffer);

	RtlSecureZeroMemory(Buffer, VMXONSize + ALIGNMENT_PAGE_SIZE);

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



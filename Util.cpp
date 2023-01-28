#include "includes.h"
#include "Nt.h"

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

ULONG HvAdjustControls(ULONG Ctl, ULONG Msr)
{
	MSR MsrValue = { 0 };

	MsrValue.Content = __readmsr(Msr);
	Ctl &= MsrValue.High;     /* bit == 0 in high word ==> must be zero */
	Ctl |= MsrValue.Low;      /* bit == 1 in low word  ==> must be one  */
	return Ctl;
}

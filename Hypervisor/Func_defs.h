#pragma once
#include "includes.h"
#include "Nt.h"

extern "C" USHORT  GetCs(VOID);
extern "C" USHORT  GetDs(VOID);
extern "C" USHORT  GetEs(VOID);
extern "C" USHORT  GetSs(VOID);
extern "C" USHORT  GetFs(VOID);
extern "C" USHORT  GetGs(VOID);
extern "C" USHORT  GetLdtr(VOID);
extern "C" USHORT  GetTr(VOID);
extern "C" USHORT  GetIdtLimit(VOID);
extern "C" USHORT  GetGdtLimit(VOID);
extern "C" ULONG64 GetRflags(VOID);
extern "C" unsigned char inline AsmPerformInvept(_In_ unsigned long Type, _In_ void* Descriptor);
extern "C" ULONG64 inline GetGdtBase();
extern "C" ULONG64 inline GetIdtBase();
extern "C" void inline AsmVmxoffAndRestoreState();
extern "C" void inline AsmSaveStateForVmxoff();
extern "C" void Launch(VOID);
extern "C" void StartVMXBack(VOID);
extern "C" void AsmVmexitHandler(VOID);
extern "C" ULONG_PTR __stdcall LoadAccessRightsByte(_In_ ULONG_PTR segment_selector);

bool
AllocateVmxonRegion(PVMM_INIT_STATE InitState);
bool AllocateVmcsRegion(PVMM_INIT_STATE InitState);
bool AllocateVmmStack(PVMM_INIT_STATE InitState);
bool AllocateMsrBitmap(PVMM_INIT_STATE InitState);

void FreeVmxon(PVMM_INIT_STATE InitState);
void FreeVmcs(PVMM_INIT_STATE InitState);
void FreeMsrBitmap(PVMM_INIT_STATE InitState);
void FreeVmmStack(PVMM_INIT_STATE InitState);
bool InitializeVMMInitState(PVMM_INIT_STATE InitState);
bool StopVmx(PVMM_INIT_STATE InitState);
bool InitVmx(PVMM_INIT_STATE InitState);
extern "C" void Start(PVOID GuestRsp);

int MathPower(int Base, int Exp);

BOOLEAN RunOnProcessor(ULONG ProcessorNumber, PVMM_INIT_STATE InitState, PFUNC Routine);

UINT64 PhysicalAddressToVirtualAddress(UINT64 PhysicalAddress);

UINT64 VirtualAddressToPhysicalAddress(PVOID VirtualAddress);

UINT64 FindSystemDirectoryTableBase();

void DrvUnload(PDRIVER_OBJECT Obj);
ULONG
AdjustControls(IN ULONG Ctl, IN ULONG Msr);
VOID
FillGuestSelectorData(
	PVOID  GdtBase,
	ULONG  Segreg,
	USHORT Selector);
ULONG64 GetSegmentAccessByDescriptor(USHORT Selector, PVOID GdtBase);
ULONG64 GetSegmentBaseByDescriptor(USHORT Selector, PVOID GdtBase);
BOOLEAN
GetSegmentDescriptor(PSEGMENT_SELECTOR SegmentSelector,USHORT Selector,PUCHAR GdtBase);
bool SetupVmcs(PVMM_INIT_STATE InitState, PVOID GuestRsp);

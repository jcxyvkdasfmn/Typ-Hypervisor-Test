#pragma once
#include "includes.h"

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
extern "C" void
AsmVmexitHandler();


bool
AllocateVmxonRegion(PVMM_INIT_STATE InitState);
bool AllocateVmcsRegion(PVMM_INIT_STATE InitState);
bool AllocateVmmStack(PVMM_INIT_STATE InitState);
bool AllocateMsrBitmap(PVMM_INIT_STATE InitState);

PEPTP InitEpt();

bool InitVmx(VMM_INIT_STATE* CpuStruct);


int MathPower(int Base, int Exp);


UINT64 PhysicalAddressToVirtualAddress(UINT64 PhysicalAddress);

UINT64 VirtualAddressToPhysicalAddress(PVOID VirtualAddress);

void DrvUnload(PDRIVER_OBJECT Obj);

bool SetupVmcs(PVMM_INIT_STATE InitState);
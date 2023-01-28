#pragma once
#pragma warning(disable: 4471 4189 4083 4005 6328 4201 4091)
#include <ntifs.h>
#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>
#include <cstdint>
#include <cstddef>
#include <ntimage.h>
#include <windef.h>
#include <intrin.h>

#define POOLTAG 0x1A312

#define DBG_LOG(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[Hyper-V][" __FUNCTION__ "] " fmt "\n", ##__VA_ARGS__)
#define MV_ASSERT(x)        NT_ASSERT(x)
#define MAX_SUPPORTED_PROCESSORS 32
#define VMXON_SIZE   4096
#define VMCS_SIZE   4096
#define ALIGNMENT_PAGE_SIZE   4096


extern "C" UINT64 g_StackPointerForReturning;
extern "C" UINT64 g_BasePointerForReturning;
extern "C" UINT64 g_VirtualGuestMemoryAddress;


//  [5/4/2015 uty]
//  [10/10/2017 rohan kumbhar]
#ifndef _VMMINITSTATE_H_
#define _VMMINITSTATE_H_
//-----------------------------------------------------------------------------//
#define VMM_STACK_SIZE      0x8000

typedef struct _VMM_INIT_STATE
{
	UINT64 VMXONRegion;                     /* VMA of VMXON region */
	UINT64 PhysicalVMXONRegion;  /* PMA of VMXON region */

	UINT64 VMCSRegion;                      /* VMA of VMCS region */
	UINT64 PhysicalVMCSRegion;   /* PMA of VMCS region */

	UINT64 MsrBitmap;                       /* VMA of MSR bitmap */
	UINT64 PhysicalMsrBitmap;    /* PMA of MSR bitmap */

	UINT64 VMMStack;                        /* VMM stack area */

	UINT64 GuestRsp;
	UINT64 GuestRip;

} VMM_INIT_STATE, * PVMM_INIT_STATE;

#define HYPERVISOR_MAX_CPUS    64
extern VMM_INIT_STATE g_VMMInitState[HYPERVISOR_MAX_CPUS];
//-----------------------------------------------------------------------------//
bool
InitializeVMMInitState(
	PVMM_INIT_STATE VMMInitState
);

//-----------------------------------------------------------------------------//
#endif
typedef void (*PFUNC)(IN ULONG ProcessorID, IN PVMM_INIT_STATE InitState);

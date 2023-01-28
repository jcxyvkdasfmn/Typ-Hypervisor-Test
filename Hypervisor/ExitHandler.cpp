#include "includes.h"
#include "Nt.h"
#include "Func_defs.h"


extern "C" VOID
ResumeToNextInstruction()
{
    size_t ResumeRIP = NULL;
    size_t CurrentRIP = NULL;
    size_t ExitInstructionLength = 0;

    __vmx_vmread(GUEST_RIP, &CurrentRIP);
    __vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &ExitInstructionLength);

    ResumeRIP = CurrentRIP + ExitInstructionLength;

    __vmx_vmwrite(GUEST_RIP, (ULONG64)ResumeRIP);
}

extern "C" VOID
VmResumeInstruction()
{
    __vmx_vmresume();

    // if VMRESUME succeeds will never be here !

    ULONG64 ErrorCode = 0;
    __vmx_vmread(VM_INSTRUCTION_ERROR, &ErrorCode);
    __vmx_off();
    DBG_LOG("VMRESUME Error : 0x%llx\n", ErrorCode);

    //
    // It's such a bad error because we don't where to go!
    // prefer to break
    //
    DbgBreakPoint();
}


extern "C" VOID
MainVmexitHandler(PGUEST_REGS GuestRegs)
{
    PAGED_CODE()
    UNREFERENCED_PARAMETER(GuestRegs);

    size_t ExitReason = 0;
    __vmx_vmread(VM_EXIT_REASON, &ExitReason);

    size_t ExitQualification = 0;
    __vmx_vmread(EXIT_QUALIFICATION, &ExitQualification);

    DBG_LOG("VM_EXIT_REASION 0x%x\n", ExitReason & 0xffff);
    DBG_LOG("EXIT_QUALIFICATION 0x%x\n", ExitQualification);

    switch (ExitReason & 0xffff)
    {
        //
        // 25.1.2  Instructions That Cause VM Exits Unconditionally
        // The following instructions cause VM exits when they are executed in VMX non-root operation: CPUID, GETSEC,
        // INVD, and XSETBV. This is also true of instructions introduced with VMX, which include: INVEPT, INVVPID,
        // VMCALL, VMCLEAR, VMLAUNCH, VMPTRLD, VMPTRST, VMRESUME, VMXOFF, and VMXON.
        //

    case EXIT_REASON_VMCLEAR:
    case EXIT_REASON_VMPTRLD:
    case EXIT_REASON_VMPTRST:
    case EXIT_REASON_VMREAD:
    case EXIT_REASON_VMRESUME:
    case EXIT_REASON_VMWRITE:
    case EXIT_REASON_VMXOFF:
    case EXIT_REASON_VMXON:
    case EXIT_REASON_VMLAUNCH:
    {
        break;
    }
    case EXIT_REASON_INVALID_GUEST_STATE:
    {
        DBG_LOG("Guest State was invalid");
        DbgBreakPoint();
    }
    case EXIT_REASON_HLT:
    {

        break;
    }
    case EXIT_REASON_EXCEPTION_NMI:
    {
        break;
    }

    case EXIT_REASON_CPUID:
    {
        break;
    }

    case EXIT_REASON_INVD:
    {
        break;
    }

    case EXIT_REASON_VMCALL:
    {
        break;
    }

    case EXIT_REASON_CR_ACCESS:
    {
        break;
    }

    case EXIT_REASON_MSR_READ:
    {
        break;
    }

    case EXIT_REASON_MSR_WRITE:
    {
        break;
    }

    case EXIT_REASON_EPT_VIOLATION:
    {
        break;
    }

    default:
    {
         DbgBreakPoint();
        break;
    }
    }
}
//-----------------------------------------------------------------------------//

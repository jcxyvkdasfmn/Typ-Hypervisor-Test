#include "Nt.h"
#include "includes.h"
#include "Func_defs.h"

extern "C" void MainVmexitHandler(PGUEST_REGS GuestRegs)
{

    UNREFERENCED_PARAMETER(GuestRegs);
    size_t ExitReason = 0;
    __vmx_vmread(VM_EXIT_REASON, &ExitReason);

    size_t ExitQualification = 0;
    __vmx_vmread(EXIT_QUALIFICATION, &ExitQualification);

    DBG_LOG("VM_EXIT_REASION 0x%x\n", ExitReason & 0xffff);
    DBG_LOG("EXIT_QUALIFICATION 0x%x\n", ExitQualification);

    switch (ExitReason & 0xffff)
    {
    case EXIT_REASON_VMCLEAR:
        DbgBreakPoint();
    case EXIT_REASON_VMPTRLD:
        DbgBreakPoint();
    case EXIT_REASON_VMPTRST:
        DbgBreakPoint();
    case EXIT_REASON_VMREAD:
        DbgBreakPoint();
    case EXIT_REASON_VMRESUME:
        DbgBreakPoint();
    case EXIT_REASON_VMWRITE:
        DbgBreakPoint();
    case EXIT_REASON_VMXOFF:
        DbgBreakPoint();
    case EXIT_REASON_VMXON:
        DbgBreakPoint();
    case EXIT_REASON_VMLAUNCH:
    {
        DbgBreakPoint();
        break;
    }
    case EXIT_REASON_HLT:
    {
        DbgBreakPoint();
        break;
    }
    case EXIT_REASON_EXCEPTION_NMI:
    {
        DbgBreakPoint();
        break;
    }

    case EXIT_REASON_CPUID:
    {
        DbgBreakPoint();
        break;
    }

    case EXIT_REASON_INVD:
    {
        DbgBreakPoint();
        break;
    }

    case EXIT_REASON_VMCALL:
    {
        DbgBreakPoint();
        break;
    }

    case EXIT_REASON_CR_ACCESS:
    {
        DbgBreakPoint();
        break;
    }

    case EXIT_REASON_MSR_READ:
    {
        DbgBreakPoint();
        break;
    }

    case EXIT_REASON_MSR_WRITE:
    {
        DbgBreakPoint();
        break;
    }

    case EXIT_REASON_EPT_VIOLATION:
    {
        DbgBreakPoint();
        break;
    }
    case EXIT_REASON_INVALID_GUEST_STATE:
    {
        DBG_LOG("Invalid Guest State");
        CheckGuestVmcsFieldsForVmEntry(GuestRegs);
        DbgBreakPoint();
        break;
    }

    default:
    {

        break;
    }
    }
}

extern "C" void
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
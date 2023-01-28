#pragma once
#include "includes.h"

#define MSR_APIC_BASE                       0x01B
#define MSR_IA32_FEATURE_CONTROL            0x03A

#define MSR_IA32_VMX_BASIC                  0x480
#define MSR_IA32_VMX_PINBASED_CTLS          0x481
#define MSR_IA32_VMX_PROCBASED_CTLS         0x482
#define MSR_IA32_VMX_EXIT_CTLS              0x483
#define MSR_IA32_VMX_ENTRY_CTLS             0x484
#define MSR_IA32_VMX_MISC                   0x485
#define MSR_IA32_VMX_CR0_FIXED0             0x486
#define MSR_IA32_VMX_CR0_FIXED1             0x487
#define MSR_IA32_VMX_CR4_FIXED0             0x488
#define MSR_IA32_VMX_CR4_FIXED1             0x489
#define MSR_IA32_VMX_VMCS_ENUM              0x48A
#define MSR_IA32_VMX_PROCBASED_CTLS2        0x48B
#define MSR_IA32_VMX_EPT_VPID_CAP           0x48C
#define MSR_IA32_VMX_TRUE_PINBASED_CTLS     0x48D
#define MSR_IA32_VMX_TRUE_PROCBASED_CTLS    0x48E
#define MSR_IA32_VMX_TRUE_EXIT_CTLS         0x48F
#define MSR_IA32_VMX_TRUE_ENTRY_CTLS        0x490
#define MSR_IA32_VMX_VMFUNC                 0x491

#define MSR_IA32_SYSENTER_CS                0x174
#define MSR_IA32_SYSENTER_ESP               0x175
#define MSR_IA32_SYSENTER_EIP               0x176
#define MSR_IA32_DEBUGCTL                   0x1D9

#define MSR_LSTAR                           0xC0000082

#define MSR_FS_BASE                         0xC0000100
#define MSR_GS_BASE                         0xC0000101
#define MSR_SHADOW_GS_BASE                  0xC0000102


typedef struct _NT_KPROCESS
{
    DISPATCHER_HEADER Header;
    LIST_ENTRY ProfileListHead;
    ULONG_PTR DirectoryTableBase;
    UCHAR Data[1];
}NT_KPROCESS, * PNT_KPROCESS;

typedef union _IA32_VMX_BASIC_MSR
{
    ULONG64 All;
    struct
    {
        ULONG32 RevisionIdentifier : 31;   // [0-30]
        ULONG32 Reserved1 : 1;             // [31]
        ULONG32 RegionSize : 12;           // [32-43]
        ULONG32 RegionClear : 1;           // [44]
        ULONG32 Reserved2 : 3;             // [45-47]
        ULONG32 SupportedIA64 : 1;         // [48]
        ULONG32 SupportedDualMoniter : 1;  // [49]
        ULONG32 MemoryType : 4;            // [50-53]
        ULONG32 VmExitReport : 1;          // [54]
        ULONG32 VmxCapabilityHint : 1;     // [55]
        ULONG32 Reserved3 : 8;             // [56-63]
    } Fields;
} IA32_VMX_BASIC_MSR, * PIA32_VMX_BASIC_MSR;



typedef struct _CPUID
{
    int eax;
    int ebx;
    int ecx;
    int edx;
} CPUID, * PCPUID;

typedef union _IA32_FEATURE_CONTROL_MSR
{
    ULONG64 All;
    struct
    {
        ULONG64 Lock : 1;                // [0]
        ULONG64 EnableSMX : 1;           // [1]
        ULONG64 EnableVmxon : 1;         // [2]
        ULONG64 Reserved2 : 5;           // [3-7]
        ULONG64 EnableLocalSENTER : 7;   // [8-14]
        ULONG64 EnableGlobalSENTER : 1;  // [15]
        ULONG64 Reserved3a : 16;         //
        ULONG64 Reserved3b : 32;         // [16-63]
    } Fields;
} IA32_FEATURE_CONTROL_MSR, * PIA32_FEATURE_CONTROL_MSR;

typedef union
{
    struct
    {
        UINT64 ProtectionEnable : 1;
#define CR0_PROTECTION_ENABLE_BIT                                    0
#define CR0_PROTECTION_ENABLE_FLAG                                   0x01
#define CR0_PROTECTION_ENABLE_MASK                                   0x01
#define CR0_PROTECTION_ENABLE(_)                                     (((_) >> 0) & 0x01)

        UINT64 MonitorCoprocessor : 1;
#define CR0_MONITOR_COPROCESSOR_BIT                                  1
#define CR0_MONITOR_COPROCESSOR_FLAG                                 0x02
#define CR0_MONITOR_COPROCESSOR_MASK                                 0x01
#define CR0_MONITOR_COPROCESSOR(_)                                   (((_) >> 1) & 0x01)

        UINT64 EmulateFpu : 1;
#define CR0_EMULATE_FPU_BIT                                          2
#define CR0_EMULATE_FPU_FLAG                                         0x04
#define CR0_EMULATE_FPU_MASK                                         0x01
#define CR0_EMULATE_FPU(_)                                           (((_) >> 2) & 0x01)

        UINT64 TaskSwitched : 1;
#define CR0_TASK_SWITCHED_BIT                                        3
#define CR0_TASK_SWITCHED_FLAG                                       0x08
#define CR0_TASK_SWITCHED_MASK                                       0x01
#define CR0_TASK_SWITCHED(_)                                         (((_) >> 3) & 0x01)

        UINT64 ExtensionType : 1;
#define CR0_EXTENSION_TYPE_BIT                                       4
#define CR0_EXTENSION_TYPE_FLAG                                      0x10
#define CR0_EXTENSION_TYPE_MASK                                      0x01
#define CR0_EXTENSION_TYPE(_)                                        (((_) >> 4) & 0x01)

        UINT64 NumericError : 1;
#define CR0_NUMERIC_ERROR_BIT                                        5
#define CR0_NUMERIC_ERROR_FLAG                                       0x20
#define CR0_NUMERIC_ERROR_MASK                                       0x01
#define CR0_NUMERIC_ERROR(_)                                         (((_) >> 5) & 0x01)
        UINT64 Reserved1 : 10;

        UINT64 WriteProtect : 1;
#define CR0_WRITE_PROTECT_BIT                                        16
#define CR0_WRITE_PROTECT_FLAG                                       0x10000
#define CR0_WRITE_PROTECT_MASK                                       0x01
#define CR0_WRITE_PROTECT(_)                                         (((_) >> 16) & 0x01)
        UINT64 Reserved2 : 1;

        UINT64 AlignmentMask : 1;
#define CR0_ALIGNMENT_MASK_BIT                                       18
#define CR0_ALIGNMENT_MASK_FLAG                                      0x40000
#define CR0_ALIGNMENT_MASK_MASK                                      0x01
#define CR0_ALIGNMENT_MASK(_)                                        (((_) >> 18) & 0x01)
        UINT64 Reserved3 : 10;
        UINT64 NotWriteThrough : 1;
#define CR0_NOT_WRITE_THROUGH_BIT                                    29
#define CR0_NOT_WRITE_THROUGH_FLAG                                   0x20000000
#define CR0_NOT_WRITE_THROUGH_MASK                                   0x01
#define CR0_NOT_WRITE_THROUGH(_)                                     (((_) >> 29) & 0x01)

        UINT64 CacheDisable : 1;
#define CR0_CACHE_DISABLE_BIT                                        30
#define CR0_CACHE_DISABLE_FLAG                                       0x40000000
#define CR0_CACHE_DISABLE_MASK                                       0x01
#define CR0_CACHE_DISABLE(_)                                         (((_) >> 30) & 0x01)

        UINT64 PagingEnable : 1;
#define CR0_PAGING_ENABLE_BIT                                        31
#define CR0_PAGING_ENABLE_FLAG                                       0x80000000
#define CR0_PAGING_ENABLE_MASK                                       0x01
#define CR0_PAGING_ENABLE(_)                                         (((_) >> 31) & 0x01)
        UINT64 Reserved4 : 32;
    };

    UINT64 Flags;
} CR0;

typedef union
{
    struct
    {
        /**
         * @brief Virtual-8086 Mode Extensions
         *
         * [Bit 0] Enables interrupt- and exception-handling extensions in virtual-8086 mode when set; disables the extensions when
         * clear. Use of the virtual mode extensions can improve the performance of virtual-8086 applications by eliminating the
         * overhead of calling the virtual- 8086 monitor to handle interrupts and exceptions that occur while executing an 8086
         * program and, instead, redirecting the interrupts and exceptions back to the 8086 program's handlers. It also provides
         * hardware support for a virtual interrupt flag (VIF) to improve reliability of running 8086 programs in multitasking and
         * multiple-processor environments.
         *
         * @see Vol3B[20.3(INTERRUPT AND EXCEPTION HANDLING IN VIRTUAL-8086 MODE)]
         */
        UINT64 VirtualModeExtensions : 1;
#define CR4_VIRTUAL_MODE_EXTENSIONS_BIT                              0
#define CR4_VIRTUAL_MODE_EXTENSIONS_FLAG                             0x01
#define CR4_VIRTUAL_MODE_EXTENSIONS_MASK                             0x01
#define CR4_VIRTUAL_MODE_EXTENSIONS(_)                               (((_) >> 0) & 0x01)

        /**
         * @brief Protected-Mode Virtual Interrupts
         *
         * [Bit 1] Enables hardware support for a virtual interrupt flag (VIF) in protected mode when set; disables the VIF flag in
         * protected mode when clear.
         *
         * @see Vol3B[20.4(PROTECTED-MODE VIRTUAL INTERRUPTS)]
         */
        UINT64 ProtectedModeVirtualInterrupts : 1;
#define CR4_PROTECTED_MODE_VIRTUAL_INTERRUPTS_BIT                    1
#define CR4_PROTECTED_MODE_VIRTUAL_INTERRUPTS_FLAG                   0x02
#define CR4_PROTECTED_MODE_VIRTUAL_INTERRUPTS_MASK                   0x01
#define CR4_PROTECTED_MODE_VIRTUAL_INTERRUPTS(_)                     (((_) >> 1) & 0x01)

        /**
         * @brief Time Stamp Disable
         *
         * [Bit 2] Restricts the execution of the RDTSC instruction to procedures running at privilege level 0 when set; allows
         * RDTSC instruction to be executed at any privilege level when clear. This bit also applies to the RDTSCP instruction if
         * supported (if CPUID.80000001H:EDX[27] = 1).
         */
        UINT64 TimestampDisable : 1;
#define CR4_TIMESTAMP_DISABLE_BIT                                    2
#define CR4_TIMESTAMP_DISABLE_FLAG                                   0x04
#define CR4_TIMESTAMP_DISABLE_MASK                                   0x01
#define CR4_TIMESTAMP_DISABLE(_)                                     (((_) >> 2) & 0x01)

        /**
         * @brief Debugging Extensions
         *
         * [Bit 3] References to debug registers DR4 and DR5 cause an undefined opcode (\#UD) exception to be generated when set;
         * when clear, processor aliases references to registers DR4 and DR5 for compatibility with software written to run on
         * earlier IA-32 processors.
         *
         * @see Vol3B[17.2.2(Debug Registers DR4 and DR5)]
         */
        UINT64 DebuggingExtensions : 1;
#define CR4_DEBUGGING_EXTENSIONS_BIT                                 3
#define CR4_DEBUGGING_EXTENSIONS_FLAG                                0x08
#define CR4_DEBUGGING_EXTENSIONS_MASK                                0x01
#define CR4_DEBUGGING_EXTENSIONS(_)                                  (((_) >> 3) & 0x01)

        /**
         * @brief Page Size Extensions
         *
         * [Bit 4] Enables 4-MByte pages with 32-bit paging when set; restricts 32-bit paging to pages of 4 KBytes when clear.
         *
         * @see Vol3A[4.3(32-BIT PAGING)]
         */
        UINT64 PageSizeExtensions : 1;
#define CR4_PAGE_SIZE_EXTENSIONS_BIT                                 4
#define CR4_PAGE_SIZE_EXTENSIONS_FLAG                                0x10
#define CR4_PAGE_SIZE_EXTENSIONS_MASK                                0x01
#define CR4_PAGE_SIZE_EXTENSIONS(_)                                  (((_) >> 4) & 0x01)

        /**
         * @brief Physical Address Extension
         *
         * [Bit 5] When set, enables paging to produce physical addresses with more than 32 bits. When clear, restricts physical
         * addresses to 32 bits. PAE must be set before entering IA-32e mode.
         *
         * @see Vol3A[4(PAGING)]
         */
        UINT64 PhysicalAddressExtension : 1;
#define CR4_PHYSICAL_ADDRESS_EXTENSION_BIT                           5
#define CR4_PHYSICAL_ADDRESS_EXTENSION_FLAG                          0x20
#define CR4_PHYSICAL_ADDRESS_EXTENSION_MASK                          0x01
#define CR4_PHYSICAL_ADDRESS_EXTENSION(_)                            (((_) >> 5) & 0x01)

        /**
         * @brief Machine-Check Enable
         *
         * [Bit 6] Enables the machine-check exception when set; disables the machine-check exception when clear.
         *
         * @see Vol3B[15(MACHINE-CHECK ARCHITECTURE)]
         */
        UINT64 MachineCheckEnable : 1;
#define CR4_MACHINE_CHECK_ENABLE_BIT                                 6
#define CR4_MACHINE_CHECK_ENABLE_FLAG                                0x40
#define CR4_MACHINE_CHECK_ENABLE_MASK                                0x01
#define CR4_MACHINE_CHECK_ENABLE(_)                                  (((_) >> 6) & 0x01)

        /**
         * @brief Page Global Enable
         *
         * [Bit 7] (Introduced in the P6 family processors.) Enables the global page feature when set; disables the global page
         * feature when clear. The global page feature allows frequently used or shared pages to be marked as global to all users
         * (done with the global flag, bit 8, in a page-directory or page-table entry). Global pages are not flushed from the
         * translation-lookaside buffer (TLB) on a task switch or a write to register CR3. When enabling the global page feature,
         * paging must be enabled (by setting the PG flag in control register CR0) before the PGE flag is set. Reversing this
         * sequence may affect program correctness, and processor performance will be impacted.
         *
         * @see Vol3A[4.10(CACHING TRANSLATION INFORMATION)]
         */
        UINT64 PageGlobalEnable : 1;
#define CR4_PAGE_GLOBAL_ENABLE_BIT                                   7
#define CR4_PAGE_GLOBAL_ENABLE_FLAG                                  0x80
#define CR4_PAGE_GLOBAL_ENABLE_MASK                                  0x01
#define CR4_PAGE_GLOBAL_ENABLE(_)                                    (((_) >> 7) & 0x01)

        /**
         * @brief Performance-Monitoring Counter Enable
         *
         * [Bit 8] Enables execution of the RDPMC instruction for programs or procedures running at any protection level when set;
         * RDPMC instruction can be executed only at protection level 0 when clear.
         */
        UINT64 PerformanceMonitoringCounterEnable : 1;
#define CR4_PERFORMANCE_MONITORING_COUNTER_ENABLE_BIT                8
#define CR4_PERFORMANCE_MONITORING_COUNTER_ENABLE_FLAG               0x100
#define CR4_PERFORMANCE_MONITORING_COUNTER_ENABLE_MASK               0x01
#define CR4_PERFORMANCE_MONITORING_COUNTER_ENABLE(_)                 (((_) >> 8) & 0x01)

        /**
         * @brief Operating System Support for FXSAVE and FXRSTOR instructions
         *
         * [Bit 9] When set, this flag:
         * -# indicates to software that the operating system supports the use of the FXSAVE and FXRSTOR instructions,
         * -# enables the FXSAVE and FXRSTOR instructions to save and restore the contents of the XMM and MXCSR registers along
         * with the contents of the x87 FPU and MMX registers, and
         * -# enables the processor to execute SSE/SSE2/SSE3/SSSE3/SSE4 instructions, with the exception of the PAUSE, PREFETCHh,
         * SFENCE, LFENCE, MFENCE, MOVNTI, CLFLUSH, CRC32, and POPCNT.
         * If this flag is clear, the FXSAVE and FXRSTOR instructions will save and restore the contents of the x87 FPU and MMX
         * registers, but they may not save and restore the contents of the XMM and MXCSR registers. Also, the processor will
         * generate an invalid opcode exception (\#UD) if it attempts to execute any SSE/SSE2/SSE3 instruction, with the exception
         * of PAUSE, PREFETCHh, SFENCE, LFENCE, MFENCE, MOVNTI, CLFLUSH, CRC32, and POPCNT. The operating system or executive must
         * explicitly set this flag.
         *
         * @remarks CPUID feature flag FXSR indicates availability of the FXSAVE/FXRSTOR instructions. The OSFXSR bit provides
         *          operating system software with a means of enabling FXSAVE/FXRSTOR to save/restore the contents of the X87 FPU, XMM and
         *          MXCSR registers. Consequently OSFXSR bit indicates that the operating system provides context switch support for
         *          SSE/SSE2/SSE3/SSSE3/SSE4.
         */
        UINT64 OsFxsaveFxrstorSupport : 1;
#define CR4_OS_FXSAVE_FXRSTOR_SUPPORT_BIT                            9
#define CR4_OS_FXSAVE_FXRSTOR_SUPPORT_FLAG                           0x200
#define CR4_OS_FXSAVE_FXRSTOR_SUPPORT_MASK                           0x01
#define CR4_OS_FXSAVE_FXRSTOR_SUPPORT(_)                             (((_) >> 9) & 0x01)

        /**
         * @brief Operating System Support for Unmasked SIMD Floating-Point Exceptions
         *
         * [Bit 10] Operating System Support for Unmasked SIMD Floating-Point Exceptions - When set, indicates that the operating
         * system supports the handling of unmasked SIMD floating-point exceptions through an exception handler that is invoked
         * when a SIMD floating-point exception (\#XM) is generated. SIMD floating-point exceptions are only generated by
         * SSE/SSE2/SSE3/SSE4.1 SIMD floatingpoint instructions.
         * The operating system or executive must explicitly set this flag. If this flag is not set, the processor will generate an
         * invalid opcode exception (\#UD) whenever it detects an unmasked SIMD floating-point exception.
         */
        UINT64 OsXmmExceptionSupport : 1;
#define CR4_OS_XMM_EXCEPTION_SUPPORT_BIT                             10
#define CR4_OS_XMM_EXCEPTION_SUPPORT_FLAG                            0x400
#define CR4_OS_XMM_EXCEPTION_SUPPORT_MASK                            0x01
#define CR4_OS_XMM_EXCEPTION_SUPPORT(_)                              (((_) >> 10) & 0x01)

        /**
         * @brief User-Mode Instruction Prevention
         *
         * [Bit 11] When set, the following instructions cannot be executed if CPL > 0: SGDT, SIDT, SLDT, SMSW, and STR. An attempt
         * at such execution causes a generalprotection exception (\#GP).
         */
        UINT64 UsermodeInstructionPrevention : 1;
#define CR4_USERMODE_INSTRUCTION_PREVENTION_BIT                      11
#define CR4_USERMODE_INSTRUCTION_PREVENTION_FLAG                     0x800
#define CR4_USERMODE_INSTRUCTION_PREVENTION_MASK                     0x01
#define CR4_USERMODE_INSTRUCTION_PREVENTION(_)                       (((_) >> 11) & 0x01)
        UINT64 Reserved1 : 1;

        /**
         * @brief VMX-Enable
         *
         * [Bit 13] Enables VMX operation when set.
         *
         * @see Vol3C[23(INTRODUCTION TO VIRTUAL MACHINE EXTENSIONS)]
         */
        UINT64 VmxEnable : 1;
#define CR4_VMX_ENABLE_BIT                                           13
#define CR4_VMX_ENABLE_FLAG                                          0x2000
#define CR4_VMX_ENABLE_MASK                                          0x01
#define CR4_VMX_ENABLE(_)                                            (((_) >> 13) & 0x01)

        /**
         * @brief SMX-Enable
         *
         * [Bit 14] Enables SMX operation when set.
         *
         * @see Vol2[6(SAFER MODE EXTENSIONS REFERENCE)]
         */
        UINT64 SmxEnable : 1;
#define CR4_SMX_ENABLE_BIT                                           14
#define CR4_SMX_ENABLE_FLAG                                          0x4000
#define CR4_SMX_ENABLE_MASK                                          0x01
#define CR4_SMX_ENABLE(_)                                            (((_) >> 14) & 0x01)
        UINT64 Reserved2 : 1;

        /**
         * @brief FSGSBASE-Enable
         *
         * [Bit 16] Enables the instructions RDFSBASE, RDGSBASE, WRFSBASE, and WRGSBASE.
         */
        UINT64 FsgsbaseEnable : 1;
#define CR4_FSGSBASE_ENABLE_BIT                                      16
#define CR4_FSGSBASE_ENABLE_FLAG                                     0x10000
#define CR4_FSGSBASE_ENABLE_MASK                                     0x01
#define CR4_FSGSBASE_ENABLE(_)                                       (((_) >> 16) & 0x01)

        /**
         * @brief PCID-Enable
         *
         * [Bit 17] Enables process-context identifiers (PCIDs) when set. Can be set only in IA-32e mode (if IA32_EFER.LMA = 1).
         *
         * @see Vol3A[4.10.1(Process-Context Identifiers (PCIDs))]
         */
        UINT64 PcidEnable : 1;
#define CR4_PCID_ENABLE_BIT                                          17
#define CR4_PCID_ENABLE_FLAG                                         0x20000
#define CR4_PCID_ENABLE_MASK                                         0x01
#define CR4_PCID_ENABLE(_)                                           (((_) >> 17) & 0x01)

        /**
         * @brief XSAVE and Processor Extended States-Enable
         *
         * [Bit 18] When set, this flag:
         * -# indicates (via CPUID.01H:ECX.OSXSAVE[bit 27]) that the operating system supports the use of the XGETBV, XSAVE and
         * XRSTOR instructions by general software;
         * -# enables the XSAVE and XRSTOR instructions to save and restore the x87 FPU state (including MMX registers), the SSE
         * state (XMM registers and MXCSR), along with other processor extended states enabled in XCR0;
         * -# enables the processor to execute XGETBV and XSETBV instructions in order to read and write XCR0.
         *
         * @see Vol3A[2.6(EXTENDED CONTROL REGISTERS (INCLUDING XCR0))]
         * @see Vol3A[13(SYSTEM PROGRAMMING FOR INSTRUCTION SET EXTENSIONS AND PROCESSOR EXTENDED)]
         */
        UINT64 OsXsave : 1;
#define CR4_OS_XSAVE_BIT                                             18
#define CR4_OS_XSAVE_FLAG                                            0x40000
#define CR4_OS_XSAVE_MASK                                            0x01
#define CR4_OS_XSAVE(_)                                              (((_) >> 18) & 0x01)
        UINT64 Reserved3 : 1;

        /**
         * @brief SMEP-Enable
         *
         * [Bit 20] Enables supervisor-mode execution prevention (SMEP) when set.
         *
         * @see Vol3A[4.6(ACCESS RIGHTS)]
         */
        UINT64 SmepEnable : 1;
#define CR4_SMEP_ENABLE_BIT                                          20
#define CR4_SMEP_ENABLE_FLAG                                         0x100000
#define CR4_SMEP_ENABLE_MASK                                         0x01
#define CR4_SMEP_ENABLE(_)                                           (((_) >> 20) & 0x01)

        /**
         * @brief SMAP-Enable
         *
         * [Bit 21] Enables supervisor-mode access prevention (SMAP) when set.
         *
         * @see Vol3A[4.6(ACCESS RIGHTS)]
         */
        UINT64 SmapEnable : 1;
#define CR4_SMAP_ENABLE_BIT                                          21
#define CR4_SMAP_ENABLE_FLAG                                         0x200000
#define CR4_SMAP_ENABLE_MASK                                         0x01
#define CR4_SMAP_ENABLE(_)                                           (((_) >> 21) & 0x01)

        /**
         * @brief Protection-Key-Enable
         *
         * [Bit 22] Enables 4-level paging to associate each linear address with a protection key. The PKRU register specifies, for
         * each protection key, whether user-mode linear addresses with that protection key can be read or written. This bit also
         * enables access to the PKRU register using the RDPKRU and WRPKRU instructions.
         */
        UINT64 ProtectionKeyEnable : 1;
#define CR4_PROTECTION_KEY_ENABLE_BIT                                22
#define CR4_PROTECTION_KEY_ENABLE_FLAG                               0x400000
#define CR4_PROTECTION_KEY_ENABLE_MASK                               0x01
#define CR4_PROTECTION_KEY_ENABLE(_)                                 (((_) >> 22) & 0x01)
        UINT64 Reserved4 : 41;
    };

    UINT64 Flags;
} CR4;

/**
 * Capability Reporting Register of CR0 Bits Fixed to 0.
 *
 * @remarks If CPUID.01H:ECX.[5] = 1
 * @see Vol3D[A.7(VMX-FIXED BITS IN CR0)]
 * @see Vol3D[A.7(VMX-Fixed Bits in CR0)] (reference)
 */
#define IA32_VMX_CR0_FIXED0                                          0x00000486

 /**
  * Capability Reporting Register of CR0 Bits Fixed to 1.
  *
  * @remarks If CPUID.01H:ECX.[5] = 1
  * @see Vol3D[A.7(VMX-FIXED BITS IN CR0)]
  * @see Vol3D[A.7(VMX-Fixed Bits in CR0)] (reference)
  */
#define IA32_VMX_CR0_FIXED1                                          0x00000487

  /**
   * Capability Reporting Register of CR4 Bits Fixed to 0.
   *
   * @remarks If CPUID.01H:ECX.[5] = 1
   * @see Vol3D[A.8(VMX-FIXED BITS IN CR4)]
   * @see Vol3D[A.8(VMX-Fixed Bits in CR4)] (reference)
   */
#define IA32_VMX_CR4_FIXED0                                          0x00000488

   /**
    * Capability Reporting Register of CR4 Bits Fixed to 1.
    *
    * @remarks If CPUID.01H:ECX.[5] = 1
    * @see Vol3D[A.8(VMX-FIXED BITS IN CR4)]
    * @see Vol3D[A.8(VMX-Fixed Bits in CR4)] (reference)
    */
#define IA32_VMX_CR4_FIXED1                                          0x00000489

typedef union SEGMENT_ATTRIBUTES
{
    USHORT UCHARs;
    struct
    {
        USHORT TYPE : 4; /* 0;  Bit 40-43 */
        USHORT G : 1;   /* 11; Bit 55 */
        USHORT GAP : 4;
    } Fields;
} SEGMENT_ATTRIBUTES;

typedef struct SEGMENT_SELECTOR
{
    USHORT             SEL;
    SEGMENT_ATTRIBUTES ATTRIBUTES;
    ULONG32            LIMIT;
    ULONG64            BASE;
} SEGMENT_SELECTOR, * PSEGMENT_SELECTOR;

enum VMCS_FIELDS
{
    GUEST_ES_SELECTOR = 0x00000800,
    GUEST_CS_SELECTOR = 0x00000802,
    GUEST_SS_SELECTOR = 0x00000804,
    GUEST_DS_SELECTOR = 0x00000806,
    GUEST_FS_SELECTOR = 0x00000808,
    GUEST_GS_SELECTOR = 0x0000080a,
    GUEST_LDTR_SELECTOR = 0x0000080c,
    GUEST_TR_SELECTOR = 0x0000080e,
    HOST_ES_SELECTOR = 0x00000c00,
    HOST_CS_SELECTOR = 0x00000c02,
    HOST_SS_SELECTOR = 0x00000c04,
    HOST_DS_SELECTOR = 0x00000c06,
    HOST_FS_SELECTOR = 0x00000c08,
    HOST_GS_SELECTOR = 0x00000c0a,
    HOST_TR_SELECTOR = 0x00000c0c,
    IO_BITMAP_A = 0x00002000,
    IO_BITMAP_A_HIGH = 0x00002001,
    IO_BITMAP_B = 0x00002002,
    IO_BITMAP_B_HIGH = 0x00002003,
    MSR_BITMAP = 0x00002004,
    MSR_BITMAP_HIGH = 0x00002005,
    VM_EXIT_MSR_STORE_ADDR = 0x00002006,
    VM_EXIT_MSR_STORE_ADDR_HIGH = 0x00002007,
    VM_EXIT_MSR_LOAD_ADDR = 0x00002008,
    VM_EXIT_MSR_LOAD_ADDR_HIGH = 0x00002009,
    VM_ENTRY_MSR_LOAD_ADDR = 0x0000200a,
    VM_ENTRY_MSR_LOAD_ADDR_HIGH = 0x0000200b,
    TSC_OFFSET = 0x00002010,
    TSC_OFFSET_HIGH = 0x00002011,
    VIRTUAL_APIC_PAGE_ADDR = 0x00002012,
    VIRTUAL_APIC_PAGE_ADDR_HIGH = 0x00002013,
    VMFUNC_CONTROLS = 0x00002018,
    VMFUNC_CONTROLS_HIGH = 0x00002019,
    EPT_POINTER = 0x0000201A,
    EPT_POINTER_HIGH = 0x0000201B,
    EPTP_LIST = 0x00002024,
    EPTP_LIST_HIGH = 0x00002025,
    GUEST_PHYSICAL_ADDRESS = 0x2400,
    GUEST_PHYSICAL_ADDRESS_HIGH = 0x2401,
    VMCS_LINK_POINTER = 0x00002800,
    VMCS_LINK_POINTER_HIGH = 0x00002801,
    GUEST_IA32_DEBUGCTL = 0x00002802,
    GUEST_IA32_DEBUGCTL_HIGH = 0x00002803,
    PIN_BASED_VM_EXEC_CONTROL = 0x00004000,
    CPU_BASED_VM_EXEC_CONTROL = 0x00004002,
    EXCEPTION_BITMAP = 0x00004004,
    PAGE_FAULT_ERROR_CODE_MASK = 0x00004006,
    PAGE_FAULT_ERROR_CODE_MATCH = 0x00004008,
    CR3_TARGET_COUNT = 0x0000400a,
    VM_EXIT_CONTROLS = 0x0000400c,
    VM_EXIT_MSR_STORE_COUNT = 0x0000400e,
    VM_EXIT_MSR_LOAD_COUNT = 0x00004010,
    VM_ENTRY_CONTROLS = 0x00004012,
    VM_ENTRY_MSR_LOAD_COUNT = 0x00004014,
    VM_ENTRY_INTR_INFO_FIELD = 0x00004016,
    VM_ENTRY_EXCEPTION_ERROR_CODE = 0x00004018,
    VM_ENTRY_INSTRUCTION_LEN = 0x0000401a,
    TPR_THRESHOLD = 0x0000401c,
    SECONDARY_VM_EXEC_CONTROL = 0x0000401e,
    VM_INSTRUCTION_ERROR = 0x00004400,
    VM_EXIT_REASON = 0x00004402,
    VM_EXIT_INTR_INFO = 0x00004404,
    VM_EXIT_INTR_ERROR_CODE = 0x00004406,
    IDT_VECTORING_INFO_FIELD = 0x00004408,
    IDT_VECTORING_ERROR_CODE = 0x0000440a,
    VM_EXIT_INSTRUCTION_LEN = 0x0000440c,
    VMX_INSTRUCTION_INFO = 0x0000440e,
    GUEST_ES_LIMIT = 0x00004800,
    GUEST_CS_LIMIT = 0x00004802,
    GUEST_SS_LIMIT = 0x00004804,
    GUEST_DS_LIMIT = 0x00004806,
    GUEST_FS_LIMIT = 0x00004808,
    GUEST_GS_LIMIT = 0x0000480a,
    GUEST_LDTR_LIMIT = 0x0000480c,
    GUEST_TR_LIMIT = 0x0000480e,
    GUEST_GDTR_LIMIT = 0x00004810,
    GUEST_IDTR_LIMIT = 0x00004812,
    GUEST_ES_AR_BYTES = 0x00004814,
    GUEST_CS_AR_BYTES = 0x00004816,
    GUEST_SS_AR_BYTES = 0x00004818,
    GUEST_DS_AR_BYTES = 0x0000481a,
    GUEST_FS_AR_BYTES = 0x0000481c,
    GUEST_GS_AR_BYTES = 0x0000481e,
    GUEST_LDTR_AR_BYTES = 0x00004820,
    GUEST_TR_AR_BYTES = 0x00004822,
    GUEST_INTERRUPTIBILITY_INFO = 0x00004824,
    GUEST_ACTIVITY_STATE = 0x00004826,
    GUEST_SM_BASE = 0x00004828,
    GUEST_SYSENTER_CS = 0x0000482A,
    HOST_IA32_SYSENTER_CS = 0x00004c00,
    CR0_GUEST_HOST_MASK = 0x00006000,
    CR4_GUEST_HOST_MASK = 0x00006002,
    CR0_READ_SHADOW = 0x00006004,
    CR4_READ_SHADOW = 0x00006006,
    CR3_TARGET_VALUE0 = 0x00006008,
    CR3_TARGET_VALUE1 = 0x0000600a,
    CR3_TARGET_VALUE2 = 0x0000600c,
    CR3_TARGET_VALUE3 = 0x0000600e,
    EXIT_QUALIFICATION = 0x00006400,
    GUEST_LINEAR_ADDRESS = 0x0000640a,
    GUEST_CR0 = 0x00006800,
    GUEST_CR3 = 0x00006802,
    GUEST_CR4 = 0x00006804,
    GUEST_ES_BASE = 0x00006806,
    GUEST_CS_BASE = 0x00006808,
    GUEST_SS_BASE = 0x0000680a,
    GUEST_DS_BASE = 0x0000680c,
    GUEST_FS_BASE = 0x0000680e,
    GUEST_GS_BASE = 0x00006810,
    GUEST_LDTR_BASE = 0x00006812,
    GUEST_TR_BASE = 0x00006814,
    GUEST_GDTR_BASE = 0x00006816,
    GUEST_IDTR_BASE = 0x00006818,
    GUEST_DR7 = 0x0000681a,
    GUEST_RSP = 0x0000681c,
    GUEST_RIP = 0x0000681e,
    GUEST_RFLAGS = 0x00006820,
    GUEST_PENDING_DBG_EXCEPTIONS = 0x00006822,
    GUEST_SYSENTER_ESP = 0x00006824,
    GUEST_SYSENTER_EIP = 0x00006826,
    HOST_CR0 = 0x00006c00,
    HOST_CR3 = 0x00006c02,
    HOST_CR4 = 0x00006c04,
    HOST_FS_BASE = 0x00006c06,
    HOST_GS_BASE = 0x00006c08,
    HOST_TR_BASE = 0x00006c0a,
    HOST_GDTR_BASE = 0x00006c0c,
    HOST_IDTR_BASE = 0x00006c0e,
    HOST_IA32_SYSENTER_ESP = 0x00006c10,
    HOST_IA32_SYSENTER_EIP = 0x00006c12,
    HOST_RSP = 0x00006c14,
    HOST_RIP = 0x00006c16,
};

typedef struct _SEGMENT_DESCRIPTOR
{
    USHORT LIMIT0;
    USHORT BASE0;
    UCHAR  BASE1;
    UCHAR  ATTR0;
    UCHAR  LIMIT1ATTR1;
    UCHAR  BASE2;
} SEGMENT_DESCRIPTOR, * PSEGMENT_DESCRIPTOR;

typedef union _MSR
{
    struct
    {
        ULONG Low;
        ULONG High;
    };

    ULONG64 Content;
} MSR, * PMSR;


// PIN-Based Execution
#define PIN_BASED_VM_EXECUTION_CONTROLS_EXTERNAL_INTERRUPT        0x00000001
#define PIN_BASED_VM_EXECUTION_CONTROLS_NMI_EXITING               0x00000008
#define PIN_BASED_VM_EXECUTION_CONTROLS_VIRTUAL_NMI               0x00000020
#define PIN_BASED_VM_EXECUTION_CONTROLS_ACTIVE_VMX_TIMER          0x00000040
#define PIN_BASED_VM_EXECUTION_CONTROLS_PROCESS_POSTED_INTERRUPTS 0x00000080

#define CPU_BASED_VIRTUAL_INTR_PENDING        0x00000004
#define CPU_BASED_USE_TSC_OFFSETING           0x00000008
#define CPU_BASED_HLT_EXITING                 0x00000080
#define CPU_BASED_INVLPG_EXITING              0x00000200
#define CPU_BASED_MWAIT_EXITING               0x00000400
#define CPU_BASED_RDPMC_EXITING               0x00000800
#define CPU_BASED_RDTSC_EXITING               0x00001000
#define CPU_BASED_CR3_LOAD_EXITING            0x00008000
#define CPU_BASED_CR3_STORE_EXITING           0x00010000
#define CPU_BASED_CR8_LOAD_EXITING            0x00080000
#define CPU_BASED_CR8_STORE_EXITING           0x00100000
#define CPU_BASED_TPR_SHADOW                  0x00200000
#define CPU_BASED_VIRTUAL_NMI_PENDING         0x00400000
#define CPU_BASED_MOV_DR_EXITING              0x00800000
#define CPU_BASED_UNCOND_IO_EXITING           0x01000000
#define CPU_BASED_ACTIVATE_IO_BITMAP          0x02000000
#define CPU_BASED_MONITOR_TRAP_FLAG           0x08000000
#define CPU_BASED_ACTIVATE_MSR_BITMAP         0x10000000
#define CPU_BASED_MONITOR_EXITING             0x20000000
#define CPU_BASED_PAUSE_EXITING               0x40000000
#define CPU_BASED_ACTIVATE_SECONDARY_CONTROLS 0x80000000

#define CPU_BASED_CTL2_ENABLE_EPT         0x2
#define CPU_BASED_CTL2_RDTSCP             0x8
#define CPU_BASED_CTL2_ENABLE_VPID        0x20
#define CPU_BASED_CTL2_UNRESTRICTED_GUEST 0x80
#define CPU_BASED_CTL2_ENABLE_VMFUNC      0x2000

// VM-exit Control Bits
#define VM_EXIT_IA32E_MODE       0x00000200
#define VM_EXIT_ACK_INTR_ON_EXIT 0x00008000
#define VM_EXIT_SAVE_GUEST_PAT   0x00040000
#define VM_EXIT_LOAD_HOST_PAT    0x00080000

// VM-entry Control Bits
#define VM_ENTRY_IA32E_MODE         0x00000200
#define VM_ENTRY_SMM                0x00000400
#define VM_ENTRY_DEACT_DUAL_MONITOR 0x00000800
#define VM_ENTRY_LOAD_GUEST_PAT     0x00004000

enum SEGREGS
{
    ES = 0,
    CS,
    SS,
    DS,
    FS,
    GS,
    LDTR,
    TR
};

typedef struct _GUEST_REGS
{
    ULONG64 rax; // 0x00         // NOT VALID FOR SVM
    ULONG64 rcx;
    ULONG64 rdx; // 0x10
    ULONG64 rbx;
    ULONG64 rsp; // 0x20         // rsp is not stored here on SVM
    ULONG64 rbp;
    ULONG64 rsi; // 0x30
    ULONG64 rdi;
    ULONG64 r8; // 0x40
    ULONG64 r9;
    ULONG64 r10; // 0x50
    ULONG64 r11;
    ULONG64 r12; // 0x60
    ULONG64 r13;
    ULONG64 r14; // 0x70
    ULONG64 r15;
} GUEST_REGS, * PGUEST_REGS;


#define EXIT_REASON_EXCEPTION_NMI                0
#define EXIT_REASON_EXTERNAL_INTERRUPT           1
#define EXIT_REASON_TRIPLE_FAULT                 2
#define EXIT_REASON_INIT                         3
#define EXIT_REASON_SIPI                         4
#define EXIT_REASON_IO_SMI                       5
#define EXIT_REASON_OTHER_SMI                    6
#define EXIT_REASON_PENDING_VIRT_INTR            7
#define EXIT_REASON_PENDING_VIRT_NMI             8
#define EXIT_REASON_TASK_SWITCH                  9
#define EXIT_REASON_CPUID                        10
#define EXIT_REASON_GETSEC                       11
#define EXIT_REASON_HLT                          12
#define EXIT_REASON_INVD                         13
#define EXIT_REASON_INVLPG                       14
#define EXIT_REASON_RDPMC                        15
#define EXIT_REASON_RDTSC                        16
#define EXIT_REASON_RSM                          17
#define EXIT_REASON_VMCALL                       18
#define EXIT_REASON_VMCLEAR                      19
#define EXIT_REASON_VMLAUNCH                     20
#define EXIT_REASON_VMPTRLD                      21
#define EXIT_REASON_VMPTRST                      22
#define EXIT_REASON_VMREAD                       23
#define EXIT_REASON_VMRESUME                     24
#define EXIT_REASON_VMWRITE                      25
#define EXIT_REASON_VMXOFF                       26
#define EXIT_REASON_VMXON                        27
#define EXIT_REASON_CR_ACCESS                    28
#define EXIT_REASON_DR_ACCESS                    29
#define EXIT_REASON_IO_INSTRUCTION               30
#define EXIT_REASON_MSR_READ                     31
#define EXIT_REASON_MSR_WRITE                    32
#define EXIT_REASON_INVALID_GUEST_STATE          33
#define EXIT_REASON_MSR_LOADING                  34
#define EXIT_REASON_MWAIT_INSTRUCTION            36
#define EXIT_REASON_MONITOR_TRAP_FLAG            37
#define EXIT_REASON_MONITOR_INSTRUCTION          39
#define EXIT_REASON_PAUSE_INSTRUCTION            40
#define EXIT_REASON_MCE_DURING_VMENTRY           41
#define EXIT_REASON_TPR_BELOW_THRESHOLD          43
#define EXIT_REASON_APIC_ACCESS                  44
#define EXIT_REASON_ACCESS_GDTR_OR_IDTR          46
#define EXIT_REASON_ACCESS_LDTR_OR_TR            47
#define EXIT_REASON_EPT_VIOLATION                48
#define EXIT_REASON_EPT_MISCONFIG                49
#define EXIT_REASON_INVEPT                       50
#define EXIT_REASON_RDTSCP                       51
#define EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED 52
#define EXIT_REASON_INVVPID                      53
#define EXIT_REASON_WBINVD                       54
#define EXIT_REASON_XSETBV                       55
#define EXIT_REASON_APIC_WRITE                   56
#define EXIT_REASON_RDRAND                       57
#define EXIT_REASON_INVPCID                      58
#define EXIT_REASON_RDSEED                       61
#define EXIT_REASON_PML_FULL                     62
#define EXIT_REASON_XSAVES                       63
#define EXIT_REASON_XRSTORS                      64
#define EXIT_REASON_PCOMMIT                      65


//
// See Table 24-8. Format of Extended-Page-Table Pointer
//
typedef union _EPTP
{
    ULONG64 All;
    struct
    {
        UINT64 MemoryType : 3;            // bit 2:0 (0 = Uncacheable (UC) - 6 = Write - back(WB))
        UINT64 PageWalkLength : 3;        // bit 5:3 (This value is 1 less than the EPT page-walk length)
        UINT64 DirtyAndAceessEnabled : 1; // bit 6  (Setting this control to 1 enables accessed and dirty flags for EPT)
        UINT64 Reserved1 : 5;             // bit 11:7
        UINT64 PML4Address : 36;
        UINT64 Reserved2 : 16;
    } Fields;
} EPTP, * PEPTP;

typedef struct INVEPT_DESC
{
    EPTP   Eptp;
    UINT64 Reserved;
} INVEPT_DESC, * PINVEPT_DESC;

enum INVEPT_TYPE
{
    SINGLE_CONTEXT = 0x00000001,
    ALL_CONTEXTS = 0x00000002,
};


//
// See Table 28-1.
//
typedef union _EPT_PML4E
{
    ULONG64 All;
    struct
    {
        UINT64 Read : 1;               // bit 0
        UINT64 Write : 1;              // bit 1
        UINT64 Execute : 1;            // bit 2
        UINT64 Reserved1 : 5;          // bit 7:3 (Must be Zero)
        UINT64 Accessed : 1;           // bit 8
        UINT64 Ignored1 : 1;           // bit 9
        UINT64 ExecuteForUserMode : 1; // bit 10
        UINT64 Ignored2 : 1;           // bit 11
        UINT64 PhysicalAddress : 36;   // bit (N-1):12 or Page-Frame-Number
        UINT64 Reserved2 : 4;          // bit 51:N
        UINT64 Ignored3 : 12;          // bit 63:52
    } Fields;
} EPT_PML4E, * PEPT_PML4E;

//
// See Table 28-3
//
typedef union _EPT_PDPTE
{
    ULONG64 All;
    struct
    {
        UINT64 Read : 1;               // bit 0
        UINT64 Write : 1;              // bit 1
        UINT64 Execute : 1;            // bit 2
        UINT64 Reserved1 : 5;          // bit 7:3 (Must be Zero)
        UINT64 Accessed : 1;           // bit 8
        UINT64 Ignored1 : 1;           // bit 9
        UINT64 ExecuteForUserMode : 1; // bit 10
        UINT64 Ignored2 : 1;           // bit 11
        UINT64 PhysicalAddress : 36;   // bit (N-1):12 or Page-Frame-Number
        UINT64 Reserved2 : 4;          // bit 51:N
        UINT64 Ignored3 : 12;          // bit 63:52
    } Fields;
} EPT_PDPTE, * PEPT_PDPTE;

typedef union _EPT_PDE
{
    ULONG64 All;
    struct
    {
        UINT64 Read : 1;               // bit 0
        UINT64 Write : 1;              // bit 1
        UINT64 Execute : 1;            // bit 2
        UINT64 Reserved1 : 5;          // bit 7:3 (Must be Zero)
        UINT64 Accessed : 1;           // bit 8
        UINT64 Ignored1 : 1;           // bit 9
        UINT64 ExecuteForUserMode : 1; // bit 10
        UINT64 Ignored2 : 1;           // bit 11
        UINT64 PhysicalAddress : 36;   // bit (N-1):12 or Page-Frame-Number
        UINT64 Reserved2 : 4;          // bit 51:N
        UINT64 Ignored3 : 12;          // bit 63:52
    } Fields;
} EPT_PDE, * PEPT_PDE;


//
// See Table 28-6
//
typedef union _EPT_PTE
{
    ULONG64 All;
    struct
    {
        UINT64 Read : 1;               // bit 0
        UINT64 Write : 1;              // bit 1
        UINT64 Execute : 1;            // bit 2
        UINT64 EPTMemoryType : 3;      // bit 5:3 (EPT Memory type)
        UINT64 IgnorePAT : 1;          // bit 6
        UINT64 Ignored1 : 1;           // bit 7
        UINT64 AccessedFlag : 1;       // bit 8
        UINT64 DirtyFlag : 1;          // bit 9
        UINT64 ExecuteForUserMode : 1; // bit 10
        UINT64 Ignored2 : 1;           // bit 11
        UINT64 PhysicalAddress : 36;   // bit (N-1):12 or Page-Frame-Number
        UINT64 Reserved : 4;           // bit 51:N
        UINT64 Ignored3 : 11;          // bit 62:52
        UINT64 SuppressVE : 1;         // bit 63
    } Fields;
} EPT_PTE, * PEPT_PTE;

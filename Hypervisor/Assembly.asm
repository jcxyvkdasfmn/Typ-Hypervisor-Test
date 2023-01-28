PUBLIC AsmPerformInvept
PUBLIC GetCs
PUBLIC GetDs
PUBLIC GetEs
PUBLIC GetSs
PUBLIC GetFs
PUBLIC GetGs
PUBLIC GetLdtr
PUBLIC GetTr
PUBLIC GetGdtBase
PUBLIC GetIdtBase
PUBLIC GetGdtLimit
PUBLIC GetIdtLimit
PUBLIC GetRflags
PUBLIC Launch
PUBLIC StartVMXBack
PUBLIC LoadAccessRightsByte

EXTERN	Start:PROC	

.code _text

;------------------------------------------------------------------------
    VMX_ERROR_CODE_SUCCESS              = 0
    VMX_ERROR_CODE_FAILED_WITH_STATUS   = 1
    VMX_ERROR_CODE_FAILED               = 2
;------------------------------------------------------------------------



;------------------------------------------------------------------------

AsmPerformInvept PROC PUBLIC

	INVEPT  RCX, OWORD PTR [RDX]
	JZ FailedWithStatus
	JC Failed
	XOR     RAX, RAX

	RET

FailedWithStatus:    
	MOV     RAX, VMX_ERROR_CODE_FAILED_WITH_STATUS
	RET

Failed:   
	MOV     RAX, VMX_ERROR_CODE_FAILED
	RET

AsmPerformInvept ENDP

;------------------------------------------------------------------------

;------------------------------------------------------------------------

GetGdtBase PROC

	LOCAL	GDTR[10]:BYTE
	SGDT	GDTR
	MOV		RAX, QWORD PTR GDTR[2]

	RET

GetGdtBase ENDP

;------------------------------------------------------------------------

GetCs PROC

	MOV		RAX, CS
	RET

GetCs ENDP

;------------------------------------------------------------------------

GetDs PROC

	MOV		RAX, DS
	RET

GetDs ENDP

;------------------------------------------------------------------------

GetEs PROC

	MOV		RAX, ES
	RET

GetEs ENDP

;------------------------------------------------------------------------

GetSs PROC

	MOV		RAX, SS
	RET

GetSs ENDP

;------------------------------------------------------------------------

GetFs PROC

	MOV		RAX, FS
	RET

GetFs ENDP

;------------------------------------------------------------------------

GetGs PROC

	MOV		RAX, GS
	RET

GetGs ENDP

;------------------------------------------------------------------------

GetLdtr PROC

	SLDT	RAX
	RET

GetLdtr ENDP

;------------------------------------------------------------------------

GetTr PROC

	STR		RAX
	RET

GetTr ENDP

;------------------------------------------------------------------------

GetIdtBase PROC

	LOCAL	IDTR[10]:BYTE
	
	SIDT	IDTR
	MOV		RAX, QWORD PTR IDTR[2]
	RET

GetIdtBase ENDP

;------------------------------------------------------------------------

GetGdtLimit PROC

	LOCAL	GDTR[10]:BYTE

	SGDT	GDTR
	MOV		AX, WORD PTR GDTR[0]

	RET

GetGdtLimit ENDP

;------------------------------------------------------------------------

GetIdtLimit PROC

	LOCAL	IDTR[10]:BYTE
	
	SIDT	IDTR
	MOV		AX, WORD PTR IDTR[0]

	RET

GetIdtLimit ENDP

;------------------------------------------------------------------------

GetRflags PROC

	PUSHFQ
	POP		RAX
	RET

GetRflags ENDP

;------------------------------------------------------------------------

Launch PROC

	PUSH RAX
	PUSH RCX
	PUSH RDX
	PUSH RBX
	PUSH RBP
	PUSH RSI
	PUSH RDI
	PUSH R8
	PUSH R9
	PUSH R10
	PUSH R11
	PUSH R12
	PUSH R13
	PUSH R14
	PUSH R15

	SUB RSP, 28h
	
	MOV RCX, RSP

	CALL Start
	;Startvmxback left here if we don't execute Vmlaunch we don't bsod
	jmp StartVMXBack
	
Launch ENDP

;------------------------------------------------------------------------
StartVMXBack PROC


	ADD RSP, 28h
	POP R15
	POP R14
	POP R13
	POP R12
	POP R11
	POP R10
	POP R9
	POP R8
	POP RDI
	POP RSI
	POP RBP
	POP RBX
	POP RDX
	POP RCX
	POP RAX
	
	RET
	
StartVMXBack ENDP

LoadAccessRightsByte PROC
    lar rax, rcx
    ret
LoadAccessRightsByte ENDP

END
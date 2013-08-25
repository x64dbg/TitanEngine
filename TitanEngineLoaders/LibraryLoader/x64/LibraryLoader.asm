format PE64 GUI
entry start

section '.text' code readable executable
    start:
	sub rsp,8*5
	lea rcx,[szLibraryName]
	call [LoadLibraryW]
	cmp rax,1
	sbb ecx,ecx
	and ecx,61703078h
	call [ExitProcess]

section '.data' data readable writeable
    szLibraryName dw 512 dup (?)

section '.idata' import data readable writeable
    dd 0,0,0,rva kernel_name,rva kernel_table
    dd 0,0,0,0,0

    kernel_table:
	ExitProcess dq rva _ExitProcess
	LoadLibraryW dq rva _LoadLibraryW
	dq 0

    kernel_name db 'KERNEL32.DLL',0

    _ExitProcess dw 0
    db 'ExitProcess',0
    _LoadLibraryW dw 0
    db 'LoadLibraryW',0
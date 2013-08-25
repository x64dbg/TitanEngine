format PE GUI
entry start

section '.text' code readable executable
    start:
	push szLibraryName
	call [LoadLibraryW]
	cmp eax,1
	sbb ecx,ecx
	and ecx,61703078h
	push ecx
	call [ExitProcess]

section '.data' data readable writeable
    szLibraryName dw 512 dup (?)

section '.idata' import data readable writeable
    dd 0,0,0,rva kernel_name,rva kernel_table
    dd 0,0,0,0,0

    kernel_table:
	ExitProcess dd rva _ExitProcess
	LoadLibraryW dd rva _LoadLibraryW
	dd 0

    kernel_name db 'kernel32.dll',0

    _ExitProcess dw 0
    db 'ExitProcess',0
    _LoadLibraryW dw 0
    db 'LoadLibraryW',0
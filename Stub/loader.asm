[BITS 64]

; x64 PIC stub finds kernel32 base via PEB using ROR13 hash
; no string literals position independent

global _start
section .text

_start:
    mov rax, [gs:0x60]         ; PEB
    mov rax, [rax + 0x18]      ; PEB->Ldr
    mov r8, [rax + 0x10]       ; InLoadOrderModuleList head

next_module:
    mov rsi, [r8 + 0x60]       ; BaseDllName.Buffer
    test rsi, rsi
    jz skip_module

    xor r9, r9                 ; hash = 0

hash_loop:
    xor rax, rax
    lodsw                      ; read wide char
    test ax, ax
    jz check_hash

    cmp al, 'a'
    jl hash_calc
    cmp al, 'z'
    jg hash_calc
    sub al, 0x20

hash_calc:
    ror r9d, 13
    movzx eax, al
    add r9d, eax
    jmp hash_loop

check_hash:
    ; KERNEL32.DLL ROR13 = 0x6E2BCA17
    cmp r9d, 0x6E2BCA17
    je found_kernel32

skip_module:
    mov r8, [r8]               ; Flink -> next entry
    jmp next_module

found_kernel32:
    mov rbx, [r8 + 0x30]      ; DllBase
    ret

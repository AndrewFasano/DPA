.text
    .global nothing 

nothing:
    inc %rdi
    pushq %rdi
    mov %rsi, %rcx
    mov %rcx, %rbx
    cmp %rcx, %rbx
    jz . + 4
    .byte 0xe5
    pop %rax
    mov %rcx, %rdi
    mov %rdx, %rsi
    ret

global _start
section .text

_start:
    ; Never take this jump
    mov eax, 0x0
    mov ebx, 0x1
    cmp eax, ebx
    jne _hideme

fake:
    db 0xE8 ; First byte of a call instruction

_hideme:
    ;Set up write syscall with args (1, "Hello World!", 14)
    mov eax, 0x4
    mov ebx, 0x1

    ; Another fake jump
    cmp eax, ebx
    jne _hideme2

fake2:
    db 0xE8;  ; First byte of a call instruction

_hideme2:
    mov ecx, message
    mov edx, 0xD
    int 0x80

exit_cleanly:
    ;execute _exit(0);
    mov eax, 0x1
    mov ebx, 0x5
    int 0x80

section .data
    message: db "Hello World!", 0xA

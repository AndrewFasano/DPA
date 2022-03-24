.intel_syntax

.text
    .global my_asm_func

my_asm_func:
    # ARGUMENTS:
    #    we have a char* in RDI
    #    and a (int) length in RSI

    # Example: put a constant value in a register,
    # then write it into memory at the start
    # of the buffer
    mov %RAX, 0x4142434445464748
    mov [%RDI], %RAX

    # I'm not assuming anyone knows how to write x86_64 assembly
    # so the main thing you should try to do here is to break the disassembler
    # and then do something (small) that it won't figure out statically.

    ret

import capstone
import os

from pandare import Panda

'''
cmp r0, r1
beq eq

neq:
mov r2, #0
b end

eq:
mov r2, #1

end:
mov r3, #1
'''
ARM_CODE   = b"\x01\x00\x50\xe1\x01\x00\x00\x0a\x00\x20\xa0\xe3\x00\x00\x00\xea\x01\x20\xa0\xe3\x01\x30\xa0\xe3"

ADDRESS = 0x1000
stop_addr = ADDRESS + len(ARM_CODE)

# Create a machine of type 'configurable' but with just a CPU specified (no peripherals or memory maps)
panda = Panda("arm", extra_args=["-M", "configurable", "-nographic", "-d", "in_asm", "-D", "log.txt"])

@panda.cb_after_machine_init
def setup(cpu):
    # map 2MB memory for this emulation
    panda.map_memory("mymem", 2 * 1024 * 1024, ADDRESS)

    # Write code into memory
    panda.physical_memory_write(ADDRESS, ARM_CODE)

    # Set up registers
    panda.arch.set_reg(cpu, "R0", 1)
    panda.arch.set_reg(cpu, "R1", 1)

    # Set starting_pc
    panda.arch.set_pc(cpu, ADDRESS)

panda.cb_insn_translate(lambda x,y: True)

md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
@panda.cb_insn_exec
def on_insn(cpu, pc):
    '''
    At each instruction, print capstone disassembly.
    When we reach stop_addr, dump registers and shutdown
    '''
    if pc == stop_addr:
        print("Finished execution. CPU registers are:")
        #panda.arch.dump_regs(cpu)

        print("\nRESULT: R2 is:", panda.arch.get_reg(cpu, "R2"))

        # TODO: we need a better way to stop execution in the middle of a basic block
        os._exit(0)

    code = panda.virtual_memory_read(cpu, pc, 12)
    for i in md.disasm(code, pc):
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        break
    return 0

import random

@panda.ppp("forcedexec", "on_branch")
def on_branch(cpu, tb, block_size):

    #print(f"Block at {tb.pc} instruction offset is {block_size} tb size is {tb.size}")

    if block_size > tb.size:
        return False

    flip = (tb.pc == 0x1000)
    if flip:
        print(f"FLIP block at {tb.pc:x} instruction +{block_size}")
        return True
    else:
        print(f"Not flipping at {tb.pc:x} instruction +{block_size} (TB sz: {tb.size})")
        return False

panda.run()

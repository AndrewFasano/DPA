import networkx as nx
from pandare import Panda

panda = Panda(generic="arm")

block_count = 0
branch_count = 0

for x in range(5):

    @panda.ppp("forcedexec", "on_branch")
    def on_branch(cpu, tb, block_size):
        if panda.in_kernel_code_linux(cpu) or panda.in_kernel_mode(cpu):
            return False
        global branch_count
        branch_count += 1
        return False

    @panda.cb_before_block_exec
    def bbe(cpu, tb):
        global block_count
        block_count += 1

    @panda.queue_blocking
    def driver():
        panda.revert_sync("root")
        print('OUTPUT IS:', panda.run_serial_cmd("grep root /etc/passwd"))
        print(f"\tSaw {branch_count} branches and {block_count} blocks")
        panda.end_analysis()
        panda.disable_ppp("on_branch") # This silences a pointless warning

    panda.run()

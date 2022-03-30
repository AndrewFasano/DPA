import pickle
import networkx as nx
from pandare import Panda

panda = Panda(generic="arm")
enabled = False
last_pc = None
run_idx = 0

graph = nx.DiGraph()

# Configuration options:
TARGET = "grep"

cur_flip_chain = [] # List of branches to flip
flip_chain = [] # List of lists
queued_to_flip = set()

run_idx = 0
enabled = False
last_pc = None
last_flipped = None

CUTOFF=100

# We have *TWO* versions of the same loop
# The outer restarts panda while the inner reruns the program.
# We try for the inner loop when we can, but we'll hit the outer loop 
# a bunch too.
while run_idx == 0 or len(flip_chain) and run_idx < CUTOFF: # XXX DEBUG < 10
    @panda.ppp("forcedexec", "on_branch")
    def on_branch(cpu, tb, block_size):
        global enabled, cur_flip_chain
        global last_flipped

        if not enabled:
            return False

        if panda.in_kernel_code_linux(cpu) or panda.in_kernel_mode(cpu):
            enabled = False
            return False

        node_name = hex(panda.current_pc(cpu))

        if node_name not in graph.nodes:
            if run_idx > 1:
                print("ADDED NEW NODE")
            graph.add_node(node_name, size=tb.size, run_idx=run_idx, is_branch=True)
        else:
            graph.nodes[node_name]['is_branch'] = True

        if len(cur_flip_chain) and node_name == cur_flip_chain[0]:
            cur_flip_chain.pop(0)
            last_flipped = node_name
            print(f"FLIP branch at {node_name}")
            return True

        #pc = panda.current_pc(cpu)
        #procname = panda.get_process_name(cpu)
        #print(f"{run_idx} Branch at", hex(pc), "in", procname)
        return False


    #@panda.cb_before_block_exec
    @panda.cb_start_block_exec
    def bbe(cpu, tb):
        '''
        Before block executes, check current process - if it's our target, set enabled=True
        and record an edge from last PC to current PC in our graph.
        '''
        global enabled

        if panda.in_kernel_code_linux(cpu) or panda.in_kernel_mode(cpu):
            enabled = False
            return

        procname = panda.get_process_name(cpu)
        enabled = procname == TARGET

        if enabled:
            global graph, last_pc
            pc = panda.current_pc(cpu)
            node_name = hex(pc)
            # This is dumb, but networkx outputs as ascii so we may as well encode the ints
            # in a nice way


            # DEBUG
            global last_flipped
            if last_flipped is not None and last_flipped != node_name:
                print(f"AFTER FLIP went from {last_flipped} to {node_name}")
                if last_flipped == node_name:
                    print("SELF LINK - bail")
                    panda.end_analysis()
                    return
                if last_flipped in graph.nodes:
                    prior_node = graph.nodes[last_flipped]
                    print("\tPreviously know outputs were:", [x for x in graph.neighbors(last_flipped)])
                last_flipped = None



            if last_pc is not None:
                if node_name not in graph.nodes:
                    if run_idx > 1:
                        print(f"ADDED NEW NODE {node_name}")
                    graph.add_node(node_name, size=tb.size, run_idx=run_idx, is_branch=False)
                if not graph.has_edge(last_pc, node_name):
                    #print(f"ADDED NEW EDGE {last_pc}-{node_name}")
                    graph.add_edge(last_pc, node_name, run_idx=run_idx)
            else:
                # Very first node, add it as a non-branching node
                graph.add_node(node_name, size=tb.size, run_idx=run_idx, is_branch=False)
            last_pc = node_name


    @panda.queue_blocking
    def driver():
        global cur_flip_chain, enabled, run_idx
        panda.revert_sync("root")

        while run_idx == 0 or len(flip_chain) and run_idx < CUTOFF: # XXX DEBUG < 10
            run_idx += 1
            print(f"Start run #{run_idx} with flip chain: {cur_flip_chain}")

            print("Guest outputs:", repr(panda.run_serial_cmd("grep root /etc/passwd")))
            enabled=False
            panda.flush_tb() # flush the IR cache... soon
            from time import sleep
            sleep(1) # Hope it clears...

            # Search the whole graph for half covered branches. Anything we've previously
            # seen will be a duplicate and subsequently ignored
            half_covered_branches = [x for x,y in graph.nodes(data=True) \
                                     if y['is_branch']==True and graph.out_degree(x) < 2]

            print(f"After run {run_idx} we have {len(half_covered_branches)} branches yet to explore\n")
            for b in half_covered_branches:
                if b not in queued_to_flip:
                    queued_to_flip.add(b)
                    flip_chain.append(cur_flip_chain + [b])

            if not len(flip_chain):
                print("Nothing left to explore - break")
                break

            cur_flip_chain = flip_chain.pop()
        # / loop
        panda.end_analysis()

    # /driver

    panda.disable_tb_chaining()
    panda.run()

print(f"Writing graph to out.graphml with data from {run_idx} runs")
nx.write_graphml(graph, "out.graphml")

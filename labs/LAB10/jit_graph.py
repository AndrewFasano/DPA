import networkx as nx
from pandare import Panda

panda = Panda(generic="arm")
enabled = False
last_pc = None
run_idx = 0
last_pc = None
last_flipped = None


graph = nx.DiGraph()

# Configuration options:

CUTOFF=100
# Simple test, target grep:
#DO_COPY_TEST = False # Should we copy ./test into the guest?
#TARGET = "grep"
#CMD = "grep root /etc/passwd"

# Advanced test, target binary from host:
DO_COPY_TEST = True # Should we copy ./test into the guest?
TARGET = "a.out"
CMD = "./test/a.out"

# end of config options

cur_flip_chain = [] # List of branches to flip
flip_chain = [] # List of lists
queued_to_flip = set()

# We have *TWO* versions of the same loop
# The outer restarts panda while the inner reruns the program.
# We try for the inner loop when we can, but we'll hit the outer loop 
# a bunch too.

while run_idx == 0 or len(flip_chain) and run_idx < CUTOFF:
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
            # We'll get the opportunity to flip a branch *before* it's run
            # but we want to see what actually happens, then make flip choices
            # on the next run
            return False
        else:
            graph.nodes[node_name]['is_branch'] = True

        import random
        # Check 1: Is the current node half covered?
        if graph.out_degree(node_name) == 0:
            # Node is uncovered, let's not mess with it until we get to it
            return False
        elif graph.out_degree(node_name) == 1:
            print(f"Half covered node at {node_name} - flip")

            if random.choice([0, 1]):
                #last_flipped = node_name
                return True
            return False

        else:
            # Check: From the current node, are there any half covered branches
            # If so, let's head towards those!
            desc = nx.descendants(graph, node_name)
            half_covered_branches = [x for x in desc if graph.nodes[x]['is_branch']==True \
                                        and graph.out_degree(x) < 2]

            if len(half_covered_branches):
                print(f"Half covered child. At {node_name}, half children are {half_covered_branches}")
                if random.choice([0, 1]):
                    #last_flipped = node_name
                    return True
                return False

            # Randomly flip in target
            #return random.choice([0, 0, 1])
        return False

    @panda.cb_start_block_exec
    def bb(cpu, tb):
        '''
        Before block runs, check current process - if it's our target, set enabled=True
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
            '''
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
            '''



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
        if DO_COPY_TEST:
            panda.copy_to_guest("test")

        while run_idx < CUTOFF:
            run_idx += 1
            print(f"Start run #{run_idx} with flip chain: {cur_flip_chain}")
            try:
                print("Guest outputs:", repr(panda.run_serial_cmd(CMD)))
            except Exception as e:
                print("Guest output timed out:", e)
                pass
            enabled=False
            panda.flush_tb() # flush the IR cache... soon
        # / loop
        panda.end_analysis()

    # /driver

    panda.disable_tb_chaining()
    panda.run()
    print("After outer panda.run")

print(f"Writing graph to out.graphml with data from {run_idx} runs")
nx.write_graphml(graph, "out.graphml")

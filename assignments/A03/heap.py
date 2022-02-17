#!/usr/bin/env python3

from pandare import Panda
import matplotlib.pyplot as plt

panda = Panda(generic="x86_64")

active_allocs    = {} # [(asid, heap_addr): (size, proc_name), ...]
recorded_results = [] # List of summarized active allocation info, updated whenever allocs is changed

def log_current_allocation_stats():
    '''
    Examine the state of active_allocs and create an entry summarizing it which
    we add to the end of recorded_results. You do not need to modify this function.
    '''
    global recorded_results

    # First examine the allocations of each process and store it along with the process'
    # name in active_sizes.
    active_sizes  = {} # e.g., asid 0x1234: {name: 'foo', total_size: X, total_allocs: Y}
    for ((asid, addr), (size, name)) in active_allocs.items():
        if asid not in active_sizes:
            # First entry for this process set name and initialize counters to 0
            active_sizes[asid] = {'name': name, 'total_size': 0, 'total_allocs': 0}

        # Update counters
        active_sizes[asid]['total_size'  ] += size
        active_sizes[asid]['total_allocs'] += 1

    # Now combine the details for all known processes into a single entry and add
    # to recorded_results
    this_result = {}
    for asid, details in active_sizes.items():
        this_result[asid] = details
    recorded_results.append(this_result)

@panda.hook_symbol("libc-", "free")
def free_enter(cpu, tb, hook):
    '''
    We're entering a function named free in a library with a name that matches "libc-"
    '''

    # TODO: Determine the current asid and address being freed
    asid = 0
    arg = 0

    print(f"free {arg:x} in {asid:x}")

    # Remove the (asid, arg) entry from active_allocs - on occasion it won't be there.
    # That's okay - just log when it happens.

    # Remove it from the list of active allocations, if we knew about it
    if (asid, arg) not in active_allocs:
        print(f"Warning: freeing {arg:x} which we didn't see get allocated in {asid:x}")
        return

    del active_allocs[(asid, arg)]

    # Finally log the now-updated heap info
    log_current_allocation_stats()


@panda.hook_symbol("libc-", "malloc")
def malloc_enter(cpu, tb, hook):
    '''
    We're entering a function named malloc in a library with a name that matches "libc-".
    We want to record the address returned by malloc, but that's not yet available.
    So let's calculate where malloc will return to after it finishes and set up a hook
    which will run exactly once when we next hit that address in the current ASID.
    We can get that information from the top of the stack by reading an integer
    out of memory at the address pointed to by RSP
    '''

    # TODO: Set up these variables
    current_asid = None # ASID for current process
    proc_name = "TODO" # Current process name
    allocation_size = 0 # Argument passed to malloc. Available in a register or via panda.arch.get_arg
    # Read the contents from the register "rsp" using the panda.arch class
    reg_rsp = None
    # Then read an integer out of memory from that address - the size of the read should be 8 bytes
    # and the format should be specified as the string "int"
    ret_addr = 0

    # Register a hook which will run when malloc returns
    @panda.hook(ret_addr, asid=current_asid)
    def on_malloc_return(cpu, tb, h):

        # TODO: Read the value malloc returns. Available in a register or via panda.arch
        return_value = 0

        # TODO: disable this hook so it only runs once for each malloc call
        #h.enabled = 

        print(f"Process {asid:x} ({proc_name}) allocated {allocation_size} bytes at {return_value:x}")

        global active_allocs
        # TODO: update active_allocs to store information about this allocation
        active_allocs[(0, 0)] = (0, 0)

        # Finally log the now-updated heap info
        log_current_allocation_stats()

@panda.queue_blocking
def drive_guest():
  '''
  Revert to root snapshot, enable analyses and  run a few programs.
  Do not modify this function unless you want add additional commands
  '''
  panda.revert_sync("root")
  print("Guest output:\n" + "="*60)
  print(panda.run_serial_cmd("python3 -c 'print(1)'", timeout=100))

  # TODO: Compile proc.c as `prog` on your host machine in a folder.
  # Then copy that folder into the guest with panda.copy_to_guest()
  # and run the program
  # panda.copy_to_guest(...)

  print(panda.run_serial_cmd("./some_directory_name/prog"))

  print("="*60)
  panda.run_serial_cmd("sleep 10s")
  panda.end_analysis()

panda.run()

########################## VISUALIZATION CODE BELOW HERE ####################################cA
# You shouldn't change anything below here
for (figname, prop_name) in [('Heap Chunks Allocated', 'total_allocs'), ('Heap Bytes Allocated', 'total_size')]:
  user_sizes = {} # asid: [ allocations_at_0, ... allocations_at_N ]
  asid_names = {} # asid: name

  # First go through all timestamps and grab all asids observed, make a list of 0s for each at each timestamp
  if not len(recorded_results):
      raise ValueError("No items in recorded_results list")

  # ts stands for timestamp here which (inaccurately) means the index into the list of recorded results
  for ts_details in recorded_results:
    for asid, asid_details in ts_details.items():
      if asid not in user_sizes.keys():
        user_sizes[asid] = [0]*len(recorded_results)
        asid_names[asid] = asid_details['name']


  # At each time stamp, append num active allocations for the asid
  for ts, ts_details in enumerate(recorded_results):
    for asid, asid_details in ts_details.items():
      user_sizes[asid][ts] = asid_details[prop_name]

  fig = plt.gcf()
  fig.set_size_inches(9, 5)

  # Plot each result
  for asid in user_sizes:
    if asid in asid_names:   label = asid_names[asid]
    else:                    label = hex(asid)
    plt.plot([x for x in range(len(recorded_results))], user_sizes[asid], label=label)

  plt.title(f'Total {figname} per Process')
  plt.xlabel('Number of Allocation')
  plt.ylabel(figname)
  lgd = plt.legend(bbox_to_anchor=(1.01, 1), loc='upper left', fontsize='small')

  plt.savefig(prop_name+".png", bbox_inches='tight')
  plt.clf()

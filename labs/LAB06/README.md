Custom Plugins
===

# Part 0: Order of operations.
This lab has two parts, the first is using PANDA and the second will use QEMU. 

Before you start Part 1, pull the [dpa-containers](https://github.com/AndrewFasano/DPA-containers) repo and begin building the `qemu` container.
Let this run while you you complete the first part so you don't have to wait before starting Part 2.

# Part 1: Tainted Syscall Logger with PyPANDA.

In general, data provided by users should not be directly passed into system calls.
If a malicious user can control a command that is executed or the path of a file that is to be read/write/deleted/etc., it may be a security vulnerability.

PANDA's taint system can track how data provided by a user flow through a system.

For this part of the lab, you will build two [PANDA PyPlugins](https://github.com/panda-re/panda/blob/dev/panda/docs/pyplugins.md)
to taint program arguments and to see if those arguments end up getting passed to any syscalls.

## Task 1: Build a test
You should first collect a recording of a guest which executes this sort of vulnerability.

Compile some C code where user input is passed to a syscall that
shouldn't be operating on untrusted data such as the path to a binary being started with `execve` or a filename passed to `open`.

You may use this trivial example based on the `execve` man page or create your own:

```
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
   char *newenviron[] = { NULL };
   execve(argv[1], &argv[1], newenviron);
}
```

Compile this program on your container, and place it in a directory.

Next write a simple PyPANDA script which does the following:

1) Start the generic `x86_64` image and load the root snapshot
2) Copy the directory you just created into the guest
3) Create a PANDA recording of running the binary with a unique string as the first argument, try `/bin/echo` if you're struck.

Note 1: [panda.copy_to_guest](https://docs.panda.re/#pandare.Panda.copy_to_guest) requires the ability to write a file on disk
in your current directory so be sure you don't run your script from a path like `/`.

Note 2: [panda.record_cmd](https://docs.panda.re/#pandare.Panda.record_cmd) function can be configured
to automate some of these steps for you.

**Check in 1**: Show off the results of replaying your recording with the asidstory plugin. Do you see what you'd expect?

## Task 2: Build a PyPlugin to log syscall arguments

In a new python file, create a [PyPlugin](https://github.com/panda-re/panda/blob/dev/panda/docs/pyplugins.md) that
logs the syscall number plus the first 4 arguments whenever a syscall is issued.
Note that not all syscalls take 4 arguments, so this approach could generate some false positives.

For each syscall, your plugin should print a line like "Syscall #X with arguments: 0xAAAA, 0xBBBB, 0xCCCC, 0xDDDD" 

You can start from the following code, perhaps call it "taintedsyscalls.py"

```
from pandare import PyPlugin

class TaintedSyscallMonitor(PyPlugin):
  def __init__(self, panda):

	# TODO: Register a PPP style callback with syscalls2 on every syscall.
	# For now just print the first 4 arguments as integers
	  

if __name__ == '__main__':
  # If this script is run directly, do a small test
  # of a live system.

  from pandare import Panda
  panda = Panda(generic="x86_64")

  panda.pyplugins.load(TaintedSyscallMonitor)

  @panda.queue_blocking
  def driver():
    panda.revert_sync("root")
    print(panda.run_serial_cmd("whoami"))
    panda.end_analysis()
  
  panda.run()
```

Create a second script, `analysis.py`, to test your PyPlugin. Start with the following:

```
from pandare import Panda
panda = Panda(generic="x86_64")

# import your pyplugin class then load it using a method in panda.pyplugins.

# Run the replay, with your plugin loaded
panda.run_replay("yourreplay")
```

Running `analysis.py` should print out syscall numbers and arguments.

**Check-in 2**: Show off your script and its output.


## Task 2: Add taint labels

Create a second pyplugin in your `taintedsyscalls.py` file or in a new file.
This plugin will use the [proc_start_linux](https://github.com/panda-re/panda/tree/dev/panda/plugins/proc_start_linux) plugin
to examine and taint the arguments passed into processes as they start.

Once your plugin has been set up, you can register the necessary callback and print the relevant information by running
this code in the right place in your new class.

```
  @panda.ppp("proc_start_linux", "on_rec_auxv")
  def proc_starts(cpu, tb, auxv):
    procname = panda.ffi.string(auxv.argv[0]).decode()
  
    for x in range(1, auxv.argc):
      data = auxv.argv[x]
      s = panda.ffi.string(data)
      ptr = auxv.arg_ptr[x]
      print(f"{procname} arg {x} is {s} at {ptr:x}. Tainting")
```

After the print, add code to apply a taint label (can be a constant integer value or you can do something more complex)
to each character in the argument. You will do this by iterating over the virtual addresses between `ptr` and `ptr+len(s)`,
converting each to a physical address using [panda.virt_to_phys](https://docs.panda.re/#pandare.Panda.virt_to_phys),
and applying a taint label with [panda.taing_label_ram](https://docs.panda.re/#pandare.Panda.taint_label_ram).

Note that virt_to_phys will return 2^64-1 (-1 cast to an unsigned value of guest pointer size),
if it is unable to map the input to a physical address.
Your code will encounter this frequently as many syscall arguments aren't pointers.
Be sure not to apply taint labels in this case.

## Task 3: Query taint at syscalls

Modify your first PyPlugin (TaintedSyscallMonitor) to check if arguments to syscalls are pointers to tainted data.

Again, you will use `panda.virt_to_phys` to try converting virtual addresses to physical addresses.
If they can be converted, use the following functions with the physical address:

1) `panda.taint_check_ram(paddr)`: returns true if a physical address is tainted.
2) `panda.taint_get_ram(paddr)`: returns a TaintQuery object with taint information if paddr is tainted. Should not be called if paddr is untainted.
3) `get_labels()`: method of TaintQuery objects to return a list of taint labels

If an argument is tainted, print a message and the labels returned calling `tq.get_labels()` on your taint query object (assuming it's the variable `tq`).

This script will take about five minutes to run.
If you want to check for simple errors before you start it, you can run `pylint -E yourscript.py` (ignore the import errors).

**Check-in 3**: Demonstrate your working code and result.

While you wait for the script to run, you could start on Part 2.

# Part 2: Custom QEMU Plugins

## Setup
Pull the `dpa-containers` repo and build the qemu container.

Run the qemu container such that your previously-downloaded panda generic x86_64 image is accessible in the guest.

```
user@host:~$ docker run --rm -it -v $(pwd):/host qemu
```

Change into the directory `/qemu/build/contrib/plugins` and run `make` to compile the plugins in `/qemu/contrib/plugins/`.

To test that everything is configured correctly, try to load the libbb.so plugin you just built with the panda generic image you have on your host:
```
/qemu/build/x86_64-softmmu/qemu-system-x86_64 -d plugin -plugin ./libhowvec.so /host/bionic-server-cloudimg-amd64-noaslr-nokaslr.qcow2 -nographic
```

After a few seconds, press ctrl-A + c to switch to the qemu monitor, then type quit. On exit, you should see a log summarizing the instructions run.
If this works, you're now set up to build your own custom QEMU plugins!

## Background
The QEMU plugin `howvec` measures how vectorized the instructions executed by the guest are.
In other words, it looks at each instruction executed, determines if it is or isn't vectorized and then reports some statistics.

We are going to abuse this plugin to report some general statistics about the instructions executed by an `x86_64` guest. In particular, we are going to log the number of `call` instructions, `jmp` instructions, and other instructions.

## Task 1: Expand the howvec plugin to count jumps in `x86_64` guests

Edit the file `/qemu/contrib/plugins/howvec.c`.
To begin update the `class_tables` variable to include a mapping for `x86_64` and create a new InsnClassExecCount array for it. To start it should just look like the `default_insn_classes`.

Rebuild the plugin by running `make` in `/qemu/build/contrib/plugins` again and rerun the guest with the plugin loaded as shown above. Again, quit the guest after a few seconds. 

Examine the commands which were executed, look through them to see `jmp` commands. You can compare the listed opcodes for each of the jumps or look it up online, but all the `jmp` instructions have a specific byte set to a specific value to indicate what type of instruction they are. 

Once you've identified this byte, add a new row to your InsnClassExecCount array which looks something like

```
{ "Jump",                "jmp",    0x00000000, 0x00000000, COUNT_CLASS},
```

Examine the definition of InsnClassExecCount to determine what the two zero values are. Set them appropriately
such that the opcode will be masked to select the relevant byte and then compared against the value which indicates
it is a jmp instruction.

Re `make` the plugin and run again. You should now see output summarizing the total number of jumps run:

```
Instruction Classes:
Class: Jump                     (6234444 hits)
Class: Unclassified             counted individually
...
```

## Task 2: Expand the `howvec` plugin to count another type of instruction for `x86_64`

Select another instruction type type that is printed such as calls, comparisons, or xors, and add support for it by modifying your InsnClassExecCount array.
Look up the instruction online and see if there are multiple versions of it (e.g., `xor{b,w,l}`), you should support at least 2 versions.

Rebuild the plugin and test your changes. You should now see a third `Instruction Class` listed at the top and a number of instructions it ran.

**Check-in 3**: Show off your code and results from running your modified plugin.



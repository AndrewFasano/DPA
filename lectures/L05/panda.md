% CS4910: Whole system dynamic analysis with PANDA
% Andrew Fasano
% Feb 15, 2022

# The value of emulation and virtualization

## Overview
Emulation and virtualization are techniques which enable
a *host machine* to run one or more *guest systems* within it.

* Guest systems are isolated from one another and the host.
* Guest systems can run different OSes and (if emulated) architectures.
* The state of a guest system can be saved and restored.

## Whole-System Dynamic Program Analysis

Programs do not run in isolation. They can:

* Launch or interact with other programs
* Interact with the kernel
* Load kernel modules

Analyses based on individual programs can't track state between them.
An analyst may not know which process(es) are of interest in a system:

* Binaries may have been modified to add malicious behavior
* Rootkits may be running
* Complex interprocess interactions, possibly including kernel modules

## Emulation vs Virtualization

*Emulation*:

* Model guest system in software accurately enough for it to be used
* Virtual CPU registers, RAM, and peripherals
* Read instruction at virtual PC, execute code to update virtual state according to it
* Slower than native system
* Guest system state can be easily observed and modified

*Virtualization* (implemented with a *hypervisor*):

* Run guest system directly on host hardware
* Use hardware features to isolate guest from host
* Nearly as fast as native system

## Honorable mention: Simulation

*Simulation*:

* Accurately model internal behavior of target system hardware
* Very slow
* Typically used to test and debug hardware designs, not the software that runs on top of it


## FOSS Emulators and Hypervisors:

*QEMU*

* First version by Fabrice Bellard published in 2005
* System- and user-level emulation for 20+ architectures
* Virtualization with KVM or Xen for x86

*Virtualbox*

* Released by Innotek in 2007. Now owned by Oracle
* Hypervisor for x86

*Bochs*

* Released in 1994 by Kevin Lawton for $25, bought in 2000 by Mandriva and released under LGPL
* x86 emulator


# How does emulation work?

## High-level view

The key components of an emulator are:

* Virtual peripherals
* Machine configurations
* CPU emulation


## Virtual peripherals

Hardware peripherals need to interact with a CPU.
Peripherals may be "on-chip" such as a timer or "off-chip"
like a display or USB keyboard.

These interactions occur via:

* *Interrupts*: Peripheral tells the CPU something has happened
* *Memory mapped IO (MMIO)*: Reads and writes of specified addresses go to peripheral instead of RAM

You might say *physical memory (RAM)* is a peripheral too.
 It's just an array that the guest can read or write into.


## Machine configuration

Different types of **machines** are **configured** differently

Example QEMU *machines*: `i386`, `x86_64`, `raspi2`, `versatilepb`

Configurations for a machine specify:

* Architecture and byte order
* Initial program counter and register state
* Peripherals and memory mappings

Configuration is standard across x86 systems, but typically varies with embedded systems (e.g., ARM Raspberry Pi vs ARM RealView).

## CPU Emulation

When a guest first starts, the virtual CPU will be configured according to the machine type.
The first instruction is fetched from the **reset vector**, on x86\_64 this is 0xF000FFF0.

If RAM contains `48 83 C0 01` at this address what should the emulator do?

. . .

This decompiles to `add rax, 1`

Any guesses now?

. . .

```
virtual_rax += 0x1
```

## CPU Emulation: It's not so simple

Most instructions have *side effects* and can raise *exceptions*.

According to the Intel manual for x86\footnote{Relevant data available at https://www.felixcloutier.com/x86/add},
the `add` command will update CPU flags: `OF`, `SF`, `ZF`, `AF`, `CF` and `PF`.

It may also raise one of ~18 different exceptions depending on the arguments
and state of the CPU when the instruction is run.
However these are all related to add instructions using memory as sources or destinations
so they don't need to be handled here.

## CPU Emulation: Interrupts

If a peripheral raises an interrupt, the CPU should (generally) handle that interrupt in some way.
The guest configures the CPU to store various interrupt handlers which are functions that run in response
to specific interrupts.

Not all interrupts will actually interrupt what the CPU was previously doing. If the CPU is processing
a more important interrupt, it won't stop to handle another.


## CPU Emulation: Bringing it all together

To emulate a CPU's behavior, an emulator will (at a high level):

* Initialize the state of a modeled CPU according to the specified machine model
* Read the machine code at the current instruction pointer
* Execute that instruction, updating the CPU state (registers, instruction pointer) and memory as necessary
* Read the next instruction


## QEMU's Design

The first time a basic block of guest code is encountered, QEMU:

1) Translates guest machine code into micro operations in TCG ("Tiny Code Generator") which is an IR
2) Optimizes the TCG IR for the block
3) Lowers the IR to host machine code which updates the virtual CPU state as necessary
4) Caches the translated block (TB)

QEMU handles exceptions and interrupts that occur in the middle of a basic block
using the C setjmp and longjmp functions to save and restore state.

# PANDA

## PANDA: Platform for Architecture-Neutral, Dynamic Analysis
Emulator designed for whole system dynamic program analysis

* Forked from QEMU
* Open source: [github/panda-re/panda](https://github.com/panda-re/panda)
* Provides API plus callbacks for 40+ events which analyses can use
* Plugin and scripting interfaces for analyses
* Record and replay
* Taint system
* LLVM IR

Developed by MIT Lincoln Laboratory, and New York University. Now maintained by MIT LL

## PANDA emulation core

The core emulation code in PANDA is just QEMU!

* Virtual machine images are typically stored as QCOW files.
* Supports QEMU machine configurations, peripherals, and (most) command line flags
* Supports `i386`, `x86_64`, `MIPS` (big and little endian), `PPC`, `ARM` and `AArch64`

Example: emulate an `x86_64` guest with a serial console on the command line, 1GB ram and load a snapshot named root:

```
# panda-system-x86_64 ubuntu2004.qcow -nographic -m 1G \
    -loadvm root
```

## PANDA API:

PANDA's API is small. The guts of it are:

* Load and unload PANDA plugins
* Register a function to run on a given callback
* Get current program counter
* Get current ASID (process identifier for x86)
* Read and write guest virtual or physical memory

Documented in PANDA's [manual.md](https://github.com/panda-re/panda/blob/dev/panda/docs/manual.md#useful-panda-functions)

## PANDA callback model

An analysis can provide a function to be run whenever the emulator does/observes/returns from a set of operations including:

* Block translation
* Block execution
* Instruction execution
* Physical or virtual memory read or write
* Snapshot load
* Exception
* Process change\*

## The power of callbacks: an example

PANDA's before block execute callback provides:

* CPUState: the virtual CPU for the current architecture which can be read or modified
* TranslationBlock: the details of the block about to be executed such as its address and number of instructions

If we register a function to run on this event, how could we then collect the set of basic blocks run by a system?

. . .

```
blocks = set()
# TODO: register this to run with PANDA before every block
def my_before_block_exec(cpustate, transblock):
    blocks.add(transblock.pc)
```


## PANDA analyses and plugins
One-off PANDA analyses can be written in Rust or Python.
Reusable **plugins** can be written in C, C++, Rust or Python.

Plugins are composable: they can provide additional callbacks and APIs which other plugins can use.

Core Plugins:

* Operating System Introspection (OSI)
* Hooks
* Syscalls2
* Taint2

## PyPANDA scripting

Python interface to control *and* analyze a guest system.

Control a guest:

* Specify the guest system, possibly using a **generic** image which will be downloaded automatically
* Load a snapshot
* Type commands into the guest console
* Read output from commands

Analysis:

* Register PANDA callbacks
* Load and interact with plugins

## PyPANDA: Demo

Let's build a script to:

1) Run a guest of some architecture - which one?
2) Run a command inside the guest - what command?
3) Log some information for the first few basic blocks - what information?
4) Print the output of the command

## Potential Demo Implementation

```
from pandare import Panda
panda = Panda(generic="x86_64")

@panda.cb_before_block_exec
def before_block(cpu, tb):
  print(panda.arch.dump_state(cpu))
  panda.disable_callback("before_block")

@panda.queue_blocking
def driver():
  panda.revert_sync("root")
  print(panda.run_serial_cmd("whoami"))
  panda.end_analysis()

panda.run()
```


## PANDA Plugins: Operating System Introspection

Question: How can an emulator tell you the current process name?

. . .

Answer 1: in general, it can't. An emulator manages registers, not high-level concepts like processes

. . . 

Answer 2: If it knows how the guest kernel is configured, it can read the relevant structures out of memory.

* For example: find the current *task_struct* object, read the `comm` field, read memory at the address it points to.
* This requires a profile for the guest system which stores information about structure sizes and offsets.

## PyPANDA: Basic OSI usage:

Easy version using a helper function:
```
name = panda.get_process_name(cpu)
```

Hard version directly interacting with a C plugin, checking for a NULL return and converting to a Python string:
```
proc = panda.plugins['osi'].get_current_process(cpu)
if proc == self.ffi.NULL or proc.name == self.ffi.NULL:
    name = ""
else:
    name = panda.ffi.string(proc.name).decode()
```

## PANDA Plugins: Hooks

Plugin to provide call user-provided functions just before the guest runs code at a specified address.

Example: whenever any process is about to execute
code at address 0x1234, call `my_function` first.

```
@panda.hook(0x1234)
def my_function(cpu, tb, hook):
    print("Guest is about to run 0x1234")
    hook.enabled = False # Now this function will never be run again
```

## PyPANDA: Syscalls2

Plugin which analyzes guest code to provide a callback whenever a system call (syscall) is about to run or has just returned.

For example, the open syscall takes two arguments, a string pathname and an int flags. See `man 2 open` for more details.

```
@panda.ppp("syscalls2", "on_sys_open_enter")
def before_open(cpu, pc, pathname_ptr, flags):
    pathname = panda.virtual_memory_read(cpu, pathname_ptr, fmt="str")
    print(f"Guest is opening {pathname} with flags {flags:x}")
```

## System-wide Analysis challenges 

* Processes can change unexpectedly
* Significant slowdown will affect guest behavior


## PANDA topics for next week:
* Record and replay
* Taint analysis


## PANDA Resources:
Pre-built "generic" QCOW images for various architectures and OSes with OSI profiles

* [panda.re/qcows](https://panda.re/qcows)
* Automatically downloaded on demand when using PyPANDA

Documentation:

* [blog](https://panda.re/blog/)
* [docs.panda.re](https://docs.panda.re)
* [manual](https://github.com/panda-re/panda/blob/dev/panda/docs/manual.md)

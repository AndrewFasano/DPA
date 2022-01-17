% CS4910: System Security with Dynamic Program Analysis
% Andrew Fasano
% Jan 18, 2022

# Course Overview

## What is this class?
This is an **experiential, survey course** designed to rapidly introduce you to a variety of dynamic program analysis technologies frequently used for:

* error detection
* software hardening
* performance testing, and
* improving developer comprehension of software
You will learn the theory behind powerful dynamic program analysis techniques and how to apply these analyses using open-source dynamic analysis platforms.

## Course goals
By the end of the semester you should be able to:

1) Explain common dynamic program analysis techniques, the results each can produce, and the theory behind each.
2) Identify situations in which dynamic program analysis techniques can assist with the process of software development, software testing, and reverse engineering.
3) Leverage dynamic program analysis techniques to improve their ability to design, debug, reverse engineer, or exploit software programs.
4) Discover novel vulnerabilities in compiled applications.

## Who am I?
* Technical Staff at MIT Lincoln Laboratory
* Projects: DEF CON CTF, McAfee CVEs, PANDA.re
* RPISEC alum
* PhD Candidate at Northeastern
    * Advised by Prof. Wil Robertson

Research focused on *rehosting* firmware into virtual execution environments so we can leverage dynamic program analysis to conduct security analyses of embedded systems.

## Who are you?
* Name
* What year are you?
* Last Co-op?
* Favorite programming language and/or text editor?

# Class Logistics

## General Overview
* Full syllabus available on Canvas

* Always bring a laptop to subsequent classes
    * Recommended: Ubuntu 20.04+ with root access
    * Minimum: a way to run containers
    * Consider: SSH (login.ccs.neu.edu), virtual machines, WSL

    * Windows: Install Ubuntu with [WSL2](https://docs.microsoft.com/en-us/windows/wsl/install) and
     [Docker for WSL2](https://docs.docker.com/desktop/windows/wsl/)
    * OSX: Install [Docker for Mac](https://docs.docker.com/desktop/mac/install/).

* Slides, assignments, labs, and grades will be released through Canvas throughout the semester.

## Schedule

### Tuesdays: 11:45-1:25
* Lecture
* Assignments released every other week
* Assignments due at start of class

### Thursdays: 1:30-2:30
* Office hours before class - Location TBD

### Thursdays: 2:50-4:30
* Hands-on labs

## Labs
* 12 hands-on lab exercises to be done\footnote{Occasionally a lab may require some simple pre-class setup (e.g., download a big file). If this happens, it will be announced in advance.} in Thursday class.

* Bring a computer to labs

* Each lab will challenge you to accomplish a set of goals using dynamic analysis
    * Interactive sessions - feel free to ask questions
    * When you finish the tasks (or run out of time), show off your solutions to get full or partial credit.
     Feel free to leave early if you finish with time remaining

* Mandatory attendance, but lowest lab grade will be dropped

## Assignments
Five assignments throughout the semester. Typically released at end of class on Tuesday and due 2 weeks later

* A01: Instruction tracing
* A02: Side channel coverage maximization
* A03: Taint analysis
* A04: Binary performance optimization (due on Thursday, March 17)
* A05: Root cause analysis with timeless debugging

## Final Project
For the final 3 weeks of the course, you will work on open-ended final projects in pairs.
During this time, no other projects will be assigned, though lectures and lab exercises will continue as normal.

* Project proposal
* Initial research
* Check-in meeting
* Final report & presentation

## Grading
- Labs: 30%
- Assignments 50%
- Final Project 20%

## Class Policies
See syllabus for full details:

* Collaboration: Labs vs Assignments
* Attendance: Labs and Lectures
* COVID & Zoom
* Late policy
* Responsible vulnerability disclosure
* Plagiarism

## Questions
Is anything unclear about how the class will run?

# Debuggers

## Debugging intro
Hopefully you've been using debuggers for a while by now!

How would you describe a debugger?

. . .

* A tool to help you analyze or modify the state of a running application

. . .

What do your favorite debuggers let you do?

. . . 

* Symbol resolution: variables & functions
* Set breakpoints, stop when they're hit
* Read & write memory and registers

## Classes of debuggers
There are different types of debuggers for different tasks.

* Debuggers for compiled binaries:
    * GDB: The `GNU DeBugger`. Linux, command line [*our focus*]
    * WinDBG: Windows debugger
        * Officially pronounced `win-d-b-g`, unofficially `wind-bag`

* Debuggers for interpreted languages:
    * Python: pdb / ipdb
    * JavaScript: DevTools in browser

* Hardware debuggers:
    * JTAG
    * Arm DSTREAM

## Debugging strategies for compiled binaries:
1. Just read the source

2. Add some unique prints, maybe variable values

    ```c
    printf("HIT %s:%d\n", __FILE__, __LINE__);
    ```

3. Starting with or attaching a debugger

    ```sh
    gdb ./a.out  OR   gdb --pid $(pgrep a.out)
    ```

4. Scripting the debugger

    ```sh
    gdb -ex 'break f' -ex 'bt' -ex 'r' ./a.out
    ```

5. Time-travel debugging

## General debugger capabilities

1. Read and write CPU registers
2. Read and write virtual memory within the debugged application
3. Set breakpoints on addresses (and sometimes symbols)
4. Single-step target program
5. Potentially: map symbols to memory locations and registers

## Debugger advantages
1. Reliably view the actual system's state (unlike reading source)
2. Interactively explore program state (unlike "printf debugging")
3. Can be scripted to conditionally log/modify state or to drop into an interactive shell

## Debugger Challenges
1. Compiler optimizations
2. Missing debug information

# Debugger Internals

## Tracing the target
Debugger asks kernel to let it trace another another process with **ptrace** system call.

* New process: fork, child sends "traceme" request, child execs target program.
* Existing process: provide PID. Target must be owned by same user or caller must be root.

Whenever a traced process receives a signal:

* Tracee is paused
* Tracer is notified (via waitpid)

Exception: SIGKILL just terminates the tracee.

## Managing the paused target

When a traced process is paused, the tracer can:

* Read/write memory and registers via ptrace syscalls
* Insert breakpoints or single-step tracee
* Resume tracee (and optionally drop the current signal)
* Detach from the tracee and resume it

## Common ptrace requests:
* `PTRACE_TRACEME`: Set the parent of this process up to trace it
* `PTRACE_PEEKDATA`: Read a word out of tracee memory
* `PTRACE_POKEDATA`: Write a word into tracee memory
* `PTRACE_O_TRACEEXEC`: Stop the tracee when it next execs
* `PTRACE_CONT`: Resume the tracee, optionally deliver a signal
* `PTRACE_SINGLESTEP`: Resume the tracee for a single instruction

## Adding Breakpoints
Breakpoints are not part of the ptrace API. How could a debugger build this?

. . .

1) Read instruction at target address, save it
2) Write an architecture-specific "trap-to-debugger" instruction (e.g., `int3`)
3) When tracee executes this instruction, a signal will be raised and the tracer
will regain control

[/a]: int 3 is 0xCC but other ints are 0xCD 0xINTNO - need single-byte instruction for 
[/b]: x86 to ensure we can break on single-byte instructions without side effects
[/c]: e.g., if we had a one byte insn followed by a jmp destination we couldn't
[/d]: handle the case where the tracee jumps straight there


## Breakpoint cleanup
How can the debugger let the tracee run the original instruction
but keep the breakpoint for subsequent executions?

. . .

1) Restore original instruction in tracee memory
2) Decrement program counter
3) Single step tracee
4) Add breakpoint back
5) Resume


## Usable Debuggers
Users want to reference variables and types instead of looking at raw memory.
Debuggers can support this if debug info is available.

Formats:

* Linux: **DWARF** (Debugging With Arbitrary Record Formats)
* Mac: **dSYM** (Debug Symbols)
* Windows: **PDB** (Program DataBase)

Common features useful for debuggers:

* Map symbols (functions and variables) to source locations and memory addresses
* Describe variable types (structure layouts)

## DWARF Info

View dwarf info with `objdump --dwarf=info a.out`

**Demo**

# Advanced GDB

## GDB: GNU DeBugger

* Available from your package manager
* Command-line interfaces
* Uses PTRACE to interact with debuggee

Startup:
* Launch binary: `gdb ./a.out`
* Binary with arguments: `gdb --args ./a.out 1 2 3`
* Attach to running process: `gdb --pid 123`
* Attach to running process: `gdb --pid $(pgrep a.out)`

## Shell
Interactive prompt available when debugger starts or when debuggee gets signaled
```
(gdb) 
```

Access registers via variables prefixed with `$`, e.g., `$rax`.
Each result is saved in `$X` where X is an increasing identifier:
```
(gdb) p $rax
$1 = 1234
(gdb) p $1
$2 = 1234
````

## Inspect state
`info registers` (or `i r`) to print register state

`x` to e*x*amine memory, supports format specifiers:
* `x/10i $pc`: print 10 instructions at program counter
* x/w $sp`: print a word at the stack pointer

`print` or `p` to view a value:
* `p $sp`

GDB understands base types and (when debug info available) custom types:
* `x/10x (*(unsigned int*)($sp+8))`
* `p *addr.__sockaddr__.sa_family`

## Breakpoints
Breakpoints: `break [location]` 

Conditionally: `break [location] if condition`

Continue from a breakpoint with `continue` or `c X` where X is the number of times to continue

Alternatively: `watch` to stop whenever an expression changes
* `watch $rax`
* `watch myvar.some_field`

## Symbol Resolution
`load`: Read debug information from an ELF for the current process

`directory X`: add `X` to the search path used to find symbols

When it's possible to get symbols set up, it pays off!

## Frames
`backtrace` or `bt`: show backtrace

`up` and `down` to navigate frames

## TUI
`tui enable` or `layout next`

Combine debug console with source code, assembly, or register view.

Up and down keys will no longer scroll through command history unless you do `focus cmd` or `focus next`

## Scripting
Persistent options can be set in `~/.gdbinit`

When re-running the same binary multiple times, you may wish to automate your analysis:
* `-x file`: run commands from file on start
* `-ex cmd1 -ex cmd2`: run cmd1 then cmd2 on start

## Extensions
* GEF ("Jeff"): GDB Enhanced Features
* PEDA: Python Exploit Development Assistance for GDB
* Pwndbg: Exploit Development and Reverse Engineering with GDB Made Easy

## Sources & additional reading
Eli Bendersky's:

* [Blog series on debuggers](https://eli.thegreenplace.net/2011/01/23/how-debuggers-work-part-1)
* [Pyelftools for parsing DWARFs](https://github.com/eliben/pyelftools)

Linux man pages:

* man (1) gdb
* man (2) ptrace
* man (2) waitpid
* man (7) signal

[Dwarf Introduction](https://dwarfstd.org/doc/Debugging%20using%20DWARF-2012.pdf)

[/comment]: PDB Information https://github.com/microsoft/microsoft-pdb)

## Any questions?

[/comment2]: ![Bendersky's small debugger](images/debugger.jpg)


% CS4910: Sanitizers
% Andrew Fasano
% Feb 8, 2022

# Intro

## Assignment 02
Part 1: Heap allocation tracking with Frida - released Friday

* Should work across OSes (except OS X?) if you don't want to use containers
* Reduced in scope to accommodate part 2

Part 2: Minecraft control from Frida - will be released tonight

* Frida's Java introspection only works on Linux / OS X and for specific JDK versions
* Created a new container, `frida/Dockerfile_mc` which sets up a working JDK and an older (1.12) Minecraft server
* See the assignment for details


# The need for sanitization

## Who can read C code?

. . .

What does the following code print?
```
#include <stdio.h>

int main() {
    int a;
    printf("The value of a is: %d\n", a);

    char msg[] = {'h', 'e', 'l', 'l', 'o'};
    strcpy(msg, "goodbye");
    puts(msg);
    return 0;
}
```

## Solution:
On my machine:
```
The value of a is: 21856
goodbye
*** stack smashing detected ***: <unknown> terminated
Aborted
```

What will it do on other machines?

. . .

Nobody knows

## Sanitization
Some low level languages such as C allow developers to write code which causes unpredictable program behavior.

> "Unlike most other programming languages, C and C++ do not trade performance for safety."\footnote{Stepanov and Serebryany. MemorySanitizer: fast detector of C uninitialized memory use in C++}

Is this the fault of the language designers?

Modern programming languages research has shown languages can provide safety guarantees without a significant performance overhead (e.g., Rust).


## Unpredictable behavior

It would be terrible if a program did different things when:

* built with different compilers (or different versions of one compiler)
* run on different machines
* run on the same machine
* unrelated portions of code were modified

But, as shown in our earlier example, these things happen!

How could we *sanitize* these types of behavior? Debuggers or DBI?

. . .

* Raise detailed and precise error **when problematic behavior occurs**.
Not when the behavior later causes unexpected changes to other components.

## Unpredictable behaviors to detect

Invalid memory accesses

* Out of bounds reads or writes
* Reads of uninitialized memory
* Use after free

Undefined behavior per compiler spec, e.g., [C spec](http://www.open-std.org/jtc1/sc22/wg14/www/docs/n1570.pdf)  (section J.2)

* Signed integer overflow
* A value is shifted by a negative number or by an amount greater than or equal to its width
* The value of a pointer to a `FILE` object is used after the associated file is closed
* The value of the second operand of the `/` or `%` operator is zero

Race conditions between threads




# Sanitizers

## Overview

*Compile time* modification to program to add *run time* checks for undesired behavior.

* Ideally low runtime overhead (2-15x slowdown and memory required)
* Can't break valid behavior
* Not designed for production deployments
* Ideally provide useful information for how to fix problems when they occur

Generally implemented as a part of a compiler (i.e., a "compiler pass")

* Developer never sees modified source code
* Same codebase can be built with or without sanitizers

## Popular sanitizers (1 of 3)

Address Sanitizer: 2012\footnote{Serebryany, Bruening, Potapenko, and Vyukov. AddressSanitizer: A fast address sanity checker. USENIX ATC}

* Detect out-of-bounds memory accesses and use after free errors using shadow memory
* Creators include Derek Bruening who made DynamoRIO!

Memory Sanitizer: 2015\footnote{Stepanov and Serebryany. MemorySanitizer: fast detector of C uninitialized memory use in C++. CGO}

* Detect use of uninitialized memory

## Popular sanitizers (2 of 3)

Thread Sanitizer: 2009\footnote{Serebryany and Iskhodzhanov.ThreadSanitizer: data race detection in practice. WBIA}

* Detect data races between threads

Leak Sanitizer: 2015\footnote{clang.llvm.org/docs/LeakSanitizer.html}

* Identify memory leaks and report details
* Unlike the others, this behavior isn't undefined, it's just bad


## Popular sanitizers (3 of 3)

Undefined Behavior Sanitizer: 2012\footnote{clang.llvm.org/docs/UndefinedBehaviorSanitizer.html}

* Detect signed integer overflow, invalid bitwise shifts, etc.
* If array bounds can be statically-determined, detects out of bounds array accesses






# Sanitizer Implementations

## Compiler Passes

Most compilers have a series of stages or passes which combine to form the "compiler pipeline".

Typically begins with lifting source code to an abstract syntax tree (AST) and
then translating to an intermediate representation. Optimizations may then be applied and
finally machine code is generated.

* Take CS 4410 `Compiler Design` if you want to learn a lot more about these!

Let's look at LLVM which has a good interface for custom compiler passes (unlike GCC)

## LLVM

LLVM is not an acronym. It's an open source compiler infrastructure.

LLVM Core handles code generation and optimization. Clang is a "front end"
to parse C/C++/Objective-c.

LLVM passes are written in C++, and operate on the LLVM IR


## Intermediate Representation (IR)

Simple, representation of operations, higher level than assembly.
Many different IRs exist in both compilers and other tools (e.g., decompilers, emulators)

Who can guess what this block of LLVM IR does?
```
define i32 @foo() {
   %a = add i32 2, 3
   ret i32 %a
}
```

## LLVM IR

* Not limited by CPU-details (e.g., number of registers)
* Static single assignment: No variable will ever be redefined.
* Clang can generate LLVM IR from a C file if run with flags `-emit-LLVM -S`

The C code defining a function, `sum`
```
int32_t sum(int32_t one, int32_t two) {
```

turns into:

```
define i32 @sum(i32 %a, i32 %b) #0 {
```

## LLVM IR details
```
define i32 @sum(i32 %a, i32 %b) #0 {
```

* Globals start with an `@`
* Locals start with `%`
* \#0 is a variable (later defined) which encodes function attributes
* Ever basic block is split up and labeled

Every instruction is documented: [llvm.org/docs/LangRef.html](https://llvm.org/docs/LangRef.html)

## LLVM Compiler Passes

Passes implemented in C++

Passes can analyze or modify IR during compilation

We will be building a custom LLVM compiler pass in lab on Thursday!



# Address Sanitizer

## Address Sanitizer Overview

``ASAN'' is implemented as an LLVM pass (over 4,000 lines of code) and a run-time library.

* Triggers run-time errors on unsafe memory operations
* Current implementation includes MemorySanitizer
* Performance overhead: 1.78x runtime, 3.4x memory

ASAN modifies the program to store metadata
about all active memory allocations in a "shadow memory"
and to check against this metadata when memory is read.

## ASAN: Shadow Memory

ASAN manages a "shadow memory" which is 1/8th the size
of the program's regular memory.

Given an address, compute `(addr>>3)+Offset` to get
shadow memory details.\footnote{This assumes malloc'd buffers are 8-byte aligned, which they generally are.}
`Offset` varies by arch, for x86\_64 it's 2^44.

Shadow memory stores 0 if all 8-bytes are valid (addressable)
1-7 if the first x bytes are valid.
Negative to indicate different types of invalid states.

## ASAN: Redzones

Memory allocations are padded with **redzones** (128 bytes by default)

* If a buffer of size `X` is requested, a buffer of `X+2*Y` is allocated at `Z`
* `Y` bytes at the start and end of the buffer are labeled as a redzone in shadow memory
* The application is given a pointer to `Z+Y`

If an application ever attempts to read or write to the redzones, it is an out of bounds
memory access!

## ASAN: Stack and global protection

The local stack  variables and globals are also padded with redzones.

```
void foo() {
    char rz1[32]        // Redzone1: before
    char arr[10];
    char rz2[32-10+32]; // Redzone2: after
    unsigned *shadow = (unsigned*)(((long)rz1>>8)+Offset);
    // poison the redzones around arr.
    shadow[0] = 0xffffffff; // rz1
    shadow[1] = 0xffff0200; // arr and rz2
    shadow[2] = 0xffffffff; // rz2
    <function body>
    // un-poison all.
    shadow[0] = shadow[1] = shadow[2] = 0; }
```

## ASAN: Runtime library

Custom memory allocation to set up shadow memory
at start.

Updates shadow memory when allocations are made
and freed

## ASAN: Instrumentation
At every memory access, first check shadow address:

```
ShadowAddr = (Addr >> 3) + Offset;
if (*ShadowAddr != 0)
    ReportAndCrash(Addr);
```

## ASAN: Real world use

ASAN pairs well with bug-finding (e.g., fuzzing) as subtle errors can be
detected as soon as they occur.

ASAN is credited with a very long list of bugs: [github/google/sanitizers/wiki/AddressSanitizerFoundBugs](https://github.com/google/sanitizers/wiki/AddressSanitizerFoundBugs)

## ASAN Usage

Use the `clang` compiler or `clang++`, and at a minimum, add 
```
-fsanitize=address
```

For better error messages, you should use
```
-O1 -g -fsanitize=address -fno-omit-frame-pointer
```

## Any questions?

Assignment 02 is due in one week

On Thursday we'll be building a custom sanitizer

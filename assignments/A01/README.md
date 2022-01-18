Assignment 01: Instruction Trace
====

Dynamic program analysis can only tell you about the parts of a program that you run. With this assignment, we will quantify exactly that using two different tools:
1) GDB: a ptrace-based debugger, configured to single-step through the binary and print the program counter.
2) DynamoRIO: a dynamic binary instrumentation framework with a custom plugin to record the program counter

The dynamic analysis capabilities you create should work on ELF binaries compiled for the x86-64 architecture. They will be tested on a standard Ubuntu 20.04 image using GDB 8.1.1

# Part 1: GDB trace

## 1A: Trace
Write a gdb script `commands.txt` such that, running
```
gdb -x commands.txt $PROG | grep TRACE > log.txt
```
populates log.txt with a line with the address of every address executed in $PROG.
```
TRACE 0xffffd5d0
TRACE 0xffffd5c8
...
```

You should not filter out duplicates or do any additional processing. Whenever the target program runs an instruction, you should record the address in hex. It's okay if your last line is just `TRACE` with no address.

### Questions:
1) Pick 3 binaries on your system to use for testing. Which ones did you pick?
2) How long does your GDB tracer take to trace each?
3) How many instructions does it log for each?
4) On average, how much time does it take per instruction?

## 1B: No Alarms
Your tracer seems to slow down programs a little bit. This could cause problems, for example consider the attached file `alarming.c`. Modify your GDB script (_not_ `alarming.c`) such that the program executes the same code when it runs under your tracer as it does normally. There are multiple approaches you could take here, but it should be pretty simple.

### Questions:
6) How did you approach the alarm problem? Can you think of any other approaches?
7) How many more instructions do you record after your fix?


# Part 2: DynamoRIO
Create a new instruction tracer for DynamoRIO. Start with the attached `skeleton_tracer.c`

### Questions:
8) Run this tracer on the same 3 programs you identified previously. How long does it take to run?
9) What is the average time per instruction for this tracer?
9) Does this tracer identify the exact same, approximate-same, or significantly different number of instructions? Does that result make sense to you?

# Writeup:
For each of the numbered questions above, please combine your answers into a text file. You only need to write a sentence for each.

# Submission details:
You will submit your code, results and write up through canvas. Please create the file `A01_[your_last_name].tar.gz` compressed archive with the following directory layout:

```
A01_[your_lastname]/
    gdb/
        commands.txt
        result.txt

    dynamorio/
        tracer.c
        result.c

    writeup.txt
```

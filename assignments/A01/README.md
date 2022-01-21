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

Select one of your binaries and save it's output as `gdb/results.txt` and include it in your submission.

### Questions:
1) Pick 3 binaries on your system to use for testing. Which ones did you pick? Which one generated results.txt?
2) How long does your GDB tracer take to trace each?
3) How many instructions does it log for each?
4) On average, how much time does it take per instruction?

## 1B: No Alarms
Your tracer seems to slow down programs a little bit. This could cause problems, for example consider the attached file `alarming.c`. Modify your GDB script (_not_ `alarming.c`) such that the program executes the same code when it runs under your tracer as it does normally. There are multiple approaches you could take here, but it should be pretty simple.

### Questions:
6) How did you approach the alarm problem? Can you think of any other approaches?
7) How many more instructions do you record after your fix?


# Part 2: Binary Bomb
You are going to defuse the cyber bomb we saw at the end of LAB01! Your goal is to stop it from printing *BOOM* in a few ways. This will require some basic reverse engineering and possibly even factoring a number.

You will use the provided `bomb` binary, its source `bomb.c`, and an example file with gdb commands `defuse.txt`

## 2A: No BOOM
Create your own gdb script, named `defuse_easy.txt` which modifies the execute such that the program never prints `BOOM` after you start it's execution with the `r` command in GDB. There are many ways to do this - but it should be easy. You're allowed to have side effects and change any behavior in the program.

### Questions:
8) What approach did you take here? Can you think of any others that would have worked?

## 2B: A proper defusal
Create a new gdb script named `defuse_real.txt` which modifies the values in `commands` and `argv` such that the bomb does not detonate. When you've accomplished this, you should see a message printed about winning and no `BOOM`.

# Part 3: DynamoRIO
You are going to use a DynamoRIO client to collect an instruction trace for the 3 programs you previously traced with GDB.


To begin, read the [instructions for running DynamoRIO](https://dynamorio.org/page_deploy.html) and about the [DynamoRIO Coverage Tool](https://dynamorio.org/page_drcov.html).
Next, clone [the container repo for the class](https://github.com/AndrewFasano/DPA-containers) and build the Dynamorio container.  Inside the DynamoRIO container, `drrun` is in `/dynamorio/built/bin64/`

Run the coverage collection tool on the same binaries you tested in part 1. Configure the tool to output in text mode instead of binary.
For the same binary you used to generated `gdb/results.txt`, save the DynamoRIO output as `dynamorio/result.txt` and include it in your submission.

*Watch out*: You may see a warning about a missing file in `clients/lib32/...` - this isn't an error and you should still have a result.

### Questions:
8) How many program counters are in your log for each binary? How does this compare to the number you saw with GDB?
9) Why is there a difference? Are the two tools recording the same thing?
10) What is the average time per program counter logged for this tracer?

# Writeup:
For each of the numbered questions above, please combine your answers into a text file. You only need to write a sentence for each question.

# Submission details:
You will submit your code, results and write up through canvas. Please create the file `A01_[your_first_name].tar.gz` compressed archive with the following directory layout:

```
A01_[your_firstname]/
    gdb/
        commands.txt
        result.txt

    bomb/
        defuse_easy.txt
        defuse_real.txt

    dynamorio/
        result.txt

    writeup.txt
```

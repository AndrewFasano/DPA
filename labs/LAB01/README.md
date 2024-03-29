LAB01: GDB Scripting
----

# Lab Goals
This lab is designed to:
1) Test the setup of your development environment to make sure it meets the minimum class requirements
2) Introduce you to basic dynamic program analysis with GDB scripting
2) Give you hands on experience using conditional breakpoints and introspecting/modifying application state dynamically.

# Environment Selection
Throughout this course, you will be building, running, using, and analyzing Linux-based applications.
As such, you will need an environment where you can run these.
Some of the tools we will use may have releases or support for other OSes or architectures - you can try to use those, but no support will be provided if things go wrong.

For today's lab, you must decide what base environment you wish to use. Your options are (ranked from best to worst):
1) Local Linux host machine (instructions will be designed for Ubuntu, if you're on another OS you can probably figure it out)
2) Remote Linux machine via SSH
3) Windows subsystem for Linux (WSL) with Ubuntu
4) Local Mac host machine (recommended to set up brew or another package manager)
5) Local docker container

Many tasks and assignments will run directly on your base environment, but sometimes containers will be provided
for all students to simplify configuration and setup. If an assignment, lab, or a part thereof doesn't recommend using
a container, then the container provided for students using containers will simply provide a starting environment.

For today's lab, the challenges will just use your base environment.

## Basic Container Setup
For students who are using containers as their base environment, it's extra important to familiarize yourself with standard docker commands and arguments so you don't lose work left in your container. You should set up a shared directory to store your work outside the container.

To begin today's labs, try the following set of commands and flags:
```sh
user@host$ cd LAB01
user@host$ mkdir shared
user@host$ docker build -t base -f Dockerfile_base
[ ... output from docker building the container ... ]
user@host$ docker run -v $(pwd)/shared:/shared --rm -it base
root@container# cd /shared
```

Now you are inside an Ubuntu 20.04 container and the contents of the `shared` directory will be synced between your host machine and the container. Create a file in that directory on your host and make sure it shows up inside the container.

# Challenges
## The Edges of Allocation
### Motivation
For our first challenge, you're going to use GDB to dynamically identify how sqlite3 allows users to configure buffer allocation sizes. Incorrectly sized buffers are often a cause of insecure logic (out of bounds reads/writes) so sqlite3's decision to allow a user to customize this is unusual - let's find out if it's a security risk.

### System Setup
Inside your base environment, install the sqlite3 database engine and the GDB debugger.

### Tasks
1) Run sqlite3 under gdb such that it mmaps an unusual buffer size.

2) Set breakpoints on all calls to `mmap`. Because `mmap` is a system call, gdb can tell you about its arguments even though your version of sqlite3 has no debug symbols.
    * You can learn about this system call with `man 2 mmap`
    * You can learn about how arguments are passed to system calls with `man syscall. 

3) Step through a few calls to `mmap` - do you see the argument you've specified anywhere? Try creating a database and creating a table in it (Something like `create table foo(int x);`) - do you see the argument now?
    * Note that `mmap` is used quite often during sqlite3 startup - you might want to set your breakpoint _after_ the sqlite prompt is first printed (use ctrl-C to trap to the GDB prompt, set things up, then continue)
    * Creating a database with sqlite is a bit strange if you're used to other, non-file based database engines

4) Replace your breakpoint with a *conditional breakpoint* which only triggers if the length matches the value you provided. When it triggers, run the `printf` command to print the program counter as hex and then continue. Run the program again, provide the necessary inputs, and validate that your breakpoint hits and the backtrace is printed. How deep is the backtrace? What symbols do you see above the call to `mmap`?

5) Automate this process so you accomplishes everything you did previously with no user interaction after pressing enter once.
    * Feed sqlite3 input from a text file by appending `< in.txt` to your command and populating that file.
    * You can make your command starts with `rm -f my.db; gdb ...` to delete an existing database on disk.
    * Use GDB's `-x` flag to read commands from a file or `-ex` to read commands from the command line
    * HINT: the GDB command `set breakpoint pending on` will avoid the error you might get of: `Function "mmap" not defined.  Make breakpoint pending on future shared library load? (y or [n]) [answered N; input not from terminal]`

6) Edit your command or input files to find the minimum and maximum values that will be passed to mmap
    * Does the application behave properly at these limits?
    * HINT: the maximum is at a either a power of 2 or a multiple of 100.

7) CHECK IN: show the instructor the command you built, the results, and the minimum/maximum values you found.


## Binary Bomb No longer a part of lab -  moved into A01
### Motivation
For our next challenge, you are going to defuse a cyber bomb! Your goal is to stop it from printing *BOOM* in a few ways. This will require some basic reverse engineering and possibly even factoring a number.

### System Setup
Inside your base environment, make sure you have gdb installed, the provided `bomb` binary, and the sample defuse.txt file. To run the provided script use `gdb --command=defuse.txt ./bomb`.

### Tasks
1) Compile the bomb and read the source code - is it possible to come up with a set of inputs to defuse it looking at the source?
2) Modify the defuse.txt script to make the program never print BOOM - don't worry about any other side effects your changes might have (hint: this should be easy, there are many solutions).
3) Modify defuse.txt to change the commands and argv to defuse the bomb. When you're done it should print a message about winning.
4) CHECK IN: show the instructor your defuse script, and the win message. Explain how you avoided the BOOMs in step 2.

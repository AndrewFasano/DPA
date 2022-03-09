LAB08: Reverse Engineering and Patching
===

In this lab you will use Ghidra to reverse engineer a simple C program and then to patch a program so it provide extra
information at runtime.

# System setup:
Install Ghidra from [https://ghidra-sre.org/](https://ghidra-sre.org/) onto your host machine. It supports Windows, Mac and Linux.

Download the following files into a local directory and compile by running `make`:
crackme.c, Makefile

For now, please do not look at the source code.


# Part 1: Simple Crackme

Analyze `crackme` with Ghidra. Determine the correct password
and test the program dynamically to test if you've gotten it right.

In particular, you should start with the following steps:

1) Open Ghidra
2) Create a new, non-shared project
3) Import the `crackme` file by selecting "import file" under the "file" menu.
4) Launch the "Code Browser" by selecting `crackme` and clicking on the green dragon icon. 
5) Run the auto analysis on `crackme` by selecting "yes" when prompted, or by pressing "a" after the program is loaded. Stick with the default options
6) Go to the main function by expanding the "exports" folder on the left pane and then finding `main` and clicking on it.
7) Read through the decompilation to get an idea of what the program is doing

After you've pulled up the decompilation of the main function, fix some of the incorrect types. The type signature of the `main` function is something standard: it returns an int, and takes an int and a char** as arguments.

Right click on a variable and select "Retype Variable" to change its type.


Next, name the variables `argc` and `argv`, right click on the auto-generated names and select "rename variable."

Run `crackme` with the correct password. After you figure this out,
examine the source code for crackme.c and try to get your decompilation in Ghidra as close to the original source code as you can.

Check in: show off your cleaned-up decompilation.

# Part 2: Harder crackme

Import the program `harder` into Ghidra, identify its main function and try to clean up the variable types and names to get reasonable decompilation.

How does this program differ from the original crackme? Is it just as easy to calculate the password?


Patch the program such that the call to printf with the string "Analyzing your password" prints the expected password instead of your input.

You will do this by editing the disassembly in the left pane.

This will be tricky - talk to your classmates and ask for help as necessary! On this architecture, the 2nd argument will be passed in the register `RSI` - this is the value you'll want to change.

A few hints:

* The hotkey ctrl-shift-g will let you patch a selected instruction
* If there are extra bytes you'll need to replace them with the `NOP` instruction
* An instruction to load the password into a different register is already in this program - if you hit ctrl-shift-g on it, you'll see the raw instructions (instead of ghidra's version which has some weird names)
* When I added the same instruction, it clobbered a part of the next one - so I had to move that farther down. I dropped the `mov EAX, 0` instruction before the call to printf so I had room for it and I didn't see any issues.

Once you've made this change, export the new binary with file - export program and select "ELF" for the format. Run this binary. If your changes are correct, it should print the password. Run it again with this password, does it print correct?

HINT: the password has some obnoxious characters in it, if you write it to a text file like inp.txt you can run the program with `./harder "$(cat inp.txt")` and you don't have to worry about them.

Check in: Show off your solution.


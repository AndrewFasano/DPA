LAB08: Qira
====

Today we will be solving a `crackme` challenge using Qira and then comparing the process to solving it with Ghidra.

## System setup

Download the provided `crackme` binary. Pull the `dpa-containers` repo and build the qira container. Launch the `qira` container according to the README in there (be sure to forward port 3002 to your host).


## Part 1: Qira Cracking

Your goal is to figure out the key for the provided crackme. You will need to figure out where the key is read from and what a correct value is.

We will approach this first with Qira.

1) Run the `crackme` program under qira, then browse (on your host) to http://localhost:3002. If you want, you can try to get qira to work with the `-S` flag which should show a graph view of the current function, but this caused a bunch of issues for me. (If you try that, you'll want to install `graphviz` from apt.)
2) Examine the trace of system calls to identify where the `crackme` file loads input from.
3) Launch a second shell in your qira container (`docker exec -it [contianername] bash`), set up a new input and rerun the crackme with qira.
4) Refresh the web view to see the traces of both inputs. Examine the traces to determine what the first character of the key should be.

Hints:
* Qira has some undocumented hotkeys. A few useful ones: `g` lets you type the name of a function or an instruction index to select it in the trace. `Esc` will go back to the last location you were at. `Up` and `Down` will seek through the trace. `Left` and `Right` will switch which trace you have focused on.
* The four text boxes at the top of qira are for: Instruction index, Trace index, program counter, and memory address shown
* The left view shows light yellow lines for where the selected memory was written, dark yellow for when it was read, red for the current program counter, and blue for the current selected access.
* Double clicking on addresses will (when possible) select that address in the code or memory view
* If you examine the list of syscalls, you can select the (small) portion of the trace where the key could be evaluated - between when it is read and when the program writes 
* Watch out: before your input string is compared, the program may check its length - if this is the case, first figure out the right length.

After you figure out the first character, repeat this process for the second. Examine how the timeline of the program on the left in `qira` has grown. When you feel ready to guess the full key, give it a try and see if you're right (instead of figuring out one character at a time).


## Part 2: Comparison to static reversing

Open `crackme` in Ghidra, analyze it and go to the main function. Examine and, as necessary, clean up the main function so you can understand what it's doing.

*Check in 1*: What was the key you found? What did the program output when you got it right? Was it easier to use Ghidra or Qira?


## Part 3: CTF Challenge

Use qira to figure out what the provided chall binary is doing.

A few hints:

The password isn't checked with a `cmp` in a loop as you might expect, instead this program uses the code:

```
repe cmpsb byte ptr [rsi], byte ptr [rdi]
```

Which roughly translates the following loop:
```
while (*rsi == *rdi) {
    rsi++
    rdi++
    rcx--
}
```

This loop breaks as soon as the compared bytes are unequal.

Identify the loop that runs over the input characters and the place where the output buffer is compared. When you have a guess as to what is going on:

*Check in 2*: Explain what you think the program is doing - how do you think you could find a solution?


*Check in 3*: Solve the challenge! Once you figure out what's going on, you can either identify the next correct character each time you run the program or you can figure out where the encoded "correct" buffer is in memory and work from that.

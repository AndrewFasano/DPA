A05: Obfscuated Crackme
===

# Part 1: Reverse Engineering

Using both Ghidra and qira as you see fit, determine the key for the provided crackme2 challenge. Be warned, the program was designed to make the Ghidra results confusing (recall L08 slide 15).

Write a few sentences describing your process and how you used the tool(s).
Also include the solution to the crackme in your writeup.


# Part 2: Build your own Crackme
Start with the provided files:

Makefile, mycrackme.c, shellcode.s

Modify these to build your own crackme which takes a user-provided password in as an argument, compares it to "P@SS-4-CS4910" and either prints "GOOD PASSWORD" or "WRONG PASSWORD" depending on the results. Your program should be non-trivial and designed to be difficult to reverse engineer (but don't go too crazy, keep yourcode under 100 lines).

The starter code shows how to call into a hand-crafted assembly function from C code. Modify this to make one or more calls such that Ghidra's static analysis gets messed up in some way. If you don't recall our discussion from class, you can view [this](https://github.com/Brandon-Everhart/Practical-Malware-Analysis/blob/master/notes/ch_15.md) and [this](https://www.slideshare.net/SamBowne/practical-malware-analysis-ch-15-antidisassembly) for more details about how to break disassemblers.

Try to reverse engineer your crackme dynamically with Qira and statically with Ghidra. Did your design make either or both of these more difficult?

You will be awarded points for creativity, difficulty, and how difficult it is to analyze your programs using qira and Ghidra.

# Submission format:
Submit a gzipped tar file `A05_[your first name].tar.gz` which extracts to:
```
A05_[your first name]/
    writeup.txt
    Makefile
    mycrackme.c
    asm.s
```

The writeup file should contian answers to the questions above.

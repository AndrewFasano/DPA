Assignment 02: Heap Analyzer + Minecraft Returns
=====

By popular demand, the original version of this assignment has been simplified and we're going to have a second part focused on Minecraft.

# Part 1: Frida Heap Analyzer

Using Frida we are going to examine malloc and free calls and track allocations. If you're not familiar with these, it's definitely
worth reading the man page or some background

### Who cares about the heap?
Use after free or UAF is a common vulnerability type where an object is allocated on the heap, a reference to it
is stored, and then the object is unallocated, but the reference to it is left behind. If the 
code then uses that reference, it will read random memory. In many situations the memory is used
as a function pointer which could cause execution to jump to somewhere it shouldn't. Even worse,
users often have some control of memory allocations and, if they have the program allocate a buffer
of the same size, they can place arbitrary data into memory where the object originally was.
For example, consider the following buggy code:

```
char* data1 = (char*)malloc(64);
data1[0] = 'h';
data1[1] = 'i';
data1[2] = 0;

free(data1);

char* data2 = (int*)malloc(64);
fgetc(data2, 64, stdin);

printf(data1); // This could now contain the attacker-provided data2.
```

We're not going to be building a UAF detector today (Frida isn't really the best tool for it), but we're
instead going to hook malloc and free and just log some information.

## Tasks

Examine the provided, `run.py`, `inject.js` and `prog.c`. Your goal is to modify the `inject.js` code
such that it reports information back to Python such that the `on_message` function in `run.py` gets the various types
of messages it supports: `heap_info`, `allocation` and `free`.

`allocation` and `free` should both be given a pointer and a size. You may want to convert the addresses you get
from Frida into regular numbers using the `Number()` function. 

`heap_info` is a little more tricky, you'll want to provide this info before recording the very first allocation. Using Frida's
APIs, you're going to take the first pointer returned from malloc and convert it into an address range for the heap.

You shouldn't need to make any modifications to files other than `inject.js`.


# Part 2: Minecraft returns
I need a few days to finish debugging the Minecraft Java setup, but (if/)once I find a solution, I'll post this part.
The goal will be to get frida-trace logging the Java function calls made by Minecraft and use it to do something interesting,
it will be different from just identifying values in memory like we tried to do for LAB03.


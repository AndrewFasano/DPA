LAB04: Custom Sanitizers
====

As the head of programming at **Lucky 12 Code**(TM), your bosses depend on  you to make sure the unlucky number 13 never shows up where it shouldn't be.
Unfortunately, another employee made a horrible mistake and a 13 was printed on a client's system.
But nobody knows where the mistake came from or how to fix it before this travesty happens again.

Being the great programmer you are, you've realized that what **Lucky 12 Code** needs are some sanitizers to detect these sorts of embarassing errors
to make sure nothing like it ever happens again.
You presented this plan to your management and they agreed to give you 90 minutes to build some sanitizers in order to track down the bug in your programs.

## Sanitizer Specification
Before every call to puts, your `luckysan` sanitizer should should check if the buffer
contains a 13. If so, it should raise an error (e.g., print warning then exit or assert).

## Performance Evaluation
After 90 minutes, you'll be called in to a meeting with the **Lucky 12 Code** management team.  Your performance will be scored as follows:
* 2 point for development of a `luckysan` sanitizer which detects whenever a buffer about to be printed with `puts` contains `13`.
Whenever this behavior is detected an error should be raise (e.g., print a warning then exit or assert) and the program should not continue.
* 1 point for development of a `veryluckysan` sanitizer which is just like `luckysan` except it sanitizes `printf` instead of `puts`.
* 1 point for identifying the ways in which the `lucky12_prog_*.c` files could print an unlucky 13.


## System Setup
Pull the latest version of [dpa-containers](https://github.com/AndrewFasano/DPA-containers) and build the `llvm` container. Launch it with a shared directory to your host.
Download the provided sanitizers.tar.gz and extract it into the shared directory with your host.

# Instructions
The LLVM container just has the following packages installed: llvm-dev, llvm, clang, cmake, build-essential and a few text editors.

Extracting the provided sanitizers.tar.gz into your container's shared directory, then build the 3 provided sanitizers by going into
the `lucky12code/passes` directory and running:
```
# cmake .
# make
```

In each of the directories, `hello`, `helloputs`, and `luckysan` you should now have a `.so` file
which is a compiled version of the pass implemented in that directory's `.cpp` file.

Compile the provided hello world program to LLVM IR bytecode
```
# clang -g -O1 -emit-llvm ../helloworld.c -c -o helloworld.bc
```

For testing, you can run the bytecode directly using the `lli` utility:
```
# lli helloworld.bc
Hello world!
```

You can also translate the bytecode back to human-readable, LLVM IR in `hello.ll` with
```
# llvm-dis helloworld.bc -o helloworld.ll
# cat helloworld.ll
```

Compare helloworld.ll to helloworld.c, can you see how the C code maps to LLVM IR?

Now use the `opt` utility to a compiled pass over the bytecode. Note that it
requires an absolute path to the library you built and the argument after the `.so`
is set in the corresponding `.cpp` file with the `Y` function.

```
# opt -load $(pwd)/hello/libhello.so -hello < hello.bc
# opt -load $(pwd)/hello/libhelloputs.so -helloputs < hello.bc
```

The `hello` example doesn't modify the bytecode at all, it just prints some messages
while analyzing the bytecode. However, `helloputs` does modify the bytecode - so let's
save that output by passing the `-o` flag to `opt`:
```
# opt -load $(pwd)/helloputs/libhelloputs.so -helloputs -o hello2.bc < hello.bc
# lli hello2.bc
[HelloPuts] detected that there's about to be a puts of the string:
hello world
[HelloPuts] now let's keep going
hello world
```

### LuckySan
The file `luckysan/luckysan.cpp` is largely a duplicate of `helloputs`, ready for you to build your own sanitizer.
You'll want to modify it to detect when a 13 is present in a buffer about to be printed with puts and, if so
print a warning (with some details about what's going on) and exit.

### VeryLuckySan
Start by duplicating the LuckySan directory. You'll need to edit the CMakeLists.txt file in both
the `passes` directory as well as the just-created `veryluckysan` directory and rename `luckysan.cpp` to `veryluckysan.cpp`.
It should be easy to figure out how to make these changes from what's in the files already.
Then `rm -rf CMakeCache.txt  CMakeFiles` and reset the build system with `cmake .`, finally build with `make`

Now that you've created a new pass, you need to make your pass work! This wll be harder than LuckySan (that's why it's *Very*LuckySan)
because the buffer that will be produced by printf isn't simply available in an operand: you have to compute the buffer first
(i.e., with sprintf), then check it.

## Resources

There are a lot of examples of working with the LLVM IR online. So long as you don't find an exact solution
for this lab, feel free to search for code examples and build your solution off of those. Be warned
that LLVM has changed significantly between versions. This lab is based off version 10. Thanks
to the type system, you're most likely to run into compile-time errors if you're trying to use
a function that's changed between versions.

The autogenerated doxygen code is very useful for figuring out what methods are available
for objects of various types. It's hard to search, but usually one of the first google results
for `llvm [classname]`.

### General
* https://github.com/llvm/llvm-project/blob/release/10.x/llvm/docs/ProgrammersManual.rst
* https://llvm.org/doxygen/

### LLVM Passes
* https://llvm.org/docs/WritingAnLLVMPass.html
* https://github.com/abenkhadra/llvm-pass-tutorial

### Build system / Out of tree passes:
* https://llvm.org/devmtg/2015-10/slides/GueltonGuinet-BuildingTestingDebuggingASimpleOutOfTreePass.pdf
* https://llvm.org/docs/CMake.html#cmake-out-of-source-pass

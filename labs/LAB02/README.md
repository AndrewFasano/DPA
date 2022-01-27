Today we will be building custom DynamoRIO client that we will then use to reverse engineer a critical vulnerability and exploit that were just disclosed on Tuesdsay!

This lab is split into five components, the first and last should just take a few minutes.
To save time, you can finish both 1+2, then check-in and then finish 3+4+5 and check-in again.
1) Container setup and exploit testing
2) Tracer feature 1
3) Tracer feature 2
4) Tracer feature 3
5) Tracer analysis


To begin, launch the DynamoRIO container (built in last class using https://github.com/AndrewFasano/DPA-containers) using the following commands:
```
mkdir lab02 
cd lab02
docker run --rm -it -v $(pwd):/host  dynamorio
```
This will set up some shared folders so you can edit files outside the container.

# Part 1: Setting up the target
```
apt update
apt install policykit-1
pkexec --version # <- should give you 0.105, the version number didn't check on the patch
```

This will install the newest (no longer vulnerable) version of pkexec to /usr/bin/pkexec as well
as all it's runtime dependencies.  Make a backup of that file by moving it to `/usr/bin/pkexec.orig`

Next, back up the new pkexec binary, and copy in the vulnerable version. Then make sure it has the suid bit set:
```
# mv /host/pkexec /usr/bin/pkexec.patched
# cp /host/pkexec /usr/bin/pkexec
# ls -al /usr/bin/pkexec
-rwsr-xr-x 1 root root 31032 Jan 27 04:07 /usr/bin/pkexec
```

if the file has different permissions, fix them by running:
```
# chmod 755 /usr/bin/pkexec
# chmod u+s /usr/bin/pkexec
```

Next, in your shared directory, clone an exploit for the vulnerability from
https://github.com/berdav/CVE-2021-4034 and build it with `make`.

Test the exploit by running
```
# useradd hacker
# su hacker
$ ./cve-2021-4034
```

Check in 1: what happened? What is your username now? If you review the 30 lines of code in the repo, does anything make more sense?

To exit the shell you're in, type `exit` once or twice until you're back at a `root@...:/host` prompt.

# Part 2: Differential Dynamic Binary Instrumentation
Now that we've seen some interesting behavior on our systems,
we are going to build a DynamoRIO client to help us figure out what's happening!

## Set up

Create a directory named `mytracer` within your shared folder and
copy the files `mytracer.c` and `CMakeLists.c` into it.

Build the skeleton code in the container by going into the directory and running
```
cmake .
make
```

You should now have a custom tool built and ready to run! Give it a try with
```
/dynamorio/build/bin64/drrun -c ./libmytracer.so -- whoami
```

It should print a message about the MyTracer starting, but warnings about
missing data from modules and 0 basic block executions.

With a little work, this tracer client is capable of reporting the program counters
executed in target programs and mapping them back to a module (i.e., a program or library)
name and relative offset. This is really helpful, because modules end up loaded at different
addresses when a program is run multiple times, but the relative offset of instructions won't
change. This information would help a reverse engineer understand what parts of a program
are worth looking at closely.


## Finish the tracer

The provided code is nearly complete, but there are three shortcomings for you to address
they are labeled and described in the code if you search for PART 1, 2, or 3.

For Part 1, you will add support for counting the total number of blocks executed.

For Part 2, you will finish the code that initialize information about modules when they are loaded.

For Part 3, you will finish the code that updates state when modules 

# Part 3: Use your tracer

Collect a trace of the `ps` program running. Use `objdump` to disassembly the binary and compare your results:

```
objdump -d $(which `ps`) | less
```

Can you get the addresses used by objdump and your tracer to align?
 Note that the tracer is increasing the addresses by `module_data[i].base` for each printed block.
 You can use objdump's `--start-address=...` option

 Optionally, you can try to rerun `ps` with different arguments and see how the coverage changes.

# Additional reading.

This isn't a part of the lab, but you might want to use your tracer to compare the behavior of `pkexec` before and after it was patched. There are a number of challenges here and ultimately, a process-level DBI tool like DynamoRIO isn't going to work here.

Issue 1) because pkexec is a suid binary, it's difficult to trace when running as non-root users.
But we could just trace the exploit running as root.

Issue 2) exploit hangs forever:
Modify the expoit so it doesn't run forever, edit pwnkit.c and comment out the call to execve on line 14. Then rebuild it by running `make`.

Now you can try running it.

You should launch your script with something like the following to save the output into patched.trace
```
# cd /host/CVE-2021-4034/
# /dynamorio/build/bin64/drrun -c /host/mytracer/libmytracer.so -- ./cve-2021-4034
```

Then move /usr/bin/pkexec to /usr/bin/pkexec.vulnerable and
move /usr/bin/pkexec.orig to /usr/bin/pkexec and try tracing again

```
# /dynamorio/build/bin64/drrun -c /host/mytracer/libmytracer.so -- ./cve-2021-4034
```

But there's no output! This is because the exploit is spawning another process and the DBI
framework is losing control of the target process! We'll solve this sort of problem later in the semester.

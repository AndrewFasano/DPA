LAB05: PANDA
====

Today we will be completing a number of exercises using the PANDA framework for whole-system dynamic program analysis.
This lab will have you 
1) manually interact with an emulated guest
2) programatically interact with a guest, and
3) analyze guest behavior


# System Setup

Pull the DPA containers repo and build the panda container. Or if you'd like, you can just pull PANDA from dockerhub and install a text editor if you need one: `docker pull pandare/panda` and then run with the name `pandare/panda`.

Start the container with a shared directory to your host and also a shared directory for ~/.panda to cache downloaded images outside the container
```
mkdir images
docker run --rm -it -v $(pwd):/host -v $(pwd)/images:/root/.panda panda
```


# Lab Resources:
* The PyPanda documentation at [docs.panda.re](https://docs.panda.re)
* The PANDA manual which provides additional details (though the function signatures listed are for C and C++): [manual.md](https://github.com/panda-re/panda/blob/master/panda/docs/manual.md).


# Exercise 1: Driving the guest manually
Download an image of an Ubuntu `x86_64` system and launch it from the root snapshot by running the following command:
```
python -m pandare.qcows x86_64
```

This will download an image and automatically start it from a previously captured snapshot after the system has booted.
The download may take a few minutes, use the time to familiarze yourself with the PyPANDA documentation.

Once the image is downloaded, run commands inside the guest to determine it's kernel version with `uname` and OS version by examining /etc/issue. Write this info down somewhere.

```
root@docker:/# python -m pandare.qcows x86_64
root@ubuntu:~/ # echo this runs inside the panda guest
```

After you've recorded this information, create a file `/root/myname.txt` inside the guest with your name in it.

Now switch to the monitor where you can control the emulation by pressing `ctrl+a` and then `c`, you should see a prompt that says `(qemu)`.

At the monitor, save the state of your VM as a snapshot named myname by typing `savevm myname`.
Finally, terminate the emulated guest by running the monitor command `quit`.


# Exercise 2: Driving the guest automatically and semi-automatically

Start from the following script:
```
from pandare import Panda
panda = Panda(generic='x86_64')

@panda.queue_blocking
def driver():
    print("Loading snapshot...")
    panda.revert_sync("root")
    print("Snapshot loaded. All done")
    panda.end_analysis()

panda.run()
```

Modify the driver function to run a commands via the serial console with a call to `panda.run_serial_cmd`.
Have it print the results of the commands to read the kernel and OS versions.

Modify the script to revert to the snapshot you previously created in exercise 1.
Expand the script to run a third command which prints the md5sum of /root/myname.txt.

**Check in**: show the instructor your script and the results. Do they match the results you collected previously?

# Exercise 3: Analysis Warm-up

You are now going to extend your script to analyze the behavior of the guest system while it runs
the actions you configured for Exercise 2.

First, add the following two lines towards the top of your script to create two dictionaries.
For both dictionaries, the key you will use to read and write data will be the ASID (identifier for the current process).
```
asid_blocks = {}
asid_names = {}
```


Set up a function to run before every basic block is **translated** by decorating it with `@panda.cb_before_block_translate`.
Look at the [documentation](https://docs.panda.re/#pandare.Callbacks.@panda.cb_before_block_translate) for this callback and read
about when the callback is triggered [in the manual](https://github.com/panda-re/panda/blob/dev/panda/docs/manual.md#emulation-details).
Note that your defined function should take two arguments.

Inside your function, you should:
1) Get the current asid using the PANDA API.
2) Check if the asid is in `asid_names`. If not, get the current process name from the OSI plugin and store it like: `asid_names[the_current_asid] = the_name`.
3) Check if the asid is in `asid_blocks`. If not, initialize a set for that asid: `asid_blocks[the_current_asid] = set()`.
4) Add the current program counter to the appropriate set for the current asid.


After the call to `panda.run()` add the following code to print and validate your results:

```
for asid, blocks in asid_blocks.items():
    if asid not in asid_names:
       print(f"ERROR: no name for {asid:x} which has {len(asid_blocks[asid])} blocks")
       continue
    print(f"Asid {asid:x} named {asid_names[asid]} has {len(asid_blocks[asid])} unique blocks translated")
```

**Check in**: How many processes ran? What are their names? How many blocks were in each?

# Exercise 4: System-Wide Analysis

Download two files: `commands_wat-rr-nondet.log` and `commands_wat-rr-snp` with the following commands and then copy them into your container.
```
wget 'https://panda.re/secret/commands_wat-rr-nondet.log'
wget 'https://panda.re/secret/commands_wat-rr-snp'
```

Together these files are a PANDA recording which captures all the detail of a system executing, we will talk about this
more in lecture next week but for now you just need to know that we can analyze this recording just like we have been doing from a PyPANDA script.
Although we can build custom analyzes, note that we can't drive the system (e.g., run commands) because it's a recording of something that
previously happened.

You do not need to set up (i.e., download) a generic image to analyze this recording, but you do need to tell PANDA
about the system's architecture. We'll also specify the kernel version so we can use the OSI plugin.

Begin with the following script:

```
from pandare import Panda
panda = Panda(arch='i386', os_version='linux-32-debian:3.2.0-4-686-pae')

print("About to run replay")
panda.run_replay("commands_wat")
print("All done")
```

When you run this script, you should see a message about `60987369` instructions in the "nondet" (nondeterminism) log which indicates that there are over 60 million instructions that will run with this replay.

For this exercise, you will modify your PyPANDA script to learn about what the guest is doing in four different ways

## 4A) Process logging
Register a callback on asid change. In it, get the name of the current process and print it. If you'd like, you can make your script only print the process name if it's different from the last-printed one. Your callback function is required to return an integer. Read the documentation to decide what value should be returned when you don't want to modify the guest's behavior.

One of the process names you see is malicious. Do any of the processes seem unusual to you? Look the names up on google if you're not sure if something is normal or not.

## 4B) ASID Story

PANDA provides a plugin called [asidstory](https://github.com/panda-re/panda/tree/dev/panda/plugins/asidstory) which will make a simple, ASCII-art representation of which processes ran over time.
Expand your script to load this plugin with a call to `panda.load_plugin("asidstory")` before you start the replay.
The results of the plugin will be stored in a file named `asidstory`. Do these seem to match your analysis?

## 4C) Syscall logging

Using the [Syscalls2 plugin](https://github.com/panda-re/panda/blob/dev/panda/plugins/syscalls2/), let's analyze what that process is doing.

Define and register a function in your script to run whenever any syscall is issued using the `@panda.ppp(plugin_name, callback name)` decorator configured to run the relevant callback provided by the syscalls2 plugin.

Inside the function, check the process name - if it matches the process of interest, print the syscall number. Compare these to a [list of x86_64 syscalls](https://filippo.io/linux-syscall-table/).

**Check in**: What types of syscalls are you seeing in the process?

## 4D) Syscall Details.
* This final portion may be completed as a part of Assignment 3 if you run out of time in lab.

Expand your script again to hook the return of both the `open` and `read` syscalls with two new, syscalls2-based callbacks.
Whenever an open syscall returns, read the filename argument and store at along with the returned file-descriptor and current asid.
Your `open` callback will be given a pointer to a string in guest memory - you can read that with the function `panda.read_str(cpu, address)`.
This may raise an exception if PANDA can't read that pointer, you can ignore when that happens.
Whenever there is a call to a read syscall, use the provided file descriptor and current asid to look up the name of the file being read and report it.

**Check in**: What files are being read by the process? Does this seem like normal behavior?

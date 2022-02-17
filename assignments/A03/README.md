Assignment 03: Heap and Taint Analysis with PANDA
===


# Part 1: Whole-System Heap Analysis

To being, you will analyze calls to malloc and free across an entire guest system.
You will use this system to analyze the behavior of proc.c from Assignment 02 as well as 
other processes that run on the system.


## System setup:
Begin by running the PANDA container (setup instructions in Lab 05) and copy
the provided heap.py script into the container. Use pip to install the `matplotlib` package
for visualizations by running `pip install matplotlib`.

`heap.py` is an incomplete script which, when finished, should generate two graphs showing
the number of heap allocations over time as well as the total heap bytes allocated over time.
The graphs will be stored as `.png` images in the directory you run the script in.
To view the image, you'll want to use your host machine: either copy the files to a shared
directory or just run the script from a shared directory

Be sure to read through all the code of `heap.py` before getting started.

## Task 1: Free Function
Modify the provided `free_enter` function such that it prints
out the asid and address being freed.
For now, the warning about freeing a previously-unseen buffer should print for every allocation.

## Task 2: Malloc Function
Modify the provided `malloc_enter` and `malloc_on_return` functions such that
they log and record the asid, buffer size and address for each allocation.

With task 1 and 2 complete, you should see graphs which mostly (but not always) increase over time.

## Task 3: Analyze prog.c
Create a directory in your contianer and copy prog.c from Assignment 2 into it.
Compile the program and modify the `drive_guest` function to copy the directory
into the guest and then run the program.

Question 1) What do you see in the allocation graph now?

# Part 2: Taint analysis

For this part, you will use PANDA's dynamic taint analysis to track how a sensitive
file is exfiltrated from a system using a PANDA recording.

## System setup:
Again, you will use the PANDA container. Download the `commands_wat` recording used by LAB05 Exercise 4.

```
wget 'https://panda.re/secret/commands_wat-rr-nondet.log'
wget 'https://panda.re/secret/commands_wat-rr-snp'
```

As we saw previously in LAB05, this recording captures the behavior of a malicious program.


## Task 1: Apply Taint Labels

Replay the recording with PANDA's `file_taint` plugin loaded. Configure it to 


You can run this plugin configred to taint bytes read from a file named `some_file.txt` using either PyPANDA
or the PANDA command line as follows:

PyPANDA:
```
from pandare import Panda
panda = Panda(arch='i386', os_version='linux-32-debian:3.2.0-4-686-pae')

panda.load_plugin("file_taint", {"filename": "some_file.txt"})
panda.run_replay("commands_wat")
```

Command line:
```
panda-system-i386 -replay commands_wat -panda osi \
-panda osi_linux:kconf_group=debian:3.2.0-4-686-pae:32 \
-os linux-32-debian -panda file_taint:filename=some_file.txt
```

As we saw in lab, the recording captures a process reading the file `id_rsa`, the ssh private key in the guest.
Configure your script or command to apply taint labels when that file is read.

If you run your script at this point you should see a log messge that starts with `file_taint read_enter: first time match of file` around 10% of the way into the replay.
Feel free to abort the replay with ctrl-c after you see that message.

## Task 2: Query Taint Labels

Now that you've applied taint labels, expand your script or command to use the `tainted_net` plugin to check
if any tainted bytes reach the network.
Read the [documentation for the tainted_net plugin](https://github.com/panda-re/panda/tree/dev/panda/plugins/tainted_net)
to identify the argument you should set for it to examine outgoing network traffic and update your code accordingly.

Run the replay again, configured to taint the data read from `id_rsa` and to record whenever tainted data reaches the network.
Examine the results in the generated file `tainted_net_query.csv`.

Save your generated command line as taint.sh or your pypanda script as taint.py.

Question 2: What do these results tell you?


# Submission:

To submit your assignment, create a .tar.gz archive with the following structure:

```
A03_[your first name]/
    heap.py
    taint.sh or taint.py
    writeup.txt
```

In writeup.txt, write a sentence or two for each of the above questions.



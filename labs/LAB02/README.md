Today we will be building custom DynamoRIO client that we will then use to reverse engineer an exploit that was just disclosed on Tuesdsay!

To begin, launch the DynamoRIO container (built in last class using https://github.com/AndrewFasano/DPA-containers) using the following commands:
```
mkdir src
docker run --rm -it -v $(pwd):/host $(pwd)/src:/dynamorio/custom/ dynamorio
```
This will set up some shared folders so you can edit files outside the container.

A provided skeleton tracer is provided. You will need to follow along in the code where labeled. If you place this code in the shared directory
between your host and the container, you can edit it using tools on your host machine and then build and run it in the container.


# Part 1: Install the target (inside the container)
```
apt update
apt install policykit-1
pkexec --version # <- should give you 0.105 - version number didn't update on the patch!
```

This will install the newest (no longer vulnerable) version of pkexec to /usr/bin/pkexec as well
as all it's runtime dependencies.  Make a backup of that file by moving it to `/usr/bin/pkexec.orig`

Next, copy the provided binary in and make sure it has the suid bit set:
```
# cp /host/pkexec /usr/bin/pkexec
# ls -al /usr/bin/pkexec
-rwsr-xr-x 1 root root 31032 Jan 27 04:07 /usr/bin/pkexec
```

if the file has different permissions, fix them with
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

Check in 1: What happened? If you review the 30 lines of code in the repo, does anything
make more sense?

# Part 2: Differential Dynamic Binary Instrumentation
Now that we've seen some interesting behavior on our systems,
we are going to build a DynamoRIO client to help us figure out what's happening!

## Set up

Create a directory named `mytracer` within your shared folder and
copy the files `drtrace.c` and `CMakeLists.c` into it.

Build the skeleton code in the container by going into the directory and running
```
cmake .
make
```

You should now have a custom tool built and ready to run! Give it a try with
```
/dynamorio/build/bin64/drrun -c ./libmytracer.so -- whoami
```

It should print a message about the MyTracer starting.

## Finish the tracer

The provided code is nearly complete, but there are two shortcomings for you to address.




# Comparison
Using your tool, you are going to compare the sequences of bsaic blocks executed in
pkexec with and without the vulnerability being fixed.

*Watch out* because pkexec is a suid binary, it's difficult to trace when running as non-root users.
To make things easier, we'll just trace the exploit running as root.

You should launch your script with something like
```
/dynamorio/build/bin64/drrun -c ./libdrtrace.so -- /host/CVE-2021-4034/cve-2021-4034
```

Move your trace to be called trace.vulnerable.

Then move /usr/bin/pkexec to /usr/bin/pkexec.vulnerable and
move /usr/bin/pkexec.orig to /usr/bin/pkexec and collect another trace.

Check in: Compare the traces. Roughly what fraction of the blocks executed have changed?
Has the number of executed blocks changed?

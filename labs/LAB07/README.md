LAB07: Profiling
===

For this lab you will use Valgrind's MemCheck and Callgrind tools to identify
and repair invalid memory accesses and to improve the performance of a target.

## Part 0: System setup
Pull and build the `valgrind` container from the dpa-containers repo or
install valgrind from your package manager on your host.

If you're using the container, launch it with the `--privileged` flag and a shared directory with your host

Download the provided C files into your container or on to your host machine and compile them with debug info.

## Part 1: Leak Detection

Use Valgrind's MemCheck to analyze leaky.c's behavior.
You should see many errors. Modify the source to fix these.

Check in 1: show off the application working correctly with no warnings from Valgrind.

## Part 2: Application Profiling

### Task 1: slow.c

To start, we'll examine the performance of `slow.c`, a program that finds prime numbers.  This program is fairly optimized but there's one slow function that can be removed.

Profile a run of the process with callgrind and open it with the {K,Q}cachegrind visualizer.

On my system, the function you can replace is one of the top 10 slowest functions. Try to find it and replace it with a more performant alternative.

Check in 2: show how you changed the code and what the performance looks like before and after your fix.


### Task 2: Profiling JQ with perf

JQ is an [open-source](https://github.com/stedolan/jq) CLI utility for parsing json files.

Clone the repo and build it. Install `autoconf` from apt first.

```
git clone --depth=1 https://github.com/stedolan/jq.git && cd jq
git submodule update --init
autoreconf -fi
./configure --with-oniguruma=builtin CFLAGS=-g
make -j
```

You can then run `./jq` to parse a JSON file.

For a non-trivial input file, download `https://gist.githubusercontent.com/EmilGedda/370e487cd658b61139b63d92059e73fd/raw/a3b7358f524b9b62af188707c985e8fc586a9997/seed.json` and run

```
./jq -CS < seed.json
```

Look at the guide to using perf [here](https://www.brendangregg.com/perf.html). Use perf to record the execution of JQ in the following ways:

1) 

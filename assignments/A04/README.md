A04: CDDA Profiling and Optimization
===

[Cataclysm Dark Days Ahead](https://github.com/CleverRaven/Cataclysm-DDA) (CDDA) is an open-source video game which can be run directly in a terminal with ncurses.
For this assignment, you will profile CDDA and try to improve its performance.

If you want to get past the initial game start up, it helps to look at a tutorial such as [this one](https://www.youtube.com/watch?v=bZr1h6fqsBA) - though you can skip ahead to 15:20 to see how the gameplay works if you don't care about config options.
I found that selecting "new game" and then "play now" got things started pretty quickly.

## System setup:

Download the attached Dockerfile, copy it into a directory named `container` and build it with
```
docker build -t cdda container/
```
Be warned, it will take a few *hours* to compile.

Once the container is built, launch it in privileged mode (necessary for `perf` to work) with:
```
docker run --priviliged --rm -it cdda2
```

Inside your container run `cd /Cataclysm-DDA; ./cataclysm` to start the game.

## Tasks:
(Look at the details of how this will be graded before you do all these!)

1) Profile CDDA with `callgrind` and visualize its output with K/Qcachegrind. Capture a screenshot of the visualization.
2) Profile CDDA using `perf` and visualize its output with a [FlameGraph](https://github.com/brendangregg/FlameGraph).
Save the generated image.
3) Using information from your profiler and the CDDA source code, identify 3 or more functions which you think can be optimized to improve the game's performance.  For each, write a sentence or two describing why you think the function is worth optimizing and a high level idea of how to improve it.
4) Recreate (i.e., copy and modify where necessary) one of these functions into a small, stand-alone C program where you can test modifications to it without needing to profile the whole game. You will need to provide the function with some input so you'll need to write that code as well. Measure the time of the function running with the test input. If the time is very small, make your test run it in a loop so you can more easily and reliably see how timing changes if it is modified.
5) Modify the function to improve its performance and measure the resulting time.
6) Copy your modifications back into CDDA, rebuild it by running `cd /cmake-build-debug && make -j` and then profile the application again.
Does the application spend less time in the function you modified? Write a few sentences describing the difference.

## Due date and Grading
This assignment will be due at the end of the day on **Thursday 3/10**.
To help with the pre-spring break workload, it will be graded differently than other assignments:
The first steps are worth most of the points even though they shouldn't take the most time.
In other words, you don't have to do too much work to get a decent grade.

The maximum points for each task are as follows:

* Task 1: 55 points
* Task 2: 15 points
* Task 3: 10 points
* Task 4:  8 points
* Task 5:  7 points
* Task 6:  5 points

If your modifications make the game run more then 0.5% faster and you issue a pull request with your changes
to [the project](https://github.com/CleverRaven/Cataclysm-DDA), you'll get an extra 5 points on the assignment.

## Submission details:
You will submit your code, results and write up through canvas. Please create the file `A03_[your_first_name].tar.gz`
compressed archive with the following directory layout:

```
A04_[your_firstname]/
    1_screenshot.png # other image formats are okay
    2_flamegraph.svg # image generate dby flamegraph is an SVG
    3_slowfuncs.txt  # writeup of functions to maybe optimize
    4_test.c         # the stand-alone version of a function
    4_writeup.txt    # details of how long 4_test.c takes to run
    5_test.c         # the improved version of 4_test.c
    5_writeup.txt    # details of how long 5_test.c takes to run
    6_profile.png    # screenshot of a flamegraph of K/Qcachegrind showing the results of profiling your improved CDDA. Other image formats are okay
    6_writeup.txt    # description of the impact of your changes
```

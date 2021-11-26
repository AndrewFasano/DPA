% CS4910: System Security with Dynamic Program Analysis
% Andrew Fasano
% Jan 18, 2022

# Course Overview

## What is this class?
This is an **experiential, survey course** designed to rapidly introduce you to a variety of dynamic program analysis technologies frequently used for:

* error detection
* software hardening
* performance testing, and
* improving developer comprehension of software

You will learn the theory behind powerful dynamic program analysis techniques and how to apply these analyses using open-source dynamic analysis platforms.

## Course Goals
By the end of the semester you should be able to:

1) Explain common dynamic program analysis techniques, the results each can produce, and the theory behind each.
2) Identify situations in which dynamic program analysis techniques can assist with the process of software development, software testing, and reverse engineering.
3) Leverage dynamic program analysis techniques to improve their ability to design, debug, reverse engineer, or exploit software programs.
4) Discover novel vulnerabilities in compiled applications.

## Who am I?
* Technical Staff at MIT Lincoln Laboratory
* Projects: DEF CON CTF, McAfee CVEs, PANDA.re
* RPISEC alum
* PhD Candidate at Northeastern
    * Advised by Prof. Wil Robertson

Research focused on *rehosting* firmware into virtual execution environments so we can leverage dynamic program analysis to conduct security analyses of embedded systems.

## Who are you?
* Name
* What year are you?
* Last Co-op?
* Favorite programming language and/or text editor?

# Class Logistics

## General Overview
* Always bring a laptop to subsequent classes
    * Recommended: Ubuntu 20.04+ with root access
    * Minimum: a way to run containers
    * Consider: SSH (login.ccs.neu.edu), virtual machines, WSL

    * Windows: Install Ubuntu with [WSL2](https://docs.microsoft.com/en-us/windows/wsl/install) and
     [Docker for WSL2](https://docs.docker.com/desktop/windows/wsl/)
    * OSX: Install [Docker for Mac](https://docs.docker.com/desktop/mac/install/).

* Everything you need is in the class repo: [github.com/AndrewFasano/DPA](https://github.com/AndrewFasano/DPA/)
    * Will be updated throughout the semester as material is released.

## Schedule

### Tuesdays: 11:45-1:25
* Lecture
* Assignments released every other week
* Assignments due at start of class

### Thursdays: 1:30-2:30
* Office hours before class - Location TBD

### Thursdays: 2:50-4:30
* Hands-on labs

## Labs
* 12 hands-on lab exercises to be done\footnote{Occasionally a lab may require some simple pre-class setup (e.g., download a big file). If this happens, it will be announced in advance.} in Thursday class.

* Bring a computer to labs

* Each lab will challenge you to accomplish a set of goals using dynamic analysis
    * Interactive sessions - feel free to ask questions
    * When you finish the tasks (or run out of time), show off your solutions to get full or partial credit.
     Feel free to leave early if you finish with time remaining

* Mandatory attendance, but lowest lab grade will be dropped

## Assignments
Five assignments throughout the semester. Typically released at end of class on Tuesday and due 2 weeks later

* A01: Instruction tracing
* A02: Side channel coverage maximization
* A03: Taint analysis
* A04: Binary performance optimization (due on Thursday, March 17)
* A05: Root cause analysis with timeless debugging

## Final Project
For the final 3 weeks of the course, you will work on open-ended final projects in pairs.
During this time, no other projects will be assigned, though lectures and lab exercises will continue as normal.

## Grading
- Labs: 30%
- Assignments 50%
- Final Project 20%

## Questions
Is anything unclear about how the class will run?

# Debuggers

## Todo
- Put
- Content
- Here

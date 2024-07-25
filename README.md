# System Security with Dynamic Program Analysis - CS4910

This repository contains the material used for Northeastern University's
2022 Spring semester class *System Security with Dynamic Program Analysis*
developed by Andrew Fasano with support from William Robertson and Markus Gaasedelen.

## About this class
This is an experiential, survey course designed to rapidly introduce students to a variety of dynamic program analysis technologies frequently used to perform error detection, software hardening, performance testing, and improve developer comprehension of software. Students will learn the theory behind powerful dynamic program analysis techniques and how to apply these analyses using open-source dynamic analysis platforms.


### Topics covered by this course include:
The following dynamic program analysis techniques:
* Error detection using sanitizers and fuzzers
* Software hardening with control flow integrity and memory tagging
* Performance testing for cache simulation, application profiling, and program optimization
* Software understanding using whole-system tracing, timeless debugging, slicing, and forced execution

The following open-source dynamic program analysis tools:
* GDB
* DynamoRIO
* Valgrind & Callgrind
* Frida
* PANDA.re
* Mozilla RR
* American Fuzzy Lop (AFL)


## Schedule

| Week   | Tuesday Lecture                                                    | Thursday Lab                  | Assignments                                                    |
| ----   | ------------------------------------------------------------------ | -------------                 |        ---:                                                    |
| Jan 16 | L01: `Intro to dynamic analysis`                                   | LAB01: `GDB Scripting`        | Release A01: `Instruction trace` |
| Jan 23 | L02: `Dynamic Binary Instrumentation (DBI): Introduction & Theory` | LAB02: `Coverage Collection`  |- |
| Jan 30 | L03: `DBI: Applications, limitations, and ongoing research`        | LAB03: `API Logging`          | **A01 due!** Release A02: `Side channel coverage maximization` |
| Feb 6  | L04: `Sanitizers`                                                  | LAB04: `CustomSanitizer`      | - |
| Feb 13 | L05: `Hypervisors: theory & virtual machine introspection (VMI)`   | LAB05: `PANDA Tracer`         | **A02 due!** Release A03: `Taint analysis` |
| Feb 20 | L06: `Hypervisors: applications, limitations, and ongoing research`| LAB06: `Cache Simulation`     | - |
| Feb 27 | L07 `Application profiling`                                        | LAB07: `Memory Leak Detection`| **A03 due!** Release A04 `Binary performance optimization` |
| Mar 6  | L08: `Binary patching & reverse engineering`                       | LAB08: `SSH Backdoor`         | **A04 due Thursday** |
| Mar 13 | *Spring Break*                                                     |                               | - 
| Mar 20 | L09: `Timeless debugging`                                          | LAB09: `CrackMe Challenge`    | Release A05: `Root cause analysis` |
| Mar 27 | L10: `Forced execution`                                            | LAB10: `CFG Reconstruction`   | **Final project proposals due** |
| Apr 3  | L11: `Dynamic program slicing`                                     | LAB11: `CrackMe V2`           | **A05 due** |
| Apr 10 | L12: `Fuzzing`                                                     | LAB12: `CTF Challenge`        | - |
| Apr 17 | L13: `Static Program Analysis`                                     | Project Check-ins             | - |
| Apr 24 | Final Project Presentations                                        | Final Project Presentations   | - |

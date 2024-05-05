# Contributing to Mimesis

In the current prototype of Mimesis, it employs S2E for full-system symbolic
execution to analyze a given network function program binaries together with the
Linux kernel running in a QEMU KVM. We implemented a custom S2E plugin to
control the symbolic execution process, combined with a kernel module built with
SystemTap to automatically instrument the Linux kernel for (1) injecting
a symbolic packet/frame as input, (2) recording the egress packets/frames, and
(3) terminating the symbolic execution.

## Background

To understand the design of Mimesis, it is encouraged to read through the code
directly. However, the following documentations provide some background
knowledge of S2E, SystemTap, QEMU, and BDDs, which may be helpful.

- S2E
    - [Getting started with S2E](https://s2e.systems/docs/s2e-env.html)
    - [Symbolic execution of Linux binaries](https://s2e.systems/docs/Tutorials/BasicLinuxSymbex/s2e.so.html)
    - [How to write an S2E plugin](https://s2e.systems/docs/Howtos/WritingPlugins.html)
    - [Copying files between the host and the guest](https://s2e.systems/docs/MovingFiles.html)
    - [Using SystemTap with S2E](https://s2e.systems/docs/Tutorials/SystemTap/index.html)
    - [Solving a CTF challenge with S2E](https://adrianherrera.github.io/posts/google-ctf-2016/)
- SystemTap
    - [SystemTap documentation](https://sourceware.org/systemtap/documentation.html)
    - [Understanding how SystemTap works (Red Hat)](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/5/html/systemtap_beginners_guide/understanding-how-systemtap-works)
    - [SystemTap - filtering and analyzing system data (SUSE)](https://documentation.suse.com/sles/15-SP3/html/SLES-all/cha-tuning-systemtap.html)
- QEMU
    - [QEMU Documentation/Networking](https://wiki.qemu.org/Documentation/Networking)
- BDDs
    - [Sylvan documentation](https://trolando.github.io/sylvan/)
    - [Graph-Based Algorithms for Boolean Function Manipulation (IEEE ToC '86)](https://ieeexplore.ieee.org/document/1676819)
    - [Solving Quantified Bit-Vector Formulas Using Binary Decision Diagrams (SAT '16)](https://link.springer.com/chapter/10.1007/978-3-319-40970-2_17)

## Where to start?

Please take a look at the code in an order similar to the following to
understand how Mimesis works.

- [`depends/setup.sh`](depends/setup.sh)
- [`scripts/build.sh`](scripts/build.sh)
- [`scripts/s2e.sh`](scripts/s2e.sh)
- [`src/sender.cpp`](src/sender.cpp)
- [`src/symbolic_ingress.stp`](src/symbolic_ingress.stp)
- [`src/s2e/libs2eplugins/src/s2e/Plugins/Mimesis.cpp`](https://github.com/kyechou/s2e/blob/master/libs2eplugins/src/s2e/Plugins/Mimesis.cpp)
- [`src/libps/manager.cpp`](src/libps/manager.cpp)
- [`src/libps/packetset.cpp`](src/libps/packetset.cpp)
- [`src/libps/klee-interpreter.cpp`](src/libps/klee-interpreter.cpp)
- [`src/libps/bitvector.cpp`](src/libps/bitvector.cpp)
- [`src/libps/bdd.cpp`](src/libps/bdd.cpp)

## Improvements

> **Note**<br/>
> Please see [the project notes](https://docs.google.com/document/d/1DTFy8Y3sblX8h9iD1Tc2zBdvMxYGR0wcHf0uoIkLcK0/edit)
> for all the updates and action items.

Functional to-do items.

- [x] Parse the SMT constraints into BDD-based packet sets. (ongoing)
- [x] Build the library for BDD-based packet sets. (ongoing)
- [ ] Create the NF model class/module. (ongoing)

Performance to-do items.

- [ ] [Parallelize the analysis.](https://s2e.systems/docs/Howtos/Parallel.html)
- [ ] [Concolic execution.](https://s2e.systems/docs/Howtos/Concolic.html)
- [ ] [State merging.](https://s2e.systems/docs/StateMerging.html)
- [ ] [Fork profiling.](https://s2e.systems/docs/Tools/ForkProfiler.html)
- [ ] [(FAQ) Handling path explostion.](https://s2e.systems/docs/FAQ.html#how-do-i-deal-with-path-explosion)
- [ ] [(FAQ) Logging for constraint solving queries.](https://s2e.systems/docs/FAQ.html#how-much-time-is-the-constraint-solver-taking-to-solve-constraints)
- [ ] [Profiling CPU and memory usage.](https://s2e.systems/docs/Profiling/ProfilingS2E.html)

## Participation

To report bugs, fix issues, or provide code changes, please either
[file an issue](https://github.com/kyechou/mimesis/issues/new/choose) or
[submit a pull request](https://docs.github.com/en/get-started/exploring-projects-on-github/contributing-to-a-project).

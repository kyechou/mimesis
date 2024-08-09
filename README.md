# Mimesis

Mimesis is a formal model extraction tool that automatically generates a model
describing all packet forwarding behavior given a software network function as
input. It utilizes S2E, KLEE, and LLVM for symbolic execution on the binary of
the input network function to analyze its packet forwarding behavior, and
translates the resulting SMT formulas to BDD-based structures. The extracted
model covers all (potentially stateful) packet forwarding behavior and is
compactly encoded in our custom format. The model output can be queried
independently or used in other formal analysis, including network verification.

<!--toc:start-->
- [Mimesis](#mimesis)
  - [Environment setup](#environment-setup)
  - [Build Mimesis and S2E](#build-mimesis-and-s2e)
  - [Usage](#usage)
    - [Create a new analysis project](#create-a-new-analysis-project)
    - [Run the symbolic execution](#run-the-symbolic-execution)
    - [Remove the analysis projects (Optional)](#remove-the-analysis-projects-optional)
  - [Future work](#future-work)
<!--toc:end-->

## Environment setup

We provide a convenience script `depends/setup.sh` to automate the setup process
for the dependencies required to build and run Mimesis. Currently the script
only supports Arch Linux and Ubuntu 22.04. Please read `depends/setup.sh` for
the details if one wants to install them manually.

After cloning the repository, enter the directory and run the following command.
This will set up S2E and build the QEMU VM image required for the symbolic
analysis. The results will be at the `s2e/` directory.

```sh
$ ./depends/setup.sh
```

> [!IMPORTANT]
> After running the setup script, it is crucial to logout and re-login again for
> the new group configuration to take effect. Otherwise, there may be permission
> errors from Docker. Alternatively, you can also reboot the OS entirely.

## Build Mimesis and S2E

To build Mimesis, including the core libraries, example target programs,
SystemTap modules, and the custom S2E plugin, please run:

```sh
$ ./scripts/build.sh --mimesis --stap --s2e
```

> [!NOTE]
> If any Mimesis code, SystemTap scripts, or the S2E code in `src/s2e/` are
> modified, you can rebuild all of them by running the command again.

## Usage

Here we demonstrate step by step how to use Mimesis to extract a formal model
from the example network function program `user-demo-stateless`, which is
located at `build/targets/user-demo-stateless`.

### Create a new analysis project

The first step is to create a new analysis project via S2E with the following
command. The created project will be located at `s2e/projects/mimesis/`.

```sh
$ ./scripts/s2e.sh -n ./build/targets/user-demo-stateless
```

> [!IMPORTANT]
> Creating a new analysis project will remove the previously created projects
> (maybe of a different target program). You can manually save the previous
> project directories if so desired.

> [!NOTE]
> It is possible to specify the number of interfaces (default: 8) for the
> extracted model. See `./scripts/s2e.sh -h` for more details.

### Run the symbolic execution

Once the project is created, you can start the analysis by running the following
command. The `-c` option force-removes any files of previous runs, and the `-r`
option starts the symbolic execution.

```sh
$ ./scripts/s2e.sh -c -r
```

(TODO: Explain how to interpret the result.)

### Remove the analysis projects (Optional)

When the symbolic execution is completed, you can remove the created projects by
running the following command.

```sh
$ ./scripts/s2e.sh --rm
```

## Future work

The current prototype is built upon S2E and KLEE. However, the core idea of
Mimesis is not tied to a specific implementation. It is possible to implement
Mimesis on other symbolic analysis tools such as Angr. This may be helpful to
expand the scope of supported programs to DPDK-based network functions, which
are not currently supported due to the limitation of S2E's QEMU.

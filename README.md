# Mimesis

Model extraction for stateful network functions.

## Environment setup

### S2E

You can set up the environment and S2E by running the following command. This
will set up `s2e-env`, `s2e`, and build VM images required for analysis. The
results will be inside the `s2e.<distro>/` directory.

```sh
$ ./depends/setup.sh
```

> **Note**<br/>
> The script will automatically detect your Linux distribution. However, only
> Arch and Ubuntu 22.04 are currently supported.

### Target programs

To build the example target programs, from which the models are extracted,
please run:

```sh 
$ ./scripts/configure.sh
$ ./scripts/build.sh
```

The program binaries will be inside `build/targets/` directory.

## Usage

### Create a new analysis project

(TODO)

```sh 
$ source ./scripts/activate.sh
$ s2e new_project -t linux -n <name> -i ubuntu-22.04-x86_64 <target program> [<arguments>]
```

Later when you finish, you can deactivate the environments by:

```sh 
$ _deactivate
```


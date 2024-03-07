# Mimesis

Model extraction for stateful network functions.

## Environment setup

### S2E

You can set up the environment and S2E by running the following command. This
will set up `s2e-env`, `s2e`, and build the VM image required for analysis. The
results will be inside the `s2e/` directory.

```sh
$ ./depends/setup.sh
```

> **Note**<br/>
> The script will automatically detect your Linux distribution. However, only
> Arch and Ubuntu 22.04 are currently supported.

If the S2E source code in `src/s2e/` is modified, you can rebuild S2E with

```sh 
$ ./scripts/build.sh --s2e
```

### Mimesis & Target programs

To build Mimesis and the example target programs, from which the models are
extracted, please run:

```sh 
$ ./scripts/build.sh --targets --stap --s2e
```

The results will be inside the `build/` directory.

## Usage

### Analyze a given program with S2E

Create a new analysis project. It will be located at `s2e/s2e/projects/mimesis`.
Note that this step will also patch the `bootstrap.sh` inside the project
directory to load *all* compiled systemtap kernel modules. You can manually edit
the `bootstrap.sh` according to the needs.

```sh 
$ ./scripts/s2e.sh [-i <num_intfs>] -n <target program> [<arguments>]
```

For example,

```sh 
$ ./scripts/s2e.sh -n ./build/targets/hello-world-1
$ ./scripts/s2e.sh -n ./build/targets/demo-router-1
```

Once an S2E project is created, you can run the analysis:

```sh 
$ ./scripts/s2e.sh -c -r
```

To remove *all* S2E projects, run:

```sh 
$ ./scripts/s2e.sh --rm
```

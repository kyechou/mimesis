# Mimesis

Model extraction for network functions.

## Environment setup

You could probably set up everything needed by running:

```sh
$ ./deps/setup.sh
```

## Usage

### Reproduce the experiments

In order to reproduce the experiments, one could simply run the script
`./experiments/run.sh`. It should use McSema, IDA Pro, and KLEE to concolically
explore the network functions as written in the script, and generate the output
directories within the `experiments` directory. `./experiments/collect-stats.sh`
can be used to collect the statistics of all output directories within
`experiments`.

### Manual analysis

To analyze each network function individually, one could take a look at the
`./experiments/run.sh` as a reference or follow these steps.

#### Get network function and driver bitcodes

You can use `Makefile` to build the LLVM IR bitcode of network function
programs and the driver. For example, the following command will first build the
target network function binary `targets/router-s1`, and then use McSema to lift
the binary to get LLVM IR bitcode.

```sh
make router-s1.bc
```

And this command would build the driver bitcode from source.

```sh
make driver.bc
```

Or you could simply use `make` to get all the bitcode files of network functions
and the driver.

#### Concolic execution with KLEE

Once we have the target program and the driver bitcode files, you can use
`klee.sh` to concolically execute the network function with the driver. It will
generate an output directory called `klee-out-*`, pointed to by a symbolic link
`klee-last`.

You might want to modify KLEE's command-line options specified within `klee.sh`
to meet your purpose, or to link additional library bitcode files.

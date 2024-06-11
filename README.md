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

### Mimesis

To build Mimesis, including the core libraries, SystemTap modules, and the S2E
plugins, please run:

```sh
$ ./scripts/build.sh --mimesis --stap --s2e
```

## Usage

### Analyze a given program with S2E

To analyze a given network function program with Mimesis, the first step is to
create a new analysis project with S2E with the following command. The created
project will be located at `s2e/projects/mimesis`.

> **Note**<br/>
> This step will also patch `s2e/projects/mimesis/bootstrap.sh` to load *all*
> the compiled systemtap kernel modules. You can manually edit the
> `bootstrap.sh` afterwards according to your needs.

```sh
$ ./scripts/s2e.sh [-i <num_intfs>] -n <target program> [<arguments>]
```

For example, the following commands create a project for analyzing the
`hello-world-1` program and the `demo-r1` program, respectively.

```sh
$ ./scripts/s2e.sh -n ./build/targets/hello-world-1
$ ./scripts/s2e.sh -n ./build/targets/demo-r1
```

Once an S2E project is created, you can run the analysis with:

```sh
$ ./scripts/s2e.sh -c -r
```

To remove *all* S2E projects, run:

```sh
$ ./scripts/s2e.sh --rm
```

Please see `./scripts/s2e.sh -h` for all available options.

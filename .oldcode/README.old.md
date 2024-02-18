# Mimesis

Middlebox analysis for network verification.

Middleboxes (or network functions) have been an issue when it comes to network
verification. The problem is the lack of accurate models for these complicated
middleboxes that can describe the behavior of the actual implementations
faithfully, due to the lack of standards, implementation bugs, and
implementation quirks across vendors. In this work, we focus on the software
network functions and apply binary analysis on them with an aim to formulate the
mapping between the inputs and outputs of such network function programs. We
tested our approach on an example load balancer that we implemented, and the
result shows that it is possible to get an accurate model within reasonable
resource consumption using binary analysis. Finally, we describe some
limitations of the method.

## How to reproduce the experiments

### Dependencies

- A modern compiler for C, C++ (GCC or Clang)
- Python 3 (tested with version 3.8.0)
- angr (tested with version 8.19.10.30)

#### Installing angr using python venv

First clone the repository and enter the directory.

```bash
$ git clone https://github.com/kyechou/mimesis.git
$ cd mimesis
```

Then create a new venv to install angr with pip.

```bash
$ python -m venv angr.venv
$ source angr.venv/bin/activate
(angr.venv) $ pip install angr
(angr.venv) $ ... # do anything you want
(angr.venv) $ deactivate
```

### Running experiments

You can run the individual experiments manually by:
```bash
$ cd mimesis
$ source angr.venv/bin/activate
(angr.venv) $ make -j -C angr/<experiment-name>
(angr.venv) $ python angr/<experiment-name>/solve.py [OPTIONS]
```
, where `<experiment-name>` should be changed to the directory of any experiment
you wish to run, and also you can use `-h` or `--help` option to see all the
supported options for each solving script.

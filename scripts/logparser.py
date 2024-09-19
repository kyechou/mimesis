#!/usr/bin/env python3

import argparse
import logging
import os
import re

import pandas as pd


def gnu_time_str_to_usec(time_str: str) -> int:
    if re.match(r"(\d+):(\d+)\.(\d+)", time_str):
        m = re.match(r"(\d+):(\d+)\.(\d+)", time_str)
        assert m is not None
        min = int(m.group(1))
        sec = int(m.group(2))
        subsec = str(m.group(3))
        assert (6 - len(subsec)) >= 0
        usec = int(subsec) * (10 ** (6 - len(subsec)))
        usec += (min * 60 + sec) * (10**6)
    elif re.match(r"(\d+):(\d+):(\d+)", time_str):
        m = re.match(r"(\d+):(\d+):(\d+)", time_str)
        assert m is not None
        hour = int(m.group(1))
        min = int(m.group(2))
        sec = int(m.group(3))
        usec = ((hour * 60 + min) * 60 + sec) * (10**6)
    else:
        raise Exception("Unknown GNU time: '" + time_str + "'")
    return usec


def parse_log(logfn, stats):
    if not os.path.exists(logfn):
        raise Exception("Log file not found: '{}'".format(logfn))
    m = re.match(r"(.*)-depth-(\d+)(-kfork)?(-ksymaddr)?\.log", os.path.basename(logfn))
    assert m is not None
    program_name = m.group(1)
    depth = int(m.group(2))
    kfork = bool(m.group(3))
    ksymaddr = bool(m.group(4))
    system_startup_time = 0
    sym_exec_time = 0
    trace_record_time = 0
    num_traces = 0
    model_export_time = 0
    memory = 0

    # timestamps
    onInitializationComplete = 0
    onProcessLoad = 0
    startInsertTrace = 0
    finishInsertTrace = 0
    onEngineShutdown = 0
    startExport = 0
    finishExport = 0

    with open(logfn) as log:
        for line in log:
            if "onInitializationComplete" in line:
                m = re.search(
                    r"Timestamp: \(onInitializationComplete\) (\d+\.\d+)", line
                )
                assert m is not None
                onInitializationComplete = float(m.group(1))
            elif "onProcessLoad" in line:
                m = re.search(r"Timestamp: \(onProcessLoad\) (\d+\.\d+)", line)
                assert m is not None
                onProcessLoad = float(m.group(1))
            elif "startInsertTrace" in line:
                m = re.search(r"Timestamp: \(startInsertTrace\) (\d+\.\d+)", line)
                assert m is not None
                startInsertTrace = float(m.group(1))
            elif "finishInsertTrace" in line:
                m = re.search(r"Timestamp: \(finishInsertTrace\) (\d+\.\d+)", line)
                assert m is not None
                finishInsertTrace = float(m.group(1))
                trace_record_time += finishInsertTrace - startInsertTrace
                num_traces += 1
            elif "onEngineShutdown" in line:
                m = re.search(r"Timestamp: \(onEngineShutdown\) (\d+\.\d+)", line)
                assert m is not None
                onEngineShutdown = float(m.group(1))
            elif re.search(r"Timestamp: \(startExport .*\.model\) (\d+\.\d+)", line):
                m = re.search(r"Timestamp: \(startExport .*\.model\) (\d+\.\d+)", line)
                assert m is not None
                startExport = float(m.group(1))
            elif re.search(r"Timestamp: \(finishExport .*\.model\) (\d+\.\d+)", line):
                m = re.search(r"Timestamp: \(finishExport .*\.model\) (\d+\.\d+)", line)
                assert m is not None
                finishExport = float(m.group(1))
            elif "maxresident" in line:
                m = re.search(r" (\d+)maxresident", line)
                assert m is not None
                memory = int(m.group(1))

    system_startup_time = onProcessLoad - onInitializationComplete
    sym_exec_time = onEngineShutdown - onProcessLoad - trace_record_time
    model_export_time = finishExport - startExport

    stats["program_name"].append(program_name)
    stats["depth"].append(depth)
    stats["kfork"].append(kfork)
    stats["ksymaddr"].append(ksymaddr)
    stats["system_startup_time"].append(system_startup_time)
    stats["sym_exec_time"].append(sym_exec_time)
    stats["trace_record_time"].append(trace_record_time)
    stats["num_traces"].append(num_traces)
    stats["model_export_time"].append(model_export_time)
    stats["memory"].append(memory)


def main():
    parser = argparse.ArgumentParser(description="Log parser for Mimesis")
    parser.add_argument("-l", "--logs", help="Log directory", type=str, action="store")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

    if args.logs:
        log_dir = os.path.abspath(args.logs)
    else:
        project_dir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
        log_dir = os.path.join(project_dir, "output")
    if not os.path.isdir(log_dir):
        raise Exception("'{}' is not a directory".format(log_dir))

    # Time: float (seconds), memory: int (KiB)
    stats = {
        "program_name": [],
        "depth": [],
        "kfork": [],
        "ksymaddr": [],
        "system_startup_time": [],
        "sym_exec_time": [],
        "trace_record_time": [],
        "num_traces": [],
        "model_export_time": [],
        "memory": [],
    }

    for entry in os.scandir(log_dir):
        if not entry.is_file() or not entry.name.endswith(".log"):
            continue
        if re.search(r"\d+-\d+-\d+T\d+:\d+:\d+", entry.name):
            continue

        logging.info("Processing %s", entry.name)
        parse_log(entry.path, stats)

    stats_df = pd.DataFrame.from_dict(stats)
    stats_df.to_csv(os.path.join(log_dir, "stats.csv"), encoding="utf-8", index=False)


if __name__ == "__main__":
    main()

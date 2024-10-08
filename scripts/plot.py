#!/usr/bin/env python3

import argparse
import os
import logging
import numpy as np
import pandas as pd
from matplotlib import pyplot as plt
from math import floor

LINE_WIDTH = 3
colors = [
    "#1f77b4",
    "#ff7f0e",
    "#2ca02c",
    "#d62728",
    "#9467bd",
    "#8c564b",
    "#e377c2",
    "#7f7f7f",
    "#bcbd22",
    "#17becf",
]


def values_compare(series):
    ids = {
        # programs
        "ST-2": 2,
        "ST-1": 3,
        "ISP-6": 4,
        "ISP-5": 5,
        "ISP-4": 6,
        "ISP-3": 7,
        "ISP-2": 8,
        "ISP-1": 9,
        # drop methods
        "timeout": 11,
        "dropmon": 12,
        "ebpf": 13,
        # LB algorithms
        "lbs": 20,  # not an algorithm column
        "rr": 21,
        "mh": 22,
        "dh": 23,
        "sh": 24,
        "lc": 25,
    }
    if isinstance(series, str):
        return ids[series]
    return series.apply(lambda m: -m if isinstance(m, int) else ids[m])


def rewrite_values(df):
    # ISP-1 (AS 3967)                      & 79    & 147   & 441
    # ISP-2 (AS 1755)                      & 87    & 161   & 483
    # ISP-3 (AS 1221)                      & 108   & 153   & 459
    # ISP-4 (AS 6461)                      & 141   & 374   & 1122
    # ISP-5 (AS 3257)                      & 161   & 328   & 984
    # ISP-6 (AS 1239)                      & 315   & 972   & 2916
    # ST-1 (Stanford AS-level)             & 103   & 239   & 717
    # ST-2 (Stanford AS-level)             & 1470  & 3131  & 9393

    # networks
    df = (
        df.replace("rocketfuel-bb-AS-3967", "ISP-1")
        .replace("rocketfuel-bb-AS-1755", "ISP-2")
        .replace("rocketfuel-bb-AS-1221", "ISP-3")
        .replace("rocketfuel-bb-AS-6461", "ISP-4")
        .replace("rocketfuel-bb-AS-3257", "ISP-5")
        .replace("rocketfuel-bb-AS-1239", "ISP-6")
        .replace("network-core1", "core1")
        .replace("network-core2", "core2")
        .replace("network-core4", "core4")
        .replace("network-core5", "core5")
        .replace("network-core8", "core8")
        .replace("network-core9", "core9")
        .replace("network-all", "all")
    )
    if "num_nodes" in df:
        df.loc[(df["network"] == "as-733") & (df["num_nodes"] == 103), "network"] = (
            "ST-1"
        )
        df.loc[(df["network"] == "as-733") & (df["num_nodes"] == 1470), "network"] = (
            "ST-2"
        )
    else:
        df.loc[(df["network"] == "as-733") & (df["total_mem"] < 1000000), "network"] = (
            "ST-1"
        )
        df.loc[
            (df["network"] == "as-733") & (df["total_mem"] >= 1000000), "network"
        ] = "ST-2"
    return df


def plot_15_perf_vs_networks(df, outDir):
    def _plot(df, outDir, emu_pct, num_invs, nproc, drop):
        # Sorting
        df = df.sort_values(by=["network"])
        # Change units
        df["total_time"] /= 1e6  # usec -> sec
        df["total_mem"] /= 1024  # KiB -> MiB
        # Rename columns
        df = df.rename(
            columns={
                "total_time": "Time",
                "total_mem": "Memory",
            }
        )

        # Plot time/memory
        ax = df.plot(
            x="network",
            y="Time",
            kind="bar",
            legend=False,
            width=0.8,
            xlabel="",
            ylabel="",
            # rot=0,
            rot=-30,
        )
        ax = df.plot(
            x="network",
            secondary_y=["Memory"],
            mark_right=False,
            kind="bar",
            legend=False,
            width=0.8,
            xlabel="",
            ylabel="",
            # rot=0,
            rot=-30,
        )

        # Merge legends
        h1, l1 = ax.get_legend_handles_labels()
        h2, l2 = ax.right_ax.get_legend_handles_labels()
        ax.legend(
            h1 + h2,
            l1 + l2,
            bbox_to_anchor=(1.0, 1.2),
            ncol=2,
            fontsize=22,
            frameon=False,
            fancybox=False,
        )

        ax.grid(axis="y")
        # ax.set_yscale('log')
        # ax.set_xlabel('Network', fontsize=22)
        ax.set_ylabel("Time (seconds)", fontsize=22)
        ax.tick_params(axis="both", which="both", labelsize=22)
        ax.tick_params(axis="x", which="both", top=False, bottom=False)
        ax.right_ax.grid(axis="y")
        # mem_start_val = (floor(df.inv_memory.min()) - 1) // 10 * 10
        # ax.right_ax.set_ylim(bottom=mem_start_val)
        ax.right_ax.set_ylabel("Memory (MiB)", fontsize=22)
        ax.right_ax.tick_params(axis="both", which="both", labelsize=22)
        fig = ax.get_figure()
        fn = os.path.join(
            outDir,
            (
                "15.perf-network.emu_pct-"
                + str(emu_pct)
                + "."
                + str(num_invs)
                + "-invs."
                + str(nproc)
                + "-procs."
                + drop
                + ".pdf"
            ),
        )
        fig.savefig(fn, bbox_inches="tight")
        plt.close("all")

    for emu_pct in df.emulated_pct.unique():
        emu_df = df[df.emulated_pct == emu_pct].drop(["emulated_pct"], axis=1)

        for num_invs in emu_df.invariants.unique():
            ninvs_df = emu_df[emu_df.invariants == num_invs].drop(
                ["invariants"], axis=1
            )

            for nproc in ninvs_df.procs.unique():
                nproc_df = ninvs_df[ninvs_df.procs == nproc].drop(["procs"], axis=1)

                for drop in nproc_df.drop_method.unique():
                    d_df = nproc_df[nproc_df.drop_method == drop].drop(
                        ["drop_method"], axis=1
                    )

                    _plot(d_df, outDir, emu_pct, num_invs, nproc, drop)


def plot_15_perf_vs_emulated_pct(df, outDir):
    # Sorting
    df = df.sort_values(by=["emulated_pct"])
    # Change units
    df["total_time"] /= 1e6  # usec -> sec
    df["total_mem"] /= 1024  # KiB -> MiB
    # Rename columns
    df = df.rename(
        columns={
            "total_time": "Time",
            "total_mem": "Memory",
        }
    )

    # Plot time
    time_df = df.pivot(
        index="emulated_pct", columns="network", values="Time"
    ).reset_index()
    ax = time_df.plot(
        x="emulated_pct",
        y=["ISP-1", "ISP-2", "ISP-3", "ISP-4", "ISP-5", "ISP-6", "ST-1", "ST-2"],
        kind="bar",
        legend=False,
        width=0.8,
        xlabel="",
        ylabel="",
        rot=0,
    )
    ax.legend(
        bbox_to_anchor=(1.05, 1.46),
        columnspacing=0.7,
        ncol=3,
        fontsize=22,
        frameon=False,
        fancybox=False,
    )
    ax.grid(axis="y")
    ax.set_yscale("log")
    ax.set_xlabel("Percentage of emulated nodes (%)", fontsize=22)
    ax.set_ylabel("Time (seconds)", fontsize=22)
    ax.tick_params(axis="both", which="both", labelsize=22)
    ax.tick_params(axis="x", which="both", top=False, bottom=False)
    fig = ax.get_figure()
    fn = os.path.join(outDir, "15.time-emu_pct.16-invs.1-procs.timeout.pdf")
    fig.savefig(fn, bbox_inches="tight")
    plt.close(fig)
    fn = os.path.join(outDir, "15.time-emu_pct.16-invs.1-procs.timeout.txt")
    with open(fn, "w") as fout:
        fout.write(time_df.to_string())

    # Plot memory
    mem_df = df.pivot(
        index="emulated_pct", columns="network", values="Memory"
    ).reset_index()
    ax = mem_df.plot(
        x="emulated_pct",
        y=["ISP-1", "ISP-2", "ISP-3", "ISP-4", "ISP-5", "ISP-6", "ST-1", "ST-2"],
        kind="bar",
        legend=False,
        width=0.8,
        xlabel="",
        ylabel="",
        rot=0,
    )
    ax.legend(
        bbox_to_anchor=(1.05, 1.46),
        columnspacing=0.7,
        ncol=3,
        fontsize=22,
        frameon=False,
        fancybox=False,
    )
    ax.grid(axis="y")
    # ax.set_yscale('log')
    ax.set_xlabel("Percentage of emulated nodes (%)", fontsize=22)
    ax.set_ylabel("Memory (MiB)", fontsize=22)
    ax.tick_params(axis="both", which="both", labelsize=22)
    ax.tick_params(axis="x", which="both", top=False, bottom=False)
    fig = ax.get_figure()
    fn = os.path.join(outDir, "15.memory-emu_pct.16-invs.1-procs.timeout.pdf")
    fig.savefig(fn, bbox_inches="tight")
    plt.close(fig)
    fn = os.path.join(outDir, "15.memory-emu_pct.16-invs.1-procs.timeout.txt")
    with open(fn, "w") as fout:
        fout.write(mem_df.to_string())


def plot_15(neoDir: str, clabDir: str, outDir: str) -> None:
    # Get neo df
    neo_df = pd.read_csv(os.path.join(neoDir, "stats.csv"))
    neo_df = rewrite_values(neo_df)
    # Filter columns
    neo_df = neo_df.drop(
        [
            "inv_time",
            "inv_memory",
            "fw_leaves_pct",
            "invariants",
            "procs",
            "drop_method",
            "num_nodes",
            "num_links",
            "num_updates",
            "total_conn",
            "invariant",
            "independent_cec",
            "violated",
        ],
        axis=1,
    )
    neo_df.drop_duplicates(inplace=True)
    # Get emulation (clab) df
    clab_df = pd.read_csv(os.path.join(clabDir, "stats.csv"))
    clab_df = rewrite_values(clab_df)
    clab_df["total_mem"] = clab_df["total_mem"] + clab_df["container_memory"]
    clab_df = clab_df.drop(["container_memory"], axis=1)
    clab_df["emulated_pct"] = 100
    # Combine the dfs
    df = pd.concat([neo_df, clab_df])
    df = df.sort_values(by=["network", "emulated_pct"])
    # Plot
    plot_15_perf_vs_emulated_pct(df, outDir)


def cites_network_compare(series):
    ids = {
        # networks
        "core1": 5,
        "core2": 6,
        "core3": 7,
        "core4": 8,
        "core5": 9,
        "core6": 10,
        "core7": 11,
        "core8": 12,
        "core9": 13,
        "core10": 14,
        "all": 15,
    }
    # if isinstance(series, str):
    #     return ids[series]
    return series.apply(lambda m: -m if isinstance(m, int) else ids[m])


def plot_17(neoDir: str, clabDir: str, outDir: str) -> None:
    # Get neo df
    neo_df = pd.read_csv(os.path.join(neoDir, "stats.csv"))
    neo_df = rewrite_values(neo_df)
    # Filter columns
    neo_df = neo_df.drop(
        [
            "inv_time",
            "inv_memory",
            "procs",
            "drop_method",
            "num_nodes",
            "num_links",
            "num_updates",
            "total_conn",
            "invariant",
            "independent_cec",
            "violated",
        ],
        axis=1,
    )
    neo_df.drop_duplicates(inplace=True)
    neo_df = neo_df.rename(
        columns={
            "total_time": "Time (Neo)",
            "total_mem": "Memory (Neo)",
        }
    )
    # Get emulation (clab) df
    clab_df = pd.read_csv(os.path.join(clabDir, "stats.csv"))
    clab_df = rewrite_values(clab_df)
    clab_df["total_mem"] = clab_df["total_mem"] + clab_df["container_memory"]
    clab_df = clab_df.drop(["container_memory"], axis=1)
    # Filter rows
    clab_df = clab_df[
        (clab_df["network"] != "core6") & (clab_df["network"] != "core10")
    ]
    assert type(clab_df) is pd.DataFrame
    clab_df = clab_df.rename(
        columns={
            "total_time": "Time (Emulation)",
            "total_mem": "Memory (Emulation)",
        }
    )
    # Combine the dfs
    df = pd.concat([neo_df, clab_df])
    df = df.groupby("network").sum().reset_index()
    # Compute the quotient
    df["time_improve"] = df["Time (Emulation)"] / df["Time (Neo)"]
    df["memory_cost"] = df["Memory (Neo)"] / df["Memory (Emulation)"]

    # Plot
    # Sorting
    df = df.sort_values(by=["network"], key=cites_network_compare, ascending=True)
    # Change units
    for col in df.columns:
        if "Time" in col:
            df[col] /= 1e6  # usec -> sec
        elif "Memory" in col:
            df[col] /= 1024  # KiB -> MiB
    # Plot time
    time_df = df.rename(
        columns={
            "Time (Neo)": "Neo",
            "Time (Emulation)": "Emulation",
        }
    )
    ax = time_df.plot(
        x="network",
        y=["Neo", "Emulation"],
        kind="bar",
        legend=False,
        width=0.8,
        xlabel="",
        ylabel="",
        rot=25,
    )
    ax.legend(
        bbox_to_anchor=(1.05, 1.2),
        columnspacing=0.7,
        ncol=2,
        fontsize=22,
        frameon=False,
        fancybox=False,
    )
    ax.grid(axis="y")
    ax.set_yscale("log")
    ax.set_xlabel("Network", fontsize=22)
    ax.set_ylabel("Time (seconds)", fontsize=22)
    ax.tick_params(axis="both", which="both", labelsize=22)
    ax.tick_params(axis="x", which="both", top=False, bottom=False)
    fig = ax.get_figure()
    fn = os.path.join(outDir, "17.time-network.1-procs.timeout.pdf")
    fig.savefig(fn, bbox_inches="tight")
    plt.close(fig)
    # Plot memory
    mem_df = df.rename(
        columns={
            "Memory (Neo)": "Neo",
            "Memory (Emulation)": "Emulation",
        }
    )
    ax = mem_df.plot(
        x="network",
        y=["Neo", "Emulation"],
        kind="bar",
        legend=False,
        width=0.8,
        xlabel="",
        ylabel="",
        rot=25,
    )
    ax.legend(
        bbox_to_anchor=(1.05, 1.2),
        columnspacing=0.7,
        ncol=2,
        fontsize=22,
        frameon=False,
        fancybox=False,
    )
    ax.grid(axis="y")
    # ax.set_yscale("log")
    ax.set_xlabel("Network", fontsize=22)
    ax.set_ylabel("Memory (MiB)", fontsize=22)
    ax.tick_params(axis="both", which="both", labelsize=22)
    ax.tick_params(axis="x", which="both", top=False, bottom=False)
    fig = ax.get_figure()
    fn = os.path.join(outDir, "17.memory-network.1-procs.timeout.pdf")
    fig.savefig(fn, bbox_inches="tight")
    plt.close(fig)
    fn = os.path.join(outDir, "17.network.1-procs.timeout.txt")
    with open(fn, "w") as fout:
        fout.write(df.to_string())


def plot_18_perf_vs_arity(df, outDir):
    def _plot(df, outDir, nproc, drop, inv):
        # Filter columns
        df = df.drop(
            [
                "num_nodes",
                "num_links",
                "num_updates",
                "independent_cec",
                "violated",
                "total_conn",
                "total_time",
                "total_mem",
            ],
            axis=1,
        )
        # Sorting
        df = df.sort_values(by=["arity", "update_pct"])
        # Change units
        df["inv_time"] /= 1e6  # usec -> sec
        df["inv_memory"] /= 1024  # KiB -> MiB

        time_df = df.pivot(
            index="arity", columns="update_pct", values="inv_time"
        ).reset_index()
        time_df = time_df.rename(
            columns={
                "None": "Time (none)",
                "Half-tenant": "Time (half-tenant)",
                "All-tenant": "Time (all-tenant)",
            }
        )
        mem_df = df.pivot(
            index="arity", columns="update_pct", values="inv_memory"
        ).reset_index()
        mem_df = mem_df.rename(
            columns={
                "None": "Memory (none)",
                "Half-tenant": "Memory (half-tenant)",
                "All-tenant": "Memory (all-tenant)",
            }
        )
        merged_df = pd.merge(time_df, mem_df, on=["arity"])

        # Plot time/memory
        ax = merged_df.plot(
            x="arity",
            y=["Time (none)", "Time (half-tenant)", "Time (all-tenant)"],
            kind="bar",
            legend=False,
            width=0.8,
            xlabel="",
            ylabel="",
            rot=0,
        )
        ax = merged_df.plot(
            x="arity",
            secondary_y=[
                "Memory (none)",
                "Memory (half-tenant)",
                "Memory (all-tenant)",
            ],
            mark_right=False,
            kind="bar",
            legend=False,
            width=0.8,
            xlabel="",
            ylabel="",
            rot=0,
        )

        # Merge legends
        h1, l1 = ax.get_legend_handles_labels()
        h2, l2 = ax.right_ax.get_legend_handles_labels()
        ax.legend(h1 + h2, l1 + l2, ncol=1, fontsize=14, frameon=False, fancybox=False)

        ax.grid(axis="y")
        ax.set_yscale("log")
        ax.set_xlabel("Fat-tree arity (k)", fontsize=22)
        ax.set_ylabel("Time (seconds)", fontsize=22)
        ax.tick_params(axis="both", which="both", labelsize=22)
        ax.tick_params(axis="x", which="both", top=False, bottom=False)
        ax.right_ax.grid(axis="y")
        mem_start_val = (floor(df.inv_memory.min()) - 1) // 10 * 10
        ax.right_ax.set_ylim(bottom=mem_start_val)
        ax.right_ax.set_ylabel("Memory (MiB)", fontsize=22)
        ax.right_ax.tick_params(axis="both", which="both", labelsize=18)
        fig = ax.get_figure()
        fn = os.path.join(
            outDir,
            (
                "18.perf-arity.inv-"
                + str(inv)
                + "."
                + str(nproc)
                + "-procs."
                + drop
                + ".pdf"
            ),
        )
        fig.savefig(fn, bbox_inches="tight")
        plt.close("all")
        fn = os.path.join(
            outDir,
            (
                "18.perf-arity.inv-"
                + str(inv)
                + "."
                + str(nproc)
                + "-procs."
                + drop
                + ".txt"
            ),
        )
        with open(fn, "w") as fout:
            fout.write(merged_df.to_string())

    # Fixed parameters
    nproc = 1
    drop = "timeout"
    inv = 1
    new_df = df[df.procs == nproc].drop(["procs"], axis=1)
    new_df = new_df[new_df.drop_method == drop].drop(["drop_method"], axis=1)
    new_df = new_df[new_df.invariant == inv].drop(["invariant"], axis=1)
    _plot(new_df, outDir, nproc, drop, inv)


def plot_18_perf_vs_nprocs(df, outDir):
    def _plot(df, outDir, drop, inv):
        # Filter columns
        df = df.drop(
            [
                "inv_memory",
                "num_nodes",
                "num_links",
                "num_updates",
                "independent_cec",
                "violated",
                "total_conn",
                "total_time",
                "total_mem",
            ],
            axis=1,
        )
        # Sorting
        df = df.sort_values(by=["procs", "arity"])
        # Change units
        df["inv_time"] /= 1e6  # usec -> sec
        # Rename values
        df["arity"] = df["arity"].astype(str) + "-ary"

        df = df.pivot(index="procs", columns="arity", values="inv_time").reset_index()
        # print(df)
        # exit(0)

        # Plot time vs nprocs
        ax = df.plot(
            x="procs",
            y=["4-ary", "6-ary", "8-ary", "10-ary", "12-ary"],
            kind="line",
            style=["^-", "o-", "D-", "s-", "x-"],
            xticks=df["procs"],
            legend=False,
            xlabel="",
            ylabel="",
            rot=0,
            lw=LINE_WIDTH,
        )
        ax.legend(ncol=2, fontsize=14, frameon=False, fancybox=False)
        ax.grid(axis="y")
        # ax.set_yscale('log')
        ax.set_xlabel("Parallel processes", fontsize=22)
        ax.set_ylabel("Time (seconds)", fontsize=22)
        ax.tick_params(axis="both", which="both", labelsize=22)
        ax.tick_params(axis="x", which="both", top=False, bottom=False)
        fig = ax.get_figure()
        fn = os.path.join(
            outDir, ("18.time-nproc.inv-" + str(inv) + "." + drop + ".pdf")
        )
        fig.savefig(fn, bbox_inches="tight")
        plt.close(fig)
        fn = os.path.join(
            outDir, ("18.time-nproc.inv-" + str(inv) + "." + drop + ".txt")
        )
        with open(fn, "w") as fout:
            fout.write(df.to_string())

    # Fixed parameters
    update_pct = "None"
    drop = "timeout"
    inv = 1
    df = df[df.update_pct == update_pct].drop(["update_pct"], axis=1)
    df = df[df.drop_method == drop].drop(["drop_method"], axis=1)
    df = df[df.invariant == inv].drop(["invariant"], axis=1)
    _plot(df, outDir, drop, inv)


def plot_18_perf_vs_drop_methods(df, outDir):
    def _plot(df, outDir, updates, nproc, inv):
        # Filter columns
        df = df.drop(
            [
                "inv_memory",
                "num_nodes",
                "num_links",
                "num_updates",
                "independent_cec",
                "violated",
            ],
            axis=1,
        )
        # Sorting
        df = df.sort_values(by=["arity", "drop_method"])
        # Change units
        df["inv_time"] /= 1e6  # usec -> sec
        # Rename values
        df = df.replace("dropmon", "drop_mon")

        df = df.pivot(
            index="arity", columns="drop_method", values="inv_time"
        ).reset_index()

        # Plot time w. drop methods
        ax = df.plot(
            x="arity",
            y=["timeout", "ebpf", "drop_mon"],
            kind="bar",
            legend=False,
            width=0.8,
            xlabel="",
            ylabel="",
            rot=0,
        )
        ax.legend(
            bbox_to_anchor=(1.1, 1.18),
            columnspacing=0.7,
            ncol=3,
            fontsize=20,
            frameon=False,
            fancybox=False,
        )
        ax.grid(axis="y")
        # ax.set_yscale('log')
        ax.set_xlabel("Fat-tree arity (k)", fontsize=22)
        ax.set_ylabel("Time (seconds)", fontsize=22)
        ax.tick_params(axis="both", which="both", labelsize=22)
        ax.tick_params(axis="x", which="both", top=False, bottom=False)
        fig = ax.get_figure()
        fn = os.path.join(
            outDir,
            (
                "18.perf-drop.inv-"
                + str(inv)
                + "."
                + updates.lower()
                + "-updates."
                + str(nproc)
                + "-procs.pdf"
            ),
        )
        fig.savefig(fn, bbox_inches="tight")
        plt.close(fig)

    for updates in df.update_pct.unique():
        upd_df = df[df.update_pct == updates].drop(["update_pct"], axis=1)

        for nproc in upd_df.procs.unique():
            nproc_df = upd_df[upd_df.procs == nproc].drop(["procs"], axis=1)

            for inv in nproc_df.invariant.unique():
                inv_df = nproc_df[nproc_df.invariant == inv].drop(["invariant"], axis=1)
                _plot(inv_df, outDir, updates, nproc, inv)


def plot_18_stats(invDir, outDir):
    df = pd.read_csv(os.path.join(invDir, "stats.csv"))
    # Rename values
    df.loc[df["update_pct"] == 0, "update_pct"] = "None"
    df.loc[df["update_pct"] == 50, "update_pct"] = "Half-tenant"
    df.loc[df["update_pct"] == 100, "update_pct"] = "All-tenant"

    plot_18_perf_vs_arity(df, outDir)
    plot_18_perf_vs_nprocs(df, outDir)


def plot_latency(df, outFn, sample_limit=None):
    # Filter columns
    df = df.drop(["rewind", "pkt_lat", "drop_lat"], axis=1)

    df = df.pivot(columns="drop_method", values=["latency", "timeout"])
    df.columns = ["_".join(col) for col in df.columns.values]
    df = df.drop(["timeout_dropmon", "timeout_ebpf"], axis=1)
    df = df.apply(lambda x: pd.Series(x.dropna().values))

    # Rename column titles
    df = df.rename(
        columns={
            "latency_dropmon": "Latency (drop_mon)",
            "latency_ebpf": "Latency (ebpf)",
            "latency_timeout": "Latency (timeout)",
            "timeout_timeout": "Drop timeout",
        }
    )

    if sample_limit:
        df = df.sample(n=sample_limit).sort_index()

    ax = df.plot(
        y=["Latency (drop_mon)", "Latency (ebpf)", "Latency (timeout)", "Drop timeout"],
        kind="line",
        legend=False,
        xlabel="",
        ylabel="",
        rot=0,
        lw=2,
    )
    ax.legend(
        bbox_to_anchor=(1.1, 1.27),
        columnspacing=0.8,
        ncol=2,
        fontsize=18,
        frameon=False,
        fancybox=False,
    )
    ax.grid(axis="y")
    # ax.set_yscale('log')
    ax.set_xlabel("Packet injections", fontsize=22)
    ax.set_ylabel("Latency (microseconds)", fontsize=22)
    ax.tick_params(axis="both", which="both", labelsize=22)
    ax.tick_params(axis="x", which="both", top=False, bottom=False, labelbottom=False)
    fig = ax.get_figure()
    fig.savefig(outFn, bbox_inches="tight")
    plt.close(fig)


def plot_latency_cdf(
    df, outDir, exp_id, logscale_for_reset=False, logscale_for_no_reset=False
):
    df.loc[:, "latency_with_reset"] = df["latency"] + df["rewind"]

    # Filter columns
    df = df.drop(["rewind", "pkt_lat", "drop_lat", "timeout"], axis=1)

    df = df.pivot(columns="drop_method", values=["latency", "latency_with_reset"])
    df.columns = ["_".join(col) for col in df.columns.values]
    df = df.apply(lambda x: pd.Series(x.dropna().values))

    no_reset_df = df.drop(
        [
            "latency_with_reset_dropmon",
            "latency_with_reset_ebpf",
            "latency_with_reset_timeout",
        ],
        axis=1,
    ).rename(
        columns={
            "latency_dropmon": "dropmon",
            "latency_ebpf": "ebpf",
            "latency_timeout": "timeout",
        }
    )
    reset_df = df.drop(
        ["latency_dropmon", "latency_ebpf", "latency_timeout"], axis=1
    ).rename(
        columns={
            "latency_with_reset_dropmon": "dropmon",
            "latency_with_reset_ebpf": "ebpf",
            "latency_with_reset_timeout": "timeout",
        }
    )

    def _get_cdf_df(df, col):
        df = df[col].to_frame().dropna()
        df = df.sort_values(by=[col]).reset_index().rename(columns={col: "latency"})
        df[col] = df.index + 1
        df = df[df.columns.drop(list(df.filter(regex="index")))]
        return df

    for df, with_reset in [(no_reset_df, False), (reset_df, True)]:
        # For each drop_method x with/without reset, get the latency CDF
        cdf_df = pd.DataFrame()
        peak_latencies = []

        for col in list(df.columns):
            df1 = _get_cdf_df(df, col)
            peak_latencies.append(df1.latency.iloc[-1])
            if cdf_df.empty:
                cdf_df = df1
            else:
                cdf_df = pd.merge(cdf_df, df1, how="outer", on="latency")
            del df1

        df = (
            cdf_df.sort_values(by="latency")
            .interpolate(limit_area="inside")
            .rename(
                columns={
                    "dropmon": "drop_mon",
                    "ebpf": "ebpf",
                    "timeout": "timeout",
                }
            )
        )
        del cdf_df

        for col in list(df.columns):
            if col == "latency":
                continue
            df[col] /= df[col].max()

        ax = df.plot(
            x="latency",
            y=["drop_mon", "ebpf", "timeout"],
            kind="line",
            legend=False,
            xlabel="",
            ylabel="",
            rot=0,
            lw=LINE_WIDTH + 1,
        )
        ax.legend(
            bbox_to_anchor=(1.1, 1.2),
            columnspacing=0.8,
            ncol=3,
            fontsize=22,
            frameon=False,
            fancybox=False,
        )
        ax.grid(axis="both")
        if (with_reset and logscale_for_reset) or (
            not with_reset and logscale_for_no_reset
        ):
            ax.set_xscale("log")
        ax.set_xlabel("Latency (microseconds)", fontsize=24)
        ax.set_ylabel("CDF", fontsize=24)
        ax.tick_params(axis="both", which="both", labelsize=24)
        ax.tick_params(axis="x", which="both", top=False, bottom=False)
        i = 0
        for peak_lat in peak_latencies:
            ax.axvline(
                peak_lat,
                ymax=0.95,
                linestyle="--",
                linewidth=LINE_WIDTH,
                color=colors[i],
            )
            i += 1
        fig = ax.get_figure()
        fig.savefig(
            os.path.join(
                outDir,
                (
                    exp_id
                    + ".latency-cdf"
                    + (".with-reset" if with_reset else "")
                    + ".pdf"
                ),
            ),
            bbox_inches="tight",
        )
        plt.close(fig)


def plot_emulation_overhead(df, outDir, exp_id):
    def _get_cdf_df(df, col):
        df = df[col].to_frame().dropna()
        df = df.sort_values(by=[col]).reset_index().rename(columns={col: "time"})
        df[col] = df.index + 1
        df = df[df.columns.drop(list(df.filter(regex="index")))]
        return df

    def _plot(df, outDir, exp_id, drop, inv):
        # Filter columns
        df = df.drop(["emu_reset", "replay", "pkt_lat", "drop_lat", "timeout"], axis=1)
        # Change units
        df /= 1e3  # usec -> msec

        cdf_df = pd.DataFrame()
        peak_latencies = []

        for col in df.columns:
            df1 = _get_cdf_df(df, col)
            peak_latencies.append(df1.time.iloc[-1])
            if cdf_df.empty:
                cdf_df = df1
            else:
                cdf_df = pd.merge(cdf_df, df1, how="outer", on="time")
            del df1

        df = (
            cdf_df.sort_values(by="time")
            .interpolate(limit_area="inside")
            .rename(
                columns={
                    "ec_time": "Total check time",
                    "overall_lat": "Emulation overhead",
                    "emu_startup": "Emulation startup",
                    "rewind": "State rewind",
                    "latency": "Packet latency",
                }
            )
        )
        del cdf_df

        for col in df.columns:
            if col == "time":
                continue
            df[col] /= df[col].max()

        ax = df.plot(
            x="time",
            y=[
                "Total check time",
                "Emulation overhead",
                "Emulation startup",
                "State rewind",
                "Packet latency",
            ],
            kind="line",
            legend=False,
            xlabel="",
            ylabel="",
            rot=0,
            lw=LINE_WIDTH + 1,
        )
        ax.legend(
            bbox_to_anchor=(1.2, 1.45),
            columnspacing=0.8,
            ncol=2,
            fontsize=22,
            frameon=False,
            fancybox=False,
        )
        ax.grid(axis="both")
        # ax.set_xscale('log')
        ax.set_xlabel("Time (milliseconds)", fontsize=24)
        ax.set_ylabel("CDF", fontsize=24)
        ax.tick_params(axis="both", which="both", labelsize=24)
        ax.tick_params(axis="x", which="both", top=False, bottom=False)
        i = 0
        for peak_lat in peak_latencies:
            ax.axvline(
                peak_lat,
                ymax=0.95,
                linestyle="--",
                linewidth=LINE_WIDTH,
                color=colors[i],
            )
            i += 1
        fig = ax.get_figure()
        fig.savefig(
            os.path.join(
                outDir,
                (exp_id + ".emu-overhead-cdf.inv-" + str(inv) + "." + drop + ".pdf"),
            ),
            bbox_inches="tight",
        )
        plt.close(fig)

    # Group by each EC
    # Also group by: 'optimization'
    ec_common_attrs = [
        "ec_time",
        "ec_mem",
        "drop_method",
        "invariant",
        "independent_cec",
        "violated",
        "total_time",
        "total_mem",
    ]
    summed_attrs = [
        "overall_lat",
        "emu_startup",
        "rewind",
        "emu_reset",
        "replay",
        "pkt_lat",
        "drop_lat",
        "latency",
        "timeout",
    ]
    grouped = df.groupby(by=ec_common_attrs, as_index=False)
    for col in summed_attrs:
        df = df.merge(
            grouped[col].agg("sum"), how="inner", on=ec_common_attrs, sort=False
        )
        df = df.rename(columns={col + "_y": col})
        df = df.drop(col + "_x", axis=1)
    df.drop_duplicates(inplace=True)

    # Filter columns
    df = df.drop(
        ["ec_mem", "independent_cec", "violated", "total_time", "total_mem"], axis=1
    )

    for drop in df.drop_method.unique():
        d_df = df[df.drop_method == drop].drop(["drop_method"], axis=1)

        for inv in d_df.invariant.unique():
            inv_df = d_df[d_df.invariant == inv].drop(["invariant"], axis=1)
            _plot(inv_df, outDir, exp_id, drop, inv)


def plot_02_latency(invDir, outDir):
    df = pd.read_csv(os.path.join(invDir, "lat.csv"))
    # Merge latency values
    df.loc[:, "latency"] = df["pkt_lat"] + df["drop_lat"]
    # Filter rows
    df = df[df.procs == 1]
    # Filter columns
    df = df.drop(
        [
            "overall_lat",
            "rewind_injections",
            "hosts",
            "procs",
            "fault",
            "num_nodes",
            "num_links",
            "num_updates",
            "total_conn",
            "invariant",
            "independent_cec",
            "violated",
        ],
        axis=1,
    )
    df = df.reset_index().drop(["index"], axis=1)

    # latency line charts
    recv_df = df[df.pkt_lat > 0]
    for apps in recv_df.apps.unique():
        plot_latency(
            recv_df[recv_df.apps == apps],
            os.path.join(outDir, ("02.latency." + str(apps) + "-apps.recv.pdf")),
            sample_limit=None,
        )
    plot_latency(df[df.drop_lat > 0], os.path.join(outDir, "02.latency.drop.pdf"))

    # latency CDF
    plot_latency_cdf(df, outDir, os.path.basename(invDir)[:2])


def plot_06_latency(invDir, outDir):
    df = pd.read_csv(os.path.join(invDir, "lat.csv"))
    # Merge latency values
    df.loc[:, "latency"] = df["pkt_lat"] + df["drop_lat"]
    # Rename values
    df.loc[df["updates"] == 0, "updates"] = "None"
    df.loc[df["tenants"] == df["updates"] * 2, "updates"] = "Half-tenant"
    df.loc[df["tenants"] == df["updates"], "updates"] = "All-tenant"
    # Filter rows
    df = df[df.procs == 1]
    df = df[df.optimization == True]
    # Filter columns
    df = df.drop(
        [
            "overall_lat",
            "rewind_injections",
            "tenants",
            "updates",
            "procs",
            "num_nodes",
            "num_links",
            "num_updates",
            "total_conn",
            "invariant",
            "independent_cec",
            "violated",
            "optimization",
        ],
        axis=1,
    )
    df = df.reset_index().drop(["index"], axis=1)

    # latency line charts
    plot_latency(
        df[df.pkt_lat > 0],
        os.path.join(outDir, "06.latency.recv.pdf"),
        sample_limit=300,
    )
    plot_latency(df[df.drop_lat > 0], os.path.join(outDir, "06.latency.drop.pdf"))

    # latency CDF
    plot_latency_cdf(df, outDir, os.path.basename(invDir)[:2], logscale_for_reset=True)


def plot_06_compare_unopt(invDir, outDir):
    def _plot(df, outDir, drop, inv):
        # Filter columns
        df = df.drop(
            [
                "inv_memory",
                "procs",
                "num_nodes",
                "num_links",
                "num_updates",
                "total_conn",
                "independent_cec",
                "violated",
                "model_only",
            ],
            axis=1,
        )
        # Sorting
        df = df.sort_values(by=["tenants", "updates"])
        # Change units
        df["inv_time"] /= 1e6  # usec -> sec
        df["opt_update"] = df.optimization + " (" + df.updates + ")"

        df = df.pivot(
            index="tenants", columns="opt_update", values="inv_time"
        ).reset_index()

        ax = df.plot(
            x="tenants",
            y=[
                "Opt. (all-tenant)",
                "Unopt. (all-tenant)",
                "Opt. (half-tenant)",
                "Unopt. (half-tenant)",
                "Opt. (none)",
                "Unopt. (none)",
            ],
            kind="bar",
            legend=False,
            width=0.8,
            xlabel="",
            ylabel="",
            rot=0,
        )
        ax.legend(
            bbox_to_anchor=(1.14, 1.2),
            columnspacing=0.8,
            ncol=3,
            fontsize=13,
            frameon=False,
            fancybox=False,
        )
        ax.grid(axis="y")
        ax.set_yscale("log")
        ax.set_xlabel("Tenants", fontsize=22)
        ax.set_ylabel("Time (seconds)", fontsize=22)
        ax.tick_params(axis="both", which="both", labelsize=22)
        ax.tick_params(axis="x", which="both", top=False, bottom=False)
        fig = ax.get_figure()
        fn = os.path.join(
            outDir, ("06.compare-unopt.inv-" + str(inv) + "." + drop + ".pdf")
        )
        fig.savefig(fn, bbox_inches="tight")
        plt.close("all")

    df = pd.read_csv(os.path.join(invDir, "stats.csv"))
    # Rename values
    df.loc[df["updates"] == 0, "updates"] = "none"
    df.loc[df["tenants"] == df["updates"] * 2, "updates"] = "half-tenant"
    df.loc[df["tenants"] == df["updates"], "updates"] = "all-tenant"
    df.loc[df["optimization"] == True, "optimization"] = "Opt."
    df.loc[df["optimization"] == False, "optimization"] = "Unopt."
    # Filter rows
    df = df[df.model_only != True]
    df = df[df.procs == 1]

    for drop in df.drop_method.unique():
        d_df = df[df.drop_method == drop].drop(["drop_method"], axis=1)

        for inv in d_df.invariant.unique():
            inv_df = d_df[d_df.invariant == inv].drop(["invariant"], axis=1)
            _plot(inv_df, outDir, drop, inv)


def plot_15_latency(invDir, outDir):
    df = pd.read_csv(os.path.join(invDir, "lat.csv"))
    # Merge latency values
    df.loc[:, "latency"] = df["pkt_lat"] + df["drop_lat"]
    # Filter rows
    df = df[df.procs == 1]
    # df = df[df.optimization == True]
    # Filter columns
    df = df.drop(
        [
            "rewind_injections",
            "network",
            "emulated_pct",
            "invariants",
            "procs",
            "num_nodes",
            "num_links",
            "num_updates",
            "total_conn",
        ],
        axis=1,
    )
    df = df.reset_index().drop(["index"], axis=1)

    # latency line charts
    plot_latency(
        df[df.pkt_lat > 0].copy(),
        os.path.join(outDir, "15.latency.recv.pdf"),
        sample_limit=400,
    )
    # No packet drops for 15
    # plot_latency(df[df.drop_lat > 0],
    #              os.path.join(outDir, '15.latency.drop.pdf'))

    # latency CDF
    plot_latency_cdf(
        df.copy(), outDir, os.path.basename(invDir)[:2], logscale_for_reset=True
    )

    # Per-CEC emulation overhead
    plot_emulation_overhead(df.copy(), outDir, "15")


def plot_18_latency(invDir, outDir):
    df = pd.read_csv(os.path.join(invDir, "lat.csv"))
    # Merge latency values
    df.loc[:, "latency"] = df["pkt_lat"] + df["drop_lat"]
    # Rename values
    df.loc[df["update_pct"] == 0, "update_pct"] = "None"
    df.loc[df["update_pct"] == 50, "update_pct"] = "Half-tenant"
    df.loc[df["update_pct"] == 100, "update_pct"] = "All-tenant"
    # Filter rows
    df = df[df.procs == 1].drop(["procs"], axis=1)
    df = df[df.invariant == 1]
    assert type(df) is pd.DataFrame
    # Filter columns
    df = df.drop(
        [
            "rewind_injections",
            "arity",
            "update_pct",
            "num_nodes",
            "num_links",
            "num_updates",
            "total_conn",
        ],
        axis=1,
    )
    df = df.reset_index().drop(["index"], axis=1)

    # latency line charts
    plot_latency(
        df[df.pkt_lat > 0].copy(),
        os.path.join(outDir, "18.latency.recv.pdf"),
        sample_limit=400,
    )
    plot_latency(
        df[df.drop_lat > 0].copy(), os.path.join(outDir, "18.latency.drop.pdf")
    )

    # latency CDF
    plot_latency_cdf(
        df.copy(), outDir, os.path.basename(invDir)[:2], logscale_for_reset=True
    )

    # Per-CEC emulation overhead
    plot_emulation_overhead(df.copy(), outDir, "18")


def program_compare(series):
    ids = {
        "": 0,
        "user-demo-stateful": 1,
        "user-demo-stateless": 2,
        "user-ip-stateful": 3,
        "user-ip-stateless": 4,
        "user-ip-echo": 5,
        "user-l2-echo": 6,
        "user-l2-forward": 7,
        "ebpf-demo-stateful": 8,
        "ebpf-demo-stateless": 9,
        "ebpf-ip-stateful": 10,
        "ebpf-ip-stateless": 11,
        "kernel-demo-stateful": 12,
        "kernel-demo-stateless": 13,
        "kernel-ip-stateful": 14,
        "kernel-ip-stateless": 15,
    }
    return series.apply(lambda m: -m if isinstance(m, int) else ids[m])


def plot_model_extraction_depth_1(df, out_dir):
    # Filter rows
    df = df[
        (df["depth"] == 1)
        & ((df["program_name"].str.startswith("ebpf")) | (df["ksymaddr"] == False))  # noqa: E712
    ]
    df = df[(-df["program_name"].str.endswith("ip-echo"))]
    df = df[(-df["program_name"].str.contains("-l2-"))]
    # Filter columns
    df = df.drop(
        [
            "depth",
            "kfork",
            "ksymaddr",
        ],
        axis=1,
    )
    # Sorting
    df = df.sort_values(by=["program_name"], key=program_compare, ascending=True)
    # Change units
    df["memory"] /= 2**20  # KiB -> GiB
    # Add total time
    df["total_time"] = (
        df["system_startup_time"]
        + df["sym_exec_time"]
        + df["trace_record_time"]
        + df["model_export_time"]
    )
    # Rename columns
    df = df.rename(
        columns={
            "system_startup_time": "System Startup",
            "sym_exec_time": "Symbolic Execution",
            "trace_record_time": "Insert Traces (BDD translation)",
            "model_export_time": "Model Export",
            "total_time": "Total Time",
            "memory": "Memory",
        }
    )

    # Plot time
    ax = df.plot(
        x="program_name",
        y=[
            "System Startup",
            "Symbolic Execution",
            "Insert Traces (BDD translation)",
            "Model Export",
            "Total Time",
        ],
        kind="bar",
        legend=False,
        figsize=(45, 10),
        width=0.75,
        xlabel="",
        ylabel="",
        rot=12,
    )
    ax.legend(
        bbox_to_anchor=(0.59, 0.74),
        columnspacing=1.0,
        ncol=3,
        fontsize=35,
        frameon=False,
        fancybox=False,
    )
    ax.grid(axis="y")
    ax.set_yscale("log")
    ax.set_ylabel("Time (seconds)", fontsize=40)
    ax.tick_params(axis="both", which="both", labelsize=40)
    ax.tick_params(axis="x", which="both", top=False, bottom=False, labelsize=35)
    # Plot memory on top
    mem_ax = ax.twinx()
    df.plot(
        x="program_name",
        y=["Memory"],
        mark_right=True,
        kind="line",
        style=["s-", "^-", "o-", "D-", "s-", "x-"],
        legend=False,
        lw=7,
        ms=20,
        ax=mem_ax,
    )
    mem_ax.legend(
        bbox_to_anchor=(0.576, 0.92),
        columnspacing=1.0,
        ncol=3,
        fontsize=35,
        frameon=False,
        fancybox=False,
    )
    # mem_ax.grid(axis="y")
    # mem_ax.set_yscale("log")
    mem_ax.set_ylim(bottom=0, top=3)
    mem_ax.set_ylabel("Memory (GiB)", fontsize=40)
    mem_ax.tick_params(axis="y", which="both", labelsize=40)
    # Output the plot figure
    fig = ax.get_figure()
    fn = os.path.join(out_dir, "model-extraction.depth-1.pdf")
    fig.savefig(fn, bbox_inches="tight")
    plt.close(fig)

    # Output stats table as text
    fn = os.path.join(out_dir, "model-extraction.depth-1.txt")
    with open(fn, "w") as fout:
        fout.write(df.to_string())


def plot_model_extraction_increasing_depth(df, out_dir):
    # Filter rows
    df = df[(df["program_name"].str.startswith("user-"))]
    df = df[(df["ksymaddr"] == True)]  # noqa: E712
    df = df[(-df["program_name"].str.endswith("ip-echo"))]
    # Sorting
    df = df.sort_values(
        by=["program_name", "depth"], key=program_compare, ascending=True
    )
    # Change units
    df["memory"] /= 2**20  # KiB -> GiB
    # Add total time
    df["total_time"] = (
        df["system_startup_time"]
        + df["sym_exec_time"]
        + df["trace_record_time"]
        + df["model_export_time"]
    )
    # Filter columns
    df = df.drop(
        [
            "kfork",
            "ksymaddr",
            "system_startup_time",
            "sym_exec_time",
            "trace_record_time",
            "model_export_time",
            "memory",
        ],
        axis=1,
    )
    # Rename columns
    df = df.rename(
        columns={
            "total_time": "Total Time",
        }
    )

    # Pivot on depth
    df = df.pivot(
        index="depth", columns="program_name", values="Total Time"
    ).reset_index()

    ax = df.plot(
        x="depth",
        y=[
            "user-demo-stateful",
            "user-demo-stateless",
            "user-l2-echo",
            "user-l2-forward",
            "user-ip-stateful",
            "user-ip-stateless",
        ],
        kind="bar",
        legend=False,
        figsize=(15, 10),
        width=0.75,
        xlabel="",
        ylabel="",
        rot=0,
    )
    ax.legend(
        bbox_to_anchor=(1.0, 1.35),
        columnspacing=1.0,
        ncol=2,
        fontsize=35,
        frameon=False,
        fancybox=False,
    )
    ax.grid(axis="y")
    # ax.set_yscale("log")
    ax.set_ylabel("Time (seconds)", fontsize=40)
    ax.set_xlabel("Depth", fontsize=40)
    ax.tick_params(axis="both", which="both", labelsize=40)
    ax.tick_params(axis="x", which="both", top=False, bottom=False)
    # Output the plot figure
    fig = ax.get_figure()
    fn = os.path.join(out_dir, "model-extraction.increasing-depth.pdf")
    fig.savefig(fn, bbox_inches="tight")
    plt.close(fig)

    # Output stats table as text
    fn = os.path.join(out_dir, "model-extraction.increasing-depth.txt")
    with open(fn, "w") as fout:
        fout.write(df.to_string())


def plot_model_query(df, out_dir):
    # Add program name
    df["program_name"] = df["model_name"].str.replace(r"-depth-.*", "", regex=True)
    # Filter columns
    df = df.drop(["model_name"], axis=1)
    # Sorting
    df = df.sort_values(by=["program_name"], key=program_compare, ascending=True)
    # Change units
    for col in df.columns:
        if "time" in col:
            df[col] /= 1e3  # usec -> msec
    df["memory"] /= 2**10  # KiB -> MiB
    # Rename columns
    df = df.rename(
        columns={
            "import_model_time": "Model Import",
            "query_time": "Process Query",
            "total_time": "Total Time",
            "memory": "Memory",
        }
    )

    # Plot time
    print(df)
    ax = df.plot(
        x="program_name",
        y=[
            "Process Query",
            "Model Import",
            "Total Time",
        ],
        kind="bar",
        legend=False,
        figsize=(45, 10),
        width=0.75,
        xlabel="",
        ylabel="",
        rot=12,
    )
    ax.legend(
        bbox_to_anchor=(0.496, 0.82),
        columnspacing=1.0,
        ncol=3,
        fontsize=40,
        frameon=False,
        fancybox=False,
    )
    ax.grid(axis="y")
    # ax.set_yscale("log")
    ax.set_ylabel("Time (milliseconds)", fontsize=40)
    ax.tick_params(axis="both", which="both", labelsize=40)
    ax.tick_params(axis="x", which="both", top=False, bottom=False, labelsize=35)
    # Plot memory on top
    mem_ax = ax.twinx()
    df.plot(
        x="program_name",
        y=["Memory"],
        mark_right=True,
        kind="line",
        style=["s-", "^-", "o-", "D-", "s-", "x-"],
        legend=False,
        lw=7,
        ms=20,
        ax=mem_ax,
    )
    mem_ax.legend(
        bbox_to_anchor=(0.62, 1.02),
        columnspacing=1.0,
        ncol=1,
        fontsize=40,
        frameon=False,
        fancybox=False,
    )
    # mem_ax.grid(axis="y")
    # mem_ax.set_yscale("log")
    mem_ax.set_ylim(bottom=0, top=1000)
    mem_ax.set_ylabel("Memory (MiB)", fontsize=40)
    mem_ax.tick_params(axis="y", which="both", labelsize=40)
    # Output the plot figure
    fig = ax.get_figure()
    fn = os.path.join(out_dir, "model-query.depth-1.pdf")
    fig.savefig(fn, bbox_inches="tight")
    plt.close(fig)

    # Output stats table as text
    fn = os.path.join(out_dir, "model-query.depth-1.txt")
    with open(fn, "w") as fout:
        fout.write(df.to_string())


def main():
    parser = argparse.ArgumentParser(description="Plotting for Mimesis")
    parser.add_argument("-l", "--logs", help="Log directory", type=str, action="store")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

    project_dir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
    if args.logs:
        log_dir = os.path.abspath(args.logs)
    else:
        log_dir = os.path.join(project_dir, "output")
    if not os.path.isdir(log_dir):
        raise Exception("'{}' is not a directory".format(log_dir))
    out_dir = os.path.join(project_dir, "figures")
    os.makedirs(out_dir, exist_ok=True)

    df = pd.read_csv(os.path.join(log_dir, "stats.csv"))
    plot_model_extraction_depth_1(df.copy(), out_dir)
    plot_model_extraction_increasing_depth(df.copy(), out_dir)
    del df

    df = pd.read_csv(os.path.join(log_dir, "query.csv"))
    plot_model_query(df.copy(), out_dir)
    del df


if __name__ == "__main__":
    main()

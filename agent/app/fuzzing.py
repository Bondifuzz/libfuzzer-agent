from typing import Dict, Tuple
import logging
import os
import re

from base_agent.utils import TimeMeasure, make_executable
from base_agent.output import Status
from base_agent.errors import AgentError, FuzzerLaunchError
from base_agent.settings import AppSettings
from base_agent.kubernetes import UserContainerManager

from .config import FuzzerConfig
from .paths import *
from .utils import (
    LibFuzzerStatistics,
    prepare_fuzz_run,
    truncate_libfuzzer_output,
    null_statistics,
    error_status,
    ok_status,
    dirsize,
)


def _get_statistics_raw(
    paths: LibFuzzerPaths,
) -> Tuple[str, Dict[str, str]]:

    latest_stat_line = ""

    def is_stats_line(line: str):
        return (
            line.startswith("#")
            and "corp:" in line
            and "exec/s:" in line
            and "rss:" in line
        )

    stat_prefix = "stat::"
    final_stats: Dict[str, str] = {}

    with open(paths.fuzzer_log, "r", encoding="utf-8") as f:
        for line in f:
            if is_stats_line(line):
                latest_stat_line = line
            elif line.startswith(stat_prefix):
                line = line.replace(stat_prefix, "")
                (param, value) = line.split(":")
                final_stats[param] = value.strip()

    return (latest_stat_line, final_stats)


units = {
    "b": 0,
    "Kb": 10,
    "Mb": 20,
    "Gb": 30,
}


def _parse_runtime_stats(stats: str, measure: TimeMeasure) -> LibFuzzerStatistics:

    # fmt: off
    pattern = (
        r"#(\d+)\s+\w+\s+"                   # "#6816   NEW    "
        r"(?:cov:\s(\d+)\s)?"                # "cov: 153 "   Optional
        r"ft:\s(\d+)\s"                      # "ft: 251 "
        r"corp:\s(\d+)\/(\d+)(b|Kb|Mb|Gb)\s" # "corp: 52/1425b "
        r"(?:focus:\s\d+\s)?"                # "focus: 123 " Optional
        r"(?:lim:\s\d+\s)?"                  # "lim: 48 "    Optional
        r"(?:units:\s\d+\s)?"                # "units: 123 " Optional
        r"exec\/s:\s(\d+)\s"                 # "exec/s: 110 "
        r"rss:\s(\d+)Mb"                     # "rss: 64Mb "
    )
    # fmt: on

    match = re.match(pattern, stats)

    if not match:
        return null_statistics(measure)

    runs = int(match.group(1))
    cov = int(match.group(2) or 0)
    ft = int(match.group(3))
    corp_items = int(match.group(4))
    corp_size = int(match.group(5)) << units[match.group(6)]
    speed = int(match.group(7))
    rss = int(match.group(8)) << units["Mb"]

    return LibFuzzerStatistics(
        work_time=int(measure.elapsed.total_seconds()),
        edge_cov=cov,
        feature_cov=ft,
        execs_per_sec=speed,
        corpus_entries=corp_items,
        corpus_size=corp_size,
        execs_done=runs,
        peak_rss=rss,
    )


def parse_statistics(
    measure: TimeMeasure,
    paths: LibFuzzerPaths,
) -> LibFuzzerStatistics:

    if not os.path.exists(paths.fuzzer_log):
        return null_statistics(measure)

    (runtime_stats, final_stats) = _get_statistics_raw(paths)
    stats = _parse_runtime_stats(runtime_stats, measure)

    execs_done = final_stats.get("number_of_executed_units")
    if execs_done is not None:
        stats.execs_done = int(execs_done)

    execs_per_sec = final_stats.get("average_exec_per_sec")
    if execs_per_sec is not None:
        stats.execs_per_sec = int(execs_per_sec)

    peak_rss = final_stats.get("peak_rss_mb")
    if peak_rss is not None:
        stats.peak_rss = int(peak_rss) << units["Mb"]

    if stats.execs_per_sec == 0 and measure.elapsed.seconds < 5:
        stats.execs_per_sec = stats.execs_done

    if stats.corpus_entries == 0:
        stats.corpus_size    = dirsize(paths.initial_corpus)
        stats.corpus_entries = len(os.listdir(paths.initial_corpus))

    return stats


async def run(
    config: FuzzerConfig,
    settings: AppSettings,
    paths: LibFuzzerPaths,
    container_mgr: UserContainerManager,
) -> Status:

    #
    # Prepare everything to run fuzzer:
    #   - read config, prepare env, cmd
    #   - find target binary
    #   - ...
    #

    logger = logging.getLogger("fuzzing")
    logger.info("Prepare everything to run fuzzer")

    cmd, env = prepare_fuzz_run(
        paths=paths,
        config=config,
        settings=settings,
    )

    #
    # Run fuzzer with builtin disk monitor
    # Ram and run time will be tracked via libfuzzer options
    #

    logger.info("Run fuzzer")

    if not os.path.exists(config.target.path):
        raise FuzzerLaunchError(f"Target not found: {config.target.path}")
    make_executable(config.target.path)

    try:
        exit_code = await container_mgr.exec_command(
            cmd=cmd,
            env=env,
            cwd=paths.user_home,
            stdin_file=None,
            stdout_file=None,
            stderr_file=paths.fuzzer_log,
            time_limit=settings.fuzzer.time_limit,
        )

        logger.info("Fuzzer finished running. Checking status")

        # detect if fuzzer exited by crash or by error
        if exit_code != 0:
            exit_by_crash = False

            # detect by crash file
            for file in os.listdir(paths.user_home):
                if file.startswith("crash-") or file.startswith("leak-") or file.startswith("timeout-") or file.startswith("oom-"):
                    exit_by_crash = True
                    break

            if not exit_by_crash:
                msg = "Fuzzer exited with error"
                raise FuzzerLaunchError(f"{msg}, exit_code={exit_code}")

        status = ok_status()

    except AgentError as e:
        truncate_libfuzzer_output(paths.fuzzer_log)
        status = error_status(e, paths.fuzzer_log)

    assert status is not None, "Should not happen!"

    logger.info("Exit with status code %s", status.code)

    return status

from contextlib import suppress
import json
import os
from typing import List

from base_agent.errors.codes import E_SUCCESS
from base_agent.errors import AgentError, InvalidConfigError

from base_agent.settings import AppSettings, EngineID, FuzzerMode
from base_agent.output import Statistics, Status
from base_agent.utils import TimeMeasure

from .config import FuzzerConfig
from .paths import *

with suppress(ModuleNotFoundError):
    from os import scandir
    from scandir import scandir


class LibFuzzerStatistics(Statistics):

    execs_per_sec: int
    """ Average count of executions per second """

    edge_cov: int
    """ Edge coverage """

    feature_cov: int
    """ Feature coverage """

    peak_rss: int
    """ Max RAM usage """

    execs_done: int
    """ Count of fuzzing iterations executed """

    corpus_entries: int
    """ Count of files in merged corpus """

    corpus_size: int
    """ The size of generated corpus in bytes """


def null_statistics(measure: TimeMeasure):
    return LibFuzzerStatistics(
        work_time=int(measure.elapsed.total_seconds()),
        corpus_entries=0,
        execs_done=0,
        feature_cov=0,
        corpus_size=0,
        edge_cov=0,
        execs_per_sec=0,
        peak_rss=0,
    )


def prepare_general_options(options: dict):
    return [f"-{k}={v}" for k, v in options.items()]


def prepare_sanitizer_options(options: dict):
    return ":".join([f"{k}={v}" for k, v in options.items()])


def prepare_fuzz_run(config: FuzzerConfig, settings: AppSettings, paths: LibFuzzerPaths):
    options = config.options.libfuzzer.dict(
        by_alias=True,
        exclude_none=True,
    )

    cmd = []

    # jazzer:
    #   jazzer --cp=<target> --target_class=<class> ...
    if settings.fuzzer.engine == EngineID.jazzer:
        cmd.append("jazzer")
        # TODO: fix later
        cmd.append("--agent_path=/opt/jazzer/jazzer_standalone.jar")
        cmd.append(f"--cp={config.target.path}")
        cmd.append(f"--target_class={config.target.target_class}")
    
    # atheris:
    #   python <target> ...
    elif settings.fuzzer.engine == EngineID.atheris:
        cmd.append("python")
        cmd.append(config.target.path)
    
    # normal:
    #   <target> ...
    else:
        cmd.append(config.target.path)

    cmd.extend(prepare_general_options(options))
    
    # new corpus
    cmd.append(paths.result_corpus)
    if not os.path.exists(paths.result_corpus):
        os.mkdir(paths.result_corpus)

    # input corpus
    cmd.append(paths.initial_corpus)
    if not os.path.exists(paths.initial_corpus):
        os.mkdir(paths.initial_corpus)

    if len(config.target.args) > 0:
        cmd.append("-ignore_remaining_args=1")
        cmd.extend(config.target.args)

    #
    # setup envs
    #
    envs = {
        **config.env,
        "ASAN_OPTIONS": prepare_sanitizer_options(
            config.options.asan.dict(by_alias=True, exclude_none=True)
        ),
    }

    return cmd, envs


def prepare_merge_run(config: FuzzerConfig, settings: AppSettings, paths: LibFuzzerPaths):
    options = config.options.libfuzzer.dict(
        by_alias=True,
        exclude_none=True,
    )

    # TODO: check close_mask_fd behavior in merge
    options["merge"] = "1"
    options["merge_control_file"] = paths.merge_control_file

    cmd = []

    # jazzer:
    #   jazzer --cp=<target> --target_class=<class> ...
    if settings.fuzzer.engine == EngineID.jazzer:
        cmd.append("jazzer")
        # TODO: fix later
        cmd.append("--agent_path=/opt/jazzer/jazzer_standalone.jar")
        cmd.append(f"--cp={config.target.path}")
        cmd.append(f"--target_class={config.target.target_class}")
    
    # atheris:
    #   python <target> ...
    elif settings.fuzzer.engine == EngineID.atheris:
        cmd.append("python")
        cmd.append(config.target.path)
    
    # normal:
    #   <target> ...
    else:
        cmd.append(config.target.path)

    cmd.extend(prepare_general_options(options))
    
    # output dir
    cmd.append(paths.merged_corpus)
    if not os.path.exists(paths.merged_corpus):
        os.mkdir(paths.merged_corpus)

    # old merged corpus
    if os.path.exists(paths.initial_corpus):
        cmd.append(paths.initial_corpus)

    # new corpus files from other runs
    if os.path.exists(paths.unmerged_corpus):
        cmd.append(paths.unmerged_corpus)
    
    # new corpus files(firstrun)
    if os.path.exists(paths.result_corpus):
        cmd.append(paths.result_corpus)

    if len(config.target.args) > 0:
        cmd.append("-ignore_remaining_args=1")
        cmd.extend(config.target.args)

    #
    # setup envs
    #
    envs = {
        **config.env,
        "ASAN_OPTIONS": prepare_sanitizer_options(
            config.options.asan.dict(by_alias=True, exclude_none=True)
        ),
    }

    return cmd, envs


def prepare_repro_run(config: FuzzerConfig, settings: AppSettings, paths: LibFuzzerPaths, crash_path: str):
    options = config.options.libfuzzer.dict(
        by_alias=True,
        exclude_none=True,
    )

    # runs when running individual inputs means:
    # how many times to run EACH input
    options.pop("runs", None)

    cmd = []

    # jazzer:
    #   jazzer --cp=<target> --target_class=<class> ...
    if settings.fuzzer.engine == EngineID.jazzer:
        cmd.append("jazzer")
        # TODO: fix later
        cmd.append("--agent_path=/opt/jazzer/jazzer_standalone.jar")
        cmd.append(f"--cp={config.target.path}")
        cmd.append(f"--target_class={config.target.target_class}")
    
    # atheris:
    #   python <target> ...
    elif settings.fuzzer.engine == EngineID.atheris:
        cmd.append("python")
        cmd.append(config.target.path)
    
    # normal:
    #   <target> ...
    else:
        cmd.append(config.target.path)

    cmd.extend(prepare_general_options(options))
    
    cmd.append(crash_path)

    if len(config.target.args) > 0:
        cmd.append("-ignore_remaining_args=1")
        cmd.extend(config.target.args)

    #
    # setup envs
    #
    envs = {
        **config.env,
        "ASAN_OPTIONS": prepare_sanitizer_options(
            config.options.asan.dict(by_alias=True, exclude_none=True)
        ),
    }

    return cmd, envs


def prepare_clean_run(config: FuzzerConfig, settings: AppSettings, paths: LibFuzzerPaths, corpus_files: List[str]):
    options = config.options.libfuzzer.dict(
        by_alias=True,
        exclude_none=True,
    )

    # runs when running individual inputs means:
    # how many times to run EACH input
    options.pop("runs", None)

    cmd = []

    # jazzer:
    #   jazzer --cp=<target> --target_class=<class> ...
    if settings.fuzzer.engine == EngineID.jazzer:
        cmd.append("jazzer")
        # TODO: fix later
        cmd.append("--agent_path=/opt/jazzer/jazzer_standalone.jar")
        cmd.append(f"--cp={config.target.path}")
        cmd.append(f"--target_class={config.target.target_class}")
    
    # atheris:
    #   python <target> ...
    elif settings.fuzzer.engine == EngineID.atheris:
        cmd.append("python")
        cmd.append(config.target.path)
    
    # normal:
    #   <target> ...
    else:
        cmd.append(config.target.path)

    cmd.extend(prepare_general_options(options))
    
    cmd.extend(corpus_files)

    if len(config.target.args) > 0:
        cmd.append("-ignore_remaining_args=1")
        cmd.extend(config.target.args)

    #
    # setup envs
    #
    envs = {
        **config.env,
        "ASAN_OPTIONS": prepare_sanitizer_options(
            config.options.asan.dict(by_alias=True, exclude_none=True)
        ),
    }

    return cmd, envs


def get_config(config_file: str):

    #
    # Default config if no file
    #

    if not os.path.exists(config_file):
        return FuzzerConfig()

    #
    # Read and parse config
    #

    with open(config_file, "r", encoding="utf-8") as f:
        config = f.read()

    try:
        config_dict = json.loads(config)
        if not isinstance(config_dict, dict):
            raise ValueError("Invalid format")

        parsed_config = FuzzerConfig(**config_dict)

    except ValueError as e:
        raise InvalidConfigError(str(e)) from e

    return parsed_config


def set_default_config_entries(
    config: FuzzerConfig,
    paths: LibFuzzerPaths,
    settings: AppSettings,
):
    libfuzzer = config.options.libfuzzer

    #
    # setup target
    # like /bondi/fuzzer/<target>
    #

    if settings.fuzzer.engine == EngineID.jazzer:
        if config.target.target_class is None:
            raise InvalidConfigError("Target class required by jazzer engine")
    else:
        if config.target.target_class is not None:
            raise InvalidConfigError("Invalid target definition: class is not supported by this engine")

    if config.target.path is None:
        config.target.path = settings.agent.default_target
    config.target.path = os.path.join(paths.user_home, config.target.path)
    

    #
    # setup limits
    #
    
    libfuzzer.rss_limit_mb    = str(settings.fuzzer.ram_limit)
    # TODO:
    libfuzzer.malloc_limit_mb = str(int(settings.fuzzer.ram_limit * 0.65))

    if settings.agent.mode == FuzzerMode.firstrun:
        libfuzzer.runs           = str(settings.fuzzer.num_iterations_firstrun)
        libfuzzer.max_total_time = str(settings.fuzzer.time_limit_firstrun)
    else:
        libfuzzer.runs           = str(settings.fuzzer.num_iterations)
        libfuzzer.max_total_time = str(settings.fuzzer.time_limit)


    #
    # setup output options
    #

    libfuzzer.print_final_stats = "1"

    # try to minimize logs
    # in cpp stacktrace reported by sanitizer
    # so we close target's stdout and stderr
    if settings.fuzzer.engine == EngineID.libfuzzer:
        libfuzzer.close_fd_mask = "3"
    
    # in python stacktrace prints to stdout
    # so we close target's stderr
    elif settings.fuzzer.engine == EngineID.atheris:
        libfuzzer.close_fd_mask = "2"
    
    # in all other binding stacktrace prints to stderr
    # so we close target's stdout
    else:
        libfuzzer.close_fd_mask = "1"

    #
    # setup engine specific options
    #

    # TODO: switch to "full"
    # Rust specific env to print stacktrace
    if settings.fuzzer.engine == EngineID.cargo_fuzz:
        config.env["RUST_BACKTRACE"] = "1"


def truncate_libfuzzer_output(filename: str):

    pos = 0
    with open(filename, "r+", encoding="utf-8") as f:
        for line in iter(lambda: f.readline(), ""):
            if "base unit:" in line:
                f.seek(pos, os.SEEK_SET)
                f.truncate()
                break
            pos = f.tell()


def ok_status() -> Status:
    return Status(code=E_SUCCESS, message="Success")


def error_status(e: AgentError, log_file: str):

    with open(log_file, "r", encoding="utf-8") as f:
        details = f.read()

    return Status(
        code=e.code,
        message=e.message,
        details=details[-10000:],
    )


def fs_consumed(fs_path: str) -> int:
    if not os.path.exists(fs_path):
        return 0

    stat = os.statvfs(fs_path)
    return (stat.f_blocks - stat.f_bavail) * stat.f_bsize


def dirsize(path: str):

    #
    # File can be deleted during stat call
    # Handle this situation using suppress
    #

    total_size = 0
    for item in scandir(path):
        with suppress(FileNotFoundError):
            if item.is_file():
                total_size += item.stat().st_size
            elif item.is_dir():
                total_size += dirsize(item.path)

    return total_size

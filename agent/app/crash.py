from __future__ import annotations
from typing import TYPE_CHECKING

import os
import logging
from base64 import b64encode
from contextlib import suppress
from base_agent.output import CrashBase

from agent.app.utils import prepare_clean_run, prepare_repro_run
from base_agent.utils import make_executable

from .paths import LibFuzzerPaths

from base_agent.errors import FuzzerLaunchError, RamLimitExceeded
from base_agent.settings import EngineID

if TYPE_CHECKING:
    from typing import List, Tuple
    from agent.app.config import FuzzerConfig
    from base_agent.settings import AppSettings
    from base_agent.kubernetes import UserContainerManager

class LibfuzzerCrash(CrashBase):
    pass


def _create_crash(
    crash_path: str, 
    crash_type: str, 
    output_path: str, 
    reproduced: bool,
) -> LibfuzzerCrash:

    with open(crash_path, "rb") as f:
        input = b64encode(f.read()).decode()

    with open(output_path, "r", encoding="utf-8") as f:
        output = f.read()

    return LibfuzzerCrash(
        input_id=None,
        type=crash_type,
        input=input,
        output=output,
        reproduced=reproduced,
    )


def _look_for_crashes(
    paths: LibFuzzerPaths,
) -> List[Tuple[str, str]]:

    crash_types = ("crash", "leak", "oom", "timeout")
    crashes = []

    for filename in os.listdir(paths.user_home):
        for crash_type in crash_types:
            if filename.startswith(crash_type):
                path = os.path.abspath(os.path.join(paths.user_home, filename))
                crashes.append((path, crash_type))

    return crashes


async def process_crashes(
    config: FuzzerConfig,
    settings: AppSettings,
    paths: LibFuzzerPaths,
    container_mgr: UserContainerManager,
) -> List[LibfuzzerCrash]:
    crashes = []
    for crash_path, crash_type in _look_for_crashes(paths):
        # TODO: exception handling in reproduce
        crashes.append(
            await _process_crash(
                paths=paths,
                config=config,
                settings=settings,
                container_mgr=container_mgr,
                crash_path=crash_path,
                crash_type=crash_type,
            )
        )
    return crashes


async def _process_crash(
    config: FuzzerConfig,
    settings: AppSettings,
    paths: LibFuzzerPaths,
    container_mgr: UserContainerManager,
    crash_path: str,
    crash_type: str,
) -> LibfuzzerCrash:

    logger = logging.getLogger("repro")
    logger.info(f"Running reproduce for \"{crash_path}\"")

    cmd, env = prepare_repro_run(
        paths=paths,
        config=config,
        settings=settings,
        crash_path=crash_path,
    )

    #
    # Try to reproduce crash
    # If crash is reproduced, then save details
    #

    # atheris writes stacktrace to stdout
    if settings.fuzzer.engine == EngineID.atheris:
        stdout_file = paths.repro_log
    else:
        stdout_file = None

    if not os.path.exists(config.target.path):
        raise FuzzerLaunchError(f"Target not found: {config.target.path}")
    make_executable(config.target.path)

    exit_code = await container_mgr.exec_command(
        cmd=cmd,
        cwd=paths.user_home,
        env=env,
        stdin_file=None,
        stdout_file=stdout_file,
        stderr_file=paths.repro_log,
        time_limit=1 * 60, # TODO:
    )

    #
    # Get rid of crash bytes in the end of fuzzer output
    # They can significantly increase file size
    #

    reproduced = exit_code != 0

    msg = "Crash info: type=%s, reproduced=%s"
    logger.info(msg, crash_type, reproduced)

    #
    # Assume -rss_limit_mb triggered
    # So, fuzzer exceeded ram limit
    #

    if crash_type == "oom" and not reproduced:
        logger.warn("Not a crash. Most likely fuzzer has reached peak rss")
        raise RamLimitExceeded()
    

    return _create_crash(
        crash_path=crash_path,
        crash_type=crash_type,
        output_path=paths.repro_log,
        reproduced=reproduced,
    )


async def clean_corpus(
    config: FuzzerConfig,
    settings: AppSettings,
    paths: LibFuzzerPaths,
    container_mgr: UserContainerManager,
) -> List[LibfuzzerCrash]:
    logger = logging.getLogger("cleaning")
    
    corpuses = []
    if os.path.exists(paths.initial_corpus):
        for path, _, files in os.walk(paths.initial_corpus):
            for file in files:
                corpuses.append(os.path.join(path, file))

    if os.path.exists(paths.unmerged_corpus):
        for path, _, files in os.walk(paths.unmerged_corpus):
            for file in files:
                corpuses.append(os.path.join(path, file))

    logger.info(f"Running corpus cleaning on {len(corpuses)} corpuses")
    
    res = []
    chunk_size = 50
    for start in range(0, len(corpuses), chunk_size):
        end = min(start + chunk_size, len(corpuses))
        logger.debug(f"start={start}, end={end}")
        chunk = corpuses[start:end]
        res.extend(
            await _clean_corpus(
                paths=paths,
                config=config,
                settings=settings,
                container_mgr=container_mgr,
                corpuses=chunk,
            )
        )

    logger.info(f"Corpus cleaning finished. Found {len(res)} crashes")
    return res


async def _clean_corpus(
    config: FuzzerConfig,
    settings: AppSettings,
    paths: LibFuzzerPaths,
    container_mgr: UserContainerManager,
    corpuses: List[str],
) -> List[LibfuzzerCrash]:
    logger = logging.getLogger("cleaning")
    res = []

    while True:

        cmd, env = prepare_clean_run(
            paths=paths,
            config=config,
            settings=settings,
            corpus_files=corpuses,
        )

        # atheris writes stacktrace to stdout
        if settings.fuzzer.engine == EngineID.atheris:
            stdout_file = paths.clean_log
        else:
            stdout_file = None

        if not os.path.exists(config.target.path):
            raise FuzzerLaunchError(f"Target not found: {config.target.path}")
        make_executable(config.target.path)

        exit_code = await container_mgr.exec_command(
            cmd=cmd,
            cwd=paths.user_home,
            env=env,
            stdin_file=None,
            stdout_file=stdout_file,
            stderr_file=paths.clean_log,
            time_limit=5 * 60, # TODO:
        )


        #
        # Get rid of crash bytes in the end of fuzzer output
        # They can significantly increase file size
        #

        logger.debug(f"Cleaning exit_code={exit_code}")

        if exit_code == 0:
            break

        last_running = None
        with open(paths.clean_log, "r") as f:
            for line in f:
                if line.startswith("Running: "):
                    last_running = line[len("Running: "):].strip()

        if last_running is None:
            details = ""
            with suppress(Exception):
                with open(paths.clean_log, "r") as f:
                    details = f.read()
            msg = "Fuzzer crashed while cleaning corpus"
            raise FuzzerLaunchError(
                message=f"{msg}",
                details=details[-10000:],
            )
        
        logger.info(f"Found crash: \"{last_running}\"")
        res.append(
            await _process_crash(
                paths=paths,
                config=config,
                settings=settings,
                container_mgr=container_mgr,
                crash_path=last_running,
                crash_type="crash", # TODO: 
            )
        )
        os.unlink(last_running)
        corpuses.remove(last_running)
    
    return res

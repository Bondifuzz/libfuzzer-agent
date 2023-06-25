from typing import List, Optional, Dict
from pydantic import Extra, Field, validator, root_validator
from pydantic import BaseModel as _BaseModel


class ConfigModel(_BaseModel, extra=Extra.forbid):
    pass


def find_forbidden_symbols(value: str):

    symbols_found = []
    bad_symbols = ["&", "|", ";", "$", "`", "<", ">", "#"]

    for symbol in bad_symbols:
        if symbol in value:
            symbols_found.append(symbol)

    return symbols_found


class OptionsModel(ConfigModel):

    """Prevents command injection"""

    @root_validator
    def check_data(cls, data: dict):

        places = []
        for key, value in data.items():

            if not isinstance(value, str):
                continue

            symbols = find_forbidden_symbols(value)

            if len(symbols) > 0:
                places.append(f"in field '{key}': {''.join(symbols)}")

        if len(places) > 0:
            places = ", ".join(places)
            msg = f"Found forbidden symbols: {places}"
            raise ValueError(msg)

        return data


class LibFuzzerOptions(OptionsModel):
    verbosity: Optional[str]  # -
    seed: Optional[str]
    runs: Optional[str]  # -
    max_len: Optional[str]
    len_control: Optional[str]
    seed_inputs: Optional[str]  # - Do not use this. Because all seeds in folder
    keep_seed: Optional[str] 
    cross_over: Optional[str]
    cross_over_uniform_dist: Optional[str]
    mutate_depth: Optional[str]
    reduce_depth: Optional[str]
    shuffle: Optional[str]
    prefer_small: Optional[str]
    timeout: Optional[str]  # -
    error_exitcode: Optional[str]  # -
    timeout_exitcode: Optional[str]  # -
    max_total_time: Optional[str]  # -
    help: Optional[str]  # -
    fork: Optional[str]  # -
    fork_corpus_groups: Optional[str]
    ignore_timeouts: Optional[str]  # -
    ignore_ooms: Optional[str]  # -
    ignore_crashes: Optional[str]  # -
    merge: Optional[str]  # -
    set_cover_merge: Optional[str]  # -
    stop_file: Optional[str]  # -
    # merge_inner
    merge_control_file: Optional[str]  # - Set this file
    minimize_crash: Optional[str]  # -
    cleanse_crash: Optional[str]  # -
    # minimize_crash_internal_step
    # features_dir
    mutation_graph_file: Optional[str]
    use_counters: Optional[str]  # -
    use_memmem: Optional[str]  # -
    use_value_profile: Optional[str]  # -
    use_cmp: Optional[str]  # -
    shrink: Optional[str]  # -
    reduce_inputs: Optional[str]  # -
    jobs: Optional[str]  # -
    workers: Optional[str]  # -
    reload: Optional[str]  # - Set to 0 because jobs, workers = 0, no other processes
    report_slow_units: Optional[str]
    only_ascii: Optional[str]
    dict_path: Optional[str] = Field(alias="dict")
    artifact_prefix: Optional[str]  # -  Set another path
    exact_artifact_path: Optional[str]  # -
    print_pcs: Optional[str]  # -
    print_funcs: Optional[str]
    print_final_stats: Optional[str]  # -
    print_corpus_stats: Optional[str]  # -
    print_coverage: Optional[str]  # -
    print_full_coverage: Optional[str]  # -
    dump_coverage: Optional[str]  # -
    handle_segv: Optional[str]  # -
    handle_bus: Optional[str]  # -
    handle_abrt: Optional[str]  # -
    handle_ill: Optional[str]  # -
    handle_fpe: Optional[str]  # -
    handle_int: Optional[str]  # -
    handle_term: Optional[str]  # -
    handle_xfsz: Optional[str]  # -
    handle_usr1: Optional[str]  # -
    handle_usr2: Optional[str]  # -
    # handle_winexcept
    close_fd_mask: Optional[str]  # -
    detect_leaks: Optional[str]
    purge_allocator_interval: Optional[str]  # -
    trace_malloc: Optional[str]  # -
    rss_limit_mb: Optional[str]  # -
    malloc_limit_mb: Optional[str]  # -
    exit_on_src_pos: Optional[str]  # -
    exit_on_item: Optional[str]  # -
    ignore_remaining_args: Optional[str]  # -
    focus_function: Optional[str]  # -
    entropic: Optional[str]  # -
    entropic_feature_frequency_threshold: Optional[str]  # -
    entropic_number_of_rarest_features: Optional[str]  # -
    entropic_scale_per_exec_time: Optional[str]  # -
    analyze_dict: Optional[str]  # -
    use_clang_coverage: Optional[str]  # -
    data_flow_trace: Optional[str]  # -
    collect_data_flow: Optional[str]  # -
    create_missing_dirs: Optional[str]  # -

    @validator(
        "verbosity",
        "seed",
        "runs",
        #"max_len",
        #"len_control",
        "seed_inputs",
        "keep_seed",
        #"cross_over",
        #"cross_over_uniform_dist",
        #"mutate_depth",
        #"reduce_depth",
        #"shuffle",
        #"prefer_small",
        #"timeout",
        "error_exitcode",
        "timeout_exitcode",
        "max_total_time",
        "help",
        "fork", # TODO: investigate
        "fork_corpus_groups", # TODO: investigate
        "ignore_timeouts", # TODO: investigate
        "ignore_ooms", # TODO: investigate
        "ignore_crashes", # TODO: investigate
        "merge",
        "set_cover_merge",
        "stop_file", # TODO: investigate
        #"merge_inner", # internal
        "merge_control_file",
        "minimize_crash",
        "cleanse_crash",
        #"minimize_crash_internal_step", # internal
        #"features_dir", # internal
        "mutation_graph_file",
        #"use_counters",
        #"use_memmem",
        #"use_value_profile",
        #"use_cmp",
        #"shrink",
        #"reduce_inputs",
        "jobs", # TODO: investigate
        "workers", # TODO: investigate
        "reload", # TODO: investigate
        "report_slow_units", # TODO: investigate
        #"only_ascii",
        #"dict_path",
        "artifact_prefix",
        "exact_artifact_path",
        "print_pcs",
        "print_funcs",
        "print_final_stats",
        "print_corpus_stats",
        "print_coverage",
        "print_full_coverage",
        "dump_coverage",
        #"handle_segv",
        #"handle_bus",
        #"handle_abrt",
        #"handle_ill",
        #"handle_fpe",
        #"handle_int",
        #"handle_term",
        #"handle_xfsz",
        #"handle_usr1",
        #"handle_usr2",
        #"handle_winexcept",
        "close_fd_mask",
        #"detect_leaks",
        "purge_allocator_interval", # TODO: investigate
        "trace_malloc",
        "rss_limit_mb",
        "malloc_limit_mb",
        "exit_on_src_pos",
        "exit_on_item",
        "ignore_remaining_args",
        #"focus_function",
        #"entropic",
        #"entropic_feature_frequency_threshold",
        #"entropic_number_of_rarest_features",
        #"entropic_scale_per_exec_time",
        "analyze_dict",
        "use_clang_coverage",
        #"data_flow_trace",
        #"collect_data_flow",
        "create_missing_dirs",
    )
    def can_not_be_overridden(cls, value):
        if value is not None:
            raise ValueError(f"Option can not be overridden")
        return value


class AsanOptions(OptionsModel):
    quarantine_size: Optional[str]
    quarantine_size_mb: Optional[str]
    redzone: Optional[str]
    max_redzone: Optional[str]
    debug: Optional[str]                     = Field(default="false")
    report_globals: Optional[str]
    check_initialization_order: Optional[str]
    replace_str: Optional[str]
    replace_intrin: Optional[str]
    detect_stack_use_after_return: Optional[str]
    min_uar_stack_size_log: Optional[str]
    max_uar_stack_size_log: Optional[str]
    uar_noreserve: Optional[str]
    max_malloc_fill_size: Optional[str]
    malloc_fill_byte: Optional[str]
    allow_user_poisoning: Optional[str]
    sleep_before_dying: Optional[str]        = Field(default="0")
    check_malloc_usable_size: Optional[str]
    unmap_shadow_on_exit: Optional[str]
    protect_shadow_gap: Optional[str]
    print_stats: Optional[str]               = Field(default="false")
    print_legend: Optional[str]              = Field(default="true")
    atexit: Optional[str]                    = Field(default="false")
    print_full_thread_history: Optional[str] = Field(default="true")
    poison_heap: Optional[str]
    poison_partial: Optional[str]
    poison_array_cookie: Optional[str]
    alloc_dealloc_mismatch: Optional[str]
    new_delete_type_mismatch: Optional[str]
    strict_init_order: Optional[str]
    strict_string_checks: Optional[str]
    start_deactivated: Optional[str]
    detect_invalid_pointer_pairs: Optional[str]
    detect_container_overflow: Optional[str]
    detect_odr_violation: Optional[str]
    dump_instruction_bytes: Optional[str]    = Field(default="false")
    suppressions: Optional[str]
    halt_on_error: Optional[str]             = Field(default="true")
    log_path: Optional[str]                  = Field(default="stderr")
    use_odr_indicator: Optional[str]
    allocator_frees_and_returns_null_on_realloc_zero: Optional[str]
    verify_asan_link_order: Optional[str]

    @validator(
        #"quarantine_size",
        #"quarantine_size_mb",
        #"redzone",
        #"max_redzone",
        "debug",
        #"report_globals",
        #"check_initialization_order",
        #"replace_str",
        #"replace_intrin",
        #"detect_stack_use_after_return",
        #"min_uar_stack_size_log",
        #"max_uar_stack_size_log",
        #"uar_noreserve",
        #"max_malloc_fill_size",
        #"malloc_fill_byte",
        #"allow_user_poisoning",
        "sleep_before_dying", # TODO: investigate
        #"check_malloc_usable_size",
        #"unmap_shadow_on_exit",
        #"protect_shadow_gap",
        "print_stats",
        "print_legend",
        "atexit",
        "print_full_thread_history",
        #"poison_heap",
        #"poison_partial",
        #"poison_array_cookie",
        #"alloc_dealloc_mismatch",
        #"new_delete_type_mismatch",
        #"strict_init_order",
        #"strict_string_checks",
        #"start_deactivated",
        #"detect_invalid_pointer_pairs",
        #"detect_container_overflow",
        #"detect_odr_violation",
        "dump_instruction_bytes",
        #"suppressions",
        "halt_on_error", # TODO: investigate
        "log_path",
        #"use_odr_indicator",
        #"allocator_frees_and_returns_null_on_realloc_zero",
        #"verify_asan_link_order",
    )
    def can_not_be_overridden(cls, value):
        if value is not None:
            raise ValueError(f"Option can not be overridden")
        return value


class ConfigOptions(ConfigModel):
    libfuzzer: LibFuzzerOptions = Field(default_factory=LibFuzzerOptions)
    asan: AsanOptions           = Field(default_factory=AsanOptions)
    # TODO: msan, ...


class TargetConfig(ConfigModel):
    path: Optional[str]         = Field(None)
    args: List[str]             = Field(default_factory=list)
    target_class: Optional[str] = Field(None, alias="class")

    @validator("path")
    def check_target(cls, value: Optional[str]):

        if not value:
            return None

        symbols = find_forbidden_symbols(value)

        if len(symbols) > 0:
            msg = f"Contains forbidden symbols: {''.join(symbols)}"
            raise ValueError(msg)

        return value


class FuzzerConfig(ConfigModel):
    target: TargetConfig   = Field(default_factory=TargetConfig)
    env: Dict[str, str]    = Field(default_factory=dict)
    options: ConfigOptions = Field(default_factory=ConfigOptions)


    @validator("env")
    def check_env(cls, value: Optional[Dict[str, str]]):

        if value is None:
            return None

        places = []
        for key, val in value.items():

            key_symbols = find_forbidden_symbols(key)
            val_symbols = find_forbidden_symbols(val)

            if len(key_symbols) > 0:
                places.append(f"in key '{key}': {''.join(key_symbols)}")

            if len(val_symbols) > 0:
                places.append(f"in value '{val}': {''.join(val_symbols)}")

        if len(places) > 0:
            places = ", ".join(places)
            msg = f"Contains forbidden symbols: {places}"
            raise ValueError(msg)

        return value

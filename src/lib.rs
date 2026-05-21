#![cfg_attr(test, allow(dead_code))]

/**
 * Copyright (c) 2023 Institute of Computing Technology, Chinese Academy of Sciences
 * sfuzz is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */
mod coverage;
mod coverage_strategy;
mod directed;
mod fuzzer;
mod harness;
mod monitor;
mod seed;
mod seed_codec;

use clap::Parser;

#[derive(Parser, Default, Debug)]
struct Arguments {
    // Fuzzer options
    #[clap(default_value_t = false, short, long)]
    fuzzing: bool,
    #[clap(default_value_t = String::from("llvm.branch"), short, long)]
    coverage: String,
    #[clap(default_value_t = false, short, long)]
    verbose: bool,
    #[clap(long)]
    max_iters: Option<u64>,
    #[clap(long)]
    max_runs: Option<u64>,
    #[clap(long)]
    max_run_timeout: Option<u64>,
    #[clap(default_value_t = false, long)]
    random_input: bool,
    #[clap(default_value_t = String::from("./corpus"), long)]
    corpus_input: String,
    #[clap(long)]
    corpus_output: Option<String>,
    #[clap(default_value_t = false, long)]
    continue_on_errors: bool,
    #[clap(default_value_t = false, long)]
    save_errors: bool,
    // DirectFuzz options
    #[clap(default_value_t = false, long)]
    directed: bool,
    #[clap(long)]
    target_module: Option<String>,
    #[clap(long)]
    dump_sancov_info: Option<String>,
    // Run options
    #[clap(default_value_t = 1, long)]
    repeat: usize,
    #[clap(default_value_t = false, long)]
    auto_exit: bool,
    extra_args: Vec<String>,
}

fn sfuzz_main() -> i32 {
    let args = Arguments::parse();
    let coverage = match coverage_strategy::normalize_coverage_strategy(&args.coverage) {
        Ok(coverage) => coverage,
        Err(err) => {
            eprintln!("Invalid --coverage value '{}': {err}", args.coverage);
            return 2;
        }
    };

    let mut workloads: Vec<String> = Vec::new();
    let mut emu_args: Vec<String> = Vec::new();

    let mut is_emu = false;
    for arg in args.extra_args {
        if arg.starts_with("-") {
            is_emu = true;
        }

        if is_emu {
            emu_args.push(arg);
        } else {
            workloads.push(arg);
        }
    }

    harness::set_sim_env(coverage, args.verbose, args.max_runs, emu_args);

    let mut has_failed = 0;
    if workloads.len() > 0 {
        for _ in 0..args.repeat {
            let ret = harness::sim_run_multiple(&workloads, args.auto_exit);
            if ret != 0 {
                has_failed = 1;
                if args.auto_exit {
                    return ret;
                }
            }
        }
        coverage::cover_display();
    }

    // Dump SanCov info if requested (for offline analysis)
    if let Some(ref filename) = args.dump_sancov_info {
        directed::dump_sancov_info_to_file(filename);
        println!("SanCov info dumped to {}. Exiting.", filename);
        return 0;
    }

    if args.fuzzing {
        let corpus_input = if args.corpus_input == "random" {
            None
        } else {
            Some(args.corpus_input.clone())
        };
        if args.directed {
            let target = args.target_module.clone().unwrap_or_else(|| {
                println!("DirectFuzz requires --target-module <path>. Using default: SimTop.soc.cc_0.tile.l2cache");
                "SimTop.soc.cc_0.tile.l2cache".to_string()
            });
            fuzzer::run_directed_fuzzer(
                target,
                args.random_input,
                args.max_iters,
                args.max_run_timeout,
                corpus_input,
                args.corpus_output,
                args.continue_on_errors,
                args.save_errors,
            );
        } else {
            fuzzer::run_fuzzer(
                args.random_input,
                args.max_iters,
                args.max_run_timeout,
                corpus_input,
                args.corpus_output,
                args.continue_on_errors,
                args.save_errors,
            );
        }
    }

    return has_failed;
}

#[cfg(not(test))]
#[unsafe(no_mangle)]
fn main() -> i32 {
    sfuzz_main()
}

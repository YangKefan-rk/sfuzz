# SFuzz 论文对比实验方案

## 定位

SFuzz 是本文的主工具。RFuzz、DirectFuzz、SurgeFuzz、PROFUZZ 不是替代主线的工程入口，而是为了论文评估而在同一工程内整理的 paper-faithful 复现对象。实验设计的目标是回答：

1. 在相同 LinkNan 设计、相同仿真器约束、相同时间或执行预算下，SFuzz 相比已有方法能否获得更多有效硬件状态覆盖、协议覆盖或目标事件触达。
2. SFuzz 的输入建模、反馈信号和调度策略对多核 SoC 仿真的贡献，是否可以通过与 RFuzz、DirectFuzz、SurgeFuzz 复现结果的差异体现出来。
3. 各方法在真实 LinkNan/VCS 条件下的成本，包括吞吐、构建成本、单次仿真耗时、有效输入比例、崩溃或断言触发效率。

当前阶段先完成并验证 RFuzz、DirectFuzz、SurgeFuzz 三个复现对象。PROFUZZ 需要 ATPG、目标站点覆盖和 EDA 报告解析边界，放到后续阶段，本文档先保留其对比口径，不把它纳入第一批必须完成的表格。

## 对比对象

| 对象 | 实验角色 | 输入模型 | 论文定义的反馈/覆盖 | 当前阶段要求 |
| --- | --- | --- | --- | --- |
| SFuzz | 主工具和主线结果 | SFUZ 结构化种子，面向 LinkNan 多核 SoC 程序镜像、共享内存和运行配置 | SFuzz 原生反馈，以及 LinkNan 可验证的真实覆盖后端，例如 FIRRTL 协议覆盖、SanCov guard/branch 覆盖、可组合覆盖策略 | 必须可以在 LinkNan/VCS 上运行真实种子并记录真实覆盖、吞吐和故障结果 |
| RFuzz 复现 | 覆盖导向 RTL fuzzing 对照 | 顶层输入引脚按周期展开的 raw pin-stream | mux-select toggle coverage；total coverage；valid-input-only coverage；crash objective | 第一阶段实现。论文主表只能使用真实 mux-select toggle 采样和真实 valid 判定 |
| DirectFuzz 复现 | 目标导向 RTL fuzzing 对照 | 与 RFuzz 相同的 RTL 输入流，结合目标 module instance | 每个 testcase 的本地 per-instance mux-toggle coverage；到目标实例的 input distance；target-instance coverage；distance-based energy；target-priority queue | 第一阶段实现。论文主表只能使用真实 per-instance mux-toggle 和真实静态距离 metadata |
| SurgeFuzz 复现 | surge-aware directed fuzzing 对照 | 能驱动 CPU 异常事件或注解事件的 testcase | 每周期 `coverage_target` 分数；selected ancestor-state coverage；`score^2` energy；FREQ/CONSEC/COUNT 注解语义 | 第一阶段实现。论文主表只能使用真实每周期注解信号和 ancestor coverage |
| PROFUZZ 复现 | 后续阶段对照 | ATPG 0/1/X pattern 及其合并、变异后的 bit pattern | target-site coverage；覆盖阈值和相对提升反馈；ATPG 目标覆盖报告 | 暂不作为第一阶段必做结果。需要先确定 ATPG 工具、target-site metadata 和仿真覆盖报告来源 |

## 实验目标

主实验应围绕 SFuzz 展开，而不是围绕脚本封装展开。建议将论文问题组织为以下四组：

1. 覆盖能力：SFuzz 在相同预算下覆盖了多少 LinkNan 协议点、RTL 覆盖点、目标实例或目标事件。
2. bug/异常发现能力：SFuzz 是否更快触发断言、模拟器错误、超时、协议非法状态或可复现的设计异常。
3. 效率：SFuzz 每小时完成多少有效仿真、单位覆盖增量需要多少时间、VCS 仿真成本是否可接受。
4. 消融：SFuzz 的结构化输入、反馈组合、调度策略分别带来多少增益。

RFuzz、DirectFuzz、SurgeFuzz 复现结果用于回答“与已有论文方法相比 SFuzz 是否更有效”。因此论文表格里应使用方法名本身，例如 `SFuzz`、`RFuzz`、`DirectFuzz`、`SurgeFuzz`，不要使用带有流水线自测含义的模式名。

## 数据指标

### 通用执行指标

这些指标所有方法都需要记录：

| 指标 | 含义 | 来源 |
| --- | --- | --- |
| `design_revision` | LinkNan git revision、配置、核心数、关键构建选项 | 实验配置记录 |
| `simulator` | VCS 版本、编译选项、运行选项 | 构建日志和运行配置 |
| `campaign_id` | 一次完整 fuzz campaign 的唯一编号 | 实验管理层 |
| `method` | `SFuzz`、`RFuzz`、`DirectFuzz`、`SurgeFuzz`、后续 `PROFUZZ` | 实验配置 |
| `seed_set` | 起始语料集合名称和 hash | 测试集清单 |
| `time_budget_sec` | campaign 时间预算 | 实验配置 |
| `exec_budget` | 最大 testcase 或仿真次数预算 | 实验配置 |
| `executions` | 实际执行 testcase 数 | fuzzer 运行状态 |
| `valid_executions` | 通过方法定义或 LinkNan 判定的有效执行数 | 真实有效性判定 |
| `timeouts` | 超时次数 | 仿真器退出状态和 fuzzer 状态 |
| `crashes` | crash/objective 次数 | 仿真器退出状态、断言和可复现错误 |
| `unique_crashes` | 去重后的 crash/objective 数 | crash signature 去重 |
| `wall_time_sec` | 总墙钟时间 | 运行器计时 |
| `execs_per_hour` | 吞吐 | `executions / wall_time` |
| `median_exec_time_sec` | 单次 testcase 中位耗时 | per-testcase 计时 |

### SFuzz 指标

SFuzz 主结果应至少报告：

| 指标 | 含义 | 必须来源 |
| --- | --- | --- |
| `sfuzz_feedback_backend` | 使用的 SFuzz 反馈后端，例如 `FIRRTL.MSHR`、`FIRRTL.all`、`llvm.branch`、`union:<a>+<b>` | SFuzz 实际运行配置 |
| `sfuzz_coverage_total` | 后端声明的总覆盖点数 | LinkNan/FIRRTL/SanCov 真实 coverage metadata |
| `sfuzz_coverage_covered` | 已覆盖点数 | 运行结束时真实 coverage map |
| `sfuzz_coverage_percent` | 覆盖率 | 真实覆盖计算 |
| `sfuzz_queue_size` | 保留到 corpus 的 interesting input 数 | LibAFL/SFuzz 状态 |
| `sfuzz_objectives` | crash、assert、timeout 等 objective 数 | fuzzer objective 状态和仿真器状态 |
| `sfuzz_seed_bytes` | 输入大小分布 | SFUZ 种子文件或 corpus metadata |

### RFuzz 指标

RFuzz 复现的论文指标必须来自真实 mux-select toggle instrumentation：

| 指标 | 含义 | 必须来源 |
| --- | --- | --- |
| `rfuzz_mux_bits_total` | 可观测 mux-select bit 总数 | RTL/FIRRTL instrumentation metadata |
| `rfuzz_local_toggle_bits` | 单个 testcase 产生的本地 toggle bit 数 | 每周期 mux-select 采样后的 `initial_sample ^ current_sample` |
| `rfuzz_total_covered_bits` | corpus 累积 total mux-toggle 覆盖 | RFuzz coverage map |
| `rfuzz_valid_covered_bits` | 有效输入 corpus 累积 valid-only 覆盖 | RFuzz valid coverage map |
| `rfuzz_valid` | 当前 testcase 是否满足接口约束 | 真实接口有效性检查 |
| `rfuzz_interesting` | 是否因新增 total/valid 覆盖或 crash 被保留 | RFuzz feedback policy |

不能把 VCS 日志中出现的运行成功、退出码、周期数、字符串匹配结果当作 RFuzz 覆盖。也不能用随机生成的 bitmap、从 seed hash 派生的 bitmap、或普通 VCS code coverage 替代 mux-select toggle coverage。

### DirectFuzz 指标

DirectFuzz 复现的论文指标必须来自目标实例的静态距离 metadata 和本地 per-input coverage：

| 指标 | 含义 | 必须来源 |
| --- | --- | --- |
| `direct_target_instance` | 目标 module instance 名称 | 实验配置和静态分析输出 |
| `direct_instances_total` | metadata 中 coverage instance 数 | DirectFuzz metadata |
| `direct_reachable_instances` | 可到达目标的 instance 数 | 距离 metadata |
| `direct_input_distance` | 当前 testcase 到目标的距离 | 当前 testcase 的本地 per-instance mux-toggle coverage |
| `direct_target_covered_bits` | 当前 testcase 覆盖到的目标实例 bit 数 | 本地 per-instance coverage |
| `direct_energy` | mutation energy | DirectFuzz distance-based power schedule |
| `direct_queue_class` | target-priority queue 或 regular queue | DirectFuzz scheduler 状态 |
| `direct_target_progress` | 是否产生目标覆盖进展 | 真实目标实例覆盖变化 |

DirectFuzz 的 `direct_input_distance` 不能从累积 coverage bitmap 计算，必须按论文定义使用单个 testcase 的本地覆盖。不能用函数名、日志行、SanCov guard、运行周期数或人工 mock distance 代替 per-instance mux-toggle coverage。

### SurgeFuzz 指标

SurgeFuzz 复现的论文指标必须来自每周期注解信号和祖先寄存器状态：

| 指标 | 含义 | 必须来源 |
| --- | --- | --- |
| `surge_annotation` | `FREQ`、`CONSEC`、`COUNT` 目标类型 | RTL/Yosys/FIRRTL 注解和 metadata |
| `surge_coverage_target` | 每周期被打分的目标信号 | 仿真器导出的真实信号值 |
| `surge_score` | 当前 testcase 的最终或最佳 score | SurgeFuzz scoring recorder |
| `surge_best_score` | campaign 累积最佳 score | fuzzer 状态 |
| `surge_energy` | `score^2` mutation energy | SurgeFuzz energy rule |
| `surge_ancestor_bits` | selected ancestor coverage 宽度 | profile/NMI/rewrite 产物 |
| `surge_ancestor_coverage` | 当前 testcase 的 ancestor-state coverage | 每周期 `coverage` 信号 |
| `surge_new_coverage` | 是否产生新的 ancestor/score coverage | SurgeFuzz coverage map |

不能用日志里的异常关键字、周期数、退出码、模拟器输出长度或 seed hash 派生值替代 SurgeFuzz 的 `coverage_target`、score 和 ancestor coverage。

### PROFUZZ 后续指标

PROFUZZ 后续阶段需要单独开表，至少包括：

| 指标 | 含义 | 必须来源 |
| --- | --- | --- |
| `profuzz_target_sites_total` | target site 总数 | target selection metadata 或 EDA 输出 |
| `profuzz_atpg_patterns` | ATPG pattern 数量 | ATPG 工具输出 |
| `profuzz_merged_patterns` | 合并后 pattern 数量 | pattern merge 记录 |
| `profuzz_target_coverage` | target-site coverage 百分比 | Xcelium/VCS/Verilator 或 IMC 真实覆盖报告 |
| `profuzz_feedback_improved` | 是否超过相对提升阈值 | PROFUZZ feedback policy |

PROFUZZ 不能只用 SFUZ 执行结果、普通日志或通用 code coverage 充当 target-site coverage。

## 表格设计

论文结果建议分成“主结果表”“时间曲线”“目标实验表”“工程成本表”“消融表”。每张表必须标注覆盖来源，避免把不同层级的覆盖放进同一列误比。

### 表 1：主结果

| Design | Test Set | Method | Budget | Executions | Valid % | Coverage Source | Covered / Total | Coverage % | Unique Bugs | Median Exec Time |
| --- | --- | --- | --- | ---: | ---: | --- | ---: | ---: | ---: | ---: |
| LinkNan | `litmus.relax.atom` | SFuzz | 12 h |  |  | `FIRRTL.all` |  |  |  |  |
| LinkNan | `litmus.relax.atom` | RFuzz | 12 h |  |  | mux-select toggle |  |  |  |  |
| LinkNan | `litmus.relax.atom` | DirectFuzz | 12 h |  |  | per-instance mux-toggle |  |  |  |  |
| LinkNan | `surge.exception` | SurgeFuzz | 12 h |  |  | ancestor-state/score coverage |  |  |  |  |

如果各方法的覆盖语义不同，主表可以分成多个 panel：`Protocol Coverage`、`Method-Native Coverage`、`Bug Finding`。不要把 RFuzz mux-toggle 覆盖率和 SFuzz FIRRTL 协议覆盖率伪装成同一物理量；可以在同一表中并列，但必须明确 `Coverage Source`。

### 表 2：覆盖随时间变化

| Time | SFuzz Coverage % | RFuzz Native Coverage % | DirectFuzz Target Coverage | SurgeFuzz Best Score | Notes |
| ---: | ---: | ---: | ---: | ---: | --- |
| 10 min |  |  |  |  |  |
| 30 min |  |  |  |  |  |
| 1 h |  |  |  |  |  |
| 6 h |  |  |  |  |  |
| 12 h |  |  |  |  |  |

曲线图应使用多次独立 campaign 的均值和置信区间，推荐至少 5 次重复。若 VCS 成本过高，最少也要 3 次重复，并明确报告随机种子和失败 run。

### 表 3：目标导向实验

| Target | Method | Time to First Hit | Final Target Coverage | Best Distance | Best Score | Unique Bugs |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| `MSHR` protocol group | SFuzz |  |  |  | N/A |  |
| target module instance | DirectFuzz |  |  |  | N/A |  |
| annotated exception signal | SurgeFuzz |  |  | N/A |  |  |

这个表只比较同一个目标族下有意义的指标。DirectFuzz 的 `Best Distance` 和 SurgeFuzz 的 `Best Score` 是方法内部指标，不能互相当成同一单位。

### 表 4：工程成本

| Method | Build Mode | Instrumentation Required | Build Time | Binary Size | Runtime Overhead | Extra Toolchain |
| --- | --- | --- | ---: | ---: | ---: | --- |
| SFuzz | LinkNan/VCS + SFUZ | SFuzz coverage backend |  |  |  | Rust + VCS |
| RFuzz | LinkNan/VCS + mux-select probes | mux-select probe insertion |  |  |  | RTL/FIRRTL pass + VCS |
| DirectFuzz | LinkNan/VCS + instance metadata | mux-select probes + distance metadata |  |  |  | static analysis + VCS |
| SurgeFuzz | LinkNan/VCS + annotation/profile/rewrite | annotation, ancestor selection, per-cycle score |  |  |  | Yosys/FIRRTL/profile pipeline + VCS |

### 表 5：SFuzz 消融

| Variant | Input Model | Feedback | Scheduler | Coverage % | Unique Bugs | Execs/Hour |
| --- | --- | --- | --- | ---: | ---: | ---: |
| SFuzz full | SFUZ structured | selected production feedback | production scheduler |  |  |  |
| no structured sections | flat bytes or restricted SFUZ | same | same |  |  |  |
| no directed feedback | SFUZ structured | non-directed coverage | same |  |  |  |
| single feedback only | SFUZ structured | one backend | same |  |  |  |

消融表用于解释 SFuzz 自身贡献，不应混入 RFuzz、DirectFuzz、SurgeFuzz 的复现结果。

## 公平性原则

1. 相同 design revision：同一组对比必须固定 LinkNan commit、submodule、配置、核心数、内存大小和差分测试开关。
2. 相同 simulator 条件：同一组对比必须使用同一 VCS 版本、相同编译优化级别、相同 coverage 编译开关、相同运行周期上限。
3. 相同预算：主结果至少提供固定墙钟时间预算；如报告固定执行次数预算，应单独成表。
4. 相同初始语料：除方法论文要求的特殊输入模型外，起始语料应来自同一测试集，并记录转换过程。转换失败要计入测试集准备报告，不得静默丢弃。
5. 相同 crash 判定：所有方法使用统一的 crash/objective 分类和去重规则，包括 simulator crash、RTL assert、协议错误、超时。
6. 分离覆盖语义：方法原生覆盖和 LinkNan 通用协议覆盖分开报告。不同语义可以并列展示，但不能合并为一个无来源的 `coverage` 数字。
7. 不用 mock 进论文主表：mock coverage、hash 派生 coverage、日志字符串派生 score 只能用于流水线自测，不能进入 paper result。
8. 失败透明：build 失败、早退、未到 coverage summary、缺失 metadata 的 run 必须保留状态并在统计中说明。
9. 固定随机性：记录 fuzzer RNG seed、初始 corpus hash、变异参数和调度参数。重复实验使用预先声明的 seed 列表。
10. 不跨运行污染状态：每次 campaign 使用独立 work directory、corpus、coverage map 和 simulator 输出目录。需要 warm-up 时应对所有方法一致。

## 测试集组织

建议将测试集按用途和输入模型组织，而不是按脚本目录组织：

```text
benchmarks/
  linknan/
    metadata/
      design_revision.txt
      vcs_version.txt
      coverage_inventory.csv
      firrtl_groups.csv
    seeds/
      sfuz/
        smoke/
        litmus_relax_atom/
        litmus_relax_mem/
        directed_mshr/
        surge_exception/
      rfuzz_pin_stream/
        smoke/
        litmus_relax_atom/
      directfuzz_pin_stream/
        target_<instance>/
      surgefuzz/
        annotation_<name>/
    targets/
      directfuzz/
        target_<instance>.csv
      surgefuzz/
        annotation_<name>.csv
        ancestors_<name>.csv
      profuzz/
        target_sites_future.csv
    manifests/
      seed_manifest.csv
      campaign_manifest.csv
```

第一阶段不要求仓库中实际创建这个目录树，但实验数据应按这个逻辑落盘。每个 seed manifest 至少包含：

| 字段 | 含义 |
| --- | --- |
| `seed_id` | 稳定 ID |
| `source` | litmus、手写汇编、随机程序、ATPG pattern、其他 |
| `source_path` | 原始文件路径 |
| `method_input_path` | 转换后的方法输入路径 |
| `sha256` | 转换后输入 hash |
| `size_bytes` | 输入大小 |
| `cores` | 目标核心数 |
| `expected_cycles` | 预期或默认周期预算 |
| `conversion_status` | 转换状态 |
| `notes` | 失败原因或特殊约束 |

测试集建议分四类：

1. `smoke`：极小集合，只证明构建、SFUZ 展开、VCS 启动和 coverage summary 可达，不进入论文主结果。
2. `litmus`：RISC-V litmus 或小程序集合，用于协议覆盖和多核交互覆盖。
3. `directed`：围绕 MSHR、Directory、Sink/Source 等目标模块或协议组组织，用于目标触达实验。
4. `surge`：带注解信号和 profile 产物的异常/事件集合，用于 SurgeFuzz 对比。

## LinkNan/VCS 运行条件

第一阶段论文对比以 LinkNan + VCS 为主要运行条件。每个 campaign 必须记录：

| 条件 | 要求 |
| --- | --- |
| LinkNan revision | 固定 commit hash，记录本地 patch 状态 |
| SFuzz revision | 固定 commit hash，记录本地 patch 状态 |
| VCS version | 记录 `vcs -ID` 或等价版本输出 |
| Build flags | 是否启用 coverage、是否启用 FIRRTL coverage、是否关闭 diff、是否关闭 FSDB、是否启用 xprop/fgp |
| Core count | `NUM_CORES` 必须与测试集 hart 数匹配 |
| Cycle limit | 每 testcase 周期上限固定，例如 smoke 使用短上限，论文 run 使用正式上限 |
| Timeout | 进程级 timeout 固定，并大于正常 testcase 周期预算 |
| DiffTest | 若关闭 diff，所有方法一致关闭；若开启，需要保证环境完整 |
| Coverage compile | VCS built-in coverage 或 FIRRTL coverage 必须在 build 阶段启用，不能只在 run 阶段传参 |
| Work directory | 每个 campaign 独立，保存 build log、run log、coverage DB、manifest、summary |

VCS 运行结果可以提供真实工程成本，如执行时间、退出码、周期数、日志路径、coverage summary 是否出现。但这些字段本身不是 RFuzz、DirectFuzz、SurgeFuzz 的论文反馈。只有当方法所需 instrumentation 和 ABI 已经把真实覆盖/反馈值导出到 fuzzer，才可以把对应方法标记为论文可比结果。

## 第一批具体性能对比实验

第一批建议固定为两个互补实验，避免把工程健康指标和论文原生反馈混成同一张主结果。

| 实验 | 比较对象 | 统一口径 | 可进入论文主表的条件 |
| --- | --- | --- | --- |
| `T1_common_backend_vcs_health` | SFuzz、RFuzz、DirectFuzz、SurgeFuzz 的 LinkNan/VCS 入口 | 同一 LinkNan revision、同一 VCS simv、同一 seed 集合或可审计转换、同一 cycle/timeout/时间预算；用 `--firrtl-cov FIRRTL.all` 或 `SFUZZ_FIRRTL_COV=FIRRTL.all` 收集 `common_coverage_*` | 只报告 common backend 或工程健康指标；RFuzz/DirectFuzz/SurgeFuzz 的日志健康字段不能标成 paper-faithful native coverage |
| `T2_paper_faithful_native_feedback` | SFuzz、RFuzz、DirectFuzz、SurgeFuzz 的论文定义反馈 | 每个方法使用真实 native ABI：SFuzz coverage backend、RFuzz mux-select toggle、DirectFuzz per-instance mux-toggle+distance、SurgeFuzz per-cycle score+ancestor coverage | 只有 `paper_faithful=true` 且 ABI/metadata 来源可审计的列可进入论文原生反馈对比 |

当前 `scripts/linknan` 输出 schema 可作为第一阶段采集表头的来源：SFuzz 使用 `BASELINE_FIELDS`，RFuzz 使用 `RFUZZ_FIELDS`，DirectFuzz 使用 `DIRECTFUZZ_FIELDS`，SurgeFuzz 使用 `SURGEFUZZ_FIELDS`。四个表都包含 `common_coverage_backend/common_coverage_name/common_coverage_value/common_coverage_source/common_coverage_status`，正式统计时建议再汇总成统一 campaign CSV，并保留原始 per-method CSV 作为审计附件。

## 真实指标边界

以下指标必须来自论文定义的真实覆盖或反馈，不能来自 mock、日志派生或占位计算：

| 方法 | 指标 | 不接受的替代来源 |
| --- | --- | --- |
| RFuzz | mux-select local toggle、total coverage、valid-only coverage、interesting decision | seed hash、随机 bitmap、VCS built-in line/toggle coverage、运行成功日志、周期数 |
| DirectFuzz | per-instance mux-toggle、input distance、target coverage、energy、target-priority queue | SanCov guard、函数名距离、累积 coverage 计算出的 distance、mock metadata、日志关键字 |
| SurgeFuzz | `coverage_target` score、ancestor-state coverage、best score、`score^2` energy | 异常日志关键字、退出码、输出行数、周期数、seed hash、随机 score |
| PROFUZZ | target-site coverage、ATPG pattern coverage、relative improvement feedback | 普通 SFUZ 覆盖、VCS 日志、通用 code coverage、人工构造 target hit |
| SFuzz | 论文报告的 coverage/backend/objective | 未启用对应 backend 的日志摘要、不可复现的现场统计 |

允许保留工程自测指标，但必须使用单独列或单独表，命名为 `pipeline_status`、`vcs_health`、`coverage_export_status` 等，不得命名为方法论文覆盖。

## 第一阶段执行计划

第一阶段目标是得到可复现、可审计的 SFuzz 对 RFuzz、DirectFuzz、SurgeFuzz 对比结果。

1. 固定 LinkNan/VCS 基线：确定 LinkNan revision、VCS 版本、核心数、周期上限、coverage build 配置。
2. 建立 manifest：列出 smoke、litmus、directed、surge 测试集，记录 hash、hart 数、转换状态。
3. SFuzz 主线运行：在真实 LinkNan/VCS 上收集 SFuzz 的 coverage、objective、吞吐和 corpus 数据。
4. RFuzz 复现接入：实现顶层 pin-stream 输入映射、mux-select probe、每周期采样、valid 判定和 RFuzz feedback 输出。
5. DirectFuzz 复现接入：在 RFuzz probe 基础上加入 instance metadata、目标距离、per-testcase input distance、energy 和 queue 记录。
6. SurgeFuzz 复现接入：完成注解信号导出、profile/NMI/ancestor 选择、每周期 score 与 ancestor coverage 记录。
7. 统一报告：生成主结果、时间曲线、目标实验、工程成本和失败 run 报告。
8. 审计边界：对每个进入论文主表的列标注数据来源，确认没有 mock/log-derived 指标混入。

## 后续阶段：PROFUZZ

PROFUZZ 需要等以下条件满足后再纳入正式对比：

1. 明确 ATPG 工具和版本，包括 TestMAX 或可替代工具。
2. 明确 target-site metadata 来源，包含 target net 名称、层级路径、总数和选择策略。
3. 明确 0/1/X pattern 到 LinkNan 输入或仿真 top-level pin 的映射。
4. 明确 target-site coverage 报告来源，例如 Xcelium/IMC、VCS coverage database 或 Verilator instrumentation。
5. 明确 PROFUZZ feedback 与 SFuzz/RFuzz/DirectFuzz/SurgeFuzz 结果并列时的表格口径。

在这些条件满足前，PROFUZZ 可以作为方法模块和后续工作描述，不应放入第一阶段性能对比主表。

# T1 Common Backend 实验设计

## 定位

T1 的目标是把 **SFuzz 当前 FIRRTL/插装信号** 固定为一套 common coverage
backend，用同一个覆盖度量评价 `SFuzz`、`RFuzz`、`DirectFuzz`、`SurgeFuzz`
在 LinkNan/VCS 上产生有效硬件状态的能力。

T1 只回答一个问题：在同一 LinkNan revision、同一仿真预算、同一覆盖库存下，
四个 fuzzer 最终覆盖了多少 **同一组 SFuzz FIRRTL 信号**，以及覆盖随时间增长的
速度如何。

T1 不替代 T2 的 paper-faithful native feedback。RFuzz 的 mux-select toggle、
DirectFuzz 的 per-instance mux-toggle/distance、SurgeFuzz 的 score/ancestor
coverage 仍然是各自论文定义的原生指标；它们可以作为辅助列保留，但 T1 主表只比较
common backend。

## Common Coverage Backend

T1 backend 固定命名为：

```text
common_backend = SFuzz.FIRRTL.common.v0
coverage_name = FIRRTL.all
coverage_inventory = firrtl_litmus_coverage_report.md 中记录的 23 个点
coverage_semantics = per-testcase local bitmap, campaign accumulator = OR(local bitmap)
```

当前 runner 已支持两种打开方式：

```bash
python3 scripts/linknan/run.py sfuzz --firrtl-cov FIRRTL.all ...
SFUZZ_FIRRTL_COV=FIRRTL.all python3 scripts/linknan/run.py rfuzz ...
```

`--firrtl-cov` / `SFUZZ_FIRRTL_COV` 只负责让 LinkNan/VCS 构建和 runner 选择同一组
SFuzz FIRRTL 覆盖点；它要求 LinkNan 构建目录已经生成
`generated-src/firrtl-cover.h` 和 `generated-src/firrtl-cover.cpp`。

当前可审计库存来自 LinkNan 侧
`scripts/linknan/sfuzz_firrtl_cov.py --groups FIRRTL.common` 自动生成的
`common_coverage_inventory.csv`。T1 仍然要做，但定位是四个 fuzzer 在同一
FIRRTL/common 覆盖库存下的健康检查和辅助横向评价；论文主对比仍然放在 T2 的
LinkNan processor-workload native feedback。

| Group | Total Points | T1 用途 |
| --- | ---: | --- |
| `all/common` | 17,920 | T1 主覆盖率分母 |
| `ready_valid` | 2,048 | ready/valid transaction fire |
| `mux` | 4,096 | FIRRTL/SystemVerilog 三目 mux select condition |
| `toggle` | 4,096 | 窄位宽 reg/logic toggle |
| `control_event` | 1,536 | flush、redirect、replay、stall、cancel 等控制事件 |
| `queue_event` | 1,024 | queue full/empty/enq/deq 类事件 |
| `memory_event` | 2,048 | miss、MSHR、TLB/PTW、AMO、uncache、retry 等内存事件 |
| `branch_event` | 1,024 | mispredict、taken、CFI、FTQ、BPU/TAGE/RAS 等分支事件 |
| `exception_event` | 1,024 | exception、trap、interrupt、fault、illegal 等异常事件 |
| `resource_event` | 1,024 | busy、hazard、bank conflict、arbiter、credit 等资源事件 |

T1 必须使用同一份 inventory 文件，建议由 sub5 在 LinkNan 构建产物旁导出：

```text
common_coverage_inventory.csv
index,group,signal_name,width,kind,source
0,Directory_1,Directory_1:l2_directory_hit_trunk,1,event,firrtl-cover.cpp
...
```

所有 campaign 记录 `common_inventory_sha256`。只要 inventory 改变，就必须换
`campaign_id`，不能把不同分母的结果合并。

## 输入设计

### 设计和仿真输入

| 项目 | T1 要求 |
| --- | --- |
| Design | 固定 LinkNan revision、submodule、构建配置、核心数和本地 patch 状态 |
| Simulator | 固定 VCS 版本、`xmake simv` 参数、`--no_diff`/`--no_fsdb`/`--no_fgp` 等开关 |
| Coverage build | LinkNan/VCS 必须启用同一组 SFuzz FIRRTL 插装信号，并在每个 testcase 结束导出 local bitmap |
| Cycle limit | 同一层级实验内所有方法一致 |
| Timeout | 同一层级实验内所有方法一致，并大于正常 testcase 周期预算 |
| Workload ABI | 每个 testcase 最终都必须能通过同一 LinkNan workload/SFUZ 或 sub5 适配后的可执行输入进入 DUT |

### Seed 和 testcase 输入

T1 的输入 manifest 按“共同可执行 testcase”组织，而不是按方法原生格式组织。

| 字段 | 含义 |
| --- | --- |
| `testcase_id` | 稳定 ID |
| `source_kind` | `sfuz`、`litmus`、`linknan-workload`、`direct-target`、`surge-annotation` 等 |
| `source_path` | 原始输入路径 |
| `method_input_path` | fuzzer 实际消费的输入 |
| `linknan_workload_path` | 最终送入 LinkNan 的 workload/SFUZ/适配产物 |
| `sha256` | `linknan_workload_path` hash |
| `cores` | 目标核心数 |
| `expected_cycles` | 该 testcase 预期周期预算 |
| `conversion_status` | `ok`、`failed`、`unsupported` |
| `notes` | 转换失败或约束说明 |

四个 fuzzer 的 T1 输入口径如下：

| Method | T1 输入口径 | 说明 |
| --- | --- | --- |
| `SFuzz` | `.sfuz` 结构化种子或 SFuzz 生成的 corpus testcase | 直接通过 LinkNan workload 路径运行 |
| `RFuzz` | RFuzz 生成的输入必须保存为可审计 LinkNan `.bin`/ELF workload，并由同一 LinkNan DUT 运行 | 当前项目按处理器验证口径使用 workload 输入；T1 主指标只看 common FIRRTL 覆盖，RFuzz mux-toggle 作为辅助原生反馈列 |
| `DirectFuzz` | DirectFuzz 生成的 testcase 加目标实例配置；最终仍导出可执行 LinkNan workload | 原生 distance/energy 只作辅助列，T1 主指标看 common FIRRTL 覆盖 |
| `SurgeFuzz` | SurgeFuzz 生成的 testcase 加 annotation/target 配置；最终仍导出可执行 LinkNan workload | 原生 score/ancestor 只作辅助列 |

转换失败不能静默丢弃。进入 run summary 时，`conversion_status != ok` 的输入应计入
`infrastructure_error` 或单独的 preparation failure 统计。

## 运行预算

T1 使用双停止条件：达到 `time_budget_sec` 或 `exec_budget` 任一条件即停止。
每个方法、每次重复使用同一预算。失败、超时、早退 run 仍保留在统计中。

| Tier | 用途 | Repeats | Time Budget | Exec Budget | Cycle Limit | Timeout | 进入论文主表 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| `T1-smoke` | 验证 build、SFUZ/workload、coverage sidecar 可达 | 1 | 10 min | 20 | 2,000 | 120 s | 否 |
| `T1-pilot` | 校准吞吐、失败率、时间桶 | 3 | 1 h | 200 | 20,000 | 300 s | 可作附录 |
| `T1-main` | 正式 common backend 对比 | 5 | 12 h | 5,000 | 100,000 | 600 s | 是 |

如果 LinkNan/VCS 成本过高，可以先把 `T1-main` 降为 3 次重复，但必须在报告中写明：
`repeats=3`、随机种子列表、失败 run 数，以及是否达到时间预算或执行预算。

推荐时间桶：

```text
0 min, 10 min, 30 min, 1 h, 3 h, 6 h, 12 h
```

每个时间桶取不晚于该时间点的最后一个 coverage snapshot。若某方法提前结束，后续时间桶
沿用最后 snapshot，并在 `status` 中标记 `ended_early`。

## 四个 Fuzzer 使用同一组 SFuzz FIRRTL 信号的方法

T1 的关键是把 coverage 采集从 fuzzer 原生反馈中剥离出来，做成 LinkNan 侧的共同
sidecar。四个 fuzzer 可以有不同的输入生成和调度策略，但每个 testcase 结束时都读取
同一组 FIRRTL 信号 bitmap。

### 统一流程

1. sub5 在 LinkNan 构建阶段固定导出 `common_coverage_inventory.csv`，并记录 hash。
2. 每个 testcase 开始时清空 local coverage bitmap。
3. VCS 仿真过程中采样同一组 SFuzz FIRRTL 插装信号。
4. testcase 结束时导出 local bitmap、covered count、group covered count 和状态。
5. T1 聚合器按 method/campaign 维护 cumulative bitmap：`campaign_bits |= local_bits`。
6. 聚合器按时间桶写 `coverage_timeline.csv`，最后写 `coverage_final.csv` 和 run summary。

LinkNan/VCS 侧当前导出的 per-case sidecar 文件名为：

```text
sfuzz_firrtl_coverage.json
sfuzz_firrtl_coverage.bin
```

其中 `.bin` 是 raw byte bitmap：每个 coverage point 一个 byte，`0` 表示未覆盖，
非 `0` 表示覆盖。`.json` 中至少包含 backend、coverage_name、group、total、
covered、coverage_percent 和 bitmap_file。T1 聚合层可以在此基础上补充
campaign/testcase/inventory hash 字段。

建议聚合后使用的 per-case 规范 sidecar：

```json
{
  "common_backend": "SFuzz.FIRRTL.common.v0",
  "coverage_name": "FIRRTL.all",
  "common_inventory_sha256": "...",
  "testcase_id": "...",
  "local_bits_hex": "...",
  "local_covered": 0,
  "total": 23,
  "groups": {
    "MSHR": {"covered": 0, "total": 10}
  },
  "reset_seen": true,
  "export_status": "ok"
}
```

### 各方法接入点

| Method | 现有 runner 能做的事 | T1 common backend 需要 sub5 适配的事 |
| --- | --- | --- |
| `SFuzz` | `scripts/linknan/run.py sfuzz` 可批量跑 `.sfuz` seed，记录 LinkNan/VCS 日志、退出码、SFUZ 展开、bug pattern、VCS coverage 健康状态 | 从同一次 LinkNan/VCS run 导出 `SFuzz.FIRRTL.common.v0` local bitmap；不要只依赖 VCS `.vdb` 或 `urg` 总覆盖 |
| `RFuzz` | 当前入口可通过 LinkNan workload 路径 smoke，能记录输入模型、valid 来源、是否缺 native RFuzz ABI | 让 RFuzz 生成的 testcase 进入同一 DUT，并在 testcase 结束导出 common FIRRTL bitmap；RFuzz mux-select bitmap 不作为 T1 主指标 |
| `DirectFuzz` | 当前入口可跑 seed、读 metadata、在 native-file/dev-mock/vcs-log 三种模式下记录 DirectFuzz 辅助字段 | 在 DirectFuzz 运行同一 testcase 时同步导出 common FIRRTL bitmap；distance/energy 作为辅助列，不参与 T1 common coverage 分母 |
| `SurgeFuzz` | 当前入口可跑 seed、读 score trace/dev trace 并记录 score/energy/ancestor 辅助字段 | 在 SurgeFuzz 运行同一 testcase 时同步导出 common FIRRTL bitmap；score/ancestor 不参与 T1 common coverage 分母 |

T1 允许两种运行模式，但主报告必须写清：

| 模式 | 含义 | 推荐用途 |
| --- | --- | --- |
| `metric-only` | fuzzer 保持自己的输入生成/调度/反馈；common FIRRTL 只作为评测指标 | T1 主模式，最少改变方法语义 |
| `common-feedback` | 四个 fuzzer 都把同一组 FIRRTL bitmap 作为保留 corpus 的反馈 | 可做补充实验，用于比较输入模型和调度策略；不能声称是各方法 paper-faithful native feedback |

## 结果字段

### 已可来自 `scripts/linknan` 的字段

以下字段可以从当前 runner 输出或日志扫描得到。字段名按现有 method CSV 保留，最终
T1 汇总时可映射为统一列。

| 统一字段 | 当前来源字段 | 方法 | 含义 |
| --- | --- | --- | --- |
| `method` | `fuzzer` | 全部 | `sfuzz`、`rfuzz`、`directfuzz`、`surgefuzz` |
| `seed_or_testcase` | `seed_name`、`seed`、`seed_path` | 全部 | 当前输入标识和路径 |
| `wall_time_sec` | `wall_time_sec` | 全部 | 单次 run 墙钟时间 |
| `cycles` | `vcs_cycles`、`cycles` | 全部 | VCS 周期；缺失时当前脚本用请求周期填充 |
| `exit_code` | `exit_code` | 全部 | 仿真命令退出码 |
| `timed_out` | `timed_out` | 全部 | 进程超时 |
| `max_cycle_exceeded` | `max_cycle_exceeded` | 全部 | 是否到达 max cycle |
| `vcs_report_seen` | `vcs_report_seen` | 全部 | 是否看到 VCS simulation report |
| `sfuz_expansion_seen` | `sfuz_expansion_seen` | 全部 | LinkNan 是否识别 SFUZ structured seed |
| `good_trap_seen` | `good_trap_seen` | SFuzz、SurgeFuzz | 是否看到 good trap |
| `bug_triggered` | `bug_triggered` | 全部 | 是否命中当前日志扫描定义的 bug/objective |
| `bug_reasons` | `bug_reasons`、`notes` | 全部 | bug、assert、timeout、日志健康说明 |
| `log_path` | `log_path` | 全部 | run log |
| `case_dir` | `case_dir` | SFuzz | LinkNan case 输出目录 |
| `coverage_backend` | `coverage_backend` | 全部 | 当前脚本记录的覆盖来源；T1 中只能作为来源状态，不能直接等同 common FIRRTL |
| `coverage_name` | `coverage_name` | SFuzz | 当前 VCS coverage 或 parsed 名称 |
| `coverage_value` | `coverage_value` | SFuzz/RFuzz | 当前 VCS/诊断/native 字段值 |
| `coverage_status` | `coverage_status`、`notes` | SFuzz/RFuzz | VCS `.vdb`、`urg`、不可用等状态 |
| `common_coverage_backend` | `common_coverage_backend` | 全部 | T1 common backend 状态；只有 `sfuzz_firrtl` 可进入 T1 主覆盖率 |
| `common_coverage_name` | `common_coverage_name` | 全部 | 解析到的 SFuzz FIRRTL coverage 名称，例如 `sfuzz_firrtl.all` |
| `common_coverage_value` | `common_coverage_value` | 全部 | 单 testcase local coverage 百分比 |
| `common_coverage_source` | `common_coverage_source` | 全部 | `sfuzz_firrtl_coverage.json/bin` 路径 |
| `common_coverage_status` | `common_coverage_status` | 全部 | parsed/missing/inventory 等解析状态 |
| `paper_faithful` | `paper_faithful` | 全部 | 是否满足各方法论文定义 native feedback；T1 不用它决定 common coverage 是否可比 |
| `required_native_abi` | `required_native_abi` | 全部 | 当前缺失的 native ABI，用于 T2 边界说明 |
| `valid` | `valid` | RFuzz | RFuzz valid 判定；T1 可作辅助列 |
| `target_instance` | `target_instance` | DirectFuzz | DirectFuzz 目标实例；T1 可作辅助列 |
| `distance`、`energy`、`target_progress` | 同名字段 | DirectFuzz | DirectFuzz 原生辅助字段 |
| `annotation_type`、`best_score`、`ancestor_coverage_bits` | 同名字段 | SurgeFuzz | SurgeFuzz 原生辅助字段 |

注意：`coverage_backend=vcs_builtin`、`coverage_name=vcs_vdb`、`urg` 文本解析值或
RFuzz/DirectFuzz/SurgeFuzz 的 dev/mock/native 字段，都不是 T1 指定的
`SFuzz.FIRRTL.common.v0`。T1 主覆盖率只读取 `common_coverage_backend=sfuzz_firrtl`
且 inventory 一致的 sidecar。

### 需要 sub5 LinkNan 适配的新字段

T1 主指标依赖以下字段。其中 `common_coverage_*` per-case 字段已经由当前
`scripts/linknan` runner 解析并输出；campaign/repeat/time-bucket/inventory hash
字段仍需要实验聚合层补齐。

| 字段 | 粒度 | 含义 |
| --- | --- | --- |
| `campaign_id` | campaign | 一次完整 T1 run 的唯一 ID |
| `replicate_id` | campaign | 重复实验编号 |
| `rng_seed` | campaign | fuzzer 随机种子 |
| `time_budget_sec` | campaign | 时间预算 |
| `exec_budget` | campaign | 执行预算 |
| `common_backend` | case/campaign | 固定为 `SFuzz.FIRRTL.common.v0`；per-case runner 中对应 `common_coverage_backend=sfuzz_firrtl` |
| `coverage_name` | case/campaign | 固定为 `FIRRTL.all` 或具体 group；per-case runner 中对应 `common_coverage_name` |
| `common_inventory_sha256` | case/campaign | coverage inventory hash |
| `common_total` | case/campaign | 覆盖点总数，当前 `all=23` |
| `common_local_bits_hex` | case | 当前 testcase local bitmap |
| `common_local_covered` | case | 当前 testcase local covered count |
| `common_new_bits` | case | 当前 testcase 相对 campaign accumulator 的新增 bit 数 |
| `common_cumulative_bits_hex` | snapshot | campaign 累计 bitmap |
| `common_covered` | snapshot/campaign | campaign 累计 covered count |
| `common_coverage_percent` | snapshot/campaign | `100 * common_covered / common_total` |
| `common_group_covered` | group snapshot | group 累计 covered count |
| `common_group_total` | group snapshot | group total |
| `snapshot_time_sec` | snapshot | 距 campaign start 的墙钟时间 |
| `snapshot_execs` | snapshot | snapshot 时已执行 testcase 数 |
| `time_to_first_common_hit_sec` | campaign | 第一次 common coverage 非零的时间 |
| `time_to_50pct_common_sec` | campaign | 首次达到 50% common coverage 的时间，未达到则空 |
| `common_auc_percent_hour` | campaign | coverage-over-time 曲线面积，用于区分早覆盖和晚覆盖 |
| `common_export_status` | case | `ok`、`missing`、`inventory_mismatch`、`reset_failed`、`parse_failed` |
| `common_export_path` | case | sub5 sidecar 路径 |

建议 sub5 同时导出三张原始表：

```text
raw_cases.csv
coverage_timeline.csv
coverage_final.csv
```

T1 汇总脚本只读取这些表和现有 `scripts/linknan` CSV，不从 VCS log 里猜 common coverage。

## 结果计算

| 指标 | 计算方式 |
| --- | --- |
| `executions` | 完成 LinkNan/VCS testcase 的次数，包含 crash/timeout |
| `valid_executions` | 能进入 DUT 且 conversion/export 状态可审计的次数；具体 valid 定义保留辅助列 |
| `execs_per_hour` | `executions / wall_time_sec * 3600` |
| `common_covered` | campaign accumulator bitmap popcount |
| `common_coverage_percent` | `100 * common_covered / common_total` |
| `common_new_bits` | `popcount(local_bits & ~old_campaign_bits)` |
| `common_auc_percent_hour` | 对时间桶 coverage percent 做梯形积分，单位 percent-hour |
| `unique_bugs` | 使用统一 signature 去重，signature 至少包含 bug reason、关键日志片段 hash、退出码 |

如果某个 testcase 缺少 common coverage sidecar，它仍保留执行状态，但该 testcase 的
`common_export_status != ok`，不得更新 cumulative bitmap。

## 表格 1：Run Summary

正式报告中每个 `method x replicate` 一行；论文主表可再按 method 聚合均值和置信区间。

| Campaign | Method | Rep | Input Manifest | Budget | Executions | Valid Execs | Wall Time | Execs/Hour | Bugs | Common Backend | Covered / Total | Coverage % | AUC | TTF First Hit | Status |
| --- | --- | ---: | --- | --- | ---: | ---: | ---: | ---: | ---: | --- | ---: | ---: | ---: | ---: | --- |
| `T1-main` | SFuzz | 1 | `seed_manifest.csv` | 12 h / 5,000 exec |  |  |  |  |  | `SFuzz.FIRRTL.common.v0` |  / 23 |  |  |  |  |
| `T1-main` | RFuzz | 1 | `seed_manifest.csv` | 12 h / 5,000 exec |  |  |  |  |  | `SFuzz.FIRRTL.common.v0` |  / 23 |  |  |  |  |
| `T1-main` | DirectFuzz | 1 | `seed_manifest.csv` | 12 h / 5,000 exec |  |  |  |  |  | `SFuzz.FIRRTL.common.v0` |  / 23 |  |  |  |  |
| `T1-main` | SurgeFuzz | 1 | `seed_manifest.csv` | 12 h / 5,000 exec |  |  |  |  |  | `SFuzz.FIRRTL.common.v0` |  / 23 |  |  |  |  |

聚合版建议：

| Method | Repeats | Final Covered Mean | Final Coverage % Mean | AUC Mean | Time to First Hit Median | Execs/Hour Median | Unique Bugs | Failed Runs |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| SFuzz | 5 |  |  |  |  |  |  |  |
| RFuzz | 5 |  |  |  |  |  |  |  |
| DirectFuzz | 5 |  |  |  |  |  |  |  |
| SurgeFuzz | 5 |  |  |  |  |  |  |  |

## 表格 2：Coverage Over Time

所有列都使用同一 `common_total=23`。如果某方法在某时间桶前没有 snapshot，则填空并在
run summary 的 `Status` 中说明。

| Campaign | Rep | Time | SFuzz Covered / % | RFuzz Covered / % | DirectFuzz Covered / % | SurgeFuzz Covered / % |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `T1-main` | 1 | 0 min | 0 / 0.0 | 0 / 0.0 | 0 / 0.0 | 0 / 0.0 |
| `T1-main` | 1 | 10 min |  |  |  |  |
| `T1-main` | 1 | 30 min |  |  |  |  |
| `T1-main` | 1 | 1 h |  |  |  |  |
| `T1-main` | 1 | 3 h |  |  |  |  |
| `T1-main` | 1 | 6 h |  |  |  |  |
| `T1-main` | 1 | 12 h |  |  |  |  |

若需要画图，横轴使用 `snapshot_time_sec`，纵轴使用 `common_coverage_percent`，每个方法画
5 次重复的均值和置信区间。不要把 RFuzz/DirectFuzz/SurgeFuzz native coverage 曲线混到
这张图里。

## 表格 3：Coverage Final by Group

该表解释 final coverage 来自哪些 FIRRTL group，避免只看 `all` 掩盖覆盖结构差异。

| Group | Total | SFuzz Covered / % | RFuzz Covered / % | DirectFuzz Covered / % | SurgeFuzz Covered / % |
| --- | ---: | ---: | ---: | ---: | ---: |
| `all` | 23 |  |  |  |  |
| `Directory_1` | 3 |  |  |  |  |
| `MSHR` | 10 |  |  |  |  |
| `RXSNP` | 1 |  |  |  |  |
| `SinkA` | 4 |  |  |  |  |
| `SinkC` | 3 |  |  |  |  |
| `SourceB` | 2 |  |  |  |  |

## 建议落盘目录

本任务可使用独立工作目录 `/nfs/home/yangkefan/SFUZZ-sub4-t1-work`，避免污染仓库和其他人
的改动。

```text
/nfs/home/yangkefan/SFUZZ-sub4-t1-work/
  inventory/
    common_coverage_inventory.csv
    common_coverage_inventory.sha256
  manifests/
    seed_manifest.csv
    campaign_manifest.csv
  raw/
    sfuzz/
    rfuzz/
    directfuzz/
    surgefuzz/
  merged/
    raw_cases.csv
    coverage_timeline.csv
    coverage_final.csv
    run_summary.csv
  tables/
    table_run_summary.md
    table_coverage_over_time.md
    table_coverage_final_by_group.md
```

## 当前可执行边界

当前 `scripts/linknan` 已经能提供真实 LinkNan/VCS 执行健康数据，但 T1 common coverage
主指标分三层推进：

| 能力 | 当前状态 | T1 结论 |
| --- | --- | --- |
| `.sfuz` workload 送入 LinkNan/VCS | 已有 runner 路径 | 可用于 T1 输入执行 |
| 日志扫描、退出码、周期、超时、bug pattern | 已有 runner 字段 | 可进入 run summary |
| VCS `.vdb`/`urg` coverage 健康检查 | 已有 `collect_vcs_coverage` | 只能作为诊断，不是 T1 指定 common FIRRTL local bitmap |
| FIRRTL coverage inventory | 已扩展为 17,920 点自动生成库存 | 可作为 T1 common 分母 |
| LinkNan/VCS 读取 `firrtl_cover[]` 并导出 `sfuzz_firrtl_coverage.json/bin` | 已有 `--firrtl_cov` 和 C++ export shim | 插装文件存在后可直接用于 T1 |
| 四个 runner 解析 common sidecar 并输出 `common_coverage_*` | 已完成 | 可用于 T1 raw case 表 |
| 当前 Chisel 7/firtool 生成流程自动产出 `firrtl-cover.h/.cpp` | 已接入 `--firrtl_cov`，需在 T1 smoke 中重建确认 | T1 smoke 检查项 |
| coverage-over-time snapshots 和 campaign accumulator | 需要聚合层 | T1 曲线 blocker |

因此，T1 报告中可以先把当前 runner 字段作为执行健康和审计附件；只有当 run 产出
`common_coverage_backend=sfuzz_firrtl`、coverage sidecar 可解析且 inventory hash 一致时，
对应 run 才能进入 T1 common coverage 主表。

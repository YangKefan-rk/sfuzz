# SFuzz 在 LinkNan 上的测试点/覆盖点设计

本文给出 SFuzz 面向 LinkNan 的真实硬件覆盖反馈设计。目标不是再造一套
“日志特征”或软件覆盖，而是在 LinkNan/Nanhu/coupledL2 的关键微结构状态上
定义可落地、可采样、可比较的覆盖点，使 SFuzz 的反馈能够指导 seed 生成到
更深的取指、预测、MMU、内存一致性、异常恢复和多核交互路径。

文中模块名和信号名来自当前工作区可见的 LinkNan 结构，包括：

- `dependencies/nanhu/src/main/scala/xiangshan/frontend/*`
- `dependencies/nanhu/src/main/scala/xiangshan/cache/mmu/*`
- `dependencies/nanhu/src/main/scala/xiangshan/cache/dcache/*`
- `dependencies/nanhu/src/main/scala/xiangshan/backend/*`
- `dependencies/cpl2/src/main/scala/coupledL2/*`
- 生成 RTL 中的 `XSCore.sv`、`RedirectGenerator.sv`、`FtqPcMemWrapper.sv`、
  `TXRSP.sv`、`Queue2_CHISNP.sv` 等模块

最终实现时必须按 LinkNan 具体 revision 的 FIRRTL/Verilog 实际层次名校准，
尤其是 Chisel 展开后的实例名、`_GEN_*` 临时线、`RegNext` 后缀和多核数组下标。

## 总体原则

SFuzz 的覆盖点应满足五个条件。

1. **真实微结构语义**：覆盖点来自 DUT 内部硬件事件，例如 redirect、TLB
   refill、MSHR retry、ROB trap commit，而不是仿真器退出码或字符串日志。
2. **低扰动可采样**：优先用已有 `XSPerfAccumulate`、FIRRTL `cover`、已有
   `valid/ready/fire`、状态机状态位和 exception/cause 位派生，不改变 DUT 功能。
3. **本地 testcase 反馈**：每个 seed 运行时先清空本地 bitmap/counter，运行结束后
   把本地覆盖与全局覆盖比较，再决定是否入队。不能把累积覆盖当作单个输入的反馈。
4. **分层组合**：覆盖后端可单独启用，如 `SFUZZ.frontend`、`SFUZZ.mmu`、
   `SFUZZ.coherence`，也可做 union，例如 `union:SFUZZ.arch+SFUZZ.coherence`。
5. **实验公平**：和 RFuzz/DirectFuzz/SurgeFuzz 对比时，同一张表只能比较同一类
   覆盖后端或明确标注 `native`/`common_backend`/`dev_only`，避免把 SFuzz 的领域覆盖
   与 RFuzz 的 mux-toggle 或 SurgeFuzz 的 ancestor-score 混成一个指标。

建议覆盖点编码为 `(group, module_pattern, event_name, bucket)` 四元组。`bucket`
可为空，也可表示 opcode、cause、state、privilege、way、port、core、latency 区间。
在 simulator ABI 中展平成稳定 index，并生成元数据：

```text
index,group,module_pattern,event_name,bucket,width,kind,priority,notes
0,SFUZZ.frontend,XSCore*/frontend/Ftq,ftq_enq_fire,core=0,1,event,P0,...
1,SFUZZ.mmu,XSCore*/TLB,dtlb_miss,port=0,1,event,P0,...
2,SFUZZ.coherence,TL2CHICoupledL2*/MSHR,mshr_state,state=w_grant,1,state,P0,...
```

## 推荐优先级

| 优先级 | 含义 | 首批建议规模 | 用途 |
| --- | --- | ---: | --- |
| P0 | 最先接入，语义强、信号稳定、覆盖稀疏适中 | 80-200 点 | 作为 SFuzz native coverage 的主反馈 |
| P1 | 增强区分度，适合定向突变和论文 ablation | 200-800 点 | 分析哪类 seed 推动了微结构深度 |
| P2 | 高维或强 revision 相关，先用于诊断 | 800+ 点 | debug、profiling、SurgeFuzz/DirectFuzz 辅助目标 |

首个可发表版本建议用 P0+少量 P1。覆盖点太多会退化成近似 RFuzz 的大 bitmap，
难以说明 SFuzz 的结构化反馈优势。

## 接出路径

### LinkNan/Chisel 层

适合在源代码附近加 `cover` 或把事件接入统一 bundle，但当前 SFuzz 仓库不应直接改
LinkNan 源码。设计层面建议：

- 对已有 `XSPerfAccumulate("name", cond)` 的模块，优先复用 `cond` 或等价逻辑。
- 对 Decoupled 通道统一采样 `fire = valid && ready`。
- 对状态机采样 `state === sXXX`，再用 `rose(state === sXXX)` 或每周期触发的
  one-hot 状态覆盖。
- 对 cause/opcode/privilege 等枚举做 bucket，而不是记录全宽数值。

### FIRRTL/Verilog 插桩

推荐在 LinkNan 生成 RTL/FIRRTL 后做后处理，方式与已有 FIRRTL coverage report
一致，生成 `firrtl-cover.cpp` 或等价 metadata。命名建议：

```text
SFUZZ.<layer>.<module>.<event>[.<bucket>]
SFUZZ.frontend.Ftq.enq_fire
SFUZZ.branch.BPU.redirect_mispredict
SFUZZ.mmu.TLB.miss.port0
SFUZZ.coherence.MSHR.task.retry
SFUZZ.rob.ExceptionGen.trap_commit.illegal
SFUZZ.multicore.L2.probe_cross_core
```

可从 Verilog AST 或 FIRRTL IR 中按模式寻找：

- `valid`/`ready` 同层存在：生成 `valid && ready`
- `bits_opcode`、`opcode`：生成 `fire && opcode == K`
- `state`、`stateVal`：生成 `state == S`
- `exceptionVec`、`cause`、`intrNO`、`interrupt`：生成按 cause 的 one-hot bucket
- `redirect`、`flush`、`replay`：生成事件边沿覆盖

### VCS

VCS 路径建议两层：

- **内建覆盖/urg**：可作为 `T1_common_backend`，用于所有方法公平比较，但不能叫
  SFuzz native 微结构覆盖。
- **DPI/PLI 导出 bitmap**：在 testbench 每周期调用 `sfuzz_cover_hit(index)` 或把
  Verilog coverage vector 暴露给 C++，每个 seed 开始清零，结束时交给 SFuzz。

实现形态：

```text
Verilog/FIRRTL cover cond -> generated sfuzz_cov_bits[N]
VCS sim loop per cycle    -> if (sfuzz_cov_bits[i]) local_bitmap[i] = 1
seed end                  -> sfuzz_record_coverage(local_bitmap, metadata_id)
```

若使用 VCS `-cm`，实验表应写 `coverage_backend=vcs_builtin`；若使用本文覆盖点，
写 `coverage_backend=sfuzz_linknan_native`。

### Verilator

Verilator 路径建议与当前 `libsfuzz.a`/SFUZ ABI 对齐：

- 在 generated C++ 中暴露 `extern "C" uint32_t sfuzz_cov_count()`。
- 暴露 `extern "C" uint8_t *sfuzz_cov_bitmap()` 或 `sfuzz_cov_hit(uint32_t idx)`。
- 每个 testcase reset 后清空本地 bitmap。
- 每个模拟周期采样组合事件，或者在事件发生的 always block 中置位。

如果继续使用 SanCov/LLVM guard，只能作为 `T1_common_backend=llvm_guard`。
本文覆盖点导出的 bitmap 才是 `T2_native_method=sfuzz_linknan_native`。

## 覆盖点分层

### 1. 前端基础流控

**为什么适合作为真实反馈**：前端决定 seed 是否能从 boot/ABI 进入真实指令流。
仅靠最终退出码无法区分“没有取到指令”“取到但 IBuffer 堵塞”“取到且进入 decode”。
前端流控覆盖能鼓励 SFuzz 产生更稳定、更深的程序形态。

| 优先级 | 模块/命名模式 | 覆盖点示例 | 说明 |
| --- | --- | --- | --- |
| P0 | `xiangshan/frontend/IFU.scala`, `FtqInterface` | `ifu_fetch_fire = io.fetch_to_bpu.fire` 或等价 fetch request fire | 判断取指请求真正流动 |
| P0 | `xiangshan/frontend/NewFtq.scala`, `Ftq` | `ftq_enq_fire`, `ftq_deq_fire`, `ftq_full_stall`, `ftq_redirect_read` | FTQ 入队/出队/满阻塞/redirect 读取 |
| P0 | `xiangshan/frontend/IBuffer.scala`, `IBuffer` | `ibuffer_in_fire`, `ibuffer_out_fire[i]`, `ibuffer_flush` | 已有 `XSPerfAccumulate("flush", io.flush)` 可复用 |
| P1 | `FtqToICacheRequestBundle`, `ICache` | `icache_req_fire`, `icache_resp_valid`, `icache_miss_req_fire` | 区分 ICache hit/miss 与响应到达 |
| P1 | `PreDecode.scala`, `FrontendTrigger` | `predecode_rvc`, `predecode_branch`, `frontend_trigger_hit` | 指令类型和 trigger 对前端扰动强 |

建议 bucket：

- `core_id`：多核时每核独立。
- `port_id`：IBuffer/dispatch 多发射端口。
- `stall_reason`：`full`、`redirect`、`flush`、`icache_wait`，只保留低维枚举。

接出方式：

- FIRRTL pass 可按 `IBuffer` 中 `io.in.fire`、`io.out(i).fire`、`io.flush` 插点。
- 生成 RTL 中模块可能为 `IBuffer`、`Ftq`、`FtqPcMemWrapper`、`ICache*`；需用
  `valid/ready` 和 `flush` 实名校准。
- VCS/Verilator 每周期采样事件，置位一次即可。

### 2. 分支预测与取指重定向

**为什么适合作为真实反馈**：CPU bug 常出现在预测、redirect、FTQ 修复和后端 flush
交界处。分支预测事件比普通 mux toggle 更语义化，能告诉 fuzzer 是否触发了
BTB/TAGE/RAS/ITTAGE 等预测器路径，以及是否进入 mispredict 恢复。

| 优先级 | 模块/命名模式 | 覆盖点示例 | 说明 |
| --- | --- | --- | --- |
| P0 | `xiangshan/frontend/BPU.scala`, `BranchPredictionResp` | `bpu_resp_valid`, `bpu_taken`, `bpu_not_taken` | 预测结果类别 |
| P0 | `BranchPredictionUpdate` | `bpu_update_fire`, `bpu_update_mispredict`, `bpu_update_correct` | seed 是否产生可训练/可纠错分支 |
| P0 | `RedirectGenerator.sv`, backend redirect bundle | `redirect_valid`, `redirect_level.flush`, `redirect_from_branch`, `redirect_from_exception` | redirect 是前后端闭环核心 |
| P1 | `Tage.scala`, `ITTAGE.scala` | `tage_provider_hit`, `tage_alt_used`, `ittage_target_hit` | 预测器子结构覆盖 |
| P1 | `newRAS.scala`, `RAS` | `ras_push`, `ras_pop`, `ras_recover`, `ras_overflow_or_empty` | call/ret 程序非常适合作为 fuzz 变异目标 |
| P1 | `NewFtq.scala`, `Ftq_Redirect_SRAMEntry` | `ftq_redirect_sram_read`, `ftq_redirect_sram_write` | 覆盖 FTQ redirect 元数据路径 |

建议 bucket：

- `redirect_cause`：branch、jump、exception、interrupt、replay。
- `predictor`：BTB、TAGE、ITTAGE、RAS、loop 或实际 LinkNan 命名。
- `branch_type`：conditional、jal、jalr、call、ret。

接出方式：

- 对 `BranchPredictionResp`/`BranchPredictionUpdate` 的 `valid` 与方向位做 bucket。
- 对 `Redirect` bundle 中 cause/level 字段做 one-hot 覆盖，若字段在 RTL 中被展开，
  用 `redirect_valid && <field>`。
- 和 RFuzz 公平比较时，这些点可作为 `SFuzz.branch` native feedback；若把同样点也给
  RFuzz 使用，就只能称作 `common_backend`，不能再比较“RFuzz 原生 mux-toggle”。

### 3. MMU/TLB/页表异常

**为什么适合作为真实反馈**：LinkNan 支持复杂虚拟化/特权态路径，TLB miss、PTW、
SFENCE、A/D bit 更新、page fault 和 guest page fault 是高价值深状态。普通指令覆盖
难以说明 seed 是否真正触发地址翻译 corner case。

| 优先级 | 模块/命名模式 | 覆盖点示例 | 说明 |
| --- | --- | --- | --- |
| P0 | `xiangshan/cache/mmu/TLB.scala`, `TLB` | `tlb_access[port]`, `tlb_miss[port]`, `tlb_refill`, `tlb_flush_mmu` | 源码已有 `access`, `miss`, `ptw_resp_count` 等 perf 条件 |
| P0 | `TLB.scala` | `tlb_pf`, `tlb_gpf`, `tlb_af`, `tlb_ma` | page/access/misaligned 异常向后端传播 |
| P0 | `PageTableWalker.scala` | `ptw_req_fire`, `ptw_resp_fire`, `ptw_page_fault`, `ptw_blocked_in` | PTW 进入、返回、阻塞 |
| P1 | `PageTableCache.scala`, `PtwCache` | `ptw_cache_l0_hit`, `l1_hit`, `l2_hit`, `l3_hit`, `sp_hit`, `pte_hit` | 源码已有多级 hit/refill perf 信号 |
| P1 | `Repeater.scala`, `PTWRepeater`, `PTWFilter` | `ptw_repeater_req`, `ptw_repeater_resp`, `ptw_filter_flush`, `tlb_req_flushed` | 对并发 TLB 请求与 PTW 回包很敏感 |
| P1 | CSR/MMU flush 输入 | `sfence_valid`, `satp_changed`, `vsatp_changed`, `hgatp_changed` | 特权切换与 TLB invalidation |

建议 bucket：

- `tlb_kind`：itlb、dtlb、ldtlb、l2tlb，按实例路径推断。
- `port_id`：`req(i)` 或 `resp(i)`。
- `stage`：stage1、stage2、two-stage、bare。
- `cause`：instr/load/store page fault、guest page fault、access fault。
- `level`：PTW l0/l1/l2/l3/superpage。

接出方式：

- `TLB.scala` 中已有：
  - `flush_mmu = sfence.valid || csr.satp.changed || csr.vsatp.changed || csr.hgatp.changed`
  - `refill = ptw.resp.fire && ... && !flush_mmu`
  - `XSPerfAccumulate("miss<i>", result_ok(i) && missVec(i))`
- FIRRTL pass 可优先寻找这些命名或从 `ptw.req.valid/ready`、`ptw.resp.valid/ready`
  派生。
- Verilator/VCS 中建议把 page fault cause 压成有限 bucket，不导出完整 VA/PA，避免
  覆盖 bitmap 被地址随机性污染。

### 4. 缓存一致性与内存系统

**为什么适合作为真实反馈**：LinkNan 的 L1/L2/CHI/TL2CHI 路径是多核和内存模型测试
最有价值的部分。已有 FIRRTL coverage report 已经证明 `Directory_1`、`MSHR`、
`RXSNP`、`SinkA`、`SinkC`、`SourceB` 等组可以在 LinkNan 构建中接出，因此这是
SFuzz native coverage 的首选落点。

| 优先级 | 模块/命名模式 | 覆盖点示例 | 说明 |
| --- | --- | --- | --- |
| P0 | `coupledL2/Directory.scala`, `Directory` | `dir_hit_trunk`, `dir_hit_branch`, `dir_hit_tip`, `dir_miss` | 已有报告包含 `l2_directory_hit_trunk/branch/tip` |
| P0 | `coupledL2/SinkA.scala`, `SinkA` | `sinkA_acquire_block`, `sinkA_acquire_perm`, `sinkA_get`, `sinkA_hint`, `sinkA_cbo_flush` | 源码已有 `XSPerfAccumulate("sinkA_*")` |
| P0 | `coupledL2/SinkC.scala`, `SinkC` | `sinkC_probe_ack`, `sinkC_probe_ack_data`, `sinkC_release`, `sinkC_release_data` | 覆盖 probe/release 回包 |
| P0 | `coupledL2/SourceB.scala`, `SourceB` | `sourceB_probe_fire`, `sourceB_probe_grant_conflict` | 已有报告包含冲突点 |
| P0 | `coupledL2/tl2chi/MSHR.scala`, `MSHR` | `mshr_send_probe`, `mshr_schedule_grant`, `mshr_retry_ack`, `mshr_comp_data` | 已有报告包含 10 个 MSHR 点 |
| P0 | `coupledL2/tl2chi/RXSNP.scala`, `RXSNP` | `rxsnp_nested_release` | 已有报告包含 nested release |
| P1 | `DCacheWrapper.scala`, `DCacheImp` | `dcache_load_hit`, `dcache_load_miss`, `dcache_store_hit`, `dcache_store_miss`, `dcache_replay` | L1D 与 L2 之间的压力来源 |
| P1 | `LoadPipe.scala`, `StorePipe.scala` | `loadpipe_req_fire`, `storepipe_req_fire`, `atomic_req_fire`, `mmio_req_fire` | 区分普通内存、AMO、MMIO |
| P1 | `AtomicsUnit.scala` | `amo_lr`, `amo_sc_success`, `amo_sc_fail`, `amo_swap/add/xor/or/and/min/max` | 多核同步 seed 的核心反馈 |
| P1 | CHI channels `TXREQ/RXDAT/TXRSP/RXSNP` | `chi_req_opcode`, `chi_rsp_opcode`, `chi_dat_opcode`, `chi_snp_opcode`, `retry` | CHI 协议交互覆盖 |

已有 FIRRTL coverage 点可以直接作为 P0 baseline：

```text
Directory_1:l2_directory_hit_trunk
Directory_1:l2_directory_hit_branch
Directory_1:l2_directory_hit_tip
MSHR:l2_tl2chi_mshr_send_probe
MSHR:l2_tl2chi_mshr_schedule_grant
MSHR:l2_tl2chi_mshr_probe_ack
MSHR:l2_tl2chi_mshr_probe_ack_data
MSHR:l2_tl2chi_mshr_probe_to_n
MSHR:l2_tl2chi_mshr_probe_to_b
MSHR:l2_tl2chi_mshr_data_sep_resp
MSHR:l2_tl2chi_mshr_comp_data
MSHR:l2_tl2chi_mshr_compdbid_resp
MSHR:l2_tl2chi_mshr_retry_ack
RXSNP:l2_tl2chi_rxsnp_nested_release
SinkA:l2_sinka_acquire_block
SinkA:l2_sinka_acquire_perm
SinkA:l2_sinka_hint
SinkA:l2_sinka_cbo_flush
SinkC:l2_sinkc_probe_ack
SinkC:l2_sinkc_release
SinkC:l2_sinkc_release_data
SourceB:l2_sourceb_probe_grant_conflict
SourceB:l2_sourceb_probe_fire
```

建议 bucket：

- `tl_opcode`：AcquireBlock、AcquirePerm、Get、Hint、CBOFlush、Release、
  ReleaseData、ProbeAck、ProbeAckData。
- `chi_opcode`：Read/Write/CompData/RetryAck/Snp 等按实际 `HasCHIOpcodes` 校准。
- `coh_state`：INVALID/BRANCH/TRUNK/TIP 或 coupledL2 实际 state enum。
- `source_core`、`target_core`、`bank_id`、`mshr_id`：只做小范围 bucket；`mshr_id`
  可按 `0`、`1`、`2+` 或 occupancy 桶化，避免 bitmap 过宽。

接出方式：

- 首批直接复用 `docs/firrtl_litmus_coverage_report.md` 中已证明的 23 点。
- 对 `SinkA.scala` 第 216 行附近的 `XSPerfAccumulate("sinkA_*", cond)` 复用 cond。
- 对 `SinkC` 使用 `io.c.fire && io.c.bits.opcode === ProbeAckData/ReleaseData`。
- 对 MSHR 使用 `state` 和 `tasks/resps` bundle 中 `s_probe/s_refill/s_retry/w_grant*`
  等位。`coupledL2/Common.scala` 的 `MSHRTasks`/`MSHRInfo` 已暴露这些语义字段。

### 5. ROB/提交/异常恢复

**为什么适合作为真实反馈**：SFuzz 的 seed 如果只触发前端和 cache，而不能走到提交、
精确异常和 rollback，就很难覆盖 CPU correctness 的关键边界。ROB/提交覆盖可把
“程序真正执行到架构状态更新”作为反馈。

| 优先级 | 模块/命名模式 | 覆盖点示例 | 说明 |
| --- | --- | --- | --- |
| P0 | `backend/rob/Rob*.scala` 或生成 RTL `Rob*` | `rob_commit_valid`, `rob_commit_count_0/1/2/3+`, `rob_empty`, `rob_full` | 提交深度和堵塞状态 |
| P0 | `backend/rob/ExceptionGen.scala` | `exception_gen_valid`, `exception_cause.<cause>`, `has_trap` | 精确异常入口 |
| P0 | backend redirect/flush | `flush_from_exception`, `flush_from_mispredict`, `flush_from_replay` | 异常恢复和 speculative recovery |
| P1 | `backend/rename/Rename.scala`, `RenameTable.scala` | `rename_fire`, `rename_stall`, `freelist_empty`, `rat_recover` | rename pressure 与恢复 |
| P1 | `backend/dispatch/Dispatch.scala` | `dispatch_fire`, `dispatch_stall_iq`, `dispatch_stall_lsq`, `dispatch_stall_rob` | 后端结构性冲突 |
| P1 | issue/writeback | `issue_fire_int/mem/fp`, `writeback_fire`, `replay_fire` | seed 是否触发不同执行簇 |
| P2 | `Rab.scala`, rename buffer | `rab_enqueue`, `rab_dequeue`, `rab_recover` | revision 相关，适合诊断 |

建议 bucket：

- `commit_count`：0、1、2、3、4+，不要直接记录全宽 popcount。
- `exception_cause`：RISC-V cause bucket，例如 illegal instruction、breakpoint、
  load/store/inst page fault、access fault、ecall、misaligned。
- `flush_source`：branch、memory replay、exception、interrupt、debug。
- `uop_type`：int、branch、load、store、amo、csr、fp/vector，按 decode/dispatch 类型。

接出方式：

- LinkNan/Nanhu 的 difftest gateway 已有 `valid` 和 `hasTrap` 相关过滤逻辑
  (`DifftestCoreGateWayCollector` 会关注 `valid`/`hasTrap` 字段)，可作为定位提交和
  trap 信号的线索。
- FIRRTL pass 可按模块名 `Rob`、`ExceptionGen`、`TrapInstMod`、`RedirectGenerator`
  搜索 `valid`、`hasTrap`、`exceptionVec`、`cause`。
- VCS/Verilator 中应以每 seed 是否命中 cause bucket 为覆盖，不建议把 commit PC
  低位直接作为覆盖点，否则会变成程序地址覆盖而非微结构覆盖。

### 6. 中断、特权态与 CSR

**为什么适合作为真实反馈**：中断和特权态路径通常很难由随机程序稳定触发，但它们是
系统级 CPU fuzzing 的核心。SFuzz 的结构化 seed 可以显式放置 CSR 写、timer/software
interrupt、`sret/mret`、`sfence.vma`、虚拟化 CSR，因此这些点应成为高权重反馈。

| 优先级 | 模块/命名模式 | 覆盖点示例 | 说明 |
| --- | --- | --- | --- |
| P0 | `backend/fu/wrapper/CSR.scala` | `csr_inst_fire`, `csr_write_mstatus`, `csr_write_satp`, `csr_write_mie/mip` | CSR 指令真实执行 |
| P0 | `backend/fu/NewCSR/*` | `trap_enter`, `trap_return_mret`, `trap_return_sret`, `priv_change` | trap/return 闭环 |
| P0 | `ClintNode`, `PlicNode`, `MtimerNode`, generated device RTL | `msip_pending`, `mtip_pending`, `meip/seip_pending`, `interrupt_taken` | 外设到 core 的中断路径 |
| P1 | delegation CSR | `medeleg_hit`, `mideleg_hit`, `hedeleg/hideleg_hit` | S/VS/HS 路径区分 |
| P1 | virtualized CSR/MMU | `vsatp_changed`, `hgatp_changed`, `virt_mode_enter`, `guest_page_fault` | 虚拟化和二阶段翻译 |
| P1 | debug/trigger | `trigger_match`, `debug_mode_enter`, `dret` | 调试路径可作为可选实验目标 |

建议 bucket：

- `priv`：U、S、M、VS、HS，按 LinkNan 实际 privilege/virt 编码校准。
- `interrupt_cause`：software、timer、external、local/custom。
- `csr_addr_group`：status、ie/ip、tvec/epc/cause/tval、satp/vsatp/hgatp、pmp、counter。
- `trap_return`：mret、sret、dret。

接出方式：

- CSR 模块中 `CSROpType`、`CSRInput`、`CSRToDecode`、`CSRSpecialIO` 是源级定位入口。
- 生成 RTL 中常见 CSR module 包括 `Mstatus*`、`McauseModule`、`MtvalModule`、
  `VSatpModule`、`HedelegModule`、`Pmp*cfgModule` 等，可作为后处理匹配入口。
- 中断 pending/taken 应采 core 内部“被接受”的信号，而不是只采外设 pending，
  否则 seed 可能因为 mask/privilege 不满足而产生假覆盖。

### 7. 多核同步与内存模型

**为什么适合作为真实反馈**：LinkNan 上 SFuzz 的论文亮点可以放在多核 litmus、
AMO/LRSC、cache probe/release、跨核 invalidation 和 memory ordering。单核指令覆盖
不能解释这些 seed 是否真正形成跨核交互。

| 优先级 | 模块/命名模式 | 覆盖点示例 | 说明 |
| --- | --- | --- | --- |
| P0 | L2 Directory/MSHR/Sink/Source | `cross_core_probe`, `probe_ack_from_other_core`, `release_from_other_core` | 由 source/client id 判断是否跨核 |
| P0 | `AtomicsUnit.scala`, load/store pipeline | `lr_seen`, `sc_success`, `sc_fail`, `amo_seen` | 同步原语覆盖 |
| P0 | fence unit `backend/fu/Fence.scala` | `fence_fire`, `fence_i_fire`, `sfence_fire`, `fence_wait_storebuffer` | memory ordering 关键点 |
| P1 | LoadQueue/StoreQueue | `load_replay`, `store_to_load_forward`, `violation_detected`, `load_wait_store` | 内存序和 replay |
| P1 | L2 bank/slice | `same_line_diff_core`, `same_bank_diff_core`, `mshr_conflict_diff_core` | 需要地址/source 低维派生 |
| P1 | NoC/CHI route | `req_from_core_i_to_home_j`, `snp_to_core_i`, `dat_return_core_i` | 多核/多 slice LinkNan 关键交互 |

建议 bucket：

- `core_pair`：`same_core`、`core0_to_core1`、`core1_to_core0`、`other_pair`。核心数大时
  不展开所有 pair。
- `addr_relation`：same cache line、same set、same bank、different bank。用地址低位
  派生，不记录完整地址。
- `sync_op`：LR、SC success、SC fail、AMO type、FENCE、FENCE.I、SFENCE。
- `coherence_relation`：self hit、shared hit、remote probe、dirty transfer、retry。

接出方式：

- L2/TL2CHI 的 `sourceId`、`clientBits`、`getClientBitOH(sourceId)` 可用于推断发起核。
- `SinkC` 的 ProbeAck/Release、`SourceB` 的 Probe、`MSHR` 的 `probe_to_n/b`、`retry`
  是首批跨核同步点。
- 对 litmus 实验，建议把 `SFUZZ.multicore` 与 `SFUZZ.coherence` 做 union，报告
  覆盖随时间和 bug/litmus outcome 的关系。

### 8. Decode/指令类别与非法输入过滤

**为什么适合作为真实反馈**：SFuzz 生成结构化 RISC-V 程序时，需要知道 seed 是否只在
非法指令/早期 trap 中打转，还是覆盖到特定 ISA 扩展和执行单元。该层不是最终目标，
但能稳定提升 mutation 的方向性。

| 优先级 | 模块/命名模式 | 覆盖点示例 | 说明 |
| --- | --- | --- | --- |
| P0 | decode/control flow | `decode_valid`, `decode_illegal`, `decode_csr`, `decode_load/store`, `decode_branch` | 输入质量反馈 |
| P1 | ISA 扩展 | `rv64m_mul/div`, `rv64a_amo`, `rv64c_rvc`, `vector_seen`, `float_seen` | 按实际启用扩展 |
| P1 | execute units | `int_fu_fire`, `bru_fire`, `lsu_fire`, `csr_fu_fire`, `fpu/vpu_fire` | 与后端执行簇关联 |

接出方式：

- 可以从 decode 输出的功能单元类型和 `illegal`/`exceptionVec(EX_II)` 派生。
- 论文中应说明 decode 类点用于 seed 有效性与分层反馈，不把它作为唯一硬件覆盖。

## 推荐首批覆盖集

### `SFUZZ.arch.P0`

用于所有单核 smoke 和基础 fuzz：

- 前端：`ftq_enq_fire`、`ftq_deq_fire`、`ibuffer_in_fire`、`ibuffer_out_fire`、
  `ibuffer_flush`
- 分支：`bpu_update_fire`、`redirect_valid`、`redirect_from_branch`、
  `redirect_from_exception`
- MMU：`itlb_miss`、`dtlb_miss`、`tlb_refill`、`sfence_valid`、`ptw_req_fire`、
  `ptw_resp_fire`、`page_fault_bucket`
- ROB：`rob_commit_valid`、`commit_count_bucket`、`exception_gen_valid`、
  `trap_cause_bucket`
- CSR/特权：`csr_write_satp`、`csr_write_mstatus`、`trap_enter`、`mret/sret`

### `SFUZZ.coherence.P0`

用于多核/litmus/内存系统论文实验：

- 直接包含已有 FIRRTL 23 点：
  `Directory_1`、`MSHR`、`RXSNP`、`SinkA`、`SinkC`、`SourceB`
- 增补：`dcache_load_miss`、`dcache_store_miss`、`lr_seen`、`sc_success`、
  `sc_fail`、`fence_fire`
- 增补：`cross_core_probe`、`probe_ack_from_other_core`、`release_from_other_core`

### `SFUZZ.full.P1`

用于 ablation 和长时间 fuzz：

- `SFUZZ.arch.P0 + SFUZZ.coherence.P0`
- predictor 子结构：TAGE/ITTAGE/RAS bucket
- PTW cache 多级 hit/refill bucket
- LoadQueue/StoreQueue replay/forward/violation bucket
- interrupt/delegation/virtualization bucket

## Coverage ABI 建议

### 元数据

生成一个稳定 metadata 文件：

```text
version,linknan_git,build_config,num_cores,coverage_name,index,group,module,event,bucket,priority,source
1,<sha>,<config>,2,SFUZZ.coherence,0,coherence,Directory_1,l2_directory_hit_trunk,,P0,firrtl
1,<sha>,<config>,2,SFUZZ.mmu,47,mmu,TLB,miss,port0:P0,scala-pattern
```

需要记录：

- LinkNan commit/build config/NUM_CORES
- 覆盖点生成脚本版本
- 每个 index 的原始模块路径或 FIRRTL source locator
- 覆盖点是否来自已有 FIRRTL cover、自动派生、手写白名单

### 运行时

每个 seed 的最小输出：

```text
seed_id,coverage_backend,coverage_name,total_points,covered_points,new_points,exit_kind,cycles
```

本地 bitmap 需要随 seed 清零。对于 counter 型事件，建议进入覆盖图前桶化：

- `0`
- `1`
- `2-3`
- `4-7`
- `8+`

例如 `rob_commit_count`、`ptw_latency`、`mshr_occupancy` 不要直接把原始计数当 index。

## 与 RFuzz/DirectFuzz/SurgeFuzz 公平比较

### 明确实验层级

沿用 [benchmark_plan.md](benchmark_plan.md) 中的三层口径：

- `T0_smoke`：只比较 VCS/Verilator 是否运行、SFUZ 是否展开、退出状态、耗时。
- `T1_common_backend`：所有方法使用同一覆盖后端，例如 VCS built-in、SanCov、
  已有 FIRRTL 23 点、或本文 `SFUZZ.coherence.P0`。此时 RFuzz/DirectFuzz/SurgeFuzz
  只是调度/变异策略不同，覆盖反馈相同。
- `T2_native_method`：每个方法使用论文定义的 native feedback：
  - RFuzz：mux-select toggle coverage + pin-stream input ABI
  - DirectFuzz：per-instance mux-toggle + target distance metadata
  - SurgeFuzz：annotated target score + ancestor-state coverage
  - SFuzz：本文定义的 LinkNan semantic microarchitectural coverage

`T2` 可以比较 bug discovery、time-to-target、coverage within method，但不要把
“RFuzz 覆盖点数”和“SFuzz 覆盖点数”直接放在同一 y 轴上当同质指标。

### 同源输入和资源预算

公平规则：

- 同一 LinkNan commit、同一 build config、同一 NUM_CORES、同一 simulator。
- 同一初始 seed corpus，或明确说明每个方法的输入模型不同。
- 同一 wall-clock budget 和 cycle limit；VCS process-per-seed 与 Verilator in-process
  必须分表或显式归一化。
- 同一 bug 判定和去重规则：assert/mismatch/trap signature/log hash。
- 同一 coverage reset 语义：每 seed local bitmap，结束后与 global 比较。
- 随机方法重复多组 random seed，报告均值/置信区间。

### 对 RFuzz 的口径

RFuzz 原生覆盖是 mux-select toggle，输入是 top-level pin stream。若当前 RFuzz
入口还只是把 raw bytes 塞入 SFUZ payload 并跑 VCS，应标注为开发调试运行：

```text
fuzzer=rfuzz
comparison_tier=T0_smoke 或 T1_common_backend
coverage_backend=vcs_log / vcs_builtin / sfuzz_linknan_common
paper_faithful=false
```

只有接出 mux-select per-cycle toggle bitmap 后，才能写：

```text
fuzzer=rfuzz
comparison_tier=T2_native_method
coverage_backend=rfuzz_mux_toggle
```

若为了公平把本文 `SFUZZ.coherence.P0` 也喂给 RFuzz scheduler，则那不是 RFuzz paper
结果，而是 `rfuzz_mutator_on_sfuzz_coverage` 之类的 ablation。

### 对 DirectFuzz 的口径

DirectFuzz 的关键是 target instance distance。本文覆盖点可以给 DirectFuzz 提供
target 候选，例如 `MSHR.retry_ack` 或 `ExceptionGen.trap_commit`，但不能替代
DirectFuzz 的 per-instance mux coverage。

公平写法：

- `T1_common_backend`：所有方法使用 `SFUZZ.arch.P0` 或 `SFUZZ.coherence.P0`，
  DirectFuzz 只用 target-aware seed priority/energy 做策略比较。
- `T2_native_method`：DirectFuzz 必须有 `instance_name,coverage_signal,width,distance`
  metadata，且 distance 从单个 testcase local coverage 计算。

不要把 SFuzz semantic event distance 伪装成 DirectFuzz paper 的 mux graph distance。

### 对 SurgeFuzz 的口径

SurgeFuzz 原生反馈是“目标异常事件的 surge score + 祖先寄存器状态覆盖”。本文中的
`mshr_retry_ack`、`tlb_page_fault`、`interrupt_taken` 很适合作为 SurgeFuzz annotation
target，但比较时要分清：

- SurgeFuzz native：`coverage_target=<event>`，`coverage=<selected ancestors>`，
  每周期 score 更新。
- SFuzz native：直接把 `<event>` 和相关语义 bucket 当覆盖点。

同一 target 可用于 time-to-target 对比，例如：

```text
target_id=MSHR.retry_ack
SFuzz feedback=SFUZZ.coherence.P0
SurgeFuzz feedback=SURGE_FREQ(MSHR.retry_ack)+ancestor_state
```

报告时用 `time_to_first_target_hit`、`unique_bug_count`、`valid_seed_rate` 更公平，
不要直接比较两者覆盖 bitmap 的 covered ratio。

## 论文实验建议

### Ablation

建议至少做四组：

| 组 | 覆盖反馈 | 目的 |
| --- | --- | --- |
| A | `llvm_guard` 或 VCS built-in | 通用软件/仿真器覆盖 baseline |
| B | `SFUZZ.arch.P0` | 证明架构/微结构语义反馈提升深度 |
| C | `SFUZZ.coherence.P0` | 证明内存系统/多核反馈提升协议覆盖 |
| D | `union:SFUZZ.arch.P0+SFUZZ.coherence.P0` | 证明组合反馈对系统级 bug 更有效 |

### 指标

- 覆盖随时间：每层单独画，不混用不同 coverage universe。
- time-to-first：branch redirect、TLB miss、page fault、MSHR retry、cross-core probe、
  interrupt taken 等目标事件。
- 有效 seed 比例：达到 commit、达到多核交互、达到 trap return。
- bug discovery：assert/mismatch/timeout/illegal state，按 signature 去重。
- seed 长度与执行周期分布：解释 SFuzz 是否只是生成更长程序。

### 推荐目标事件

短期最有把握：

- `Directory_1:l2_directory_hit_trunk/branch/tip`
- `MSHR:l2_tl2chi_mshr_retry_ack`
- `RXSNP:l2_tl2chi_rxsnp_nested_release`
- `SinkA:l2_sinka_cbo_flush`
- `SourceB:l2_sourceb_probe_grant_conflict`
- `TLB.miss + PTW.resp`
- `ExceptionGen.trap_commit.<cause>`
- `CSR.satp_changed + sfence.valid`
- `AtomicsUnit.sc_fail/sc_success`

这些点分别覆盖一致性状态、冲突重试、嵌套释放、cache flush、probe 冲突、
地址翻译、精确异常、特权刷新和多核同步，适合作为论文中“结构化反馈命中深状态”
的案例。

## 实现注意事项

- 覆盖点命中应在 reset 结束后启用，避免 reset 初始化状态污染 coverage。
- 对 boot ROM/ABI 固定路径，可以用 warmup cycle 或 `sfuzz_start` 标志屏蔽前 N 周期，
  也可以保留但在报告中单独标注 `boot_coverage`.
- 多核实验必须记录 `NUM_CORES`。已有 litmus 报告显示 2-hart corpus 与 1-core build
  会导致早期失败，这类 run 不能用于覆盖结论。
- 对地址、PC、data、source ID 等高基数字段要桶化，不要全量展开。
- 对异常类点要区分“异常产生”和“异常提交/被接受”。论文中优先用提交/接受点。
- 对中断类点要区分 pending 与 taken。pending 可作为 P1，taken 才是 P0。
- 对 ready/valid 通道优先采 `fire`，单独采 `valid` 只能表示压力，不表示事务完成。
- 对 replay/flush/redirect 建议采边沿或单周期 pulse，避免同一事件长时间拉高导致
  counter 误解；bitmap 语义下长高只置位一次。

## 最小落地路线

1. **复用已有 FIRRTL 23 点**：形成 `SFUZZ.coherence.P0.initial`，先跑 VCS/Verilator
   smoke，验证 local bitmap reset 和 metadata 输出。
2. **补前端/MMU/ROB P0**：从 `IBuffer`、`TLB`、`PageTableWalker`、`ExceptionGen`、
   `RedirectGenerator` 接 40-80 个点，形成 `SFUZZ.arch.P0`.
3. **加入多核同步 bucket**：从 `AtomicsUnit`、`Fence`、`SinkC`、`SourceB`、`MSHR`
   加 cross-core/probe/release/SC bucket。
4. **统一 runner schema**：所有 run 输出 `coverage_backend`、`coverage_name`、
   `comparison_tier`、`local_new_points`、`global_covered_points`。
5. **做公平对比**：先 `T1_common_backend`，再在 RFuzz/DirectFuzz/SurgeFuzz native
   ABI 准备好后做 `T2_native_method`。

这条路线的优点是第一步已经有现成 LinkNan FIRRTL coverage 证据，后续每加一层都能
独立评估，不需要一次性完成完整 RFuzz/DirectFuzz/SurgeFuzz 级别的插桩基础设施。

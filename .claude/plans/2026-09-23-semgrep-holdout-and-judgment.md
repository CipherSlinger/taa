# 阶段 H：留出集非劣验证（实施计划）

- 关联规范：`.claude/specs/2026-09-23-semgrep-engine-integration-design.md` §9（证据门槛）、§10 阶段表 H 行
- 关联证据：`.claude/specs/2026-09-22-semgrep-engine-noninferiority-evidence-design.md`（主基准，拟合集）
- 前置阶段：A–G 已完成并提交（`1c71cd7` 为最后一次）
- 状态：**H1.1–H1.4 全部完成；语料已落盘为 311 条，要求 9 的 Go 等价性在留出集上零分歧通过。卡口在 H2 开跑前**（H2 需先做容器内存的重新规划，宿主 9.7 GiB）：**该规划已于 2026-09-24 实测标定并写入 §9.1**（五项参数已定：第 4 项落点经更正为「两处调用点各加 `--jobs 4`」，第 5 项定为 **`--memory 7g`**；原「OOM 按构造可达」的归因经实测**部分撤回**）。**H2.5 的规模实测已完成，读数见 §17**（单扫描 168→221 MiB 匿名、并发 burst level 12 达 1.72 GiB、`tests/` 被静默丢扫、`--jobs` 语义无关性已证、一次仪器故障与一处假结论的撤回）。恶意臂与近失臂口径均已收紧并裁定（四源状态与实测体量见 §12.1）。过程中处理**七处**预登记缺陷：DataDog 臂构成（§13 决策 6）、**证伪并修订规则 3 的「整包皆恶意」前提**（§12.2 规则 3 修订稿、§13 决策 7）、CodeQL 近失口径（§13 决策 8，**两次收紧**：27 处标记 → 14/15 文件 → **5 个纯否定文件**）、退化样本与重复的机械口径（§12.2 规则 8，新追加）、**超长单行的提示体量上限**（§12.2 规则 9、§13 决策 9：剔除 5 条并计数，实测代价是 5 条真阳性）、**参照集的证据资格**（空文件哈希不作证据、自指不构成复制；§12.2 新增）、以及**撤回**一处曾据错误实测作出的窗口修订（§12.2 规则 7、§13 决策 5）。计数与归因更正见 §14（窗口的自指测量）与 §15（CodeQL 文件数连错两次、恶意臂副本归因连错两次——第二次的「19 个 `boltons` 副本」实为 19 个 0 字节文件）。恶意臂**参照集已就位**（`dd/vendor-references.json`，确认来源为 `aiogram` 与 `scrapper_boilerplate`）。**H1.2/H1.3/H1.4 的实测读数见 §12.5**；两处**产品/工装缺陷**已登记未修（§11.9 提示体量无界、§11.11 `attribution_precision` 恒为 0）。下一步为 **H2 判定运行**——**H2.1 首启（2026-09-24T06:47:46Z，受载）已于约 07:15 中止**：受载条件下判据**自己的** LLM 仲裁失效（只会产出假通过），中止理由、完整证据链与两处**我自己造的错误仪器**见 **§17.11**；已中止的产物保留为 `/root/taa/verify/h2-assist-ABORTED-loadstarved`（**不得用于判定**）。**H2.2 的 `gate` 不重跑，改由 H2.1 产物精确重打分导出**（你于 2026-09-24 裁定「gate 能免跑就免跑」；机制、四处必写事项与验证要求见 §7 H2.2，工具 `models/audit/tools/gate_rescore.py`，已提交 `801983a`，22 项测试全绿，12/12 真产物逐字段复现）。**H2.3 必须排在 H2.1 之后串行**（其唯一真实负载是 semgrep，非 LLM）。**已裁定（2026-09-24）**：§2 主判定读**无载**条件，受载条件改作部署可行性结论，**受载矩阵不再重跑**（§17.11）。**H2.1 已按 `LOAD=0` 重启**（`/root/taa/verify/h2-assist-unloaded`，2026-09-24T07:09:23Z，311 条，`assist`，规则 `c06ffd2c`），量测前先 warm 模型；正在跑（见 §17.11 末尾的裁定与落地）。**进度**：`regex-run1` 已完成（`exit=0`、`seconds=3562` ≈ 59.4 min，`tp49/fp17/tn137/fn108`），`semgrep-run1` 运行中（09:19Z 时 199/311）。**§17.12 于 2026-09-24 更正了一处方向性错误**：失败调用的失效方向是 **fail-closed（把样本推向 malicious，只抬高 FPR）**，**不是**先前记的 fail-open；run 1 实测受影响 **8 份样本 / 11 处失败调用**（超时 7、解析截断 4），其中**已致 1 例假阳性**（`pypi-0057`）、**假阴性 0 例且在本语料不可达**（零低危发现）。**§17.12 D-2 追加（实测结清）**：该假阳性**在 semgrep 臂同样存在**故于 `ΔFP` 中相减为零；两臂失败所致 FP 分别为 regex **2**（皆与 semgrep 共有）、semgrep **0**，而 round 1 的 `ΔFP = +1` 完全由 `sr-0155` 承担——它是**静态 `NET_001` 分歧**（semgrep `llm_state=ok`、regex `matched_rules=[]`），在 §16.1 的 `--llm-backend none` 运行里同样是 FP ⇒ **LLM 与超时都不参与**。故**重放不可能把 round 1 的 FAIL 翻成 PASS**（重放只能移除失败所致 FP，而 FPR 只统计良性样本：semgrep 侧无可减、regex 侧每减一例 `ΔFP` 反 +1 ⇒ `ΔFPR` 只能持平或上升）。**我先前「`ΔFP` 可能是 OOM 制造的、故反事实对判定承重」的话已撤回**；重放仍要做，但它结清的是 `Δrecall` 一侧。**§17.13 追加**：**08:22:13Z 容器 OOM 杀掉了 `llama-server` 本体**（cgroup 长期贴 7 GiB 上限，`memory.peak == memory.max`；约 40 s 后重启，重启后头几次调用还要付 ~29 s 模型加载）。落点为 `semgrep-run1`，方向**对 semgrep 不利（保守）**，且事后补查**未再复发**（`oom_kill` 恒为 1）。但同机制若落在 `regex` 轮次，会抬高 regex 的 FPR、把 `ΔFPR` 变小，**可能制造假通过**——`regex-run2/3` 尚未跑，故为**持续威胁**。处置：**不改 `--memory 7g`**（属 §9.1 已定参数，中途改即破坏 `RUN_ORDER` 所要控制的机器漂移），事后用已修正的反事实工具量化，**必要时按预登记判据报不可判定**。**§18 追加（本条严重性高于 §17.13）**：**留出集已被污染**——语料落盘于 11:22:33 且此后未再写过，而 §16 于 12:04 在该集上诊断出两处 semgrep 规则缺陷、12:08 与 12:29 据此改了 `ENV_001` 与 `_pickle` 两条规则、12:50 又在同一集上复核、14:47 起在同一集上判定；**两处改动都把判据的量本身朝 semgrep 方向推**（`ΔFPR` `+0.0714 → +0.0065`，`Δrecall` `+0.0255 → +0.0382`）。这违反了本轮 spec §12 写死的「生成后不对规则做任何修改」。故本语料已降为**开发集**：FAIL 仍可报（且在被人为调优过的集合上仍失败，结论更强），**PASS 则不可解释**；三条处置路线见 §18 F，**在裁定前矩阵继续跑完**。**§19 追加（2026-09-28）**：矩阵**并非**这次宿主重启所杀——驱动日志末行写在 **2026-09-24T09:40:32Z**（`----- regex run 2 -----`），而 run 2 只留下 288/311 份产物、无混淆矩阵，按 run 1 实测速率折算进程约在 **09-24T10:35Z** 就停了，容器此后空转四天，重启只是收尸。故 **pair 1 沿用**（两臂皆 311/311 且带矩阵），**`regex-run2` 丢弃重跑**。为此给驱动加了 `RESUME`（`568faee`，**默认关闭**；完备性由产物判定——矩阵存在**且**报告数等于语料条数；失败仍停机；8 项测试含一次变异检查全绿）。发射前另登记两处**我自己的仪器故障**（`dpkg` 是逐包瞬态、不能当忙碌证据；非 root 抢 dpkg 锁只得到 `EACCES`，与 `EAGAIN` 分不开）。另登记：「`LOAD=0`」的准确含义是「除常驻工装外无压测负载」——本会话与 VS Code 常驻约占 0.5–1.0 核、`load1≈1.3`，该基线在两臂恒定故相消。**进度**：已按 `RESUME=1` 于 **2026-09-28T02:57:45Z** 续跑（容器内 detach，pid 381），pair 1 两轮报 `already complete, kept` 且读数与重启前**逐位相同**，`regex-run2` 重新测量中。另登记两处宿主事实（**有待重启**：新内核 `6.8.0-142` 已装而当前仍跑 `6.8.0-139`，`Automatic-Reboot` 未配置故无人代重启；**容器 `RestartPolicy=no`，重启后不自启**）与监视器两处**静默分支**的修复（`4eeceb9`，变异验证：旧代码下 `runs=2154 … llama_pid=3`，GONE 告警永不触发）。**§20（你于 2026-09-28 裁定）**：选 §18 F 的 **(b)**——`audit-holdout` 由留出集改判为**开发集**，**非劣性主张收回（＝未确立，不等于证否）**，默认引擎**保持 `regex`**（`internal/config/config.go:287` 实测未动）、**不进灰度**；因 (a)/(c) 未选，「干净留出集上是否非劣」**仍未被回答**。同时登记一处**规范缺口**：spec 阶段 H 的出口是**二值**的（第 576/577、598 行），本裁定产生了**第三种状态「未确立」**（判据的**仪器自身**不合格，故判据从未在其自身前提下被评价），spec 无此分支，**本轮不改**、待 H 收尾后处理。**§21（自我更正 + 一处新发现）**：我在续跑初期据「报告产出速率」判 run 2 慢 1.34×，**该说法撤回**——同口径实测（同样 25 个样本）请求数 39 vs 38、模型速率 run 2 **更快**（prefill 40.6→54.1 tok/s、decode 9.2→10.5 tok/s），**机器未退化**；我读错了指标（把产出速率当机器速率）。真正测到的是：**60 s 是客户端等待上限、不是服务端工作时限**——一个被客户端在 60 s 处放弃的请求，服务端实测跑满 **611.8 s**（上限的 10 倍），期间占着那唯一一个槽，故超时**会级联**、方向 fail-closed（只抬 FPR，且不利于发现多的一臂），并与 §17.13 的 OOM 同源（§11.9 那条 22 MB 提示的压力发生在客户端已不再等待之后）。不影响 §2 判定：pair 2 背靠背同状态测量，跨对差异不进判据。**§21 F（对上述 D2 的实测核查，结论是撤掉它）**：pair 1 实测发现多的一臂**调用更多（73 vs 66）却未仲裁更少（6 vs 8）**，故「级联偏置不利于发现多的一臂」在本语料**不成立**；机制未被证否而是**错位**——级联需要并发，本矩阵串行提交，被放弃的调用只付一次延迟（属同容器部署的风险，非本矩阵读数）。留下的是报告可用的一句：两臂 FP 差 1 条而失败数差 2 条 ⇒ **开发集 ΔFPR 不能归因于调用失败**。**§22（你于 2026-09-28 在岔路上选定）**：**H 收尾即止、接入停在此处**——矩阵跑完 → 开发集读数 + gate 并列 → 写报告 → **停在报告**；**不刷规则**（`deploy-docker.sh --scan-engine semgrep` 本可不依赖非劣性独立执行，你仍没选 ⇒ 属**有意不做**）、**不切 `CodeScanEngine`**（此后是**有意保持** `regex`）、**不部署**。后果须写进报告：spec 548 行的门**无限期关闭**（唯一开法＝补建干净留出集重判，即原 §18 F 的 (a)，你未选），故「semgrep 作默认引擎」**不是延后而是未取得资格**，不得写成「待后续观测即可切换」。「收 H 尾」范围内照做：gate 重打分、两基读数、反事实重放的 `Δrecall` 侧、H2.3、H2.6、最终报告。**§23（监视器第三次缺陷，`3e63d13`）**：仲裁失败的可读信号是 **`statistics.uncertain`**，不是 `conclusion.verdict`——pair 1 实测 `statistics.uncertain > 0` 的样本集合与 `llm_state ∈ {llm_unavailable, parse_error}` 的集合**逐位相同**（8/8、6/6），而 verdict 只能找到 8 中的 1、6 中的 2；旧信号会让「服务器活着但持续报错」的失败潮漏掉约 **7/8**。已改读该字段并加 7 项测试（含两方向钉）+ 变异验证（换回旧信号精确失败 2 项）。报告须用此口径报未仲裁率。**§21 G（把 F 精确化到样本级，结论反转两次后定下）**：失败只落在 **regex** 侧造成 FP（2 条：`pypi-0057`、`sr-0012`），semgrep 侧 **0 条**——与我在 D2 的预测方向相反。pair 1 读数 `FPR` 17/154 vs 18/154 ⇒ **ΔFPR=+0.0065>0（FAIL 在 ΔFPR）**，`recall` 49/157 vs 55/157 ⇒ Δrecall=+0.0382。扣掉失败机制的确定性部分后 **ΔFPR 变 +3/154，比实测更大** ⇒ 失败**掩盖**了 semgrep 劣势的约 2/3，**不是**成因而直接堵死「你的调用在失败」这一反驳。**§24（`regex-run2` 整轮完成，2954 s）**：**两轮 regex 逐位复现**——发现数 126、调用数 192、`invoked` 66、**混淆矩阵四项全同**（tp=49 fp=17 tn=137 fn=108）⇒ §17.12 D-2「重放不能翻转 pair 1」由推理升为**实测**。**LLM 调用模型实测**：`llm_duration_sec` 是**样本级多次调用之和**（每发现一次 + 每文件一次），`192` 与 ollama 日志实测 **191 个请求**吻合；`total_findings` 全语料最大 **7** ⇒ `MaxFindings: 20` 截断**从不生效**；上限为 `code_security_analyzer.py:733` 的 `urlopen(timeout=60)`、**无重试**（§9 正确），`num_predict` 200/300 ⇒ **单次生成 ≤ 约 30 s**，故 §21 D 那条 611.8 s **只能**是排队主导（我原先「服务端算了 611.8 s」的猜测与 `num_predict` 冲突，**已废**；§21 D 的 431.4 s>60 s 读法亦错——那是 7 发现⇒8 次调用的和，54 s/次贴着上限）。**两臂暴露量不对称且须写入报告**：semgrep 多发 41% 发现 ⇒ 多打 31% 调用（**251 vs 192**），但**失败率更低**（8.2% vs 12.1%）⇒ 是**调用量**不对称而非失败率不对称。**§25（2026-09-28）**：**首次 OOM 击杀**（04:13:51Z，`oom_kill 0→1`，容器 `memory.peak == memory.max == 7168 MiB` 即 headroom 为零 ⇒ 可预期而非意外），8 秒后 `llama-server started in 7.06 seconds`（该日志行自带时间戳），**矩阵存活**（驱动未停、无 `exit=`、eval 重启后 3 分钟内 11 任务/10 次 prefill 完成，是真在生成）。落点为 `dd-0055`（恶意，18 发现，**19 次调用**），其 `statistics.uncertain=2` 的两条**性质不同且都可读**：`NET_001@128` = **`HTTP Error 500`**（runner 被杀、ollama 代答 ⇒ **OOM 的物证**），`NET_001@95` = `timed out`（60 s 上限，与 OOM 无关）⇒ 该击杀 **verdict 中性、未制造误报**。那段 6.5 分钟空档**早于**击杀 3 分 21 秒、且由样本自身成本（19 次调用 ≈22 s/次、在飞提示 2050 token）解释，**不是 OOM 造成的**。**报告须用三种失败模式的分表**：`timed out`（regex-r1 7、semgrep-r1 2、semgrep-r2 1）／**`HTTP Error 500`（全四轮仅 1 次，对应首次 `oom_kill`；该「一一对应」**已由 §31 F 证伪并收窄**——击杀仅当发生在**解码中**才留下 500）**／`无法解析模型输出`（regex-r2 全部 5），且 **`oom_kill` 计数须与 500 计数并列报出**。**更正 §24 B/E**：「语料最大 7」是 **regex 一臂**的值；semgrep 返回每个匹配，实测 **≥18**，故「`MaxFindings: 20` 从不生效」的**依据须分臂写**。另登记**第三个诊断错误**：`grep -v grep` 滤掉任何含子串 `grep` 的行，而 eval 命令行含 `--engine semgrep`，故我把自己要找的那一行滤掉了、据此误判「eval 已死」；**我先前对你说「是 `ps` 不可信」也是错的**——`ps` 一直是对的。规矩：进程存在性用 `/proc/*/cmdline` 或 `pgrep -af`，**禁用 `grep -v grep`**；空结果先排除过滤器自身。三次仪器故障中**两次**是「把『我没看到』当成『不存在』」。**§26**：`decide()` 的判定顺序是「先失败、再 void、最后才看对数」，而判据**逐对成立** ⇒ **pair 1 一失败即终局**，pair 2/3 是确认而非翻盘；并更正我先前「少于 3 对不给结论」的说法（那个门只在既不失败也无 void 时才咬合）。**§27**：监视器**第四次缺陷**——把 ollama 的**空闲卸载**（keep_alive 到期）报成 OOM 击杀，并断言「本窗口每个调用都会失败」而紧随的那次调用**成功了**；判别量就是它已在读的 `oom_kill`（全程恒为 1），已修并用**双向变异**钉住；顺带实测**空闲卸载后的冷加载 5.79 s**，并登记一个**未验证假设**（两臂失败率差或部分源于「regex 发现少 ⇒ 空闲段长 ⇒ 卸载多 ⇒ 冷加载多」，验证方法见 §27 D，**验证前不得归因**）。**§28**：**pair 2 读数**——两对以**同一幅度**失败在 `ΔFPR`（皆 18 vs 17，`+0.0065`），`regex-run2` 四项与 run1 全同；semgrep 两轮唯一的一票之差（55→54）是失败造出来的（`dd-0029`：run1 两次失败 ⇒ 抬升阻断 ⇒ 真阳性；run2 无失败 ⇒ 假阴性）⇒ **一次失败总把样本推向 malicious，效果取决于真标签**（benign ⇒ FP，malicious ⇒ TP），故**失败数须按臂并按真标签拆开报**；并更正 §25 B「落在恶意样本上 verdict 中性」不可推广。**§29**：按真标签拆开后，**semgrep 两整轮 benign 侧失败为 0、regex 为 2 与 1**，两臂 benign 侧暴露量几乎相同（43 vs 40）故非暴露量差异，**但 Fisher 双侧 p = 0.2292** ⇒ 「semgrep 的 FPR 不被失败抬高」**不予主张**（我口算的 0.27 亦更正为 0.11–0.19）；另更正 §24 E 的调用数：`251` 是未去重数，真实为 **249**（去重后才逐条调用），方向不变、幅度 31%→30%。**§30（重要撤回）**：`regex-run3` 完成，**三轮 regex 的判恶意样本集合逐位相同**（66 条）而失败数为 8/5/3，其中 **run3 的 benign 侧失败为 0 而 `fp` 仍为 17** ⇒ `pypi-0057`、`sr-0012` 是**与失败无关的**假阳性 ⇒ **撤回 §21 G「失败掩盖 semgrep 劣势」的全部推论**（含 `+3/154`）与 §24 H-4 的 `+2/154`。**更正后的陈述**：**FPR 侧失败完全不参与**，`ΔFPR = +0.0065` 是不含失败效应的读数、**没有任何反事实能救**；**recall 侧失败参与**且方向是**夸大 semgrep**，不含失败效应的值是 run 2 的 **`+0.0341`**。过程教训：杀死该推论的证据（§24 H-3 的表）**早已在计划里**，我把「某样本失败了且被判恶意」读成了「它因为失败而被判恶意」——**共现不是因果**，这是同一形状错误的第三次。**§31 F（预测被证伪）**：第二次击杀（`dd-0003`）落盘后**产物里没有任何 500**（全库仍为 1）、`uncertain=0` ⇒ §25 D 的「`oom_kill` ↔ 500 一一对应」**撤回并收窄**。收窄后的规则由 GIN 日志实测支撑：击杀**仅当一次请求正处于解码中**才留下 500（ollama 替死掉的 runner 代答 500）；**尚未解码**的请求被透明吸收——击杀瞬间（≈06:00:36）到达的那次调用 06:00:57 以 **200** 返回、耗时 20.91 s（≈7 s 装载 + 14 s 解码）。故 `oom_kill` 是击杀致失败的**上界**、产物**低估** OOM 事件数，判别式是「是否已在解码」而非「是否落在两次调用之间」；报告仍须并列两个计数，但理由反转为「它们**不**等」。**§32**：`dd-0007` 的失败是**轮次间非确定性**而非引擎属性——`regex-run1` 与 `regex-run3` 的 finding 对象**除 `llm_*` 三个输出字段外逐字段相同**（`run1 ≡ run2` 则全字段相同），同一 prompt、同一 `seed=42`，第 3 轮却生成另一段文本并把代码原文 `os.system("python wz.py")` 的**未转义引号**写进 JSON ⇒ 解析失败。故 `无法解析模型输出` 至少含两种成因（截断、**内容触发**）。该非确定性**分臂传播不同**：regex 三轮判恶意集合逐位相同（66/66/66，两种结果在 `assist` 下都阻断故不传播），semgrep 两轮差一项 **`dd-0029`**（run1 两次解析失败⇒抬升⇒TP，run2 解析成功⇒FN，`tp 55→54`）⇒ **已实测传播到判据 recall 侧**，并把 §29 C 的拒绝加强为机制性。另实测 `assist` 的 `predicted_label` 由 **`risk_level`** 驱动（`audit_benchmark_eval.py:860-866`，UNCERTAIN/HIGH 即阻断）⇒ 产物**头条 `verdict` 与 `predicted_label` 可以不一致**，按 verdict 统计会得到错误混淆矩阵。**§33（pair 读数点名，取代「+0.0065 边缘失败」读法）**：两个完整配对下 **regex 的判恶意集合是 semgrep 的严格子集**（良性侧与恶意侧**都**是，`regex-only = ∅` 四次）；ΔFPR 的 FAIL **由唯一一个良性样本 `sr-0155` 承担且两轮稳定**——regex 在它上面 `total_findings=0`（`llm_state=static_only`，**未调 LLM**）、semgrep `total_findings=2` 且 `llm_state=ok`（LLM 成功仲裁为恶意）、两侧 `fail_closed=False` ⇒ **不含失败、不含非确定性、不含 fail-closed 的纯检测能力差**；Δrecall 的 +6/+5 里只有 `dd-0029` 漂移。故结构是 **semgrep = regex + 额外标记**（恶意侧 +5/+6 TP 换良性侧 1 FP），**0 容差下严格超集不可能在 FPR 侧非劣**，pair 1/2 的 `未通过` **不是边缘噪声判决**。**§34（并更正我在 §32 E 刚写错的一处数字与方向）**：失败逐轮按样本对齐后，**大部分失败是样本内禀且可复现的**——`dd-0020` **6/6 全失败**、`dd-0019` **只在 regex 侧失败 ×3**、`dd-0018` **只在 semgrep 侧失败 ×3**（后者可解释：两臂对同一规则同一行的 finding 对象本就不同 ⇒ prompt 不同 ⇒ 解析结果不同，故失败在很大程度上是 **(样本 × 引擎)** 对的确定性函数）；非确定性（§32 B/D）只属**边缘样本的边界漂移**（`dd-0007`、`dd-0029`），报告须把失败拆成**内禀**与**边缘**两层。并**撤回 §32 E** 那句「两臂失败数之差（11 vs 3）至少部分落在 semgrep 侧」——**数字与方向都错**（我把 `regex-run1` 的失败**发现数** 11 与 `regex-run3` 的失败**样本数** 3 混为一谈）；实测失败负载**在 regex 侧更重**（样本 8/5/3 vs 6/5/2，发现 11/5/2 vs 7/6/?，benign 侧 2/1/0 vs 0/0/0），**不存在「semgrep 侧失败偏多」**。仍成立三条：FPR 侧失败完全不参与（§30、§33 B）；recall 侧失败抬高 semgrep 是**单样本**机制（`dd-0029`）而非总体偏向；benign 侧失败全在 regex 侧抬高其**绝对** FPR，但那些样本 semgrep 也标记（§17.12 D-2），故 **`ΔFPR` 不受影响**。另：监视器读数 **29** 与逐轮合计 **29** 逐位吻合，是 §23 信号口径在六轮上的独立自校验；**`HTTP Error 500` 全库仍仅 `dd-0055@semgrep-run2` 一处**。

---

## 1. 这一步要解决什么

主基准（`audit-100`）**是拟合集**：规则对齐以它为参照做的（证据 spec §9.9、本规范 §9.1）。因此它的「Δ=0」只支持「在规则对齐所依据的语料上无退化」，**不支持「可在未见过的新代码上替换」**。且同一份数据在 `assist`（生产默认）下给出**相反**结论（ΔFPR 0 → +0.04，本规范 §3.2.2）。

阶段 H 补两件事：**未见构造** + **生产默认策略下的判定**。**通过之前默认引擎保持 `regex`**（本规范 §9 开头）。

## 2. 判定口径（不可协商，来自 §9.2 要求 5/6/7）

| 项 | 取值 |
|---|---|
| 判据 | `ΔFPR ≤ 0` **且** `Δrecall ≥ 0`，**逐对成立** |
| 容差 | **0** |
| 配对 | 3 轮配对（第 *i* 次 regex ↔ 第 *i* 次 semgrep） |
| 主判定策略 | **`assist`**（生产默认，`--policy assist`） |
| 并列报告 | **同时**给出 `gate` 下的数值 |
| 两臂 | 同测 |

> 只报 `gate` 下的通过**不算通过**（§9.4）。这条收紧是从主基准实测里学到的。

## 3. 样本单元：单个 `.py` 文件（附实测理由）

**决定**：Δ 指标用的样本单元 = **一个 `.py` 文件**，不是整个包目录。

**理由（实测，非推测）**：命中密度在真实代码上远高于合成样本（实测 `requests-2.31.0`：`socket` 58 处、`os.environ` 17 处、`import … as` 25 处），而两侧都有「按条数截断」的上限：

- 生产 Go 静态侧 `MaxFindings = 200`（`internal/codeaudit/scanner.go:23`），触顶 → `Truncated = true`（`:97-101`）→ `ProvesCleanScan()` 为假（`internal/codeaudit/rules.go:124`）→ fail-closed。
- 评测侧 `--max-findings` 默认 **50**（`models/audit/tools/audit_benchmark_eval.py:1492`），且只对 `findings[:max_findings]` 调 LLM（`:875`）——**超出的 high/medium finding 永不被开脱 → 直接阻断**（`models/examples/code_security_analyzer.py:863-866`）。

两者都是**按条数而非语义**阻断，而 semgrep「每条匹配都报、regex 每行只报首条」（本规范 §7.4）→ 两臂的截断幅度**不对称** → 整包样本测出来的是截断差异，不是引擎差异。

**因此**：单文件承担 Δ 指标；**大目录/大文件另做 scale 子测量**（§8 的 H2.5）。两条路径用途不得混同。

## 4. 两个臂的来源（你于 2026-09-23 选定：真实第三方源码 + 公开标注语料）

### 4.1 良性臂 = 真实第三方 sdist，**未改一字**

- 来源：真实发布的包（`pip download --no-deps --no-binary :all:`），固定版本号。
- 作者 = 上游社区 → **要求 1 完全满足**：构造与标注都不由我们出。
- 标注：`label=benign`、`expected_final=BENIGN`、`primary_attack_finding=null`。**不做「会不会被报」的判断**——那正是 FPR 要测的量。
- 预登记选取规则见 §12。

### 4.2 恶意臂与近失良性臂 = 三个公开来源（普查已实测）

**已定组合（2026-09-23 你选定）**：semgrep-rules（主力，正例 + `# ok:` 近失负例）+ CodeQL（MIT，显式近失负例）+ DataDog（真实恶意包，补 `PER_001` 等）。

| 来源 | 许可 | 用途 | 关键限制 |
|---|---|---|---|
| `semgrep/semgrep-rules` | Semgrep Rules License v1.0（**仅内部业务使用，禁止再分发/作为服务**） | 恶意正例（1387 条 `# ruleid:`）+ 近失良性（930 条 `# ok:`） | **纯 `# ok:` 文件 = 0**（316/368 是混合）→ **必须窗口抽取** |
| `github/codeql` | **MIT** | 显式近失负例（实测 30 处标记、15 个文件，其中**仅 5 个为纯否定**；更正见 §15） | **纯否定文件 5 个**（原记的「27」是标记出现次数，「14/15 个文件」又把正负混合文件算了进去），单源远不足 50，只作补充与交叉验证 |
| `DataDog/malicious-software-packages-dataset` | **Apache-2.0** | 真实恶意包，补 `PER_001`/`EXF_001`（semgrep-rules 里 `PER_001` 仅 1 文件） | **真实恶意软件**（口令 `infected` 加密 zip）；**无逐行标签、无良性样本** |

**处理真实恶意样本的安全约束（写进构建脚本，不可绕过）**：

1. **只解包与扫描，绝不执行**：不得 `pip install`、不得 `import`、不得运行包内任何脚本（含 setup.py 的 install/develop 钩子——实测样本正是靠它持久化）。
2. 解包落点仅限 gitignored 的语料目录，不进入任何被跟踪路径。
3. 构建脚本不得调用 `py_compile`/`compileall`（评测侧既有测试会做，留出集**不走那条路径**）。
4. 报告中只引用**行为类别与文件路径哈希**，不粘贴恶意代码全文。

**窗口抽取（预登记口径，**冻结**）**：`# ruleid:` / `# ok:` 的语义是**逐行** ground truth——标注写在它所标注的那一行的**上一行**（出处：semgrep 官方测试文档）。窗口 =「**包含被标注语句的最内层 `def`/`class` 体**」；窗口**并含标注行本身**（标注落在 `def`/`class` 之上的情形，窗口起点上移一行）——片段即样本，标注是它 ground truth 的唯一记录，不含标注的片段下游无从审计。落在**模块层**的标注**丢弃并计数**。抽取是**机械的**（只按标注行与行号定位，不看我方规则、不看判定结果）。

**实测（2026-09-23；口径如上，代码 = `models/audit/tools/holdout_corpus.py`，`tests/test_holdout_corpus.py` 23 项全绿）**：368 个文件、**2317 条标注行**（`ruleid` 1387 / `ok` 930，与上表吻合）→ **1167 个窗口**（`ruleid` 697 / `ok` 470）；模块层丢弃 **758** 条标注、混合窗口（同窗口内两种标注并存）丢弃 **51** 个、4 个文件不可解析；去缩进后不可解析的片段仅 **1** 个（无映射族）。**映射到我们 13 族的窗口 156 个**：

| 族 | 恶意（`ruleid`） | 近失（`ok`） |
|---|---|---|
| `CMD_001` | 43 | 15 |
| `NET_001` | 45 | 45 |
| `NET_002` | 0 | 0 |
| `DYN_001` | 3 | 0 |
| `OBF_001` | 4 | 1 |
| **合计** | **95** | **61** |

即：**两侧都已超过要求 4 的 50 条门槛**，semgrep-rules 一源即可支撑恶意臂与近失臂，DataDog / CodeQL / PyPI 起补强与覆盖扩展作用。`NET_002`、`FIL_001`、`ENV_001`、`EXF_001`、`PER_001`、`EMB_001`–`EMB_004` 在上游 Python 语料中**无窗口映射**，按 §12.2 规则 5 以「证据不足」上报，**不降门槛**。

「窗口并含标注行」这一处收窄的实测影响：1535 条落入 `def`/`class` 的标注里只有 **104 条**（6.8%）窗口因此上移，其中 12 条属映射族（全为 `NET_001`）。

### 4.3 标注 → 我们规则 ID 的翻译（机械、可审计）

映射轴用现成字段：13 条 semgrep 规则都带 `metadata.category`（实测：execution / network / dynamic / credential / payload / persistence / embedded）。

| 我们的族 | category | 严重度（semgrep / Go） |
|---|---|---|
| `CMD_001` | execution | ERROR / HIGH |
| `NET_001` `NET_002` | network | ERROR / HIGH |
| `DYN_001` | dynamic | WARNING / MEDIUM |
| `FIL_001` `ENV_001` | credential | WARNING / MEDIUM |
| `OBF_001` | payload | ERROR / HIGH |
| `EXF_001` | credential | ERROR / HIGH |
| `PER_001` | persistence | ERROR / HIGH |
| `EMB_001`–`EMB_004` | embedded | ERROR/WARNING / HIGH/MEDIUM |

**严重度一律取「生产 Go」列**（镜像集）：目标态 §5 的严重度列无证据支撑，且改严重度会使已取得的证据立即失效（§7.3）。映射表条目在回填项 A 后写定，**写定即冻结**。

## 5. §9.2 十条要求 → 动作

| # | 要求 | 动作 |
|---|---|---|
| 1 | 独立来源 | 良性取 sdist 原样；恶意取公开标注语料。**不使用 `FAMILY_SPECS`/`PROJECT_ALLOCATION`**（定义在 `audit_benchmark_eval.py:76,103`） |
| 2 | 对抗构造优先 | 良性臂含真实别名/`getattr`/`importlib`；恶意臂取上游正/负例对。**我们不手工构造** |
| 3 | 标注口径与 `audit-100` 一致 | 复用同一 `sample.json` 字段。**注意实测**：真正被消费的只有 `primary_attack_finding`（算 `attribution_precision`），`findings_manifest`/`variant_file`/`expected_severity` 评测侧**一概不读**（`audit_benchmark_eval.py:514-567`、`:1040`） |
| 4 | 良性/恶意各 ≥50 | 见回填项 A；不足按 A 的退路处理，**不得降门槛** |
| 5 | 0 容差逐对 | §2 |
| 6 | 两臂同测、3 轮配对 | §2；见 §9 运行协议 |
| 7 | **`assist` 下判定** | §2 |
| 8 | **两臂 Prompt 逐样本等价性** | **今日无任何工具**，且已存在**活的不等价**（见 §6.5）。须先建捕获与比对工具，再判定 |
| 9 | **先证「regex 臂 == 生产 Go 引擎」** | **已参数化（`0bb357c`）**：`TAA_PARITY_CORPUS_ROOT` / `TAA_PARITY_RESULTS_DIR` 可选，默认值不变（100/100 一致、证据 JSON 的 sha256 前后完全相同）；两级 glob 换为可识别 `<root>/<id>/` 与 `<root>/<project>/<id>/` 两种布局的遍历；报告改写在其结果目录旁（默认解析回原路径），留出集运行不再覆盖主基准证据。留出集上**零分歧**方可判定。**调用命令见 §6.7**——`-run Parity` 匹配不到任何测试（静默 PASS），必须用全名 |
| 10 | 适配器判据在容器内复现 | **已由阶段 G 关闭**（§10.1 G-1） |

## 6. H0 —— 评测工装的前置修复（侦察已证，必须先做）

**为什么必须先做**：评测管线（`models/audit/tools/audit_benchmark_eval.py`）**是为合成语料写死的**，直接拿真实语料跑，测出来的是工装的偏差而不是引擎差异。以下五条，每条都带实测出处。

### 6.1 语料清单是**代码**，不是数据 → 新语料无法接入

`BASE_PROJECTS` 是字面量（`:51-56`），`sample_id`/`relative_path` 是合成出来的（`:244-245`：`f"{spec.family}-{index:02d}"`、`f"{base_project}/{sample_id}"`），`label` 也只来自 `FAMILY_SPECS`（`:253`）；样本 ID 与路径在运行时按 `<root>/<base_project>/<sample_id>/` 解析（`:1516`）。**没有任何 CLI 或环境变量能提供样本清单**（参数表 `:1472-1495`）。落盘的 manifest 文件**不被任何评测路径读回**。

**修复**：给评测增加一个**语料清单输入通道**（清单含 `sample_id` / `base_project` / `label` / 相对路径），留出集**不经过** `FAMILY_SPECS`/`PROJECT_ALLOCATION`。这属**评测资产改动**：须对**两臂同时施加**、单独提交、并在报告里登记（纪律见证据 spec §12.4）。

### 6.2 按条数截断 → 真实代码上的**结构性 FPR 膨胀**，且两臂不对称

`--max-findings` 默认 50（`:1492`），超出的 finding 不被开脱即阻断（`code_security_analyzer.py:863-866`）。真实第三方代码命中密度高（§3），且 semgrep 每行多条而 regex 每行只报首条（本规范 §7.4）→ 截断幅度两臂不同。

**修复选项（须预先登记、两臂同施）**：
- (a) 判定用的上限**对齐生产语义**（Go：静态 200 / LLM 20），或
- (b) 送 LLM 前按 `(rule_id, line)` 去重后再截断（使两臂的「条数」口径可比），或
- (c) 提高上限并在报告里同时给出「被截断样本数」。

三者都不改变判定口径，只改变仪器的分辨率。

**【已定，2026-09-23】(b) 送 LLM 前按 `(rule_id, line)` 去重后再截断**：regex 臂每行只报首条、semgrep 每行多条（本规范 §7.4），去重后两臂的「条数」口径才可比，截断不再单方面惩罚 semgrep；改动小、不动生产语义、**两臂同施**。上限保留 50。
> 该改动属评测资产改动：单独提交、写进报告、两臂同施（纪律见证据 spec §12.4）。

### 6.3 「整棵树任意一处 parse error」即判样本不可评 → 真实语料极易整轮作废

`scan_complete = (exit_code in (0, 1)) and parser_errors == 0`（`models/audit/tools/semgrep_runner.py:122`）。真实包常带 Python 2 文件、语法错误的 fixture、模板文件 → 一旦命中，该样本不可评（`:126`）→ 从指标里被丢弃（`audit_benchmark_eval.py:1012-1027`）→ `round_complete=False`（`:1298`）→ **配对作废、判定为「证据不足」**（`models/audit/tools/engine_compare_report.py:172-181,642-645`）。

**修复选项**：(a) 保留该语义，但**建集时按预登记规则排除不可解析文件**（用 semgrep 自身的 `errors` 归因，机械、不看判定结果）；(b) 改为 per-file 归因。

**【已定，2026-09-23】(a)**：保留「整棵树解析干净才算可评」的语义（它本身就是生产 fail-closed 的镜像），在建集阶段排除不可解析文件。**另需登记的口径差**：评测侧 per-sample 超时 120 s（`semgrep_runner.py:178`，调用处未覆盖），生产是 300 s（本规范 §12.2 Q5）。

### 6.4 两臂失败语义**不对称**：regex 臂永远「完整」，semgrep 臂可被判不完整

`RegexScannerAdapter` 无条件返回 `scan_complete=True`（`audit_benchmark_eval.py:349`），而 semgrep 臂可因 parse error / 超时 / 二进制缺失被判不完整（`semgrep_runner.py:122,182,215,225,232`）。在 0 容差判定下，这只表现为**单侧**「证据不足」——即**只有 semgrep 会被作废**，regex 不会。

**修复**：要么让 regex 臂也判完整性，要么在报告里把这条不对称**显式登记**为已知的判定偏差。**不接受「不说」**。

**【已定，2026-09-23】显式登记，不改语义**：让 regex 臂也判完整性会与历史 6 轮矩阵的可比性断裂，而该不对称在留出集上只会让 semgrep 侧**更保守**（更容易判证据不足，而不是更容易通过），方向安全。报告须单列一节写明：`round_complete=False` 只可能由 semgrep 侧触发。

### 6.5 Prompt 等价性：**今日无工具**，且**已存在活的不等价**

- 现无任何工具比对两臂送给 LLM 的 Prompt 内容（唯一近亲 `tests/test_engine_rule_parity_corpus.py` 只比 `(rule_id, line)` 集合）。
- 且不等价**已经发生**：Python regex 适配器只设 `context_before`/`context_after`，semgrep 适配器**总是**设 `ast_enclosing_block`、**有时**设 `cpg_evidence`（`audit_benchmark_eval.py:369-378,395,437`），而 `analyze_finding` **恰恰按这些字段分支**（`code_security_analyzer.py:533-546`）→ **同一规则同一行，两臂送出不同文本**；semgrep 臂还额外注入合成的 CPG finding（`:453-472`），regex 臂从不产生。

这正是 §9.2 要求 8 要防的东西，也正是主基准里 `B3-04`/`B3-09` 的成因。**要求 8 不是走过场**：先建捕获与逐样本比对工具，判定时逐条归因。

### 6.6 H0 出口

语料清单通道可用、截断口径选定并冻结、可解析性预登记规则定稿、不对称登记、Prompt 捕获工具就绪；以上各自带测试（评测侧已有 `tests/test_benchmark_samples_matrix.py`、`tests/test_engine_rule_parity_corpus.py` 可挂），单独提交，**不与留出集数据混在一次提交里**。

### 6.7 H0 出口状态（五条全部落地）

| 条 | 交付 | 提交 |
|---|---|---|
| 6.1 语料清单通道 | `--corpus-list`（JSON：`sample_id`/`base_project`/`family`/`label`/`relative_path`），替换 `FAMILY_SPECS` 展开而非叠加；拒绝未知 `label`（非 `malicious` 一律按良性计分）与重复 `sample_id`（配对按它建索引，重复即静默塌缩一对）；summary 的 `run_id`/`benchmark_version` 随语料走，不再自称 `audit-100` | `b35f76e` |
| 6.2 截断口径 | `dedupe_findings_for_llm()`：送 LLM 前按 `(file, rule_id, line)` 去重再截断，两级 prompt 同视图；报告仍拿全量 findings（条数不说谎） | `9edfda5` |
| 6.3 可解析性 | 预登记规则已定稿（§12.2 规则 4），落地在建集脚本（H1） | — |
| 6.4 两臂不对称 | 已在 §6.4 登记为已知判定偏差，报告须单列一节 | — |
| 6.5 Prompt 捕获 | `models/audit/tools/prompt_equivalence.py`：捕获（自带 `backend="none"` 分析器，**不会调用 LLM**）+ 逐样本比对，区分「命中集不同」（即引擎差，非违规）与「同一命中不同 prompt」（confound，违规并指名差异字段） | `9cd8697` |

配套：生产分析器开出 `build_finding_prompt` / `build_file_prompt` 接缝（行为保持，`6d16ee5`），使「被发送的 prompt」可被观测而无需复制一份构造逻辑。

**留出集上的调用命令（要求 9）**：

```bash
python3 models/audit/tools/audit_benchmark_eval.py \
  --benchmark-root <CORPUS_ROOT> --corpus-list <CORPUS_LIST.json> \
  --manifest-out <SCRATCH>/manifest.json --results-dir <RESULTS_DIR> \
  --engine regex --llm-backend none
TAA_CORPUS_PARITY=1 TAA_PARITY_CORPUS_ROOT=<CORPUS_ROOT> \
  TAA_PARITY_RESULTS_DIR=<RESULTS_DIR> \
  go test ./internal/codeaudit/ -v -run TestGoEngineMatchesBenchmarkRegexArm
```

> `-run Parity` **匹配不到任何测试**（Go 打印 `[no tests to run]` 并以 0 退出，看起来像通过却什么都没验证）。测试函数名是 `TestGoEngineMatchesBenchmarkRegexArm`，不得简写；改名会改动证据 JSON 的 `source` 字段，故不改名，只登记命令。
> 非 audit-100 布局**必须**给 `--corpus-list`：只给 `--benchmark-root` 时 harness 仍按 `FAMILY_SPECS` 合成样本并硬编码 `relative_path`，单层语料会生成错 `sample_id` 的工件。

### 6.8 H0 期间新发现的两处收窄（H1 必须处理，写进报告）

1. **两侧「跳过目录」集合不同**：Go 的 `DefaultConfig().SkipDirs` 含 `node_modules`/`venv`/`.venv`/`.idea`/`.vscode`/`.git`/`__pycache__`，而 Python 的 `discover_sample_py_files` **只排除点目录与 `__pycache__`**。含 `.py` 的 `venv/` 或 `node_modules/` 会让两侧读到的文件集合不同 → `files_scanned` 不匹配 → 看起来像引擎分歧。**对单文件样本（§3 的样本单元）不触发**；对 H2.5 的整目录 scale 子测量需注意。
2. **静态条数上限是单边的**：Go 静态侧 `MaxFindings = 200` 会**截断扫描**（`scanner.go:97-98,295-296`，并置 `Truncated`），而 Python 正则臂**完全无上限**（`RegexScannerAdapter`/`StaticScanner` 均不截断；`--max-findings` 只管送 LLM 的那部分）。任一留出集样本的静态命中数 ≥200，parity 就会出现 `only_in_python` 分歧，**成因与规则漂移无关**。§3 已实测真实第三方代码命中密度高，故这是 H1.4 的**必查项**（见 §12.2 规则 6）。

## 7. 阶段拆分（H1 建集与前置证明 → H2 判定运行）

### H1 —— 建集与前置证明（**不产生任何判定结论**）

1. **H1.1 取数**：按预登记规则取得两臂样本；记录每个样本的**出处、版本、URL、sha256**，落 `provenance.json`。
2. **H1.2 建集**：生成 `models/audit/benchmarks/audit-holdout/`，每样本一目录，含 `<sample>.py` + `sample.json`。
3. **H1.3 等价性证明（要求 9）**：regex 臂 vs 生产 Go 引擎，逐样本 `(rule_id, severity, line)` 比对，**零分歧**；有分歧先修，判定不得开始。
4. **H1.4 可判定性自检**：逐样本确认 `scan_complete=true`（含 6.3 的预登记排除规则已生效）、`errors` 为空；触顶则按预登记规则处理并写明，**不得静默删样本**。

**出口**：语料 + 出处清单 + 等价性证明 + 可判定性自检，四件齐备并提交。

### H2 —— 判定运行（协议先定死，再开跑）

1. **H2.1 主判定**：`assist` 下 3 轮配对（3×regex + 3×semgrep），**无载**（你于 2026-09-24 裁定；受载条件下判据自己的 LLM 仲裁失效，理由与读数见 **§17.11**）。驱动 `models/audit/tools/h2_loaded_rounds.sh` 以 `LOAD=0` 运行；该驱动的两种模式已在脚本头写明，且**在量测前先 warm 模型**（冷启会额外付约 29 s 载入，把首个样本顶到 60 s 线上，那是仪器假象而非引擎差异）。
2. **H2.2 并列报告**：`gate` 下同规模**不重跑**——由 H2.1 产物**精确重打分**导出（2026-09-24 你裁定「gate 能免跑就免跑」）。依据：`static-llm` 路径上 `gate`/`assist` 出自同一个 `compute_conclusion(stats, file_summaries, policy)`，两者**只差 policy 一个字符串**（`code_security_analyzer.py:898-899`），而该函数的全部输入都能从 `audit_report.json` 还原（`statistics` 七项逐字落盘、键集相同；`file_summaries` 的 `chained`/`exfiltration`/`risk_level` 来自 `file_reports[]` 的 `chained`/`has_exfiltration_pattern`/`risk_level`）。工具：`models/audit/tools/gate_rescore.py`，其 `--validate` 必须在**真实产物上逐样本复现 `assist`** 之后才允许导出 `gate`。**三处必须照此写报告**：(a) 重打分**调用**生产 `compute_conclusion` 而非转写其分支，否则「精确」就变成关于转写的断言而非关于生产代码的事实；(b) `llm_enabled == False` 时 `file_reports[].risk_level` 来自 `infer_risk_level()`（`code_security_analyzer.py:971-974`，即「仅静态扫描，未进行语义分析」的占位级），**不得**喂进 chain 判定，否则把未做语义分析的高危误判成 `CRITICAL`；(c) 精确性依赖「`generate_audit_report` 从不把 `scan_complete`/`parser_errors`/`timed_out` 写进 `stats`」这一**隐含不变式**，重打分须**断言并拒跑**（`compute_conclusion` 以 `.get(default)` 读三者，故此路径的 fail-closed 分支恒不触发），而该不变式一旦被破坏，偏离方向是**放宽门禁**（默认 `True`/`0`/`False`）。附注：重打分**不是**在复读 `assist` 的标签——无 LLM 时单个 MEDIUM finding 即 assist 过、gate 不过（合成样本已证分支是活的）；而 `static-llm` 的 gate **不**因 `llm_unavailable`/`parse_error` fail-close（`compute_conclusion` 里没有 `llm_state`，只有 pure-llm 分支读它，`audit_benchmark_eval.py:841`）。
3. **H2.3 Prompt 等价性逐样本比对**（要求 8）：逐条归因差异。**前置条件（2026-09-24 实测）：必须排在 H2.1 之后串行跑**——`prompt_equivalence.py` 已证**从不调用 LLM**（capture 用 `backend="none"`，唯一 HTTP 出口 `_call_ollama`（`code_security_analyzer.py:718-741`）只在 `backend == "ollama"` 分支内，结构性不可达），但它会调 `load_module_scanner(engine=semgrep)`，那是**真实 semgrep 子进程扫描** ⇒ 与 H2.1 并发会叠加 semgrep 负载（`be-host-memory-ceiling`）。
4. **H2.4 并发受载条件**（§9.3 第 1 条）：**改为独立的部署可行性读数，不再承载 §2 判据**（理由见 §17.11）。复用已入库的 `models/audit/tools/semgrep_press_test.sh`（带单实例守卫与 `llama_pid`/RSS 逐样本记录）与 `h2_loaded_rounds.sh` 的 `LOAD=1` 模式。**读数已取得且结论为「共置不可行」**：本机 decode 空载回暖 9.5 tok/s（300 token ≈ 32 s / 60 s 上限），受载跌破 3.3 tok/s ⇒ >90 s ⇒ 判据调用失败 ⇒ `UNCERTAIN`（`assist` 下高/中危发现 fail-closed 阻断，**方向更正见 §17.12 结论先行**）。**该结论不重跑**（一次受载矩阵只会再产出一份不可判定的产物）。**这是两次实测失效的场景，主基准的串行 6 轮矩阵没覆盖它**——且这次实测给出了成因。
5. **H2.5 scale 子测量**（§9.3 第 2 条）：对真实包整目录两臂各扫一次，量时长/内存/`Truncated`/`MaxFindings`，**与单文件 Δ 判定分开报告**。
6. **H2.6 判定**：按 §2 口径，0 容差。

## 8. 出口与不通过的处置

- **通过** → 允许把默认引擎切到 semgrep（本规范 §6.5），进入灰度。
- **不通过** → 回到规则对齐循环（§9.4）；**不得**因「主基准已通过」而放宽，**不得**改判据、改样本、改映射表。改任何一项都要重走 H1 的等价性证明。

## 9. 运行协议与算力

- 逐样本成本 = 静态扫描 + 逐 finding 的 LLM 调用（评测侧上限 `--max-findings`；生产 `LLMConfig.MaxFindings = 20`，`internal/codeaudit/llm.go:45`）。
- Ollama 调用硬超时 60 s 且**无重试**（`code_security_analyzer.py:707`），失败变 `UNCERTAIN`——`gate` 下阻断、`assist` 下只在高/中危时阻断，两策略反应不同（`audit_benchmark_eval.py:717-742`）。H2.4 的并发受载正是要把这条压出来（阶段 G 实测同域并发把延迟抬高约 30 倍）。
- H2 合计 **6 轮全量，全部无载**（H2.1 = 3×regex + 3×semgrep，`assist`），第 *i* 轮配对即第 *i* 次 regex ↔ 第 *i* 次 semgrep；`gate` **不产生运行**，由 H2.2 的重打分导出（§7 H2.2）；受载条件改为**独立的部署可行性读数**（§7 H2.4、§17.11）。**先跑 H2.5 估时**，再决定 H2.1 是否分批（结论：**不分批**，§17.9）。
  - **实测口径与真实工期（2026-09-24 更新；先前两次估时均作废）**：**第 1 轮已跑完，`regex run 1: exit=0 seconds=3562`（59.4 min）**。据此**六轮合计 ≈6 h，收工约 2026-09-24T13:10Z**。样本耗时**非平稳**——语料按目录序排列、发现密度前后不均：前 65 个间隔中 26 个 > 5 s（即需 LLM 仲裁者，均值 ≈70 s、最长 431 s），后段降到 ≈12 s/样本。故**估时须以「已完成轮次」为单位，不得用前段样本外推**：本计划先后给出过 5.6 h（按 10.8 s/样本）与 20 h（按 39.3 s/样本）两个错误数字，前者取前 13 个发现稀疏的样本，后者取一段密集区间，**两者皆作废**。每轮读数记入驱动日志（`echo "$engine run $index: exit=$code seconds=..."`）。
  - 该斜率**不得**用压缩语料或抬高并发去削——被量测的条件就是它本身。**须注意超时缺陷（§17.12）的方向已更正**：失败→`UNCERTAIN`→高/中危发现上 fail-closed→`HIGH`→`assist` 阻断，故它**只抬高 FPR，不吃 recall**（假阴性方向需一条失败的低危发现，本语料**零低危**故不可达）。两臂发现量不同 ⇒ 失败次数不同 ⇒ 偏置**不对称**，且方向确定：**失败多的一臂 FPR 被抬高，于是偏置偏向让失败少的那一臂在 `ΔFPR ≤ 0` 上占便宜**。0 容差判据不能吸收它，故须由反事实**量出**大小；反事实的方向分类（`false_positive_repaired` 与 `false_negative_introduced` 等）**分列不合并**。

### 9.1 H2 前的容器内存重新规划（2026-09-24 实测标定，**开跑前必须落地**）

内存是 H2 的**唯一硬件卡口**（状态行所指）。先前的容器内 OOM 不是一个「偶发」，而是**按构造可达**的：下面先用实测把可达性说清楚，再定参数。**本节只动运行时环境，不动任何冻结项**——提示构造（§11.5/§11.9）、13 条规则、样本与映射表都不在改动范围内。

**实测（容器内 `taa-env-slim-v2`，2026-09-24）**

| 量 | 实测 |
|---|---|
| 宿主内存 | total **9935 MiB**，swap 4095 MiB（空载未用），`available` 7519 MiB |
| 容器限制 | `HostConfig.Memory=0`、`MemorySwap=0`、`CpuQuota=0` ⇒ cgroup `memory.max` = **`max`**，**无上限** |
| 容器 CPU | `nproc` = **16** |
| 容器空载占用 | `memory.current` 1929 MiB（其中大部分是可回收页缓存，**不等于**匿名工作集） |
| ollama 服务端 env | 仅 `OLLAMA_HOST`/`OLLAMA_MODELS`/`OLLAMA_LIBRARY_PATH`；**无** `OLLAMA_KEEP_ALIVE`、`OLLAMA_NUM_PARALLEL`、`OLLAMA_MAX_LOADED_MODELS` |
| 模型常驻 | 冷加载 + 8 token = **7 s**；`llama-server` RSS **2,104,696 kB ≈ 2.0 GiB**；cgroup 增量 2136 MiB；`ollama ps` 报 `SIZE 2.2 GB`、**`CONTEXT 4096`**、`UNTIL 4 minutes from now` |
| 受载语料 | `/root/taa/verify/bench` 400 个 `.py`、9.2 MB；`semgrep 1.177.0` |

**根因（两条，缺一不可）**

> **先读告示（2026-09-24 实测后补）**：下面两条的**形状**成立（`--jobs` 确是真口子、无 cgroup 上限则受害者确由内核挑），但第 1 条的**算术界在单次扫描上远未接近**（实测差约 15 倍），故它**不能**用来解释先前那次 OOM。正确读法与撤回声明见本节末「更正」与 §17.3。

1. **`--max-memory` 是「每文件」上限，不约束「同时在飞的文件数」。** `semgrep_press_test.sh:114` 已钉 `--max-memory 1024`，但脚本**未钉 `--jobs`**，而容器有 16 个 CPU ⇒ 聚合上限 **16 × 1024 MiB = 16 GiB**，**超过宿主全部物理内存**。故 OOM 不是运气差，是参数留出来的口子。
2. **无 cgroup 上限 ⇒ OOM 域是整个宿主，受害者由内核按 oom_score 自由挑选。** 容器里 RSS 最大的进程正是 `llama-server`（≈2.0 GiB），于是「Semgrep 并发把 ollama 打死」是这个配置下的**必然受害者选择**，不是巧合。

**参数集（H2 开跑前逐条落地；1–3 项在启动 `ollama serve` 时生效，故须在**第 1 轮之前**重启一次服务）**

| # | 参数 | 值 | 作用 | 明确不改什么 |
|---|---|---|---|---|
| 1 | `OLLAMA_KEEP_ALIVE` | `-1` | 分析器**不发送** `keep_alive`（`code_security_analyzer.py:726` 的 `options` 只有 `temperature`/`num_predict`/`seed`），故走服务端默认 **5 分钟**；而 311 条样本里带 finding 的是稀疏少数，间隙可远超 5 分钟 ⇒ 模型反复卸载/重载，制造 2 GiB 级的驻留**抖动**与额外延迟 | 不改请求载荷：`options` 不变，提示文本不变 |
| 2 | `OLLAMA_NUM_PARALLEL` | `1` | 评测是**逐条串行**发问，多余槽位零收益，却各自分配一份 4096-token KV cache 与计算图 | 同上 |
| 3 | `OLLAMA_MAX_LOADED_MODELS` | `1` | 只装了一个模型，钉死即从失败面里去掉一个旋钮 | 同上 |
| 4 | semgrep 自身 `--jobs` | `4`（**两处调用点都要加**） | 见下方更正：**不是**内存修复，是**协议钉死 + 消掉唯一无界旋钮** | 钉死的是并发度，规则与 `--max-memory` 不变；`--jobs` 已被证明**不改变 finding 集合**（§17.6），故不改语义 |
| 5 | 容器 `--memory` | **`7g`**（`--memory-swap 7g`，实测定，见 §17.3） | 兜底：把 OOM 域从宿主收进容器，保护**宿主**会话（上次被杀的正是宿主侧） | 不改变容器内可用内存的**量级**，只在越界时改变**谁被杀**；**不保护 `llama-server`**——它与 semgrep 同容器（§17.3 末） |

第 4 项改动的是 H2.4 的**读数仪器**，按 §14 的纪律在此**预先登记**（不静默改）：它是延迟测量的协议参数，必须在 H2 开跑前定死，否则 H2.4 的两次读数不可比。

**更正（2026-09-24 实测后，两处）**

- **第 4 项的原表述写错了旋钮。** `semgrep_press_test.sh` **没有** `--jobs` 参数；它的并发旋钮是 `LEVELS`（`semgrep_press_test.sh:38`，默认 `"0 4 8 12"`，即**同时跑几个 `semgrep scan` 进程**）。真正无界的是**每个 `semgrep scan` 自己的 `--jobs`**：`semgrep_press_test.sh:113-114` 与评测的 `semgrep_runner.py:187-195` **两处都没钉**，而容器有 16 个 CPU ⇒ 每个扫描各自最多 16 个 worker。故第 4 项的正确落点是**这两处调用点各加 `--jobs 4`**。原表述「聚合上限从 16 GiB 压到 4 GiB」也随之作废（真正的聚合是 `level × jobs × max_memory`）。
- **第 1 项根因的算术界「按构造可达」在单次扫描上并未接近。** 实测单扫描在 `--jobs 16` 时匿名峰值仅 **221 MiB**——即每在飞文件约 14 MiB，而非 `--max-memory` 的 1024 MiB。该算术界为真但**空转**（差约 15 倍）。OOM 的真实形状在**并发**里：见 §17.3，press 脚本自己的 level 12 上 semgrep 匿名峰值 **1.72 GiB**（线性于 level，约 150 MiB/扫描），加常驻模型 2.0 GiB = **3.78 GiB**，`MemAvailable` 最低 **3.61 GiB**。**故先前那次容器内 OOM 的成因仍属「未归因」**——本节先前把它归给「16 × 1024 MiB 的界」是**过度自信**，此处撤回该归因，只保留「`--jobs` 是唯一无界旋钮」这一条有实测支撑的结论。

**预算算术（按 §17.3 实测重写）**：最坏实测容器 `current` **5872 MiB**（level 12、含可回收页缓存）、匿名 **3775 MiB**（= 模型常驻 **2.01 GiB** + semgrep burst **1.72 GiB**）；容器上限取 **7168 MiB**，高于最坏 `current` 约 **1.3 GiB**，低于宿主总量 9935 MiB ⇒ 容器先于宿主触限，同时给宿主留约 **2.0 GiB**（宿主非容器占用实测约 780 MiB）。容器空载那 1929 MiB 以可回收页缓存为主，不重复计入。

**顺序**：**先跑 H2.5**（对真实包整目录两臂各扫一次）——**已于 2026-09-24 完成，全部读数见 §17**。它同时产出第 5 项所需的**峰值内存**读数与真实规模的 `Truncated`/`MaxFindings` 行为，据以定容器上限、并据此决定 H2.1/H2.2 是否分批（结论：**不分批**，§17.9）。**H2.5 不出判定结论**，其读数与单文件 Δ 判定分开报告（§7 H2.5、§11.2）。

## 10. 明确不做

- 不在本轮修 `DYN_001`/`FIL_001`/`EXF_001` 的严重度（§7.3）。
- ~~不在本轮收窄 `taa-env-secret-python`（§3.6：真实缺口，两臂同等）。~~ **该条前提已于 2026-09-24 被实测证伪（§16）**：regex 臂在全部 311 个样本上触发 `ENV_001` **0 次**，semgrep 臂 **47 次**——一侧有「敏感词名」约束、另一侧对键名无任何约束，是**两套不同的规则**，不是「两臂同等」的缺口。**是否收窄待裁定**；处置口径见 §8。
- 不把留出集结论外推到「任意真实模型代码」之外（报告措辞照 §2.3）。

## 11. 已知收窄（写进报告，不藏）

1. **评测管线不调用 Go 守护进程**：判定在 Python 侧复现（`code_security_analyzer.py:755-903`），生产 Go 与 regex 臂的等价性由 **Go parity 测试单独证明**（要求 9）。报告的结论边界必须照此写。
2. 单文件样本**不覆盖**整目录扫描的截断路径——由 H2.5 单独测量，两者结论不得互相替代。
3. 外部语料的标注最初是给**上游规则**的，映射表由我们写（属**翻译**，不改上游构造与标注）；与语料一同提交、冻结。
4. 每条样本的出处与 license 记入 `provenance.json`；许可条款在回填项 A 确认后写入。
5. **同一命中、两臂给的 `category` 与 `description` 不同**（H0 期间由捕获工具实测，2026-09-23，此前记录未含此轴）：同一 `CMD_001` 同一行，regex 臂送 `category='命令执行'`、`description='shell 命令执行或危险外部命令 — 可能绕过参数化保护'`，semgrep 臂送 `category='execution'`、`description='Suspicious subprocess execution detected in Python code'`。即两臂**用不同措辞向模型描述同一条规则**，加之 §6.5 的上下文差异，构成要求 8 的违规。**本轮不修**（修它等于改判定输入，会使已有证据失效），H2.3 逐条归因并在报告中写明。
6. 两侧跳过目录集合不同、静态条数上限单边（§6.8）——前者对单文件样本不触发，后者由 §12.2 规则 6 在建集时排除。
7. **DataDog 臂只用 `malicious_intent`**（§12.2 规则 3，2026-09-23 定），且该类别下的包**极小**（zip 中位 10 KB，每包 1–3 个 `.py`，多为 typosquat）——它代表的是「小体积投毒包」，**不能代表真实大型库**的命中密度。大型库方向由 §3 已实测的命中密度事实与 H2.5 scale 子测量承担，两者结论不得互相替代。**补充（2026-09-24）**：该臂另有两处**覆盖限制**必须一并写入报告——(a) 我方抽取的 220 文件上限触发在字典序倒数第二个归档 `aiogram-types-v3/3.1.0`，该归档自身从 610 个 `.py` 被截到 100 个，且**字典序在其后的 29 个归档从未被处理**（`archives_selected: 80`，实际进入汇总 51 个）：这是**我方抽取上限**造成的，不是数据本身的限制，故不得据此推断上游分布；(b) 按 §12.2 规则 3 修订稿剔除逐字节副本后，样本单位是**非副本的 payload 文件**，不代表整包，也不代表「恶意包的平均文件数」。
8. **semgrep-rules 的样本是「标注所在 `def`/`class` 的片段」**（§4.2 冻结口径），不是完整模块：它保留了上游逐行 ground truth，但**丢失了模块层上下文**——`import ... as` 别名、模块级常量、同一文件内其它函数的调用习惯都不在片段里。良性臂（PyPI 整包 sdist 的单文件）仍具完整上下文，故两臂在这条上不对称——报告须写明：该不对称**不是两引擎之差**，而是两个来源的构造之差。
9. **提示体量可被样本无限放大（2026-09-24 实测发现的产品缺陷，本轮不修）**：`finding_prompt_slots` 把 `code_snippet`（来自 `line.strip()`）与 `context_before`/`context_after` 原样拼进提示，**三者都没有字节上限**；上下文窗口只按行数（两侧各 15 行）设限，故一个超长单行能让提示体量无界——实测 `dd-0060` 的 22,608,571 字节单行使**单条 finding** 的提示载荷达 22,608,716 字节（`code_snippet` 仅 43 字节，其余全在 `context_before`）。这是一条**内存/可用性向量**：恶意文件可以撑爆 TEE-LLM 侧内存，而 `_call_ollama` 的 `timeout=60` 只保证超时后降级为 `UNCERTAIN`，**不阻止 ollama 在超时前尝试吃下这 22 MB**。本轮由 §12.2 规则 9 在建集时绕开（剔除 5 条），**生产侧未修**；修复方案（给三个字段加字节上限并加显式截断标记）列为 H 之后的任务，因其会改动冻结的提示构造。报告须写明该缺陷存在且未修。**第二副面孔（2026-09-24 无载矩阵实测，见 §17.12）：即使单行长度正常，行数预算本身的 token 成本也已越过超时**——`extract_finding_centered_context` 的上限是 **400 行**，而 400 行密集 Python ≈ **2800–4000 token** ≈ 本机 **56–80 s prefill**（服务器自报 prefill 42–52 tok/s），恰把 **≈2800 token 的悬崖压在 60 s 上限上**；命中即 `UNCERTAIN`——而高/中危发现上的 `UNCERTAIN` 在 `compute_conclusion`（`code_security_analyzer.py:855-875`）里把 `risk_level` 抬到 `HIGH`，`assist` 下即阻断 ⇒ **失败把样本推向 malicious**。故本条不只是内存/可用性向量，也是一处**假阳性来源**（实测 `pypi-0057`，§17.12 D）；**假阴性方向需要一条失败的低危发现，而本语料零低危，故不可达**。**先前此处写作「`assist` 下读作 benign ⇒ 判据自身的假阴性来源」，是引错了判分层（`audit_benchmark_eval.py:877-878` 属 `pure-llm` 路径），已更正。**
10. **semgrep-rules 臂的样本集中度**：156 条样本只来自 **28 个上游文件**，`NET_001` 一家占 90/156（58%）。**样本数高估了语料多样性**（§12.5），报告须写明。
11. **`attribution_precision` 在无 LLM 的轮次里恒为 0，且这是工装缺陷而非测量结果（2026-09-24 H1.4 实测发现，本轮不修）**：`check_sample_attribution`（`audit_benchmark_eval.py:636`）在 static-llm 模式下对「未被 LLM 复核」的 finding 有一条**按严重度兜底**的判据（`:51-53`，`if not verdict or verdict == "UNCERTAIN"` → `severity in ("HIGH","MEDIUM")` 即算归因成功）。但上一行写的是 `str(finding.get("llm_verdict", "")).upper()`：当键**存在且值为 null**（`--llm-backend none` 下每条 finding 都是这个状态）时，`str(None).upper()` 得到**真值字符串 `"NONE"`**，既不是 `""` 也不是 `"UNCERTAIN"` → 兜底分支**永不可达** → 函数落到末尾 `return False`。手工核对反例：`sr-0005` 满足文档所述全部条件（`label=malicious`、`blocked=True`、目标是 `sample.py` 的 `CMD_001`、该 finding 在该文件内 severity=`HIGH`、`llm_verdict=None`），逐条手工判定均为真，函数仍返回 `False`。故 regex 臂 `attribution_precision = 0.0` **是缺陷产物**：真实可达上限为 **23/66**（95 条带目标规则的恶意样本中 23 条的规则实际命中，其中 66 条被阻断）。**影响范围**：该指标不在 §2 的判定判据（`ΔFPR`/`Δrecall`）内，故**不影响 H2 判定**；但**报告不得把它当测量值引用**，H2 若引用须注明此缺陷。修复是一行（`finding.get("llm_verdict") or ""`），**本轮不修**——H2 的 LLM 会写入真实 `llm_verdict`，届时受影响面收窄到「LLM 未复核且高/中危」的 finding，改工装会让 H1 与 H2 的测量仪器不同，须先登记再动（同 §11.9 的处置）。

12. **两臂在 13 条规则里有 5 条不同，且这不是「引擎之差」而是「规则的差」（2026-09-24 实测，§16）**：`ENV_001` 是**规则不同**（semgrep 侧对键名无约束，regex 侧要求敏感词名）——这是**端口缺陷**，须在对齐循环里处置；`NET_001`/`CMD_001`/`OBF_001` 是**引擎能力**（semgrep 解析 import，故 `from X import y` / `import X as z` 之下仍能命中，regex 的限定名模式不能）——这正是本比较要测的东西，**不得**为对齐而抹掉。另有 2 处方向相反的差异实测**参考臂为错**：`pypi-0080:1591` 的 regex `DYN_001` 命中**文档字符串散文**里的 `eval()`（按 AST 匹配的 semgrep 正确忽略），`sr-0149:3` 的 regex `OBF_001` 因**无锚子串**匹配到 `_pickle.loads`（按上游 `# ruleid: avoid-pickle` 标注它是真阳性，故此处漏的是 semgrep）。报告不得把「两臂命中数之差」一律当作 semgrep 更强或更弱——**须按方向逐条写明**。

## 12. 来源与预登记规则（已定，冻结）

### 12.1 检索配方（普查实测，含观测到的状态与体量）

| 来源 | 取回方式 | 实测 |
|---|---|---|
| `semgrep/semgrep-rules` | `curl -L -o sr.tgz https://codeload.github.com/semgrep/semgrep-rules/tar.gz/refs/heads/develop`（整仓仅 22 MiB 解压，**无需 sparse checkout**） | `HTTP 200`、1,215,769 字节；HEAD `a84ff9cc2453ca91d581380de4b8b3f272f6f4be` |
| `github/codeql` | 只取 `python/ql/test/query-tests/Security/` 下 102 个 `.py`（约 145 KB），走 raw 逐个抓取（**不要 clone 整仓 504 MB**） | 102 个文件全部 `HTTP 200` |
| `DataDog/…-dataset` | 走 **GitHub API**（`raw.githubusercontent.com` 对该仓反复超时，实测 `exit 28`/`HTTP 000`）；只取 `samples/pypi/` 下所需包 zip；**切勿整仓 clone（约 20 GB）** | `samples/pypi/malicious_intent/` tree `HTTP 200`、2502 blob、731 MiB；解包口令 `infected` 已验证可用 |
| 良性 sdist | `pip3 download --no-deps --no-binary :all: -d <dir> <pkg>==<ver>` | 可用（`requests-2.31.0.tar.gz` 110,794 字节 已验证） |

**每个样本都必须记入 `provenance.json`**：来源 URL、commit SHA 或版本号、文件 sha256、上游标注原文（`# ruleid:`/`# ok:`/`# $ Alert` 行）、映射到的我方族。

**H1.1 实测补充的取数通道（2026-09-23，不改变上表任何来源）**：

- DataDog **不必走 API 逐包取**（API 限速 60/h，而 `malicious_intent` 有 2502 个 zip）：`git clone --filter=blob:none --no-checkout --depth 1` 仅 **5.1 MB**，随后对任意 blob 用 `git cat-file blob <sha>` 惰性取数（实测 ~1 s/个），**不受 API 限速**。整仓 clone（20 GB）仍然禁止。
- 良性 sdist 除 `pip3 download`（本机可用，~30–60 s/包）外，亦可用 **PyPI JSON API**（`https://pypi.org/pypi/<pkg>/<ver>/json` → `urls[].packagetype == "sdist"`）直取 `.tar.gz`：同一个被 pin 的工件、**不触发 pip 的构建后端（不执行包内任何脚本）**、且能顺带记录 URL 与 size 供 `provenance.json`。**建集脚本采用后者**；`pip3 download` 保留为交叉校验手段（两者 sha256 应一致）。
- DataDog 恶意包的目录布局为 `<category>/<pkg>/<version>/<zip>`（少数包把 zip 直接放在 `<pkg>/` 下），zip 内为 `<date>-<pkg>-v<ver>/<pkg>-<ver>/…`，并含上游元数据 `package_info-<pkg>-<ver>.json`。
- **DataDog 抽取的覆盖边界（2026-09-24 实测，`malicious-manifest.json`）**：候选 80 个归档中 **51 个**进入汇总；**2 个归档无 `.py`**（`ailzynitro/1.0` 是空 zip、`aiogram-sever-patch/3.3.7` 只有非 `.py` 成员）；**唯一的截断**发生在 `aiogram-types-v3/3.1.0`（610 → 100 个 `.py`），**字典序在其后的 29 个归档从未被处理**——抽取上限是**我方设的**，非上游限制。总量：220 个 `.py`、26 MiB、去重前 181 个不同内容（**39 个冗余副本**，多为同包多版本重复）。**装载器必须 `is_file()` 判定**：实测有 6 个成员是**名为 `*.py` 的目录**，`rglob("*.py")` 会把它们当文件计入。逐字节副本的实测分布见 §12.2 规则 3 修订稿。

### 12.2 预登记选取规则（写定即冻结，不按结果挑样本）

1. **良性臂（PyPI）**：取与本次规则**无关**的第三方工具（semgrep 1.177.0）的直接依赖集合，版本以 G-1 的 `pip-freeze.txt` 为准；排除路径含 `tests/`、`test_`、`fixtures/`、`examples/`、`__init__.py` 的文件；每包按**路径字典序**取前若干 `.py`，每样本一文件。
2. **近失良性臂**：semgrep-rules 的 `# ok:` 窗口（机械抽取，见 §4.2）+ CodeQL 的**纯否定文件**。**2026-09-24 修订（第三次收紧）**：原件写「`result=OK` / `SPURIOUS: Alert` 所在文件」，把「文件含否定标记」当成了「整个文件是负例」。实测 102 个源文件中带否定标记的 15 个里，**10 个是正负混合**（同一文件既有否定标记又有「应当告警」的正类标记，合计 78 处），整文件标良性会让正确检出这些位置被记成误报。故收窄为：**至少 1 个否定行，且每个注解行都是否定行**——实测 **5 个**（`CWE-022-PathInjection/test_chaining.py`、`CWE-078-UnsafeShellCommandConstruction/setup_posix.py`、`CWE-943-NoSqlInjection/{flask_mongoengine_good,flask_pymongo_good,mongoengine_good}.py`）。**标注是行尾注释**（`os.system("ls " + path)  # $ result=OK`），不是整行注释——按「注释起始处锚定」写正则会选出空集（实测 0 个文件），这条已作为实现约束写进模块。
3. **恶意臂**：semgrep-rules 的 `# ruleid:` 窗口 + DataDog **`samples/pypi/malicious_intent/`** 下的恶意包（逐文件为样本，包级标签直接继承）。**2026-09-23 定：`compromised_lib` 排除**——其 28 个 zip 装的是**整库源码**（348 MiB），只有个别文件是后门，包级标签继承会把大量真实良性文件标成恶意，而该类别**无逐文件标签**可用；`malicious_intent` 的包则整包皆恶意，规则 3 的「包级标签直接继承」语义成立。**包内 `__init__.py` 与 `setup.py` 不排除**——规则 1 的排除项不适用于本臂，payload 恰恰常在 `__init__.py` 与 `setup.py` 的 install 钩子里。

**2026-09-24 修订（第二次修订；原件前提被实测证伪）**：上句「`malicious_intent` 的包则整包皆恶意，规则 3 的『包级标签直接继承』语义成立」**已被实测证伪**。把 220 个已抽取文件逐字节与真实 PyPI 发布版比对：**118 个（54%）与真实发布版逐字节相同**，分布在 **13 个包**——99 个等于 `aiogram==3.1.0`（`aiogram-types-v3` 一个包 106 个文件里占 99 个）、19 个等于 `boltons==21.0.0`（散布在 `advpruebitaa`/`advpruebitaa3`/`advpruebitaa4`/`advpruebitaa6`/`advpruebitaa8`/`advpruebitaa9` 各 2 个，`a-b27`/`aeivasta`/`aeodata`/`aeodatav04`/`aes44`/`aietelegram` 各 1 个）；另经候选名核验，`aio3` 的 15 个文件中有 **14 个**落在真实 `scrapper_boilerplate` 参照集内（由 `0.2.8` 一个版本即可全覆盖）。原件同段曾记「19 个等于 `boltons==21.0.0`」，**该归因已作废**，见下条勘误。

**2026-09-24 勘误（同日，参照集扩齐后复核；本条两处数字与全部归因均作废）**：

- **「19 个等于 `boltons==21.0.0`」不存在。** 复核发现 `boltons==21.0.0` 的哈希集内含**空文件的 sha256**（`e3b0c442…b855`），而臂内恰有 **19 个 0 字节文件**，实测分布为 `advpruebitaa*` 六包各 2（12）+ `a-b27`/`aeivasta`/`aeodata`/`aeodatav04`/`aes44`/`aietelegram` 各 1（6）+ `aiogram-types-v3` 1 = **19**。原件那段分布只列了前两项（**18 个**）——一个自称「19 个」的清单自己加不到 19，正是退化匹配的旁证。以本地 `sdist/boltons-21.0.0.tar.gz` 独立复算：该发布版 31 个 `.py` 哈希中确含空摘要，对全集命中 19、对**非空**子集命中 **0**。**boltons 不是 vendoring 来源**，「白捡的参照」一说作废。
- **`118 / 54%` 需改写为 `118（含 19 条退化命中）`，真实副本数为 `113`（51%）。** 118 是对 `aiogram==3.1.0` **含空摘要的全集**的命中数 = 99 非空 + 19 空文件；把空摘要逐出参照集后，实测全参照并集命中 **113**（99 aiogram + 14 `scrapper_boilerplate`），220 − 113 = 107 条残余。**后文的 81 因此不再是终值**，须按 H1.2 实测重出。
- **`aio3` 由「14 个里 6 个」更正为「15 个里 14 个」。** 首次测量只拿了 `sdist/` 里现成的 `scrapper_boilerplate==0.2.13` **单个版本**去比（0.2.13 恰好只覆盖 6 条），而真实的 14 条**由 `0.2.8` 一个版本的哈希集即可全部覆盖**（0.2.12 覆盖 9 条）。**测单个版本会漏**，这正是规则 1 要求取候选**全部** sdist 发布版的实测依据。未命中的 1 条是 `aio3/2022-12-20-aio3.zip/setup.py`（install 钩子所在，符合「副本 + 自写 setup.py」的形态）。
- **附带发现：参照记录里的逐版本 `matched_entries` 是「首次命中归属」，不是集合命中数。** 生成该字段时按「排序分」认领，而空摘要曾给 `0.2.12` 凭空加 +19 分，使其在认领顺序上压过 `0.2.8`（14 条真实命中），报出「0.2.12 命中 9 + 0.2.8 命中 5」——**9 和 5 都对，但它们是归属数，两者相加才是并集**，且 5 会因为归属顺序变化而变成 14。故：**多版本参照一律按并集判定，逐版本数字只能读作归属、不得读作「该版本贡献了几条」**；`provenance.json` 中各参照的命中数由建集时**重算**得出，不采信记录内的声明值（§12.2 参照集证据资格）。

两处更正的全过程见 §15「二」。

**参照集的证据资格（2026-09-24 新增，机械口径）**：除规则 1 的自我验证外，参照集还须过两道资格判据，均在 `load_vendor_reference` 内机械执行：

- **空文件哈希不是证据**：`sha256("")` 不得进入任何参照的比对哈希集。**任何**在 PyPI 上发布了空 `__init__.py` 的项目都会因此「命中」；实测仅此一条就凭空确认了 `file_handler`（2 个发布版）、`folders`（Folders-esolang 解释器）、`rs`（远程服务器管理工具）三个**明显无关**的项目，并使 `boltons` 报出 19 个假命中。实现：从每个参照的哈希集中移除该摘要，**移除后哈希集为空者直接拒绝加载**（该行不携带任何证据，留下只会误导），移除数量与来源写入 `provenance.json`。
- **多版本参照按并集判定**：逐版本的 `matched_entries` 是**首次命中归属**（生成时按排序分认领），不是「该版本贡献了几条」，两者不可混读——空摘要曾给 `0.2.12` 凭空加 19 分而抢在 `0.2.8` 前认领，使同一个并集 14 被报成「9 + 5」。故各参照的命中数一律由**建集时重算**，记录内的声明值只作对照并在不一致时写入 `declared_vs_measured`。
- **自指不构成复制**：候选 `a-b27` 在 PyPI 有发布版，其 sdist 匹配的是**它自己**的 payload 文件。保留这类参照会让「剔除逐字节副本」变成「删除恶意样本」，故一并丢弃，命中条目退回残余。即 **`malicious_intent` 同样普遍采用「复制真实库 + 加后门」**——与我们当初排除 `compromised_lib` 时认定的失效模式**同源**，差别只在体积（`compromised_lib` 装整库，`malicious_intent` 多为小包），**不在语义**。原件的推理错在把「类别名为 `malicious_intent`」当成了「包内每个文件都有恶意意图」；类别标签是**包级**的，而包级标签继承恰恰在这里失效。

**修订后的恶意臂构成（2026-09-24 你裁定，§13 决策 7）**：

（a）**剔除**内容 sha256 落在**已确认参照集**内的文件。参照集必须**自我验证**地建：候选名（`relpath` 的目录分量）→ PyPI 解析 → 取其全部 sdist 的 `.py` 文件哈希 → **只有能匹配到臂内条目的候选才确认为参照，匹配不到的一律丢弃**。如此通用词误命中（`examples`、`setup`、`cookies`、`types` 等确实存在于 PyPI）不会造成任何过度剔除，而「剔掉的必是真实发布版的逐字节副本」这一语义得以保持。参照集、建法与各参照的命中数一并写入 `provenance.json`。
（b）剔除后按**内容 sha256 去重**，保留 `(package, relpath)` 字典序最小者作为代表。
（c）**不设每包上限**：当时参照集下实测为 **81 样本 / 32 包**（该数成立：`boltons` 那 19 个命中即空文件，本就会被规则 8 剔除，故在不在参照集内都不改变结果），最大单包贡献 22/81（27%），**无包被清空**；43 个 `setup.py`、30 个 `__init__.py` 入选（payload 恰在这些位置）。扩入 `scrapper_boilerplate`（`aio3` 14 条）后的最终数**以 H1.2 建集实测为准**，残余集中度写入报告。
（d）**原件其余部分不变**：类别仍只用 `malicious_intent`（`compromised_lib` 仍排除，理由见上），`__init__.py` 与 `setup.py` 仍不排除。
4. **可解析性（H0.3 落地处）**：建集时对每个候选文件跑一次 semgrep，`errors` 非空者**排除并计数**，写入报告；该判定**不看**命中结果。
5. **规模**：良性（含近失）≥50、恶意 ≥50；**不足不降门槛**，按族写明「证据不足」。
6. **静态命中数上限（H0 期间新发现，2026-09-23 追加）**：要求 9 的 parity 在任一留出集样本的静态命中数 ≥200 时会因**单边截断**（Go 截断、Python 不截断，§6.8-2）产生与规则无关的分歧。故 H1.4 时对每个候选样本记录其在**去重前**的静态命中数：`< 200` 者进入语料；`≥ 200` 者**排除并计数**，并在报告中写明（**不得静默丢弃**）。与规则 4 同理：该判定**不看**命中结果与判定结论，只看条数。
7. **窗口口径（2026-09-23 曾修订，同日撤回；现状 = 按 §4.2 冻结口径执行）**：曾据「A 口径只映射出 12 个样本」把窗口改为「标注行 ± 2 行」。**该实测有误**：普查脚本用 `^#\s*(ruleid|ok):` 找标注（锚定列 0），而 Python 侧 2317 条标注中有 **1534 条是缩进的**，于是三分之二的语料从未被读入——「12 个样本」是正则造成的假象，不是口径的结论。改用 `^\s*#` 后，**A 口径产出 1167 窗口 / 156 个映射（恶意 95 + 近失 61）**，两侧均超过要求 4 的门槛（§4.2 表）。故**修订撤回，回归冻结口径**；±2 行口径的备选数字（K=2/3/5/8/12）不再作为对照保留，因为其对照前提已不成立。更正全过程见 §14。

8. **退化样本与重复（2026-09-24 追加，机械口径）**：三臂同施两条，**均在去重之前**：
   - **(a) 0 字节文件排除并计数**。0 字节不含任何代码，不可能构成有效样本；与规则 4（不可解析即排除）同类，且对三臂同施、对 Δ 中性。实测：恶意臂 **19** 条（且内容全同，若先去重会塌缩成 1 条，把 19 个「空文件」误报成 18 个「重复内容」）、CodeQL **3** 条。
   - **(b) 按内容 sha256 去重**，三臂同施，保留排序键最小者做代表。实测：恶意臂 39 条重复、良性臂 1 条（89→88）、近失臂 2 条。不剔则会以重复样本重复计入指标。
   **两条都必须逐项计数（零值也报）**，并在报告中写明：它们改变的是两侧**共同的**分母，不影响 Δ 的差分语义，但会改变绝对 FPR/recall 的读数。

9. **超长单行的提示体量上限（2026-09-24 追加，机械口径）**：样本源码中**任一行**超过 **100 KB** 者**排除并计数**，四臂同施。理由是**提示体量可被样本无限放大**：Tier 2 的提示按 finding 拼装，其上下文窗口**按行数（两侧各 15 行）设限而不按字节设限**，故一个巨行会让提示变成任意大——实测 `dd-0060` 的单行 22,608,571 字节使该条 finding 的提示载荷达 **22,608,716 字节**（其中 `code_snippet` 仅 43 字节，22,608,629 字节全在 `context_before` 里）。该样本**静态命中只有 1 条**，故规则 6（≥200 条）拦不住它。与规则 4/6 同形：**判据是文件属性，建集时静态可测，不看命中结果与判定结论**。
   - **实测（剔除前，2026-09-24）**：命中恰好 **5** 条，最大行长分别为 22,608,571 / 624,660 / 613,852 / 198,052 / 188,904 字节（即 `dd-0060`、`dd-0053`、`dd-0022`、`dd-0023`、`dd-0024`，全在恶意臂）；**全语料下一名的最大行长仅 42,869 字节**，即阈值落在 **4.6 倍的空档**里，**不是刀刃上的切分**。
   - **阈值不敏感**：除这 5 条外，全语料单条 finding 的提示载荷**最大仅 1,127 字节**，故任何 ≥4 KB 的上限对其余 **311** 条逐字节无影响。选 100 KB 是取「远大于正常行、又远小于巨行」的中间值。
   - **未采用的备选（登记备查）**：(b) 在 `finding_prompt_slots` 给 `code_snippet`/`context_*` 加字节上限——能保留 5 条样本并**顺带修掉一个真实的产品缺陷**（恶意文件可撑爆 TEE-LLM 的内存，`_call_ollama` 的 `timeout=60` 只保证超时降级为 `UNCERTAIN`，不阻止 ollama 在超时前尝试吃下 22 MB），但会**在度量阶段改动生产提示构造**，故本轮不做，改列为 H 之后的产品修复项（§11 第 9 条）；(c) 照原样全跑——会以每条最多 60 秒超时、且可能把容器 OOM 打死在运行中途的风险，换取 5 条一致降级为 `UNCERTAIN` 的样本。
   - **落地实测（2026-09-24，见 §12.5）**：代码侧为 `MAX_SAMPLE_LINE_BYTES = 100_000` + `sample_max_line` + `drop_long_lines`，**在 `merge_arms` 之后、写盘之前**对合并后的语料施加一次，故任何臂都无法绕过；四臂的丢弃表各增 `long_line` 与 `long_line_max_bytes` 两键（零值也报），`provenance.json` 增 `long_line_exclusion` 段。**边界取 `>` 而非 `>=`**（与规则 6 的 `>=` 相反），因为规则 6 镜像的 Go 判断本身是 `>=`，而这里下游没有任何含端点的判断。剔除后实测 5 条、id 与预估清单**逐一相符**；这 5 条**在原语料上全部是真阳性**，故召回率下降 2.1 个百分点，已计入 §12.5 并登记为决策 9 的代价。

> 规则 6 是 §7 H1.4 已要求的「触顶则按预登记规则处理并写明」的具体化，在任何留出集数据产生**之前**写定。备选口径（**未被采用，登记备查**）：(b) 在 parity 比较中给 Python 臂镜像同一上限——会改动比较语义因而不可比；(c) 仅作收窄声明——会让「零分歧」的覆盖面小于语料本身。

### 12.3 「上游类别 → 我方族」映射表

映射由构建脚本按**上游规则 ID 的词元表**机械生成（例：`system-call`/`subprocess`/`shell` → `CMD_001`；`socket`/`request`/`urllib` → `NET_001`/`NET_002`；`eval`/`exec` → `DYN_001`；`importlib`/`getattr` 动态调用 → `DYN_001`；`file`/`path`/`credential` → `FIL_001`；`env`/`secret`/`hardcoded` → `ENV_001`；`base64`/`marshal`/`pickle`+`exec` → `OBF_001`；`exfil`/`send`/`post` → `EXF_001`；`backdoor`/`persistence`/`cron`/`authorized_keys` → `PER_001`；模型权重/数据外带 → `EMB_*`）。**具体表在 H1 生成、提交、冻结**；未映射到任何族的上游文件**排除并计数**（不静默丢弃）。严重度一律取 §4.3 的「生产 Go」列。

### 12.4 许可处置（你已定：语料不入库）

- **语料本体不提交进 git**：沿用 `audit-100` 先例（`.gitignore:7` 忽略 `models/`，其 400 个 `.py` 无一入库），留出集放 `models/audit/benchmarks/audit-holdout/`（已被忽略）。
- **提交的只有**：构建脚本、`provenance.json`、冻结的映射表、以及重建所需的固定版本清单 —— 任何人可一键重建。
- 这同时满足 Semgrep Rules License v1.0 的「仅内部业务使用、不得再分发、不得作为服务提供」；**改动上游文件时须显著标注已修改**（本次是机械窗口抽取，须在 provenance 里写明）。

## 12.5 H1.2 建集实测（2026-09-24，跑通并落盘）

命令即默认值，无额外参数：`python3 models/audit/tools/holdout_corpus.py`，3.1 秒，退出 0。产物在 `models/audit/benchmarks/audit-holdout/`（gitignored），含 `corpus-list.json`、`provenance.json`、`corpus-report.json` 与四个臂的样本目录。

**建集前的版本检查（fail-closed）**：`sr.tgz` sha256 = `a08f4fb3…6964d`、`tree_digest`（430 个 `.py`）= `d6a87432…ce102`、上游 `develop` HEAD = `a84ff9cc…`，三项全中才继续；**网络检查排在最后**，本地锚点不符时根本不发请求。任一不符即以非零退出，且**语料目录根本不会被创建**。

**语料构成（实测）**：

| 臂 | 样本 | 恶意 | 良性 |
|---|---|---|---|
| semgrep-rules 窗口 | 156 | 95 | 61 |
| datadog-malicious | **67** | 67 | 0 |
| pypi-sdist | 88 | 0 | 88 |
| codeql | 5 | 0 | 5 |
| **合计** | **316** | **162** | **154** |

- **恶意臂 67 的对账**：`220 − 19(空文件) − 113(逐字节副本) − 21(内容重复) = 67`。**§12.2 规则 3（c）里那个 81 到此作废**，实测终值是 67——差在参照集扩齐后多剔除的 14 条 `aio3` 副本。
- 各臂丢弃表逐项计数（零值也报）：恶意臂 `entries=220 empty=19 vendored=113 duplicate_content=21 loaded=67 family_mapped=0 family_unmapped=67`；`pypi-sdist entries=89 duplicate_content=1 loaded=88`；`codeql entries=102 empty=3 loaded=5`，其选取分类 `negative_only=5 positive_only=67 no_marker=17 mixed=10`；semgrep-rules `annotations=2542 dropped_mixed=51 dropped_outside=907 unmapped=1087 unparseable_files=4`。
- 要求 4 门槛**四侧全过**（恶意 162、良性 88、近失 66、良性侧 154）。
- **幂等性实测**：连跑两次，`corpus-list.json` 逐字节相同，`provenance.json` 除 `built_at` 外相同。
- **评测器可读性**：`ev.load_corpus_list` 直接解析 316 条，`sample_id` 无重复，316 个样本目录全部存在且非空，语料总计 26.1 MB。

**规则 9 落地后的读数（2026-09-24 复建实测，终值）**：按超长单行剔除 5 条后为 **311 / 恶意 157 / 良性 154**（恶意臂 67→62），门槛四侧仍过（恶意 157、良性 88、近失 66、良性侧 154）。剔除的 `sample_id` 精确为 `dd-0022, dd-0023, dd-0024, dd-0053, dd-0060`，实测最长行 613,852 / 198,052 / 188,904 / 624,660 / 22,608,571 字节（与规则 9 预登记的命中清单逐一相符）；除这 5 条外全语料最长行 42,869 字节，故任何 ≥4 KB 的界限都留下其余 306 条不变。5 条全部来自恶意臂，故良性侧 154 不变。语料文本体量 **26.1 MB → 1.8 MB**（四臂样本文件合计 1,888,939 字节），降幅几乎全部来自 `dd-0060` 的单行载荷。复建后**幂等性复测通过**：连跑两次，`corpus-list.json` 逐字节相同，`provenance.json` 与 `corpus-report.json` 除 `built_at` 外相同。

- **规则 9 的代价已实测，不是估计**：把这 5 条单独重建为 5 样本语料重跑 regex 臂，**5 条全部被判 `malicious`**（各 1–2 条静态命中）——即规则 9 剔除的是**5 条真阳性**。故 regex 臂的混淆矩阵从 `TP=54 FP=17 TN=137 FN=108`（316 语料）变为 **`TP=49 FP=17 TN=137 FN=108`（311 语料）**：良性侧逐项不变（FPR 恒为 17/154 = 0.1104），**召回率由 54/162 = 33.3% 降到 49/157 = 31.2%**。这不是漂移，是剔除的代价，报告须写明；且**不影响两臂比较**——两臂跑同一语料，非劣判据是成对差，与语料绝对难度无关。
- 各臂丢弃表新增两键（零值也报）：`long_line` 与 `long_line_max_bytes`。实测 semgrep-rules `long_line=0 max=119`、pypi-sdist `0 / 302`、codeql `0 / 90`、datadog-malicious `5 / 22,608,571`。记 `long_line_max_bytes` 是为了让「本臂一条没剔」与「本臂根本没接近界限」可区分。
- `provenance.json` 新增 `long_line_exclusion` 段（`limit_bytes`、写明判据的一句话、`count`、逐条的 `sample_id`/`source`/`max_line_bytes`/`sample_bytes`）；`corpus-report.json` 新增同名段的计数与 id 清单。

**H1.3（要求 9）在 311 语料上通过**：`TAA_CORPUS_PARITY=1` + `TAA_PARITY_CORPUS_ROOT` / `TAA_PARITY_RESULTS_DIR`（**必须绝对路径**——测试的两个默认值相对包目录解析为 `../../`，传相对路径会走 `os.IsNotExist` 分支得到「no samples」并以 fail 退出，这是响亮失败，不是静默跳过）→ **`samples=311 identical rule/severity multiset=311 divergent=0`（其中 0 条仅行号不同）**，用时 1.32 s，证据落 `models/audit/audit-results/holdout/engine-compare/corpus-parity-go-vs-python-regex.json`。**注意事实基线核对**：留出集运行**不覆盖**主基准证据（结果目录与报告路径均由环境变量指向留出集目录）。

**H1.4 可判定性自检（311 语料，实测全清）**：311/311 `scan_complete=true`；`scan_error` 与 `scan_parser_errors` 全空；`incomplete=0`、`fail_closed=0`；`round_complete=true`。规则 6 **在本语料上惰性**：逐样本 `total_findings` 最大值 **7**（`dd-0057`），距 200 的截断线有 28 倍余量（良性侧最大 3）——故这条预登记排除规则**一条都不会触发**，与 §6.8 的「必查项」结论一致。规则 4 已在建集期生效（semgrep-rules 4 个不可解析文件，其窗口无一进入样本）。规则 9 已生效。**另发现工装缺陷一处**（`attribution_precision` 恒为 0，详见 §11.11），不影响 §2 判据。

**§4.2 与 §12.1 的计数口径澄清**：模块走**整个 checkout（430 个 `.py`，2542 条标注）**，而 §12.1 记录的 368 个文件 / 2317 条标注是 **`python/` 子树**的数字。差异全部落在 `ai/` 等**不产出任何样本**的子树：实测 156 条样本**全部来自 `python/`**（28 个源文件）。故两套数字并存不矛盾，**所有决定语料构成的数字完全一致**（窗口映射 156、混合丢弃 51、不可解析 4、恶意 95 / 近失 61）。

**一处该进报告的集中度事实**：semgrep-rules 臂的 **156 条样本只来自 28 个上游文件**，且 `NET_001` 一家占 90/156（58%）。**样本数高估了语料多样性**，报告须写明。

## 13. 决策记录（2026-09-23，你已拍板）

| # | 决策 | 取值 |
|---|---|---|
| 1 | 留出集来源 | **真实第三方源码 + 公开标注语料**；恶意/近失臂取 **三源组合**（semgrep-rules + CodeQL + DataDog） |
| 2 | 语料入库 | **不入库**，只入配方 + 出处 + 冻结映射表 |
| 3 | H0.2 截断口径 | **送 LLM 前按 `(rule_id, line)` 去重**，上限保留 50，两臂同施 |
| 4 | H0.3/H0.4 解析错误与不对称 | **建集时排除不可解析文件**；两臂失败语义不对称**显式登记**，不改语义 |
| 5 | §4.2 窗口口径（H1.1 普查后曾修订） | **已撤回，回归 §4.2 冻结口径**（§12.2 规则 7、§14）：修订所据的「A 口径只映射 12 个样本」出自列 0 正则的假象；改用 `^\s*#` 后 A 口径产出 156 个映射窗口，两侧均过要求 4 门槛 |
| 6 | DataDog 臂构成 | **只用 `malicious_intent`**（§12.2 规则 3）：`compromised_lib` 无逐文件标签、装的是整库源码，包级标签继承会把大量真实良性文件标成恶意 |
| 7 | 恶意臂构成（**第二次修订**，2026-09-24 拍板；同日勘误） | **剔除逐字节等于真实发布版的副本 + 按内容去重，不设每包上限**（§12.2 规则 3 修订稿）：实测 118/220（54%）文件与真实发布版逐字节相同（**99 aiogram + 14 scrapper_boilerplate**），原件「整包皆恶意」的前提被证伪；参照集须**自我验证**（解析得到但匹配不到臂内条目的候选一律丢弃），且过**证据资格**两道判据（空文件哈希不作证据、自指不构成复制，见 §12.2）；命中分布、移除数量与建法写入 `provenance.json`。**勘误**：曾记「19 个等于 `boltons`」经复核为 19 个 0 字节文件，「白捡的参照」一说作废；`118 / 54%` 相应改读为「118（含 19 条退化命中）、真实副本 **113（51%）**」；`81` 不再是终值，按 H1.2 重出 |
| 8 | CodeQL 近失臂取数口径（2026-09-24 拍板，**两次收紧**） | **只取纯否定文件**（§4.2 表、§12.2 规则 2、§15）：原记的「27」是标记出现次数而非文件数（第一次更正 → 14/15 个文件）；进一步实测这 15 个里 **10 个是正负混合**、含 78 处「应当告警」的正类标记，整文件标良性会让正确检出被记成误报（第二次更正 → **5 个**）。近失臂 = semgrep-rules 61 + CodeQL 5 = **66** |
| 9 | 超长单行样本（**规则 9，2026-09-24 拍板**） | **剔除并计数**，界限「任一行 > 100 KB」，四臂同施（§12.2 规则 9、§11.9）：剔除的 5 条 `dd-0022/0023/0024/0053/0060` 实测最长行 613,852 / 198,052 / 188,904 / 624,660 / 22,608,571 字节，与下一条 42,869 字节之间有 4.6 倍空档，故界限不是刀锋；语料 316→**311**、恶意臂 67→**62**。**代价已实测**：这 5 条在原语料上**全部是真阳性**，故 regex 臂 `TP 54→49`、召回率 `33.3%→31.2%`，FPR 不变（§12.5）。**理由**：提示的上下文窗口只按行数设限，超长单行使单条 finding 的提示载荷无界（`dd-0060` 达 22,608,716 字节），是内存/可用性向量而不仅是语料偏斜；**不截断而剔除**，因为截断会改变送给模型的文本，那是提示构造决策、且会让样本与生产实际所送不同 |

## 14. 更正记录：窗口口径修订的撤回（2026-09-23）

**发生了什么**：H1.1 普查后我报告「§4.2 的冻结口径实测只产出 89 个窗口、其中仅 12 个映射到我们 13 族，不足以支撑要求 4」，据此把窗口改为「标注行 ± 2 行」（提交 `93b77a4`），并请你裁定；你据该报告裁定「修订为 ±2 行窗口」。

**该报告为何是错的**：普查脚本用 `re.match(r"^#\s*(ruleid|ok):", line)` 找标注——**锚定第 0 列**。而 Python 侧 2317 条标注里 **783 条在列 0、1534 条是缩进的**（占 66%）。于是三分之二的标注从未被读入，「89 / 12」是**正则的产物**，不是窗口口径的结论。更糟的是这个错误**自洽得看不出来**：用列 0 正则找标注、再用它判断缩进分布，必然得出「无缩进」。

**更正后的实测**（`^\s*#`，AST 两遍一致）：

| 项 | 值 |
|---|---|
| 标注行 | **2317**（`ruleid` 1387 / `ok` 930） |
| 其中列 0 / 缩进 | 783 / 1534 |
| §4.2 冻结口径的窗口 | **1167**（去重后） |
| 映射到 13 族 | **156**（恶意 95 + 近失 61） |
| 模块层丢弃 / 混合丢弃 | 758 条标注 / 51 个窗口 |

**结论**：**§4.2 原本就是可用的**——它当初记录的 `1387` / `930` 与本次实测算出的数字**逐字吻合**，即它从未出错；出错的是我的普查脚本。修订既建立在错误前提上，**予以撤回**：§4.2 恢复冻结文本（仅补「窗口并含标注行」一处收窄及其实测影响 104/1535），§12.2 规则 7 与 §13 决策 5 改写为撤回记录，§11 第 8 条按冻结口径重述。**DataDog 臂构成的裁定（§12.2 规则 3、§13 决策 6）不受影响**：它依据的是 `compromised_lib` 装整库源码、无逐文件标签这一**独立且复核过**的事实。

**教训（写进纪律）**：凡用于**改变预登记规则**的测量，必须先证明测量本身无偏——尤其「先按 X 找样本、再统计 X 的分布」这类自指测量。本次已改为：口径的每一次报数都由 `models/audit/tools/holdout_corpus.py` **本身**（带测试）产出，而不是另写一次性脚本。

**顺带记下的一处陷阱**：`models/audit/holdout-sources/semgrep-rules-develop/` 是 codeload 解包的产物，**无 `.git`**；在该目录里跑 `git log -1` 会向上找到 taa 主仓并报出**主仓**的 HEAD（实测报出 `93b77a4`，正是本仓提交），若照抄即把主仓 SHA 写成上游版本。出处里的 semgrep-rules 版本一律取 §12.1 记录的 `HEAD a84ff9cc2453ca91d581380de4b8b3f272f6f4be`，并在 H1.2 建集时**重新取一次 HEAD 校验**。

## 15. 更正记录：计数与归因（2026-09-24）

**一、CodeQL 近失臂的文件数被连错两次（27 处标记 → 14/15 个文件 → 5 个纯否定文件）。**

- **第一次**：§4.2 表原记「16 `result=OK` + 11 `SPURIOUS: Alert`，负例总量 27」。27 是**标记出现次数**，不是文件数；我据此把近失臂写成「14 个文件」。根因是**采信了 `benign-manifest.json` 的聚合字段 `label_category_occurrences`**（它自报 `near-miss-negative: 16`，与同一文件 `label_occurrences` 列的 29 处**互不自洽**），而**没有自己数**。
- **第二次**（子代理按规则实测）：带否定标记的是 **15 个文件 / 30 行**，差异唯一来源是 `CWE-078-CommandInjection/command_injection.py` 的中缀形式 `# $ Alert SPURIOUS: result=BAD`（两种读法都指向「此处告警是假阳」，故属否定）。但真正的缺陷不在 14 还是 15：**这 15 个里 10 个是正负混合**——同一文件既有否定标记又有「应当告警」的正类标记（合计 **78 处**）。把它整文件标成良性，会让「正确检出这些位置」被记为**误报**。
- **最终口径**（2026-09-24 你裁定，§13 决策 8）：只取**纯否定文件**——至少 1 个否定行、且**每个注解行都是否定行**，实测 **5 个**。近失臂 = semgrep-rules 61 + CodeQL 5 = **66**，仍过要求 4 的 ≥50。

**102 个源文件的完整标记构成**（逐条 sha256 校验后实测）：纯正类 **67**、无标记 **20**、正负混合 **10**、纯否定 **5**。**标注形态**：写在**行尾注释**里（`os.system("ls " + path)  # $ result=OK`），不是整行注释——按「注释起始处锚定」写正则会选出**空集**（实测 0 个文件），这条已作为实现约束写进模块。同一行还可能先在字符串字面量里出现 `$`（Mongo 的 `$eq`/`$expr`），故判据必须锚在 `#` 之后。

**教训**：本条与 §14 同源——**凡进入报告或用于改变预登记规则的计数，必须由带测试的模块自己数出来**。采信第三方聚合字段，等于把口径的解释权交给了别人；而那个聚合字段连自身内部都不自洽。我这次犯的正是 §14 结尾写下的纪律的反面。

**同一失效模式的第三次（2026-09-24，险些进入指令）**：在给实施子代理的修正指令里，我断言「旧顺序下 report 会写 `duplicate_content: 57`」——**57 是我推测的，实测是 39**（改后为 21：18 条从 `dup` 移入 `empty`，19 个 0 字节条目的归属被纠正，220 − 19 − 21 = 180 完全对上）。子代理按实测报数并附了完整对账，这个编造的数字才没进报告。**结论：连「我预期旧代码会报什么数」都必须先测**——预测一旦写进指令，指令本身就成了污染源。

**二、恶意臂的 118 个副本，归因被推翻了两次。** 第一次：只拿 `aiogram==3.1.0` 作参照集，测得「118 个文件与其逐字节相同」，我据此报告「118 个都是 aiogram 副本」。扩充参照集后重测为「99 个 aiogram + 19 个 boltons」——当时我把这当成**白捡的参照**（boltons 恰是良性臂 26 个依赖之一，本就在 `sdist/` 里），并把 19 个的**分布**也一并写进了 §12.2：「散布在 `advpruebitaa`/… 各 2 个，`a-b27`/… 各 1 个」。第二次：参照集扩齐后逐条复核 `boltons==21.0.0` 的哈希集，发现其中含**空文件的 sha256**——那 19 个命中**就是 19 个 0 字节文件**，「各包 1~2 个」正是空 `__init__.py` 的散落形态。**boltons 根本没有被复制。**

两次错的层级不同。第一次错在**参照集不完备时外推来源分布**——我只能断言「落在当前参照集内」，不能断言「就是 aiogram」；这条教训已经写进 §12.2 规则 3 修订稿（要求参照集自我验证、各参照命中数入 `provenance.json`），事后看它是对的。第二次错得更基础：**我报告了一个命中数，却从没问过「命中的是什么字节」。** 一条 `hashlib.sha256(open(path,'rb').read())` 的输出长度就能看出的退化匹配（`e3b0c442…b855` 是空文件的公认摘要），我却在它上面盖了一整段分布叙述。**教训**：记命中数时必须同时记**命中的性质**（非空/空、自指/他指、单一版本/全版本），否则「19 个副本」这种读数会在下游被当成实据。

**同一失效模式的第四次**：第一次是 CodeQL 的「27 处标记」被我当成文件数，第二次是「14/15 个文件」把正负混合文件算了进去，第三次是编造 `duplicate_content: 57`，**第四次就是本条的「19 个 boltons 副本」**——四次都是**把一个未经检验的读数当成结论写进报告或指令**。第四次还多一层：它同时暴露了**测单个版本会漏**——`aio3` 我记「14 个里 6 个」等于 `scrapper_boilerplate`，扩齐后是「**15 个里 14 个**」（0.2.12 命中 9 + 0.2.8 命中 5），因为我只拿了 `sdist/` 里现成的 0.2.13 一个版本去比。故参照集必须取候选的**全部** sdist 发布版，这一条已写进 §12.2 规则 3 修订稿。

**第三次读数更正：118 也不是真实副本数。** 逐出空摘要后实测全参照并集命中 **113**（99 aiogram + 14 `scrapper_boilerplate`），残余 107；118 里有 19 条是退化命中。故「118 个副本 / 54%」应读作「**113 个副本 / 51%**」。这一条此前被 `81` 掩盖着：`81` 是在「参照集 = aiogram 全量 + boltons 退化匹配」下算出的，而那 19 个空文件本就会被规则 8 的退化条剔除——**两个错误互相抵消，所以 81 当时是对的**；参照集一扩齐，它必然变。这正是 §12.2 写下「最终数以 H1.2 建集实测为准」的原因。**错误互相抵消是运气，不是正确性。**

**机制（比数字更要紧）**：该记录里的逐版本 `matched_entries` 是**首次命中归属**，生成时按「排序分」认领。空摘要给 `scrapper_boilerplate==0.2.12` 凭空加了 +19 分，使它抢在 `0.2.8`（14 条真实命中）之前认领，于是同一个并集 14 被报成「0.2.12 命中 9 + 0.2.8 命中 5」。**9 与 5 都是真的，但它们相加才是并集**——把这种字段读成「每个版本各贡献几条」必然出错。故 §12.2 参照集证据资格新增一条：多版本参照一律按并集判定，逐版本数字只能读作归属；`provenance.json` 里的各参照命中数由建集时**重算**，声明值只作对照。

**与 §14 的共性**：本条与 §14 同属「统计口径与结论层级不匹配」——§14 是自指测量，本条是**命中数被当成了命中证据**。共同纪律有两条：**凡用于改变预登记规则或写入报告的测量，都必须由带测试的模块产出，并写明该测量的适用范围**；以及**记数的同时必须记性质**——空/非空、自指/他指、单一版本/全版本，任一未记，「19 个副本」这类读数就会在下游被当成实据。

## 16. 规则级归因实测（2026-09-24）：两臂不是同一套规则，§10 的前提被证伪

**工装**：`models/audit/tools/arm_rule_divergence.py`（配套 18 条测试 `tests/test_arm_rule_divergence.py`）。读两臂各自的 `sample-results.jsonl`，逐行按 `report_path` 打开该样本的报告取 `(rule_id, file, line)`；**不重扫**——重扫测的是另一次运行，读数就不再描述判据所据的那份证据。它把「一臂有、另一臂没有」的 finding 分成两类：

- **shape**：该位置另一臂**也报了**（只是规则不同，或同一规则报了不同的次数）。这是**工装形态**之差（regex 每行只留首条匹配、semgrep 每条匹配都报），`tests/test_engine_rule_parity_corpus.py` 正是为消掉它而写。
- **coverage**：该位置另一臂**什么都没报**。这才是规则或引擎之差。

**判据读数**（311 样本，两臂同集，`--llm-backend none`；由管线自己的 `confusion_counts` 按各行自带的 `blocked` 计算，不由本工具重算）：

| 臂 | TP | FP | TN | FN | recall | FPR |
|---|---|---|---|---|---|---|
| regex | 49 | 17 | 137 | 108 | 0.3121 | 0.1104 |
| semgrep | 54 | 28 | 126 | 103 | 0.3439 | 0.1818 |

`ΔFPR = +0.0714`、`Δrecall = +0.0318` → **不通过**（0 容差、逐对）。

**逐规则（semgrep − regex）**：

| rule | regex | semgrep | delta | sg_cov | sg_shape | rx_cov | rx_shape | 备注 |
|---|---|---|---|---|---|---|---|---|
| CMD_001 | 67 | 76 | +9 | 9 | 0 | 0 | 0 | |
| DYN_001 | 19 | 20 | +1 | 0 | 2 | 1 | 0 | |
| ENV_001 | **0** | **47** | +47 | 47 | 0 | 0 | 0 | **参考臂从不触发此规则** |
| NET_001 | 21 | 46 | +25 | 25 | 0 | 0 | 0 | |
| NET_002 | 8 | 8 | 0 | 0 | 0 | 0 | 0 | |
| OBF_001 | 11 | 26 | +15 | 16 | 0 | 1 | 0 | |

不变量 `(sg_cov + sg_shape) − (rx_cov + rx_shape) = delta` 在每一行成立，并由测试守住。

**一、shape 在本语料上几乎不存在（全语料仅 2 条，都在 `DYN_001`）。** 这条先说，因为它排除了一个真实的混淆源：§3 与 `test_engine_rule_parity_corpus.py` 都警告过「semgrep 每条匹配都报、regex 每行只报首条」会让命中数不可比。实测该效应在本语料上可忽略，故下面的 coverage 差**不是工装形态造成的**。

**二、`ENV_001` 不是「两臂同等的缺口」，而是两套不同的规则。** regex/Go 侧（`internal/codeaudit/rules.go:222-224`、`code_security_analyzer.py:119-121`）要求环境变量**名**匹配敏感词交替（`secret|token|api[_-]?key|access[_-]?key|…`）；semgrep 侧 `taa-env-secret-python`（`models/audit/semgrep/rules/python/rules.yaml`）的 `os.environ[$KEY]` / `os.environ.get($KEY, ...)` / `os.getenv($KEY, ...)` **对 `$KEY` 无任何约束**。后果：**regex 臂在全部 311 个样本上一次都没触发 `ENV_001`，semgrep 臂触发 47 次**（47 条全为 coverage，0 条 shape）。触发到的键名实测包括 `SPHINX_BUILD`、`READTHEDOCS`、`READTHEDOCS_CANONICAL_URL`、`READTHEDOCS_VERSION`、`PAGER`、`TERM`、`LESS`、`GLOM_CLI_DEBUG`、`MCP_CONFORMANCE_CONTEXT`、`MCP_CONFORMANCE_SCENARIO`、`XDG_CONFIG_HOME`、`RUAMEL_DEBUG`、`YAMLDEBUG`、`DVDEBUG`、`PYDISTBASE`、`LOCALAPPDATA`、`APPDATA`、`TEMP`、`envvar` —— 无一在敏感词交替内。故 **§10「真实缺口，两臂同等」被证伪**：一侧有该约束、另一侧没有，谈不上「同等」。

**三、其余四条规则的差是引擎能力，且其中两处是参考臂错、semgrep 对。**
- `NET_001 +25` / `CMD_001 +9` / `OBF_001 +16`（均 coverage）源自 semgrep **解析 import**：`from urllib.request import urlopen`、`import subprocess as sbprc`、`import base64 as b64`、`from requests import get` 之下调用点是裸名或别名，regex 的**限定名**模式必然看不见。实测出现这类 import 的正是发生分歧的那 5 个样本（dd-0055/0056/0057、sr-0155、sr-0156）。这是**引擎能力**，正是本比较要测的东西。
- `DYN_001` 的 `rx_cov 1`：`pypi-0080:1591` 在**文档字符串的散文**里命中 `(unless you are familiar with how eval() and exec() work)` —— regex 按文本匹配故命中，semgrep 按 AST 解析故正确忽略。**这是参考臂的假阳性。**
- `OBF_001` 的 `rx_cov 1`：`sr-0149:3` 的 `_pickle.loads(exploit_code)`，regex 的 `pickle\.loads?\s*\(` 是**无锚子串**匹配故命中 `_pickle.`；semgrep 的 import 感知模式看不见 `_pickle`。而该行上游标注为 `# ruleid: avoid-pickle`——**按上游标注者自己的判据它是真阳性**（该 fixture 就是为 `avoid-pickle` 写的正例，用 `_pickle` 规避），故这里**漏的是 semgrep**。两处 `rx_cov` 一为参考臂多报、一为参考臂真检而 semgrep 漏，方向相反。

**18 个翻面样本的分解**（判据的 Δ 全部由它们产生）：

- 良性 11 个转为 semgrep-only（= 新增 FP）：`pypi-0001/0002/0005/0015/0029/0037/0040/0071/0073/0081`（**10 个，且全部只有 `ENV_001` 一条**）+ `sr-0155`（`NET_001`，import 能力）。
- 恶意 6 个转为 semgrep-only（= 新增 TP）：`dd-0011`、`dd-0029`、`sr-0034`、`sr-0035`、`sr-0036`、`sr-0156`。
- 恶意 1 个转为 regex-only（= 丢失 TP）：`sr-0149`（上述 `_pickle`）。

对账：`ΔFP = 11`、`ΔTP = 6 − 1 = 5`，与判据表一致。

**四、把 `ENV_001` 从两臂同时拿掉的**近似**读数**：semgrep 侧 `FP 28→18`、`TP 54→53`（`dd-0011` 只靠 `ENV_001` 翻面），故 `ΔFPR` 由 `+0.0714` 降到约 `+0.0065`（**恰好剩一个样本 `sr-0155`**）、`Δrecall` 约 `+0.0255`。**此数必须标注为近似**：它由「有 finding 即算阻断」近似 `blocked` 得到，而本工装**刻意不提供**「删规则后重算判据」的功能——`blocked` 取决于规则严重度与策略，从过滤后的 finding 列表重算等于重实现一遍策略，那正是 §14 禁止的那类测量。真实读数须由**对齐后实跑一次**得出（regex 臂 ~4 s、semgrep 臂 ~20 min，代价可接受）。**注意此近似仍不影响第一条结论的方向**：`ENV_001` 独占 11 个新增 FP 中的 10 个，这一点由实测的翻面分解直接给出，与近似无关。

**教训（§15 同族的第五次，新变体：仪器不合格而数值侥幸正确）**：本条结论最初的版本出自 `/tmp` 里的一次性脚本，它用「有 finding 即算阻断」近似判据，并用**集合**（而非多重集）匹配 finding。集合匹配会把「一臂同一位置报两次、另一臂报一次」吸收掉——实测 `DYN_001` 报出 `delta +1` 却同时报 `sg_cov 0 / rx_cov 1`，这两个数**自相矛盾**（多重集下应为 `sg_shape 2 / rx_cov 1`，才对得上），矛盾本身就是缺陷的指纹。这次数**值**最终与管线自己的 `confusion_counts` 逐字一致，但**仪器**不合格；§14 已写死「凡用于改变预登记规则的测量，必须由带测试的模块产出」。故本次先补工装（含上面那条不变量测试），再由它出数——**与前四次不同的是，这次错的不是读数而是读数的来源，而它与正确读数长得一模一样**。

### 16.1 对齐后的实测（2026-09-24，两次改动后各重跑一轮）

你 2026-09-24 裁定「收窄 semgrep 侧」后，落地两处改动并各重跑一次全量（`--llm-backend none`、`policy gate`，311 样本）：

- 改动 1：`taa-env-secret-python` 按键名收窄（commit `9e7cbfb`）。
- 改动 2：`taa-obf-exec-python` 补 `_pickle.load`/`_pickle.loads`（commit `4f4d0be`）。

| 阶段 | semgrep TP | FP | TN | FN | recall | FPR | ΔFPR | Δrecall | 翻面 |
|---|---|---|---|---|---|---|---|---|---|
| 原始 | 54 | 28 | 126 | 103 | 0.3439 | 0.1818 | +0.0714 | +0.0318 | 18 |
| 收窄 `ENV_001` 后 | 53 | 18 | 136 | 104 | 0.3376 | 0.1169 | +0.0065 | +0.0255 | 7 |
| 补 `_pickle` 后 | **55** | **18** | **136** | **102** | **0.3503** | **0.1169** | **+0.0065** | **+0.0382** | 7 |

regex 臂三轮恒为 `TP49 / FP17 / TN137 / FN108`（`recall 0.3121`、`FPR 0.1104`），故只列 semgrep 侧。**收窄 `ENV_001` 后实测的 `ΔFPR = +0.0065` / `Δrecall = +0.0255` 与 §16 第四条的近似值逐字吻合**——该近似由此转为实测，其「近似」标注撤销。

**`_pickle` 补丁的收益比预想多一条，原因值得记下。** 除恢复 `sr-0149`（`_pickle.loads(...)`，参考臂靠无锚子串匹配本就能抓到）外，还**新增**了 `sr-0150`：

```python
def insecure_deserialization_2(exploit_code):
    import _pickle as adaasfa

    # ruleid: avoid-pickle
    adaasfa.loads(exploit_code)
```

即**把 `_pickle` 别名化成 `adaasfa` 再调用**。参考臂的 `pickle\.loads?\(` 看不见 `adaasfa.loads(`，故 regex 臂在此**一条都没有**；semgrep 按 import/别名解析，使 `pattern: _pickle.loads(...)` 命中了 `adaasfa.loads(...)`。上游把该行标为 `# ruleid: avoid-pickle` 真阳性。故这 +1 TP 是**引擎的别名解析能力**，不是补丁的副作用——补丁只提供了一个能被解析到的模式。这与 `sr-0149` 合起来说明：`_pickle` 那个「缺口」其实有两个层次，`sr-0149` 是参考臂**靠意外**抓到而 semgrep 缺模式，`sr-0150` 是参考臂**结构性抓不到**而 semgrep 有能力抓到。

**同时记一处两臂共同的漏**：`sr-0148` 的 `_pickle.dumps(Exploit())` 上游亦标 `# ruleid: avoid-pickle`，但参考侧模式 `pickle\.loads?\s*\(` 只含 `load`/`loads`，**两臂都抓不到** `dumps`。这是**共同缺口、非两臂之差**，不影响判据（计入两臂共同的 FN）；`dumps` 是序列化（写）而非反序列化（读），是否该覆盖属规则语义问题，登记备查。

**终局读数**：`ΔFPR = +0.0065`、`Δrecall = +0.0382` → **仍判 FAIL**，但**性质已变：没有任何样本是 semgrep 臂丢失的**。7 个翻面全是 semgrep-only（6 个恶意 TP：`dd-0029`、`sr-0034`、`sr-0035`、`sr-0036`、`sr-0150`、`sr-0156`；1 个良性 FP：`sr-0155`），唯一的丢失项 `sr-0149` 已恢复。对账 `ΔTP = +6`、`ΔFP = +1`。

**剩余唯一失败项是单个良性样本 `sr-0155`，而它是 §12.3 翻译表的产物**：

```python
def from_import_test1(url):
    from requests import get, post
    # ok:no-auth-over-http
    good_url = "https://www.github.com"
    bad_url  = "http://www.github.com"
    r = get(good_url, timeout=3)
    r = post(bad_url)
```

上游 `# ok:` 是给 `no-auth-over-http` 那条规则的——判的是「是否把**凭据**走明文 HTTP」，该样本确实不带凭据，故对**那条规则**是 ok。而我方 `NET_001`（`internal/codeaudit/rules.go`）标的是「HTTP/HTTPS 网络请求 — 可能向外发送数据」，`post(bad_url)` 正是它要抓的东西。即**该样本上 semgrep 臂是对的**，regex 臂只因 `from requests import get, post` 让调用点成裸名而看不见；判据却因这一个样本不过。

**于是对齐循环走到尽头**：可对齐的两处端口缺陷（`ENV_001` 规则不同、`OBF_001` 覆盖缺口）均已修好，剩下的两类**都不是「对齐规则」能处理的**——(a) **引擎能力**（import/别名解析、AST 而非文本匹配）：这是本次比较要测的对象本身，对齐掉它等于把实验做空；(b) **一处映射表产物**（`sr-0155`）：§8 明令「不得改判据、改样本、改映射表」。

**结论的边界（必须照此写报告）**：以上全部是 `--llm-backend none` 的**静态前置读数**，**不是 §2 的判据**。§2 判的是 `assist`/`gate` 下 LLM 介入后的**最终裁决**，须由 H2 测出。故当前准确表述是：**静态前置读数判 FAIL，且唯一失败项出自一处映射表产物**；判据本身在 H2 跑完前**未定**。另据 §11.5，两臂**用不同措辞向模型描述同一条规则**，故 LLM 未必对两臂的 finding 一视同仁，静态差未必按比例压缩——这正是 H2.3 要逐条归因的。

## 17. H2.5 规模实测（2026-09-24，跑完，读数如下）

**本节不出任何判定结论**（§7 H2.5、§11.2）。它测的是「真实规模的代价」：单文件判据用不到它，但它定 §9.1 的两项参数、暴露三处工程缺陷、并撤回一处我先前写错的结论。工装 = `models/audit/tools/scale_submeasure.py`（带测试，`tests/test_scale_submeasure.py` 40 项全过），非一次性脚本（§14 纪律）。

### 17.1 单次扫描：press 语料（400 个 `.py`、9.2 MB）

`/root/taa/verify/bench`，对齐后规则，`--max-memory 1024`，`--timeout-seconds 120`（生产自己的界）。

| `--jobs` | 秒 | findings | 匿名峰值 MiB | `current` 峰值 MiB | 进程树 RSS MiB | `MemAvailable` 最低 MiB |
|---|---|---|---|---|---|---|
| 1 | 6.90 | 80 | 168.3 | 580.7 | 308.4 | 7137.1 |
| 2 | 6.09 | 80 | 171.9 | 585.2 | 311.6 | 7103.6 |
| 4 | 5.28 | 80 | 179.3 | 592.6 | 319.9 | 7097.1 |
| 8 | 5.28 | 80 | 194.2 | 607.8 | 332.7 | 7069.5 |
| 16 | 5.28 | 80 | 221.4 | 637.6 | 361.5 | 7062.3 |

每一级 `per_rule` **完全相同**（`CMD_001 12 / EMB_002 6 / EMB_003 12 / ENV_001 8 / FIL_001 12 / NET_001 8 / NET_002 2 / OBF_001 10 / PER_001 10`，共 80），78 个文件命中，`semgrep_errors 0`。**两点读数**：(a) 并发 1→16 只买到 **1.6× 提速**（6.90→5.28 s），此语料上 semgrep 基本不并行；(b) 内存只从 168 涨到 221 MiB 匿名 ⇒ **单扫描不可能是多 GiB 级溢出的来源**（直接否掉 §9.1 原根因表述的适用性）。

### 17.2 单次扫描：真实非均匀代码树（`requests-2.34.2`，35 个 `.py`）

| 臂 | findings | 扫描秒 | 匿名峰值 MiB | 进程树 RSS MiB | 扫到的文件 |
|---|---|---|---|---|---|
| regex adapter | **141** | 0.41 | 28.7 | 14.6 | 35 |
| semgrep adapter（**评测当前口径**） | **3** | 5.89 | 218.8 | 366.0 | **20** |

`per_rule` regex = `DYN_001 2 / EXF_001 1 / NET_001 121 / NET_002 10 / OBF_001 7`；semgrep = `DYN_001 2 / OBF_001 1`。

### 17.3 并发 burst：press 脚本**自己的** level，模型常驻（这才是峰值）

`semgrep_press_test.sh` 的默认 `LEVELS="0 4 8 12"`；每扫描 `--jobs 4`；burst 前先把 `qwen2.5-coder:3b` 置为常驻（`keep_alive 15m`，cgroup 匿名基线 **2.01 GiB**）。

| level（并发扫描数） | 秒 | 退出码 | 匿名峰值 MiB | `current` 峰值 MiB | 进程树 RSS MiB | `MemAvailable` 最低 MiB |
|---|---|---|---|---|---|---|
| 4 | 7.36 | 全 0 | 2703.2 | 4787.8 | 1275.8 | 4610.7 |
| 8 | 8.57 | 全 0 | 3325.4 | 5418.3 | 2542.1 | 4005.6 |
| 12 | 11.03 | 全 0 | 3775.3 | 5872.4 | 3501.9 | 3609.4 |

每扫描 findings 恒为 **80**。扣掉模型基线后 semgrep 自身匿名占用：level 4 ≈ **644 MiB**、8 ≈ **1266 MiB**、12 ≈ **1716 MiB** ⇒ 约 **150 MiB/并发扫描，线性于 level**（与 §17.1 单扫描同量级，互相印证）。**这是容器上限的唯一依据**：最坏 `current` **5872 MiB**、匿名 **3775 MiB** ⇒ 取 **`--memory 7g`（7168 MiB）**，高于最坏 `current` 约 1.3 GiB，低于宿主总量 9935 MiB，先于宿主触限。

**必须写进协议的一处局限**：容器上限**不保护 `llama-server`**。按 D4 拓扑 semgrep 与 LLM 同容器，故触限时被杀的仍是容器内 RSS 最大者——很可能还是模型。真正保护模型的是 `--jobs` 钉死 + `keep_alive` 常驻，**不是**这个上限；上限只保护**宿主**会话。原 §9.1 第 5 项措辞已按此更正。

### 17.4 顺带证到的一处工程缺陷：semgrep 默认排除**静默丢掉 `tests/` 目录**

上表 20 vs 35 就是这个：semgrep 扫了 20 个文件、regex 臂 35 个，**差的正好是 15 个 `tests/` 下文件**，且**不报**在 `paths.skipped` 里（不是 `.gitignore`、不是 `.semgrepignore` 文件驱动，是 semgrep 内置默认排除）。

- **证明**：4 个相同文件的探针里 `tests/` 被丢、`mytests/` 保留；`--x-ignore-semgrepignore-files`（`[INTERNAL]`，随版本可能消失）或在被扫树内放含 `!tests/` 的 `.semgrepignore` 均能恢复。
- **故 141 vs 3 的差几乎全是文件集差，不是检测差。** 恢复 `tests/` 后 semgrep 得 **139/35 文件**（`DYN_001 2 / NET_001 119 / NET_002 10 / OBF_001 8`），对 regex 的 141/35 文件，**残余仅 2**：`NET_001` −2、`OBF_001` +1、`EXF_001` −1（`EXF_001` 正是已登记的 taint↔regex 语义差）。残余 2 **登记备查，本轮不追**。
- **判据不受影响（已核）**：311 个样本的 `relative_path` **无一**穿过默认被排除的目录名，且每个样本目录恒为 `sample.json` + `sample.py` ⇒ H2.1/H2.2 不受此影响（§11.2 要求两者分开，此处得到确认）。但**生产风险已登记**：Go `SkipDirs`（`internal/codeaudit/scanner.go`）**不含** `tests/`，故引擎一旦切到 semgrep，测试目录会被静默停扫。

### 17.5 两处部署口径不一致（H2.4 前必须处理）

- **容器内已部署的规则是旧的**：`/opt/taa/semgrep/...` 与 `/root/taa/verify/...` 的 md5 为 `34519c59`（对齐**前**），而评测用的 `/root/taa/holdout/...` 为 `c06ffd2c`（对齐**后**）。`deploy-docker.sh:65` 从仓库存放这些规则，故以 `--scan-engine semgrep` 重跑一次即刷新。
- **press 脚本的 `RULES` 默认指向旧副本**（`semgrep_press_test.sh:33`，`/opt/taa/semgrep/rules/python/rules.yaml`）⇒ H2.4 若不显式覆盖，测的会是**另一套规则**，与 H2.1 不可比。
- **消费者不止 press 脚本：容器内正在运行的 TAA 服务本身就在用旧规则（2026-09-24 实测）**。`/root/taa/taa-config.json` 的 `security` 块实测为 `{"codeScanEngine": "semgrep", "semgrepRulesPath": "/opt/taa/semgrep/rules/python/rules.yaml"}`，读取链 `internal/config/config.go:126`、`:366-367` → `internal/app/taa/app.go:568` → `internal/codeaudit/engine.go:125-127`（作为 `--config`）；生产者是 `deploy-docker.sh:69`（默认目录）、`:334`、`:365-366`（同时置 `codeScanEngine=semgrep`）；另有容器内 `verify/press.sh:15`、`verify/press2.sh:28` 两个副本；`internal/config/config_test.go:963`、`:971` 仅为测试字面量、无运行时依赖。**故部署态服务与 H2 基准加载的不是同一套 python 规则，两者结论不可互推**——而 §17.5 第 1 条原先只把这一漂移记到 press 脚本那一个出口上。漂移范围已收紧为**只有 python 规则**：go 规则两边同为 `46522d30`、shell 规则同为 `ae2cc633`；容器内 `/opt/taa/semgrep/MANIFEST` 的 sha256（`ff0c7cb8…`）与容器文件自洽 ⇒ 是安装时取自对齐**前**的源（部署于 Sep 23 02:16），**不是**安装损坏。
- **评测路径本身也没钉并发**：`semgrep_runner.py:187-195` 既不钉 `--jobs` 也不钉 `--max-memory`，只以 `timeout=120` 兜整个扫描——即 §9.1 根因 1 的形状**出现在判据自己的路径上**，不止 press 脚本。（好消息：它用 `subprocess.run(capture_output=True)`，内部走 `communicate()` 会排空管道，**没有**下面 17.7 那个死锁。）

### 17.6 `--jobs` 的语义无关性：**已在判据自己的语料上证明**

对 311 样本语料根目录整树扫描，`--jobs 1` vs `--jobs 16`：

```
jobs=1  findings=178  scanned=311
jobs=16 findings=178  scanned=311
diff 结果：两集合的 (规则, 样本, 行号) 三元组完全一致
```

故钉 `--jobs 4` 是**可证不改变语义**的协议参数（§14 要求的那种「改了但登记、且证明不动结论」）。

### 17.7 仪器故障与撤回：`stdout_bytes 68096` vs 64 KiB 管道

本条必须留档，因为它差一点被我写成一个**关于 semgrep 的假结论**。第一轮 sweep 出现「12 分钟不返回、>600 s」，我据此**推断**「taint 规则（`EXF_001`）让真实树扫描超线性爆炸」。**该推断是错的，现撤回**，真正的两个原因都在**我自己的工装**里：

1. **管道缓冲死锁**：`stdout=PIPE` 时子进程写满一个管道缓冲（64 KiB）即阻塞，而无人读；本语料 semgrep 的 JSON 是 **68,096 字节 > 65,536**，故进程永远停在 100% 而轮询循环等一个永不会退出的进程。指纹就是这个数：**68096 > 65536**。
2. **两个 sweep 并发**（一个被挪到后台时我又起了一个）互相抢 CPU（load ≈5.1）。

修法两处并各有回归测试：输出落**临时文件**而非管道；`start_new_session=True` + `os.killpg` 杀整组（否则 `semgrep-core`/`pysemgrep` 子孙存活，下一级量的就是上一级的残骸）。修正后**同一语料同一界**为 **5.28–6.90 s**。

**教训（§15 同族第六次，新变体：仪器卡住，而我把「卡住」读成了被测系统的属性）**：前五次的错在读数或读数来源，这次错在**把工具的失败投射到被测对象上**——而且这个假结论「看起来像发现」（超线性、taint 规则重、真实代码更贵），比真读数更像结论。故凡「某配置慢得异常」必须先自证仪器（本处只需看一个数：输出是否超过 64 KiB）。

### 17.8 对 §6.8-2 单侧上限的量化（真实代码上）

regex 臂在**一个 516 KB 的库**上就产出 **141 条 finding** = 生产 Go `MaxFindings = 200` 的 **70%**，且是评测「送 LLM」上限 50 的 **2.8 倍**。即 §6.8-2 那条单侧上限（超限即 `Truncated` → fail-closed）在真实包尺度上**近在眼前**，不是理论担忧。

### 17.9 H2.5 出口

- §9.1 第 4 项落点已更正并登记（两处调用点各加 `--jobs 4`，语义无关性已证）；第 5 项已定为 **`--memory 7g`（`--memory-swap 7g`）**。**两项均已于 2026-09-24 落地**：第 5 项经 `docker update` 生效（实测 `Memory=MemorySwap=7516192768`，`RestartCount=0`、`StartedAt` 未变 ⇒ 未重启容器）。
- H2.1 是否分批：**不分批**——最坏实测 `MemAvailable` 最低 3609 MiB，仍高于 §9.1 的 1024 MiB abort 地板与 3072 MiB 升级地板，无内存理由分批。
- 原先「阻塞 H2.4 的两项」其一已闭合：H2.1 的驱动以**绝对路径**显式传入对齐副本（实测容器内 md5 = `c06ffd2c…`，与宿主一致），故 press 负载与判据同用一套规则；旧部署副本的刷新**仍待做**，且**不得在 H2.1 期间做**（`deploy-docker.sh` 会重建/重启容器）。刷新范围按 §17.5 新增第 2 条连带部署态服务。
- **容器无 bind mount ⇒ 宿主编译不等于容器生效（本轮第二次咬人，登记为操作纪律）**：容器 `taa-env-slim-v2` 的 `Mounts` 为空，全部投放靠 `docker cp`。本轮先因容器内 `scale_submeasure.py` 落后于宿主（缺 `--burst-levels`）失败一次，又因**漏投 `semgrep_press_test.sh`** 使 H2.1 首启失败一次（驱动守卫正确拒跑：「press load produced no start banner; refusing to continue」，未产出无负载的矩阵）。**规程**：每次投放后以 md5 对宿主逐一核验（本轮 5 个工具全部一致），驱动以绝对路径传参、不依赖 CWD。

### 17.10 上游建议（登记，本轮不改）

重打分的「精确」目前依赖一条**隐含不变式**：`generate_audit_report` 从不把 `scan_complete`/`parser_errors`/`timed_out` 写进 `stats`——这正是 `compute_conclusion` 的 fail-closed 分支在 `static-llm` 路径上恒不触发的原因，也是重打分能**精确**而非**近似**的支点。**上游最小修法**：让 `generate_audit_report` 把这三项（内存中已算好，见 `audit_benchmark_eval.py:1055-1057` 的 `outcome.scan_complete`/`timed_out`/`parser_errors`）原样写入 report，把不变式**显式化**。

**本轮不做的理由**：改落盘格式会让 H2.1 的 run1 与 run6 不同构（同一矩阵内两套产物 schema，配对无从谈起）。替代做法是让重打分**断言并拒跑**——这比改格式更保守：不变式若被破坏，重打分**响亮失败**，而不是静默按放宽方向偏离。

**（2026-09-24 补记）** 重打分工具已落地并提交（`801983a`，`models/audit/tools/gate_rescore.py`，22 项测试全绿）。B 在自审中发现并修掉了一处**自己的 fail-open**：原 `_run_dirs` 以「`summary.json` 是否存在」筛选，于是被中断的 `regex-run1` 会以 **「matched 0/0 over 0 run(s)」退出 0**——在零样本上的一次干净通过，且 `materialise` 会写出空门禁集。已改为按目录名 `(regex|semgrep)-run(1|2|3)` 选取，布局名匹配但缺 `summary.json` 即拒跑（exit 2），并对真实被中止目录验证过。**另须写进报告**：`gate` 下**每一条新被阻断的样本都是未归因的**——两策略在 `static-llm` 内唯一的可能分歧是 `has_high_or_medium and not has_llm_verdict` 且 `high == 0`（`code_security_analyzer.py:889`），而 `check_sample_attribution` 读 `finding["llm_verdict"]`，未复核 findings 的 verdict 经 `asdict` 序列化为 JSON `null`（`:990`），该检查把它强制成字符串 `"NONE"` 而非它视作「未复核」的空串。故 `gate` 的 `attribution_precision` **按构造**低于 `assist` 的，不是建模差异。

### 17.11 H2.1 首启中止：受载条件下判据自己的 LLM 仲裁失效（2026-09-24）

**结论先行**：在 press 脚本自身的负载档位下，判据所需的 LLM 仲裁**无法完成**，且其失效方向**朝向假通过**，故该条件下**不可**读 §2 判据。H2.1 首启已于 07:15 中止，产物改名 `h2-assist-ABORTED-loadstarved` 保留备查，**不得用于判定**。

**证据链**

1. **设计好的仪器（press 逐 probe 的 `llama_pid`/RSS）说明「运行器活着，只是慢」**：level 0 的 10 个 probe 全 `ok` @ **0.2 s**；level 4 起 13 个中 12 个 `state=timeout` @ **恰好 30.0 s**（唯一的 29.0 s 那个返回了 `ok`）。全程 `llama_pid` **恒为 73889**、RSS 2.48→2.70 GB 缓升、`mem_avail` 5.1–5.9 GB ⇒ **不是被杀、不是 OOM（`oom_kill=0`）、不是内存压力**，是延迟。
2. **判据自身产物中的直接证据（2026-09-24 重读产物后更正，附带一处旧推论的撤回）**：前 8 个样本里**只有 `cq-0002` 需要 LLM**（1 条 finding，`CMD_001`、`sev=HIGH`）。**重读 `/root/taa/verify/h2-assist-ABORTED-loadstarved/regex-run1/cq-0002/audit_report.json`，实际记录为**：
   - finding：`llm_verdict = UNCERTAIN`、`llm_reason = "ollama 调用失败: timed out"`；
   - 文件摘要：`risk_level = UNCERTAIN`；
   - 样本结论：**`passed = False`、`verdict = UNCERTAIN`、`risk_level = HIGH`**。

   即**受载把该样本判成 blocked（= malicious），而不是 benign**。故先前此处写的「受载把 finding 翻成 benign——真阳性与假阳性一起被抹掉」「两臂皆 benign ⇒ ΔFPR 0、Δrecall 0」**与产物相反，撤回**：那是把 `pure-llm` 路径的判分层（`audit_benchmark_eval.py:877-878`）安到了 `static-llm` 路径上（§17.12 结论先行）。**更正后的读数**：受载矩阵的 Δ 测的是「臂的命中量 × 超时率」而非检测能力，偏置方向是**抬高失败那一臂的 FPR**（`cq-0002` 即一例**受载超时导致的假阳性**），两臂命中量不同 ⇒ 偏置不对称（偏向失败少的那一臂）。**§17.11 的结论「受载读数不可承载 §2 判据」不变，但理由由「两臂一起变干净」更正为「失败那一臂被抬高 FPR」。**
   另注：同批 8 份里 6 份（`cq-0001/0003/0004/0005`、`dd-0001/0002`）`risk_level = NONE` ⇒ **零 finding ⇒ 根本没有 LLM 调用**，与失败无关；`dd-0003` 无报告（中止于此处）。故这批样本里**只有 1 份对判据有信息量**。
3. **我自己造的两处错误仪器（§17.7 同族第七次，须一并撤回）**：为定位病因我做了两轮隔离实验，读数 7–15 s，据此写下了「CPU 饥饿不成立」的结论——**该结论作废**。因为我的探针 prompt 要求「回复单个判定词」，模型 **`eval_count=2`** 即停。`num_predict` 是**上限不是字数**，于是那两轮只测了 **prefill**，从未测 **decode**——而 decode 正是受载下变贵、也正是真实审计要付的那部分。**教训**：探针必须回读 `eval_count` 自证它真的做了它声称的测量。
4. **改正后的读数（强制长生成，并以 `eval_count=300` 自证）**：空载冷启 **68.0 s / 300 tok（4.4 tok/s）**；空载回暖 **31.6 s / 300 tok（9.5 tok/s）**；4 路并发 semgrep 下 **>90 s 失败**；再叠加 press 形状的探针回路同样 **>90 s 失败**。
5. **故主因是「本机 decode 速率 vs 60 s 硬上限」本身余量极薄**：空载回暖 300 tok ≈ **32 s / 60 s**，尚可；冷启 ≈ 61 s **已在线上**；受载下 decode 跌破 ~3.3 tok/s ⇒ >90 s ⇒ 判据的调用失败 ⇒ `UNCERTAIN` ⇒ 高/中危发现上 fail-closed 阻断（`code_security_analyzer.py:855-875`，**方向已更正，见 §17.12 结论先行**）。**这是关于部署的真结论，不是仪器假象**（第 3 条改正后仍成立），且它解释了 §9.3 记录的两次部署失效。**（该条的「尚可」已由 §17.12 E 更正：那 32 s 是小提示 + 300 token 生成的数字，真实风险由提示体积设定，提示可达 2900 token。）**
6. **一处须记录的近失**：我一度把 `/tmp/ollama-h2.log` 当作现役 ollama 日志读（其末行为 06:38，早于矩阵），差点据此推断「矩阵期间 ollama 无请求」。真实日志是 **`/root/taa/ollama.log`**（pid 73831 的 `fd/1`），其中 07:05–07:06 有 `500 | 30.0s` 与 `500 | 1m30s`。**取日志须先 `readlink /proc/<pid>/fd/1`。**

**受载条件是否还有救（据此给出待裁定的两条路）**

- **降载不可行**：空载回暖已占 60 s 预算的 32 s（~53%），任何有意义的 semgrep 负载都会越过它；而 press 脚本的 level 0 就是无载。故不存在「既压得住系统、又保得住仲裁」的窄带。**抬超时也不可取**：60 s 是**生产事实**（`code_security_analyzer.py:707`），改它就不是在描述生产。
- 因此受载读数在本机应作为**部署可行性结论**（§9.3 第 1 条要的正是这个），而不是 §2 判据；§2 须在**仲裁真的发生**的条件下读。

**裁定与落地（2026-09-24）**：你选定 **「无载读主判定」**。故 §2 判据改由**无载矩阵**承载（上表第 4 条的空载回暖读数 31.6 s / 60 s 即其可行性依据），受载读数按上一条作为部署可行性结论写进报告。**受载矩阵不再重跑**——一次重跑只会再产出一份不可判定的产物，而它要回答的问题（共置可不可行）已由 press 逐 probe 记录 + 上表改正后的 decode 读数答完。H2.1 已按 `LOAD=0` 重启（`/root/taa/verify/h2-assist-unloaded`，2026-09-24T07:09:23Z），并在量测前先 warm 模型。

### 17.12 无载矩阵期间仲裁仍会失败：真因是「行 / token 单位错配」，不是负载（2026-09-24）

**结论先行**：**§17.11 末尾那条「无载 ⇒ 安全」的推论不成立，此处更正。** 无载确实去掉了 semgrep 的争抢，但判据自己的 LLM 调用**仍在撞 60 s 上限**，因为本机的底座速度使**提示体积（以 token 计）**而非负载成为主因。

**失效方向先前记反了，此处更正（2026-09-24，本条文最实质的一次更正）。** 判据有**两层判分**且失败语义相反：`pure-llm` 路径读 `audit_benchmark_eval.py:877-878`（`UNCERTAIN` → `predicted_risk = "LOW"` → benign，fail-open），而**留出集跑的是 `static-llm` 路径**，它读 `compute_conclusion`（`code_security_analyzer.py:855-875`）：高/中危发现上的 `UNCERTAIN` 使 `risk_level → HIGH`、`passed=False`，而 `assist` 下 `HIGH` 即阻断 ⇒ **失败把样本推向 malicious（fail-closed）**。我先前引的 `:877-878` 是前者，**串了两条路径的语义**。

由此，本缺陷在**本语料里只能制造假阳性，不会吃掉 recall**：假阴性方向需要一条**失败的低危发现**才能触发，而本语料**零条低危发现**（run 1 仲裁发现严重度实测 `HIGH 113 / MEDIUM 20 / LOW 0`）⇒ 该方向**不可达**。**且已产生 1 例实测误判**：`pypi-0057`（benign → 超时 → `UNCERTAIN`/HIGH → 判 malicious），是一例**超时导致的假阳性**。详见 D 节。

**A. 现场与发现经过**

1. 监视器在 **07:45:49Z** 报出第 1 个 `UNCERTAIN`（`pypi-0057`），遂查。该样本 `llm_reason = "ollama 调用失败: timed out"`。
2. 我的第一个假设（§11.9 的超长单行）**被量测否定**：用分析器自己的函数算得该样本文件级提示 **1592 字符**、发现级 **680 字符**，都是小提示。
3. 转读服务器日志（`/root/taa/ollama.log`，`--log-verbosity 4`，含逐 task `print_timing`），拿到**服务器自报**速率：**prefill 持续 42–52 tok/s**（≈20 ms/token，跨所有 task 稳定）、**decode 7.6–11.4 tok/s**（≈90–130 ms/token）、**实际生成长度仅 50–84 token**（远未用满 `num_predict=200`）。
4. **据此正常调用是安全的**：400–1300 token 提示的整次调用为 **15–35 s**（例：task 8652 = 422 token prefill 8.2 s + 84 token decode 10.9 s ≈ 19 s）。**危险的是提示变大**：1044 token → 20.7 s、1267 → 24.7 s，外推到 **≈2800 token 即 60 s 悬崖**。

**B. 两次超时的原形（决定性证据）**

- **task 8448：`task.n_tokens = 2894`**。prefill 进度逐行可读：512@9.77 s、1024@19.84 s、1536@30.65 s、2048@41.28 s、2560@52.07 s，sampler init 约 58 s，随即 **`[GIN] 2026/09/24 - 07:43:47 | 500 | 1m0s | POST /api/generate`**。即**60 s 上限在 prefill 末尾就到期，decode 一步都没跑**。
- **task 8456：`n_tokens = 455`，同样 `500 | 1m0s`**，但**全程没有一条 prefill 进度行**（连 512 token 都没走到），最终 `n_tokens = 466` ⇒ 那 60 s 里只产出 11 个 token。日志给出原因：`slot get_availabl: id 0 | task 8456 | - skipping, is_processing = 1`——**单 slot（`-np 1`）下它排在已超时的前一个请求后面**。故一次超时会连带废掉紧随其后的调用。

**C. 真因：预算按「行」计，成本按「token」计（§11.9 的第二副面孔）**

`extract_finding_centered_context(lines, findings, max_lines=400)` 的上限是 **400 行**，但代价是 **token**：400 行密集 Python ≈ **2800–4000 token** ≈ 本机 **56–80 s prefill**。于是 **≈2800 token 的悬崖正好压在 60 s 上限上**。`dd-0056`/`dd-0057` 都是 DataDog 的密集多发现样本，窗口被填满 400 行，遂踩线。§11.9 记的是「超长单行使体量无界」，**本条补上第二面：即使单行正常，行数预算的 token 成本本身也已越过超时**。

**D. 影响面（实测：8 份样本受影响，其中 1 例已致误判）**

- 无载段共 **9 次 60 s 超时**（`07:23:18`、`07:24:18`、`07:26:55`、`07:27:56`、`07:30:29`、`07:31:29`、`07:32:29`、`07:43:47`、`07:44:48`），成双成三连续出现。日志总计 41 条 `500`，其余属已中止的受载段与我的 30 s 探针。
- **失败有两个家族，先前只登记了第一个**（这是「4 份 / 7 处」这个错数的来源）：
  - `llm_unavailable` = 「调用失败」，即超时/连接失败，本次 **7 处**；
  - `parse_error` = 「无法解析」：调用**成功返回**，但 `num_predict`（发现级 200 / 文件级 300）在 JSON 闭合前截断了生成，`extract_json_response` 无物可解，本次 **4 处**。
  两者在 `audit_benchmark_eval.py:820-822` 是**互不相同**的 `llm_state`，但都落成 `UNCERTAIN`；且**需要的修复方向相反**——超时要更多**时间**，截断要更多 **token**。故反事实重放必须**同时**放宽这两者（见 F）。
- 落到产物的是 **8 份样本、11 处失败调用**（`--dry-run`，修正标记集后；先前的 4 份 / 7 处是标记集漏掉整个 `parse_error` 家族造成的少算）。

| 样本 | 标签 | 失败调用 | 产物判读 | 是否错判 |
|---|---|---|---|---|
| `dd-0019` | malicious | 1 × 无法解析 | MALICIOUS / CRITICAL，阻断 | 否（另有成功的仲裁） |
| `dd-0020` | malicious | 1 × 无法解析 | MALICIOUS / CRITICAL，阻断 | 否（同上） |
| `dd-0056` | malicious | 3 × 超时 | MALICIOUS / CRITICAL，阻断 | 否（另有 4 处仲裁成功） |
| `dd-0057` | malicious | 2 × 超时 | MALICIOUS / CRITICAL，阻断 | 否（另有 5 处仲裁成功） |
| `sr-0039` | malicious | 1 × 无法解析 | MALICIOUS / CRITICAL，阻断 | 否（另有成功的仲裁） |
| `sr-0142` | malicious | 1 × 超时 | MALICIOUS / CRITICAL，阻断 | 否（另有成功的仲裁） |
| `pypi-0057` | **benign** | 1 × 超时 | **UNCERTAIN / HIGH，阻断** | **是——超时导致的假阳性** |
| `sr-0012` | benign | 1 × 无法解析 | MALICIOUS / CRITICAL，阻断 | 否（`CRITICAL` 需 `suspicious > 0`，即已有被判 MALICIOUS 的发现，故即使该处失败成功也照样阻断） |

- **6 份恶意样本全部 `passed=False`**：失败**没有改变**它们的判读。这与更正后的方向一致——它们本来就是 malicious，失败推向 malicious 等于没推。
- **2 份良性样本中只有 `pypi-0057` 是失败所致**：它的唯一发现失败 ⇒ `has_uncertain and has_high_or_medium` ⇒ `risk_level = "HIGH"` ⇒ 阻断。这正是 fail-closed 的签名。`sr-0012` 的假阳性是**引擎间的真实分歧**，与失败无关。
- **故本缺陷在本语料：假阳性 1 例（`pypi-0057`），假阴性 0 例。** 危险子类「单发现 + malicious + 失败」需要**一条失败的低危发现**才能触发，而本语料**零低危发现** ⇒ **该方向不可达**，不是「属运气」。
- **第二例（同一机制，取自已中止的受载段，故只作机制证据、不作判据读数）**：`cq-0002`（`h2-assist-ABORTED-loadstarved`）——唯一 finding `CMD_001`（`sev=HIGH`）超时 ⇒ `UNCERTAIN` ⇒ 文件摘要 `risk_level=UNCERTAIN` ⇒ 样本结论 **`passed=False`/`risk_level=HIGH`**，即一例**受载超时导致的假阳性**。此例同时证伪了 §17.11 旧记的「受载把 finding 翻成 benign」，详见该条。
- **严重度分布的实测依据**（`regex-run1` 全部 311 份报告、126 条被仲裁 finding）：`HIGH 107 / MEDIUM 19 / LOW 0`。这正是「假阴性方向不可达」的量化基础——不是推断，是计数。
- **对判据的含义**：本缺陷**只抬高 FPR**。而两臂的发现量不同 ⇒ 失败次数不同 ⇒ **偏置不对称**：失败更少的那一臂被量到更干净的 FPR。就 run 1 而言 regex 臂受影响 8 份、semgrep 臂（截至收工时）少得多，故**记录下来的对比是偏向 semgrep 的**（对 semgrep 宽松）。0 容差判据不能吸收这一项，故其大小必须**量出**（F 的反事实），但方向上它**只会让 semgrep 显得更好**，不会掩盖 semgrep 的劣处。

**D-2. 用产物直接结清：本缺陷（含 OOM）在 run 1 上不移动 `ΔFPR`（2026-09-24 实测）**

在反事实重放之前，两臂产物本身已能结清 FPR 一侧——把 `sample-results.jsonl` 的 `label` / `predicted_label` / `llm_state` 逐样本取出做集合差（只读，`nice -n 19`）：

| | regex-run1 | semgrep-run1 |
|---|---|---|
| FP 集合大小 | 17 | 18 |
| **FP 差集** | `regex-only = 空集` | **`semgrep-only = {sr-0155}`** |
| 受失败影响的样本 | **8**（`parse_error` 4 + `llm_unavailable` 4） | **6**（`parse_error` 4 + `llm_unavailable` 2） |
| **其中落成 FP 的** | **2**：`pypi-0057`、`sr-0012` | **0** |
| FN 差集 | 6（全部 semgrep-only，即 semgrep 的净增益 TP） | — |

1. **本轮的 `ΔFP = +1` 完全由 `sr-0155` 承担，而它与调用成败无关**：semgrep 侧 `llm_state=ok`、`llm_invoked=true`、命中 `NET_001`；regex 侧**一条都没命中**（`matched_rules=[]`、`static_only`、未调 LLM）。且 §16.1 的 `--llm-backend none` 运行里它**同样是** semgrep 臂的 FP ⇒ **LLM 与超时都不参与**。这正是 §16.1 早已归因的那处 §12.3 映射表产物。
2. **两臂的失败所致 FP 互相抵消**：regex 臂那两例在 semgrep 臂里**同样是 FP**（`sr-0012` 在 semgrep 侧 `llm_state=ok` 且照样 FP；`pypi-0057` 亦然），故在 `ΔFP` 里相减为零。semgrep 臂**一例失败所致 FP 都没有**——它那 6 份受影响样本**全是 malicious 且本就判 TP**。
3. **故 run 1 的 `ΔFPR = +1/154` 不含任何缺陷或 OOM 成分。** 更强的形式：**重放不可能把本轮的 FAIL 翻成 PASS**——重放只能**移除**失败所致 FP（并使失败样本由「被推向 malicious」回到真实判读），而 FPR 只统计良性样本，故重放对 FPR 的唯一作用就是减去失败所致 FP。实测：semgrep 臂该量为 **0**（减不动），regex 臂为 **2**（减得动，每减一例 `ΔFP` 就 **+1**）。故 `ΔFPR` 只能**持平或上升**，而它本已 `> 0`（§2 要求 `ΔFPR ≤ 0` 且 `Δrecall ≥ 0` 同时成立）⇒ **判定不变**。

**这更正了我在汇报里的一处话**：我先前说「`ΔFP = +1` 可能是 OOM 制造的，故反事实对判定承重」——**不成立，撤回**。反事实重放**仍然要做**，但它要结清的是 **`Δrecall` 一侧**：失败会**制造** TP，从而**压低** `Δrecall`（失败多的一臂 recall 被抬高）。把失败修好后，regex 臂那 6 份 malicious 样本是否会翻成 FN，只有重放能答。**但它的结果改变不了 run 1 的判定**——FAIL 已由 `ΔFPR` 单方面钉死。

**E. 「无载」到底还成不成立（须精确表述）**

- 宿主 `%Cpu(s) 99.5 us / 0.0 id`、load **17.6/16 核**；`llama-server` 占 **1571% CPU（≈15.7/16 核）**，其余最大消费者是**本会话自己**（`claude` 14.6%）。容器内**无第二个 LLM 客户端**（无 TAA 服务在跑），`ss` 无外部连接。
- 故「无载」在**「无 semgrep 争抢」**这一含义上成立（这正是 §17.11 要的条件），但**不等于机器有余量**：模型工作时会吃掉整台机器。**§17.11 末尾「空载回暖 32 s / 60 s ⇒ 尚可」的说法须更正**——那 32 s 是「小提示 + 300 token 生成」的数字；真正的风险由**提示体积**设定，而提示可达 2900 token。

**F. 处置（本轮不改系统，改则测量失效）**

1. **矩阵不中断、不改造，如实跑完**——被量测的就是「按现配置的系统」，中途改提示预算或超时等于换掉被测对象。
2. **矩阵跑完后做有界反事实**：对每一处失败调用，用**原样提示**、放宽上限后重发，看仲裁结果**是否本来会改写该样本标签**。规模仅数十次调用，不触碰主运行，用以界定本次缺陷对判据两列的实际影响。若某处确实会改写，须在报告中**按方向单独列出**（修复的假阳性 / 新引入的假阴性），不得混入引擎比较。**工具已写定并提交（`4548270`）**：`models/audit/tools/llm_timeout_counterfactual.py`（26 项测试，`tests/test_llm_timeout_counterfactual.py`）。**预登记判据（先于任何反事实运行写定）**：一次失败**有实质影响**当且仅当反事实的 `predicted_label` 与记录值**不同**；仅 finding 判读变化、风险级变化、`llm_state` 变化**都不算**。实质变化**按方向分列**（`false_negative_repaired` / `false_negative_introduced` / `false_positive_repaired` / `false_positive_introduced`），**不得合并成一个「有变化」的数**。实现要点：①复用**生产** `analyse_sample`；②**两个层级都收**——文件级失败只落在文件摘要上，而策略读的正是文件摘要，只扫 finding 会**少算受影响样本（朝好看的方向少算）**；③**拒绝在矩阵运行期间重放**（在量测窗口内花模型调用会扰动被解释的那次运行，且受影响集会变成移动靶；`--dry-run` 因不写不调而豁免，并显式警告其列表是快照）；④**两个上限一起放宽**——HTTP 超时 60 s → 300 s，且 `num_predict` 加下限 800（生产为发现级 200 / 文件级 300）。**这不是「唯一改动是超时」**：D 节已证失败有两个家族，只放宽超时会**修不了截断那一半**，因而把 `parse_error` 全部重放成同一失败、得出「无实质影响」的假结论。两个补丁都**只在调用确被截断/超时时才起作用**，故反事实问的仍是「那次失败」而非「另一条流水线」。
5. **反事实重放期间同样要 `nice`**：本机无 CPU 配额，重放会在被测机器上花模型调用；矩阵跑完后宿主虽空载，仍以 `nice -n 19` 起，且**绝不在矩阵窗口内跑 `--dry-run` 以外的任何动作**——D 节的 8 份受影响样本里，可能就有本会话早先**未降优先级**的 dry-run 自己造成的（该 dry-run 解析约 600 份 JSON，在 16 核被 `llama-server` 占 15.7 核时不被 nice 就让出）。**这是一处自查发现的仪器污染，登记备查**；其影响面同样由反事实上界覆盖。
3. 缺陷按 §11.9 同一处置：**登记、写进报告、H 之后修**（加 token 预算并显式截断标记、给失败加重试或明确的失败语义）。

**G. 本次同时修掉的三处仪表问题（自查，非他人反馈）**

- 我的监视器 `read -r unc oom pid nrun` **只吃第一行**，而容器侧 python 的 `print(n)` 带换行，致 `oom_kill` / `llama-server` pid / run 计数**三路读数恒为空**——空值恰好长得像「一切正常」，已加 `tr '\n' ' '` 并单发验证四值均可解析。**UNCERTAIN 通道自始有效**（它在第一行）。
- 容器内残留一条指向**已中止矩阵**日志的孤儿 `tail -F`（pid 100274）与上一场的残留采样回路（pid 363 的 `while true` 内存采样），均与被测无关，登记备查。
- 本机无 CPU 配额（`NanoCpus=0`），故模型与宿主其它工作**共享全部 16 核**；这解释了为何宿主负载几乎等于模型自身占用，也意味着**任何宿主侧活动都会扰动判定**——故矩阵期间除只读检查外不跑编译、不跑 semgrep。

### 17.13 无载矩阵期间容器 OOM **杀掉了 LLM 服务本身**（2026-09-24T08:22:13Z，落在 `semgrep-run1`）

**结论先行**：容器 cgroup 长期贴在 7 GiB 上限上（`memory.peak` **恰好等于** `memory.max`），于 **08:22:13Z** 触发 OOM，**被杀的是 `llama-server` 本体**，ollama serve 约 40 s 后把它重新拉起。这一次落在 semgrep 轮次，方向**对 semgrep 不利（保守）**；但同一机制若落在 `regex` 轮次，会**抬高 regex 的 FPR**、把 `ΔFPR` 变小，**可能制造假通过**——而 `regex-run2/3` 尚未跑，故这是**悬在判据上的持续威胁**。

**A. 证据链**

1. `memory.events`：`oom_kill 1`、`oom 2`、**`max 223067`**（触顶次数），`memory.peak == memory.max == 7516192768`（恰为 7 GiB），事发后 `memory.current` 仍为 7.34 GB ≈ **上限的 98%**。即**不是一次偶发，是长期贴顶**。
2. **runner 身份实测**：容器内 pid 129759（宿主 346714），其 `ppid` 为 ollama serve（容器 73831 / 宿主 191310）。`/proc/129759/stat` 的 `starttime=2428239` ticks 对 `uptime=24330` s ⇒ **启动距今仅约 48 s**；同进程 `utime=63154` ticks ⇒ 这 48 s 里已耗 631 s CPU（≈1315%），即**新进程正在加载/预填充**。两条合起来即「被杀后重启」。
3. **日志里没有那次 500**：`/root/taa/ollama.log` 最后一条 500 是 **08:17:27**，08:22:13 无任何 500——**被杀的 server 无法为自己写日志**。这是「沉默即失败」的又一例（同 §17.12 G 的 `read` 空值）。
4. **一处差点误判的自证**：`tail` 里出现 `task 115`，而我先算得 runner 只有 48 s 寿命，两者矛盾。实测后结论：**`task N` 是 ollama serve 的计数器，跨 runner 重启不归零**，故不能据它判断 runner 是否重启。**日志里的计数器不属于你以为的那个进程**——与 §17.11 第 6 条（须 `readlink /proc/<pid>/fd/1` 才能确认日志归属）是同一族错误。

**B. 机制与影响面**

- 死亡→重启窗口内到达的调用得到**连接失败**（reason 属反事实工具的 `other` 类，**不是 `timed out`**），落成 `UNCERTAIN`；按 §17.12 更正后的 fail-closed 语义 ⇒ **抬高该臂 FPR**。
- 重启后头几次调用还要付 **~29 s 模型加载**并压在 60 s 上限上 ⇒ **失败窗口比「死亡瞬间」更长（约 1–3 分钟）**，不是单点。
- 落点：事发时 `semgrep-run1` 正在 `dd-0017`/`dd-0018` 附近（`dd-0017` 目录已建、报告未写）。
- **第二次（09:39:57Z，`oom_kill` 1→2）**：落点为 `semgrep-run1` 的**最后一份样本 `sr-0156`**——311 个目录已建满、只有它的报告缺失，新 runner pid 150886（`utime` 仅 128 ticks，刚起）。**杀伤面 = 1 份**，且 `sr-0156` 是**恶意**样本（§16 记为 semgrep 臂 6 个恶意 TP 之一），失败方向推向恶意 ⇒ **标签不变，判为无实质影响**（待反事实复核）。
- **事后补查（09:19Z，覆盖监视器空白的半小时）**：`oom_kill` 仍为 1、`llama_pid` 恒为 129759 ⇒ **空白期无污染**。`regex-run1` 判定分布 `BENIGN 245 / MALICIOUS 65 / UNCERTAIN 1`（65+1=66=`tp49+fp17`，自洽）；`semgrep-run1` 199 份、`UNCERTAIN 2`。

**B2. 结构不对称：内存压力是 semgrep 臂自身的性质（本次最重要的推论）**

- **实测事实**：`oom_kill` 在 **08:22 之前恒为 0**——该计数自 cgroup 创建起累计，故它覆盖了 06:47–07:15 的**已中止受载矩阵**与 07:09–08:08 的 **`regex-run1` 全轮**。两次 OOM（08:22、09:39）**全部落在 `semgrep-run1`**。
- **`max`（触顶次数）的加速度**：08:20 为 221606、09:19 为 223067（一小时 +1461），09:40 为 **524488**（二十分钟 **+301421**）。即**触顶几乎全部由 semgrep 轮贡献**。
- **机理**：`regex` 轮**根本不跑 semgrep**，容器内存只有 llama-server（~2 GiB，实测 2175680 KB）对 7 GiB 上限；`semgrep` 轮要在此基础上叠上 semgrep 扫真实代码的峰值。故**不是运气，是结构**。
- **两条推论**：
  1. **危险方向（`regex` 轮被 OOM 污染 ⇒ 抬高 regex 的 FPR ⇒ `ΔFPR` 变小 ⇒ 可能制造假通过）在结构上不易发生**，因为 regex 轮不制造那个压力。**该推论已于 2026-09-24T09:49Z（`regex-run2` 进行到 8.6 min）实测确认**：`max` 触顶计数仍为 **524488**，与第二次 OOM 后记下的值**完全相同** ⇒ **regex 轮至今一次都没触顶**；同时 `oom_kill` 仍为 2。故危险方向**在 `regex-run2` 上关闭**，待 `regex-run3` 复核。
     **读法警告（新增，属本项目「数值看着像一回事、实为另一回事」的又一例）**：确认不能靠心跳里的 `mem=`。同一时点 `memory.current` = **5013 MiB / 7168 MiB**（看着像 70% 压力），但拆开是 `anon` **2910 MiB** + `file` **2052 MiB**——`file` 是读语料留下的**页缓存，可回收**，而 `anon` 里 `llama-server` 一个进程就占 2823 MiB（python runner 仅 28 MiB）。**真正指示压力的是 `anon` 与 `max` 计数的增量，不是 `memory.current`**；单看 `current/max` 会把 regex 轮误读成「也快贴顶了」。
  2. **偏置系统性地不利于 semgrep**：semgrep 臂的 LLM 仲裁被**自己的内存足迹**打掉 ⇒ 该臂 FPR 被抬高。故**若 semgrep 仍满足 `ΔFPR ≤ 0`，该通过是保守的、更可信**；**若它不通过，则必须用反事实区分「引擎的真实劣处」与「OOM 所致」**，不得直接把失败归给引擎。

**C. 处置（不改配置，事后量化）**

1. **不改 `--memory 7g`**：它属 §9.1 已定的五项参数，中途改会让 `run1` 与 `run2/3` 的被测条件不同，恰好破坏 `RUN_ORDER` 交替设计所要控制的那件事（机器漂移应收敛到 run 序号上，而不是混进引擎比较）。
2. 矩阵跑完后用**已修正的**反事实工具逐样本量化（它已能收 `other` 类，见 §17.12 F），并按方向分列。
3. **预登记的失效判据**：若某轮被 OOM 窗口覆盖的样本数与失败数达到**不可忽略**，该轮（乃至整轮矩阵）报 **不可判定**，**不得宣布通过**。诚实处置优先于产出结论——这与 §17.11 中止受载矩阵是同一条纪律。
4. **若判为不可忽略，处置优先级（预先写定，避免事后按结果挑选）**：
   - ① 若污染**限于某一对**（第 *i* 次 regex ↔ 第 *i* 次 semgrep，按 `RUN_ORDER` 的配对），**作废该对并只重跑该对**（约 2.8 h），以恢复三对齐全；
   - ② 若污染**跨越多个对**，或落在**无法定位**的窗口（产物里读不出是哪几个样本被覆盖），则整轮矩阵报 **不可判定**，并在报告中写明「本机在 7 GiB 下无法承载该判定的量测」；
   - ③ **不得**用「另两对通过」代替三对判定——§2 要求**逐对成立**，两对通过不是通过。

**D. 由此得到的第二条部署结论（与 §17.11 并列）**

§17.11 已证 **CPU 共置不可行**；本条补上**内存**：按 D4 生产拓扑（taa+semgrep 同容器、LLM 单独部署），在本机把 semgrep 与 LLM 放进**同一个 7 GiB cgroup** 时，**LLM 会被 OOM 杀掉**。故该拓扑在本机要求二者在**内存上也真正分开**，或在同一容器内给 LLM 预留**硬性下限**。这不是仪器假象，是配置的直接后果。

**E. 仪表自查（本项目第五次，仍是我自己的仪器）**

- 我的监视器原先只在「pid 变了」时报，而 runner 被杀到重启之间它**不存在**：空值与空值比对 ⇒ **不报警**。**「缺失」被读成了「正常」**——与 §17.12 G 那处多行 `read` 完全同类。已改为**缺失本身即报警**，并对重启**单列一条**（因为重启后头几次调用要付模型加载）。
- 另：我一度想用宿主 `ps` 的 RSS（632 MB）与容器 `ps` 的 RSS（2.07 GiB）不一致来推断「有两个 llama-server」。**实为同一个进程的两个 pid 命名空间视图**（`docker inspect .State.Pid`=7636，宿主侧 ollama serve 的 ppid 即 7636），且两次读数取自不同时刻。**跨命名空间比对读数前必须先确认 pid 映射**。

## 18. 留出集污染：两处规则改动是在留出集上选定并复核的（2026-09-24 发现）

**这一条的严重性高于 §17.13。** OOM 是仪器在测中被扰动（偏置**不利于** semgrep，保守）；这一条是**被测集合本身在判据之前被朝着 semgrep 的方向调过**。二者方向相反，不可互相抵消地谈。

**发现经过**：`semgrep-run1` 的判据读数 `ΔFPR = +0.0065` / `Δrecall = +0.0382`（`ΔTP = +6`、`ΔFP = +1`）与 §16.1「终局读数」**逐位相同**。两套语料不该如此巧合，遂回溯。

**A. 事实链（全部为时间戳与提交记录，非推断）**

| 时刻（2026-09-24 +0800） | 事件 | 证据 |
|---|---|---|
| **11:22:33** | 留出集语料落盘，**此后未再写过** | `models/audit/benchmarks/audit-holdout/` 的 `corpus-list.json`、`corpus-report.json`、`provenance.json` 及全部 311 个样本目录 mtime 均为 `11:22:33`；容器内同一副本为 `03:22:33Z`（`docker cp -p` 保时）⇒ 两侧同为一次写入，**没有事后重建** |
| 11:22–11:23 | 留出集上的 H1.3 parity 运行 | `models/audit/audit-results/holdout/engine-compare/regex-run1/`（311 个样本目录，`confusion-matrix.json` = `tp49/fp17/tn137/fn108`）与同目录 `corpus-parity-go-vs-python-regex.json` |
| **12:04** | `dd4ed87` §16 规则级归因实测 | 该节自述读数口径为「**311 样本**，两臂同集，`--llm-backend none`」；其 regex 行 `49/17/137/108` 与上一行 parity 运行**逐字相同** |
| **12:08** | `9e7cbfb` 收窄 `taa-env-secret-python`（`ENV_001`） | 改动依据即 §16 的 `ENV_001` 逐规则归因 |
| **12:29** | `4f4d0be` 补 `_pickle` 覆盖（`OBF_001`） | 同上 |
| 12:50 | `d6f40bd` §16.1「对齐后的实测」 | 两次改动后**在同一 311 样本上**各重跑复核 |
| 14:47 起 | H2.1 判定运行（受载 → 中止 → `LOAD=0` 重启） | 同一语料 |

**样本身份是独立的第二道证据**：§16/§16.1 引用的 ID —— `sr-0149`、`sr-0150`、`sr-0155`、`sr-0156`、`dd-0011`、`dd-0029`、`dd-0055/0056/0057`、`pypi-0001…0081`、`pypi-0080` —— **全部落在 `models/audit/benchmarks/audit-holdout/` 内**（已逐个 `find` 确认）。而**拟合集 `audit-100` 是另一个命名空间**（`p1_xgboost_finance` 等 100 个样本，无 `sr-`/`dd-`/`pypi-`/`cq-` 目录）。故 §16/§16.1 用的**不是**拟合集。

**B. 违反的是本计划自己的预登记，不是我的事后标准**

证据 spec §9.9 与本轮 spec §12 写死的口径是：「需要一份**不参与任何规则调整**的样本集——**在规则冻结之后生成、且生成后不对规则做任何修改**」。实际顺序是：**生成（11:22）→ 在该集上诊断（12:04）→ 据诊断改规则（12:08、12:29）→ 在同一集上复核（12:50）→ 在同一集上判定（14:47 起）**。四条全违反。

**C. 偏置方向：恰好落在判据的两个量上，且利于 semgrep**

- 改动 1（`ENV_001` 收窄）把 `ΔFPR` 从 `+0.0714` 压到 `+0.0065`（**10 倍**）——这是整个过程里唯一一次把判据从「差 7 倍容差」推到「差一个样本」的动作。
- 改动 2（`_pickle`）把 `Δrecall` 从 `+0.0255` 抬到 `+0.0382`，并新增一个 TP。
- **被调节的量就是判据的两个量本身**（§2 的 `ΔFPR ≤ 0` 且 `Δrecall ≥ 0`）。这不叫「对齐后无退化」，叫**在判定集上做定向优化**。

**D. 对结论的影响（分三种情形写，避免事后择一）**

1. **「留出集」这个标签不再成立**：本语料在 11:22 之后、判定之前被用于改规则，它现在是**开发集**。H2 的读数只能作为开发集读数报告，**不得**写成 held-out 非劣性结论。
2. **若 H2 判 FAIL，该 FAIL 仍可报**，且比在干净留出集上的 FAIL 更强：在一个**已被朝着 semgrep 调整过**的集合上都没能通过。但**不得**据此推断「在未见过的新代码上差多少」——幅度不可外推。
3. **若 H2 判 PASS，该 PASS 不可解释**，因为「为让它通过而做的调整」已经发生过一次，无法与「引擎本就非劣」区分。**这正是 0 容差判据最怕的那种通过。**

**E. 两处修复不该撤回，也不是「作弊」**

§16 的分析本身是对的，且是**真缺陷**：semgrep 的 `taa-env-secret-python` 对 `$KEY` 无键名约束而 regex/Go 侧有（两臂语义不同，`ENV_001` 在 regex 臂 311 个样本上**一次都没触发**），`_pickle.load/loads` 是覆盖缺口。**错的是拿留出集当拟合集用，不是修复本身**——修复在未见过的新代码上同样正确。撤回去只会留下已知缺陷。

**F. 待裁定（我不擅自选择；三条路代价不同）**

- **(a) 重建一份全新留出集**，规则冻结后不动，重跑 H2。代价：建集本身不贵（§12.5 记 3.1 s + 检索工时），但 **H2 矩阵每对约 2.6 h、三对约 7.9 h**，且 §17.13 的 OOM 风险仍在（`LOAD=0` 下已实测两次）。
- **(b) 保留现语料，把 H2 降级为开发集读数**，非劣性主张**收回**，报告按 D1 措辞写。
- **(c) 现语料照跑完 + 另建一份小而干净的确认集**（例如 100 条、规则冻结后生成、只跑一对）作为独立复核。
- **无论选哪条，当前矩阵都继续跑完**：它是对本语料的唯一读数，且是 D2 那条 FAIL 结论的载体，中途停只会同时失去两样东西。

**G. 附带发现：改规则所依据的那次 semgrep 读数，产物已不存在**

§16（`semgrep 54/28/126/103`）与 §16.1（`53/18/136/104`、`55/18/136/102`）的三次 semgrep 全量运行，其产物在**宿主与容器中均已不再存在**——两处唯一留存的留出集 semgrep 产物是 H2 的 `semgrep-run1`。这与 §14 写死的「凡用于改变预登记规则的测量，必须由带测试的模块产出」**精神相冲**：工装（`arm_rule_divergence.py`，18 条测试）是合格的，但**输入产物没留下**，读数**不可复跑复核**。所幸 §16.1 的终局行 `55/18/136/102` 与 H2 的 `semgrep-run1` **逐位相同**，属事后独立复现。

**H. 同一巧合顺带给出一个观察（未证实，登记备查）**

`--llm-backend none` 与 `static-llm + ollama(assist)` 下，两臂的混淆矩阵**逐位相同**（regex `49/17/137/108`、semgrep `55/18/136/102`）⇒ 在本语料上 **LLM 仲裁没有翻动任何样本的标签**。最可能的机制与 §17.12 那条一致：本语料**零低危发现**，静态层已由高/中危命中把标签定死，`assist` 下 LLM 的无罪判定不解除阻断。**这是推断，不是实测**；若要写成结论，须按 §14 用带测试的模块逐样本比对 `--llm-backend none` 与 `ollama` 两次运行的 `predicted_label`。

## 19. 中断登记：矩阵在 run 2 中途就死了，四天后的宿主重启只是收尸（2026-09-28 发现）

**A. 事实（实测；本节所有数字均可复核）**

| 项 | 读数 | 来源 |
|---|---|---|
| 容器上一次退出 | `2026-09-28T02:44:43Z` | `docker inspect .State.FinishedAt` |
| 当前容器实例启动 | `2026-09-28T02:51:57Z` | `.State.StartedAt` |
| 宿主本次启动 | 2026-09-28 10:42 本地（10:55 测得 `up 13 min`） | `uptime` |
| 驱动日志最后写入 | `2026-09-24T09:40:32Z`，末行 `----- regex run 2 -----` | 容器内 `stat` |
| 容器自上次启动起连续运行 | `2026-09-24T01:56:56Z → 2026-09-28T02:44:43Z` ≈ 4 天 | `.State.StartedAt` |

产物清点（容器内 `find` 实测）：

| 轮次 | `audit_report.json` | `confusion-matrix.json` | 处置 |
|---|---|---|---|
| `regex-run1` | 311/311 | 有 | **完整，保留** |
| `semgrep-run1` | 311/311 | 有 | **完整，保留** |
| `regex-run2` | 288/311 | 无 | **不完整，丢弃重跑** |

**B. 归因：不是这次重启杀的**

日志末行写在 `09:40:32Z`，而 run 2 只留下 288 份产物。以 `regex-run1` 的实测速率（3562 s / 311 条 ≈ 11.45 s 一条）折算，run 2 又推进了约 55 min，即驱动进程大约在 **2026-09-24T10:35Z 前后停止推进**。而容器本体此后又活了四天才在重启时退出。⇒ 驱动在四天前就停了，容器随后空转四天，**重启只是给一具已经停跳的躯体收尸**；把死因记成"重启"会指向错误的防护措施。

死因本身未被直接观测到（日志无异常、退出码无从取得）。最可能是驱动进程挂在上一轮会话的进程组上，会话结束时被一并收掉——这正是本轮改用 `docker exec -d`（让容器持有驱动、不挂会话）的理由。

**C. 为什么 pair 1 可直接沿用，run 2 不能**

§2 判据**逐对成立**，第 1 对（`regex-run1` ↔ `semgrep-run1`）两臂都完整、都带自产混淆矩阵，是一对合法读数。run 2 缺矩阵且少 23 份样本，沿用即「用比语料少的样本打分而任何地方都不报错」——正是下面完备性谓词要挡的那一种。

**D. 引入的恢复能力与它的三条边界（`568faee`）**

`h2_loaded_rounds.sh` 新增 `RESUME`，测试见 `tests/test_h2_loaded_rounds_resume.py`（8 项全绿，另做一次变异检查：把完备性谓词弱化为「矩阵存在」后，`test_a_matrix_without_all_the_reports_is_rerun` 如期失败）。三条边界写死在这里：

1. **默认关闭**（`RESUME=0`）：预登记协议一行未改，默认行为仍是重跑全部六轮，故没有任何判定会依赖上一轮矩阵恰好留下的产物。
2. **完备性由产物判定**，既不看日志、也不看目录是否存在：`confusion-matrix.json` 存在 **且** `audit_report.json` 计数等于 `EXPECTED`（与横幅同源同一个数，避免「完整」按另一个数判定）。
3. **失败仍然停机**：resume 就在同一个循环里，某轮退出非零照样 `break`。

**E. 续跑的协议参数（与首启逐项相同，唯 `RESUME=1`）**

`LOAD=0`、`POLICY=assist`、`MODEL=qwen2.5-coder:3b`、`SEED=42`、规则 `c06ffd2c`、`OUT=/root/taa/verify/h2-assist-unloaded`，六轮交替次序不变。驱动自带的 `warm_model` 照旧先跑。续跑边界在驱动日志里追加一行标记，以便事后区分首启段与续跑段。

**F. 「无载」这个词的限度（登记，不修饰）**

宿主的**基线负载不是零**：本 agent 会话（`claude`，实测 ≈10% CPU）与 VS Code server（≈5%）持续占用约 0.5–1.0 核；在没有矩阵、只有这些常驻进程时，`load1` 已经 ≈1.3。所以 `LOAD=0` 的准确含义是「除常驻工装外没有压测负载」，**不是**「机器空闲」。该基线在六轮、两臂上恒定，故在配对差分里相消；但它占掉的余量是真实的，也是 §17.13 那次贴着 7 GiB 上限行走的背景之一。

**读法补充（2026-09-28 实测，防止把正常状态误读成污染）**：`load1 ≈ 1.3` 只在**没有 LLM 调用在飞**时成立。调用期间 llama-server 在 `NanoCpus=0` 下按设计占满整机，实测 `regex-run2` 跑 LLM 密集样本时 `load1 = 16.06`（16 核全饱和，1/5/15 分钟均值 16.06/12.66/6.74 呈爬升），而进程表里只有**一个** `audit_benchmark_eval`。⇒ **调用中的高负载既是预期的、也是必需的**（它是被测仪器本身，不是外加负载）；`LOAD=0` 约束的是**压测负载**的有无，不是核的空闲。这与 §17.11 判定「受载矩阵作废」的理由一致：作废的原因是 semgrep 压测与 LLM 抢核把仲裁逼到超时，而不是核被占用这件事。

**G. 发射前的两处仪器故障（记录以免重犯）**

1. 第一版等待器的条件是「`pgrep -x dpkg` 无匹配」。**瞬态进程不能当作「某事正在做」的证据**：`unattended-upgrade` 是逐包 spawn `dpkg` 的，两次之间有空隙。实测它在报出 `CLEAR: load1=1.39` 之后 30 秒，`dpkg` 13812 仍在删旧内核。
2. 第二版探针用非 root `open()` + `fcntl.lockf(LOCK_NB)` 抢 `/var/lib/dpkg/lock-frontend`，只拿到 `EACCES`（权限不足），与 `EAGAIN`（确实被锁）**分不开**，故该探针不能判定。最终采用 `/proc/locks` 按 inode 查持有者（任何用户可读）：实测报出持有者 pid **5939**，即 `unattended-upgrade` **父进程本身**持有整个运行期 ⇒ 无空隙问题。等待条件同时要求 `load1 < 2.0` 连续两次成立，避免锁一释放就在负载衰减期内开跑。

**H. 顺带发现：判定产物对「用的是哪一版规则」自称不了（登记，本轮不修）**

续跑前复核规则一致性时实测到的事实：

- 规则文件 md5 = **`c06ffd2c1518ced9815885d7a7224982`**，宿主与容器**一致**，与 §17.5 记录的 `c06ffd2c` 一致 ⇒ 续跑与 pair 1 同规则。
- 文件 `mtime = 2026-09-24T04:28:53Z`（= 12:28:53 本地），落在 §18 A 时间线的第二条（12:29 `4f4d0be`，即第二处规则改动）上，**此后未再被触碰** ⇒ 规则在判定开跑（`07:09:23Z`）之前就已冻结，六轮同版。

但产物本身**不记录规则内容**：`manifest-*.json` 里的 `rule_set_version` 是常量 `default-rules-13`（`audit_benchmark_eval.py:49`、`:1454` 直接赋值），与规则文件内容无关；整个评测工具里**没有任何 `hashlib`/md5/sha256 调用**。⇒ 这六轮产物**无法自证**是哪一版规则产出的，唯一的内容锚点是**手工记录在本节与 §17.5 里的 md5**。这与 §18 G 是同一类缺口（改规则所依据的读数已不可复跑），也与 §14 的「凡改变预登记规则的测量必须由带测试模块产出」精神相冲：工装合格，但**产物留不下内容指纹**。本轮不修（改工具即改判定工装，中途改会破坏 `RUN_ORDER` 要控制的机器漂移），登记待 H2 之后再处理。

**I. 两处宿主事实，决定这条矩阵能否自己跑完**

1. **有待重启**：`/var/run/reboot-required` 于 10:55 写出，包为 `linux-image-6.8.0-142-generic` 与 `linux-base`；而**当前运行的内核仍是 `6.8.0-139-generic`**（已写进续跑的边界行，可事后核对）。`Automatic-Reboot` 未配置（§17.11 已核），故**不会有人替我重启**；但用户手动重启会杀死矩阵。
2. **容器 `RestartPolicy=no`**：宿主重启后容器**不自启**。本次重启后是 10:51:57 才被手工起起来的（`FinishedAt=02:44:43Z` → `StartedAt=02:51:57Z`，相隔 7 分钟）。⇒ 重启后必须先起容器，矩阵才可能续上——这是 `RESUME` 之外的又一步人工动作。

**J. 监视器有两处静默分支，已修并钉住（`4eeceb9`）；另登记一处我自己引入的扰动**

读监视器代码时发现它的 gather 探针有**一个静默分支**，恰好在它唯一要报警的那件事上静默：

- 模型 runner 不在时（正是 OOM 击杀的情形），探针**不输出 pid 字段**，于是其后每个字段左移一位：运行数落进 `pid`，`pid_now` 变成数字，`llama-server GONE` 告警拿数字比 pid，**永不触发**；心跳同时把 anon 内存数当成运行数报出。
- 心跳原本报 `current/max`，读起来像"逼近上限"。而 `current` = anon（真实压力）+ 可回收 page cache：本机实测 `current=4133/7168 MiB` 而 `anon=2154 MiB`，读数方向偏于报警。

两处均已修（pid 字段恒输出，缺失时写字面量 `none`；内存改为 `mem_anon/mem_file/mem_current/mem_max` 分解报告）。**不是断言而是变异验证**：把旧的 gather 行还原后，对齐测试的期望值 `runs=3 uncertain_total=0` 实测变成 `runs=2154 uncertain_total=0 oom_kill=0 llama_pid=3`，四个内存标签全部错位一格、`mem_max` 为空——这就是那处腐蚀的实测形态，也证明了旧代码下 GONE 告警不可能触发。测试见 `tests/test_h2_matrix_watch.py`（5 项，全绿；为可测把轮询周期与 cgroup 路径改成参数，测试用假 docker/假 ps/夹具 cgroup 驱动真脚本）。

**登记扰动**：为跑这 5 项测试与两次变异检查，在 `regex-run2` 正在测量期间的 03:00–03:01Z 向宿主加了约 30 s 的轻负载（已 `nice -n 19`；估算 ≤0.1 核·秒，相对 `claude`+VS Code 常驻的 0.5–1.0 核基线可忽略）。登记而非默认无害，依据是 §17.12/§17.13 已确立的口径：对这条运行的任何扰动都要登记，不能假设它无害。

**K. 续跑的实测落地（2026-09-28T02:57:45Z 发射）**

驱动在容器内独立运行（`docker exec -d`，pid 381，`.running`=381），边界行记下 `host kernel=6.8.0-139-generic rules_md5=c06ffd2c1518ced9815885d7a7224982 driver=7c867ae4ae7f31c4`。恢复行为实测符合设计：

```
model warmed (attempt 1)
----- regex run 1 (already complete, kept) -----
  tp=49 fp=17 tn=137 fn=108
----- semgrep run 1 (already complete, kept) -----
  tp=55 fp=18 tn=136 fn=102
----- regex run 2 -----
```

两组被保留的读数与重启前**逐位相同**。产物形态已抽查与 pair 1 一致（`audit_report.json` 同为 7 个键；`llm_state`/`llm_duration_sec` 在 `sample-results.jsonl` 而不在此文件里）。

**L. 这条运行的耗时几乎全部是 LLM 时间（实测），故续跑段的慢速率不是机器变慢**

续跑初期我按"已出报告数 / 已过秒数"算出 19 s/条（run 1 是 11.45 s/条），一度疑心机器慢了 67%。**这是读错了指标**。`regex-run1` 的 `sample-results.jsonl` 实测：

| 量 | 读数 |
|---|---|
| 行数 | 311 |
| 调用过 LLM 的样本 | 66（`ok` 58、`parse_error` 4、`llm_unavailable` 4） |
| `llm_duration_sec` 总和 | **3545 s** |
| 该轮总时长 | **3562 s** |
| 单样本最大 | **431.4 s**（`dd-0056`，状态 `llm_unavailable`，即失败重试累计） |
| 前 5 名合计占比 | **31.1%**（全是 `dd-*` 族，且 ID 连续） |

⇒ **3562 s 里有 3545 s 是 LLM 调用**，非 LLM 样本的固定开销可忽略（`scan_duration_ms` 实测为 1）。所以单位时间的产出完全由"这一段样本是否发现、发现几处"决定：实测窗口 03:01:23→03:03:53 是 3 份/150 s（50 s/条），03:03:53→03:05:02 是 2 份/69 s（34.5 s/条）。而 `dd-*` 族集中在语料前段、又占三分之一的 LLM 预算，故**前段慢、后段快**是语料决定的，不是机器漂移。这条也解释了为什么 `llm_unavailable`（失败重试）是最贵的结果：`dd-0056` 一次 431 s。

**M. 剩余时间预报（据 run 1 实测线性外推，属预报不是实测）**

同一语料、同一顺序、同一引擎，故用 run 1 的实测时长外推：`regex-run2` ≈ 59 min、`semgrep-run2` ≈ 92 min、`regex-run3` ≈ 59 min、`semgrep-run3` ≈ 92 min，合计 ≈ **5.0 h**。续跑发射于 `02:57:45Z`（评测进程约 `02:58:10Z` 起），故矩阵**预计约 `08:00Z`（16:00 本地）跑完**。此预报只用于安排监视器；判定一律以 `confusion-matrix.json` 落地为准。

## 20. 裁定：H2 降级为开发集读数，非劣性主张收回（你于 2026-09-28 选 §18 F 的 (b)）

**A. 裁定内容**

你选 **(b)**。此处只记录被选中选项的原文，**不代你补充理由**：(b)「**保留现语料，把 H2 降级为开发集读数**，非劣性主张**收回**，报告按 D1 措辞写。」

**B. 三条效力**

1. **语料身份**：`audit-holdout` 由「留出集」改判为**开发集**；H2 六轮的读数**只能**作为开发集读数报告。
2. **主张状态**：**「semgrep 在未见过的新代码上非劣」这一主张收回，即未确立**。措辞上**不得**把「收回」写成「证否」的同义词：唯一的测量跑在一份被人为朝 semgrep 调过的集合上，故它同样**不构成**「semgrep 其实更差」的结论。§18 D2 允许报 FAIL 方向，但**幅度不可外推**。
3. **操作后果**：默认引擎**保持 `regex`**——spec 第 548 行「**在留出集通过之前，默认引擎不得切到 semgrep**」；实测当前值为 `internal/config/config.go:287` 的 `CodeScanEngine: "regex"`，本次裁定**不动它**。**不进入灰度**，spec 第 717 行的灰度门槛因此**未满足**。

**C. 未选 (a)/(c) 的后果：问题保持开放；并登记一处规范缺口**

(a) 重建干净留出集、(c) 另建小而干净的确认集，**均未选**，故「semgrep 在一份干净留出集上是否非劣」**仍未被回答**。它现在是**一个有现成配方的开放待办**：建集配方与实测成本见 §12.5，判定口径见 §2，判据工具见 §7。

**规范缺口**：spec 的阶段 H 出口是**二值**的（第 576/577 行「留出集通过 → 允许切默认引擎」／「留出集未通过 → 回到规则对齐循环」；第 598 行阶段表 H 行「通过才允许切默认引擎」）。本裁定产生了**第三种状态：未确立**——判据的**仪器自身**不合格（语料在判定前被用于改规则），故判据**从未在其自身前提下被评价**。spec **没有这一分支**。这不是本裁定的缺陷，是规范缺一条「证据仪器半途失效」的出口。**本轮不改 spec**（阶段中途不动判定工装与规范，同 §17.11 与 §19 H 的处置），登记待 H 收尾后一并处理。

**D. 对报告措辞的硬性约束（沿用 §18 D，并据本裁定收紧）**

1. **禁止**出现「留出集非劣」「held-out non-inferiority」及任何等价表述，一律改为「**开发集读数**」。
2. 若三对判 FAIL：**可报**，且强于干净留出集上的 FAIL（在**朝 semgrep 调过**的集合上仍未通过）；但**幅度不得外推**到未见过的新代码。
3. 若判 PASS：**不可解释，不得报为通过**（§18 D3）。
4. `gate` 读数照 §2 **并列**报告，且**同样**标注为开发集读数。
5. 报告须写明：非劣性问题**未被回答**，而**不是**被回答为否。

**E. 本裁定不改动的东西**

- 判据一行未改（§2：0 容差、逐对成立、`assist` 主判定、`gate` 并列）。
- 矩阵继续跑完（§18 F 预登记：「无论选哪条，当前矩阵都继续跑完」）。
- §18 E：两处规则修复是**真缺陷**的修复，**不撤回**。
- H2.2（`gate` 重打分）、H2.3（Prompt 等价性逐条归因，§11.5）、H2.6（0 容差判定）照原计划执行——它们产出的是**开发集读数**，不因此失去意义。

## 21. 更正：续跑不比 run 1 慢；但实测到 60 s 是**客户端**上限、不是服务端工作时限（2026-09-28）

**A. 被撤回的说法**

我在续跑初期据「已出报告数 / 已过秒数」判断 run 2 比 run 1 **慢 1.34×**（27 s/条 vs 20 s/条），并据此疑心机器退化。**该说法按下面的实测撤回**——慢的是我选的指标，不是机器。

**B. 同口径实测（同样 25 个样本：`cq-0001`…`dd-0020`，区间由两轮各自的产物 mtime 界定）**

| 量 | run 1（09-24） | run 2（09-28） |
|---|---|---|
| 产物 mtime 跨度 | 486 s | 651 s |
| 区间内 ollama 请求数 | **39** | **38** |
| 服务端请求时长之和 | **1098 s** | 650 s |
| 单请求最大（服务端墙钟） | **611.8 s** | 53.8 s |
| prefill 速率 | 24.6 ms/tok（40.6 tok/s）、72658 tok | **18.5 ms/tok（54.1 tok/s）**、21829 tok |
| decode 速率 | 109.1 ms/tok（9.2 tok/s）、12967 tok | **94.9 ms/tok（10.5 tok/s）**、3431 tok |

**C. 结论**

1. **请求数相同（39 vs 38）** ⇒ 两轮做的是同一份工，续跑没有多发调用。
2. **模型速率 run 2 反而更快**（prefill 快 33%、decode 快 14%）⇒ **机器没有退化**。先前「慢了」的印象来自把「报告的产出速率」当成了「机器速率」，而产出速率由**这一段样本的发现密度**决定（§19 L 已立此口径，我在此处又违反了它一次）。
3. **两个跨度量的不是同一个量**：run 1 的服务端时长之和（1098 s）**超过**其跨度（486 s），在单槽串行服务上不可能，除非有请求**并非都在该区间内**。实测正是如此——多出来的正是那个 **611.8 s 的请求**。

**D. 真正的发现：60 s 只终止客户端等待，不终止服务端工作**

计划 §9 写的是「Ollama 调用硬超时 60 s 且**无重试**」。实测：**超时只让客户端放弃**——日志里有一条 **611.8 s** 的请求时长（上限的 10 倍）。

**该数字的内部构成无法从日志分辨**，须写明：它既可能是「服务端真的算了 611.8 s」，也可能是「排在别人后面等了 550 s + 自己算了 60 s」（ollama 的 GIN 时长含**排队**）。按 §21 C 实测的 token 速率，单请求 611.8 s 的纯计算需要约 6000 个输出 token，远超审计调用的输出形态（均值约 68–80），故**排队成分更可能占大头**。两种解释下 C 节的三条后果都成立，且第二种**更强**：槽被占用到客户端等待上限的 10 倍。

三条后果都须写入报告：

1. **超时不是免费的**：被放弃的调用继续占用**那一个槽**（日志实测 `id 0`、`n_ctx_slot = 4096`），后续请求排在「已经没有人在等的活」后面 ⇒ 60 s 上限**会被前一个已放弃的调用推爆**。级联需要**并发提交**才累积；本矩阵样本**串行**提交，故这里只观察到一次性延迟（见 F）。
2. **方向是 fail-closed**（§17.12：失败 → `UNCERTAIN` → 高/中危发现上 `HIGH` → `assist` 阻断）⇒ 它**只抬高 FPR**，不可能掩盖恶意样本。这是**机制的**方向判断；在 pair 1 上的**不对称性断言已被 F 节撤掉**。
3. **与 §17.13 的 OOM 同源**：§11.9 那条 22 MB 提示的调用，客户端 60 s 就放弃了，而服务端**仍会轮到它**——内存压力发生在**客户端已经不再等待之后**。这与上面两种解释都相容。这解释了为什么 OOM 击杀与超时率看上去互不相干：二者由同一个被放弃的长调用驱动。

**E. 不影响 §2 的判定**

pair 2 ＝（`regex-run2`, `semgrep-run2`）在同一天、同一机器状态下**背靠背**测量，逐对比对仍然成立；run 1 与 run 2 的差异是**跨对**的，而判据只比**对内**。这正是 `RUN_ORDER` 交替设计要挡住的那类漂移。

**F. 对 D2「不对称」断言的实测核查：pair 1 上不成立**

D2 说「级联超时的偏置不利于发现多的一臂」。这是**机制推理**，pair 1 的两份 `sample-results.jsonl` 可以验（读两个文件，负载可忽略）：

| 臂 | 调用 | `ok` | `parse_error` | `llm_unavailable` | **未仲裁** | tp | fp |
|---|---|---|---|---|---|---|---|
| `regex-run1` | 66 | 58 | 4 | 4 | **8（12.1%）** | 49 | 17 |
| `semgrep-run1` | 73 | 67 | 4 | 2 | **6（8.2%）** | 55 | 18 |

（`static_only` 245 / 238，即无高/中危发现、根本不需要仲裁的样本。）

**结论：断言在 pair 1 上不成立。** 发现多的那一臂（semgrep）**调用更多（73 vs 66）但未仲裁更少（6 vs 8）**。若级联真按发现量放偏置，semgrep 的失败数应当更高。

**但机制本身未被证否**，因为两点：D 的级联要**并发**才发生（单槽 + 客户端串行提交），而本矩阵是**串行**跑样本的，被放弃的调用只有在下一次调用提交时才阻塞后续——串行下它退化为一次性的延迟，而非累积级联。故 D2 描述的**是并发部署下的风险，不是本矩阵内的已观测效应**；报告须按此措辞，不得把它当成本语料的读数。

**对本语料更重要的一条推论**：两臂 FP 差只有 1 条（17 vs 18），而失败数差 2 条 ⇒ **两臂的差异不是由 LLM 失败驱动的**。这是 (b) 措辞里可以直接用的一句话：开发集上的 ΔFPR 不能归因于调用失败。

**G. F 的精确化：失败只落在 regex 侧，且是在掩盖劣势**（实测归因）

F 只说了「不是失败驱动的」。把失败**归因到样本**之后结论更强：

| 轮 | 失败 | 落在**良性**样本 | 落在恶意样本 | FP 总数 | **其中由失败造成** |
|---|---|---|---|---|---|
| `regex-run1` | 8 | **2**（`pypi-0057`、`sr-0012`） | 6 | 17 | **2** |
| `semgrep-run1` | 6 | **0** | 6 | 18 | **0** |

失败**只在 regex 侧造出 FP**（失败 ⇒ 阻断 ⇒ 良性样本被误报），semgrep 侧 **0 条**。这与 §21 D2 预测的**方向相反**（我预测偏置不利于发现多的一臂）。

pair 1 的判据读数（`fp+tn=154` 良性、`tp+fn=157` 恶意）：

| 量 | `regex-run1` | `semgrep-run1` | Δ = semgrep − regex |
|---|---|---|---|
| FPR | 17/154 = 0.1104 | 18/154 = 0.1169 | **+0.0065 > 0** |
| recall | 49/157 = 0.3121 | 55/157 = 0.3503 | +0.0382 ≥ 0 |

pair 1 **FAIL 在 ΔFPR**（与 §17.12 D-2 一致：重放不能翻转）。

**扣掉失败机制的确定性部分**（失败必然阻断，故良性样本上的失败**必然**是 FP；恶意样本上的失败是否仍为 TP 不由本步决定）：regex 的 FPR 变 15/154 ⇒ **ΔFPR = +3/154**，比实测的 +1/154 **更大**。

**报告可用的结论**：失败机制**掩盖**了 semgrep 劣势的约三分之二，**不是**它的成因。这一条直接堵死对 FAIL 最顺手的反驳（「你的 LLM 调用在失败」）。

## 22. 裁定：H 收尾即止，接入停在此处（你于 2026-09-28 在岔路上选定）

**A. 裁定原文（只记你选的那条的原文，不代拟理由）**

「先收 H 尾，接入停在此处（推荐）」——「矩阵跑完 → 出开发集读数 + gate 并列 → 写完报告 → 停在报告。不刷规则、不切 `CodeScanEngine`、不部署。接入等其他依据。这与「先证据后接入」一致：证据没成立，就不要接入。」

**B. 三项直接后果**

1. `deploy-docker.sh --scan-engine semgrep`（刷新容器内陈旧规则）**不执行**。这一条须记明：该步骤**不依赖非劣性、本可独立做**，你仍没选它，故这是**有意的不做**，不是被谁挡住。**「陈旧」已实测坐实**，三处副本的哈希如下：

   | 位置 | md5 | mtime (UTC) |
   |---|---|---|
   | `/opt/taa/semgrep/rules/python/rules.yaml`（**已部署，TAA 读这份**） | `34519c59…` | 2026-09-22 06:51:15 |
   | `/root/taa/verify/models/audit/semgrep/rules/python/rules.yaml`（工作副本） | `34519c59…` | 2026-09-23 02:29:10 |
   | `/root/taa/holdout/…/rules/python/rules.yaml`（**判据在用**） | `c06ffd2c…` | 2026-09-24 04:28:53 |

   即已部署规则**早于 §18 A 的两次规则改动**——它是 09-22 的版本，而判据跑的是 09-24 的版本。故报告须写明：**本论证据链的读数与容器当前默认部署所依据的规则不是同一份**。
2. `internal/config/config.go:287` 的 `CodeScanEngine` **保持 `regex`**，且此后是**有意的保持**，不再只是「按 spec 第 548 行暂时未切」。
3. 接入链（本地代码接入 semgrep → `docker.sh docker` 部署 TAA+semgrep 到容器测试 → D4 拓扑：semgrep 与 LLM 同容器、真实部署时 taa+semgrep 绑定而 LLM 单独）**整条停在报告**。

**C. 须写进报告的一条后果**

spec 第 548 行的门（「在留出集通过之前，默认引擎不得切到 semgrep」）现在**无限期关闭**：唯一能开它的路径是补建一份干净留出集并重判（原 §18 F 的 (a)），而你没有选。故「semgrep 作为默认扫描引擎」在本次证据链内**不会发生**——这不是**延后**，是**未取得资格**。报告不得写成「待后续观测即可切换」；正确措辞是「该门未被打开，且本次工作未安排打开它的路径」。

**D. 未受影响的，即「收 H 尾」的范围**

H2.1 矩阵照跑完（§18 F 的预登记：无论选哪条，当前矩阵都继续跑完）、`gate_rescore.py` 重打分、`engine_compare_report.py` 两基读数、反事实重放的 `Δrecall` 侧、H2.3（prompt 等价性）、H2.6（0 容差判定）、以及最终报告。全部产出按 §20 D 的五条措辞约束书写：**开发集读数**，非劣性**未确立**。

## 23. 仲裁失败的正确可读信号：`statistics.uncertain`，不是 `conclusion.verdict`（2026-09-28，监视器第三次缺陷）

**A. 缺陷**

监视器第 2 路（仲裁失败计数）读的是 `conclusion.verdict == "UNCERTAIN"`。但 verdict 是失败**被抬升之后的结果**，不是失败留下的痕迹：`assist` 策略下失败的 UNCERTAIN 会把高危发现抬到 `CRITICAL`，`verdict` 于是写成 `MALICIOUS`，`statistics.uncertain` 才是那条痕迹。

**B. 实测（pair 1 两轮各 311 样本，`sample-results.jsonl` 的 `llm_state` 为真值）**

| 轮 | `llm_state` ∈ {`llm_unavailable`,`parse_error`} 的样本 | `statistics.uncertain > 0` 的样本 | `verdict == "UNCERTAIN"` 的样本 |
|---|---|---|---|
| `regex-run1` | **8** | **8** | 1 |
| `semgrep-run1` | **6** | **6** | 2 |

**ID 集合逐位相同**（两轮都是 `bystat == byfail`：`True`，两侧差集皆空）。故 `statistics.uncertain > 0` **精确**等于「本样本至少有一次未仲裁」；verdict 只能找到 8 中的 1、6 中的 2。

**C. 后果**

「服务器还活着但持续报错」这一类失败潮，本该由这一路计数器报警，而旧信号会漏掉约 **7/8**。已修（`3e63d13`）：改读 `statistics.uncertain`，同时报**样本数**与**失败发现数**两个字段，并加 7 项测试（含两个方向的钉：失败但 verdict 是 `MALICIOUS` 必须计；verdict 是 `UNCERTAIN` 但无失败发现必须不计），**变异验证**（换回 verdict 信号）精确失败 2 项。

**D. 对报告的直接用处**

1. 失败痕迹**运行中即可读**（`audit_report.json` 随样本落盘），而 `llm_state` 要等轮末 `sample-results.jsonl`；报告若需要「失败率」的**实时**口径，用前者。
2. 两点提示：`sum(statistics.uncertain)` 是**失败的发现条数**（11 与 7），`> 0` 的**样本数**是失败的样本数（8 与 6）——两者别混。
3. 这给了 H2.6 一个**可独立复核**的口径：报告里的未仲裁率必须与这两个数一致，不是与 verdict 分布一致。

**已知的措辞不精确（待下次换监视器时一并改）**：心跳里的 `failed_samples` / `failed_findings` 是 `$OUT` 下**所有轮累计**，不是单轮——首报 `20 samples / 24 findings`（`03:52:54Z`）即 8 + 6 + 5 + 1。对告警用途无碍（任一次增长都意味着新失败），但标签应写成 `failed_samples_all_runs`。**报告一律用 `sample-results.jsonl` 的**单轮数**（§24 E 那张表），不用心跳的累计数。**

## 24. 整轮对比：两轮 regex 逐位复现；LLM 调用模型实测；§21 D 第二次更正（2026-09-28）

**A. 完整轮对比（`regex-run2` 已于 2954 s 完成，run 1 为 3562 s）**

| 量 | `regex-run1` | `regex-run2` |
|---|---|---|
| n / `invoked` | 311 / **66** | 311 / **66** |
| **发现数** | **126** | **126** |
| **调用数**（= 发现数 + 文件数） | **192** | **192** |
| **tp / fp** | **49 / 17** | **49 / 17** |
| `llm_sum` | 3558 s | 2949 s |
| 单样本最大 | 431.4 s | 139.3 s |
| top5 占比 | 1107 s（31%） | 609 s（21%） |
| 未仲裁样本 | 8（`llm_unavailable` 4 + `parse_error` 4） | 5（`parse_error` 5，`llm_unavailable` **0**） |

**逐位复现**：发现数、调用数、`invoked`、**以及混淆矩阵的全部四项**在两轮之间完全相同。这是 seed 固定的复现性，**实证了 §17.12 D-2「重放不能翻转 pair 1 的 FAIL」**——不再是推理，是测量。

时间差 609 s 中 top5 占 498 s（82%），而 run 1 贵的样本正是那 4 个 `llm_unavailable`：**失败是最贵的结局**。

**B. LLM 调用模型（实测，取代 §21 里的次数猜测）**

1. `audit_benchmark_eval.py:994-1006`：`llm_started` 起，`for finding in arbitrated[:max_findings]: analyzer.analyze_finding(...)`，再 `for file_path, ...: analyzer.analyze_file(...)`，最后一次计时。故
   **`llm_duration_sec` 是一个样本内多次调用的和**，不是一次调用。
2. 语料侧：**245 个样本 0 发现 0 文件**（⇒ `static_only`，不走 LLM），**66 个样本各 1 个文件**，发现数分布 `{1:35, 2:22, 3:1, 4:3, 5:1, 6:1, 7:3}`。故 **regex 全轮调用数 = 126 + 66 = 192**。
3. `total_findings` **全语料最大 = 7** ⇒ `MaxFindings: 20`（`internal/codeaudit/llm.go:41`）的截断**从不生效**，无此混淆，可排除。
4. `192` 与我在 ollama 日志里实测的 **191 个请求**吻合（差 1 为窗口边界）⇒ 模型得证。
5. 上限：`models/examples/code_security_analyzer.py:733` `urllib.request.urlopen(req, timeout=60)` ⇒ **每次调用 60 s 硬上限、无重试**（§9 的「无重试」正确），`num_predict` 200/300。

**C. §21 D 的第二次更正（我的读法错了两层）**

§21 D 曾据「431.4 s > 60 s 上限」推断矛盾。**不矛盾**：431.4 s 是 `dd-0056`（7 发现 ⇒ 8 次调用）的和，**54 s/次，正好贴着上限**。字段口径看错第二层（第一次是把「产出速率」当机器速率）。

**D. 由此可推导：611.8 s 必为排队主导**

`num_predict ≤ 300` 且实测 decode 94.9 ms/tok ⇒ **单次生成不可能超过约 30 s**。故 611.8 s 的 GIN 时长**只能**来自排队，**不可能是**单次计算。机制因此可以写实：唯一一个槽 + 客户端在 60 s 处放弃 ⇒ 被放弃的工作留在槽里，下一次调用排在它后面 ⇒ 「放弃 → 排队 → 再放弃」自持。这是 §21 D 结论的**推导版**，取代我原先「服务端算了 611.8 s」的猜测（该猜测与 `num_predict` 上限冲突，已废）。

**E. 两臂的 LLM 暴露量结构上不对等（须写入报告）**

| 轮 | `invoked` | 发现数 | **调用数** | `llm_sum` | s/次 | 未仲裁（样本） | 每样本失败率 |
|---|---|---|---|---|---|---|---|
| `regex-run1` | 66 | 126 | **192** | 3558 s | 18.5 | 8 | **12.1%** |
| `semgrep-run1` | 73 | 178 | **251** | 4200 s | 16.7 | 6 | **8.2%** |

**semgrep 多发 41% 的发现 ⇒ 多打 31% 的 LLM 调用**（251 vs 192）。这是本语料的结构性不对称，且它**就是被比较的那个量**（发现数）的函数——报告必须写明，否则「两臂同样的 LLM」是错的。

**但方向又一次与直觉相反**：暴露更多的一臂**失败更少**（8.2% vs 12.1%）。故这是**调用量**的不对称，**不是失败率**的不对称；**不是** §21 D2 设想的偏置。§21 G 的样本级归因已经把它钉死（失败只在 regex 侧造 FP）。

**F. 报告须据此写三句**

1. 两臂的 LLM 暴露量不同（251 vs 192 次调用），差异**由发现数驱动**，且**不产生**失败率差异。
2. `llm_duration_sec` 是**样本级和**；任何把它当成单次调用延迟的读数都是错的（本计划自己错过两次）。
3. 单次调用上限 60 s、无重试，单次生成 ≤ 约 30 s ⇒ **超时现象的本质是单槽排队自持**，属**同容器部署**的风险，串行矩阵下只表现为一次性延迟（§21 F）。

**G. 收尾命令序列（接口已核对，2026-09-28）**

```
# 1. 免跑派生 gate（只读校验，不写入源轮；你的「gate 能免跑就免跑」）
gate_rescore.py --base-dir /root/taa/verify/h2-assist-unloaded --validate
# 2. 产出 gate 基（--out-dir 必须不同于 --base-dir，源轮只读）
gate_rescore.py --base-dir /root/taa/verify/h2-assist-unloaded \
                --out-dir  /root/taa/verify/h2-gate-unloaded
# 3. 两基读数（主判定 assist + 并列 gate）
engine_compare_report.py --base-dir /root/taa/verify/h2-assist-unloaded
engine_compare_report.py --base-dir /root/taa/verify/h2-gate-unloaded
```

**闸门（实测）**：`engine_compare_report.py:661` 在 `len(outcomes) < EXPECTED_PAIRS` 时**直接返回「证据不足」**，附 `only N of 3 pairs were analysed`。**只有 2 对时不给判据结论**——故「先 2 对就停」这条路走不通，矩阵必须跑满 3 对；pair 级读数（如 §21 G）只能手工算，不能替代工具的结论。常量：`RUN_ORDER` 6 项（严格交替）、`EXPECTED_PAIRS = 3`、`BOOTSTRAP_N = 1000`、`BOOTSTRAP_SEED = 42`。

**H. 失败集**不**按样本复现；§24 A 的说法据此收窄（2026-09-28，`semgrep-run2` 进行中）**

**H-1 我先前推断错了。** 我在 §24 A 之后据「semgrep-run2 先出的 2 条失败与 run 1 的失败集重合」推断「失败按样本 ID 复现，是语料+种子的性质」。**该推断被实测推翻**：

| 样本 | `semgrep-run1` | `semgrep-run2` |
|---|---|---|
| `dd-0007` | 失败 | 失败 |
| `dd-0008` | **失败** | 未失败（`uncertain=0`，verdict 仍 `MALICIOUS`） |
| `dd-0009` | **失败** | 未失败 |
| `dd-0018`、`dd-0020` | 失败 | 失败 |
| `dd-0021` | **未失败** | **失败** |

`regex` 侧同样是**部分重合**：两轮共享 4 个 ID（`dd-0019`、`dd-0020`、`sr-0012`、`sr-0039`），run 1 独有 4 个（`dd-0056`、`dd-0057`、`pypi-0057`、`sr-0142`），run 2 独有 1 个（`dd-0063`）。

**⇒ 失败是时序驱动的，不是内容驱动的**：一次调用是否贴到 60 s 上限，取决于机器时序（排队、争用），不取决于样本内容。这与 §21 D 的排队自持机制一致。

**H-2 §24 A 必须收窄。** 混淆矩阵逐位相同**不能**作为「LLM 判定确定」的证据——它与**不同的失败集**共存。正确的说法是：**verdict 层面的稳定，在失败集变动之下仍然成立**。

**H-3 但该稳定是稳健的，且原因已实测。** 把失败状态不同的样本逐个查过，**两轮 `predicted_label` 全部相同**：

| 样本 | label | run1 `llm_state` | run2 `llm_state` | 两轮预测 |
|---|---|---|---|---|
| `pypi-0057` | benign | `llm_unavailable` | **`ok`** | malicious / malicious |
| `sr-0012` | benign | `parse_error` | `parse_error` | malicious / malicious |
| `sr-0142` | malicious | `llm_unavailable` | **`ok`** | malicious / malicious |
| `dd-0063` | malicious | `ok` | **`parse_error`** | malicious / malicious |

即**变动的那几次失败都是 verdict 中性的**：要么落在恶意样本上（失败⇒阻断⇒与被判恶意同路），要么该样本即便 LLM 正常作答也被判恶意（`pypi-0057`）。**矩阵相同因此是稳健的，不是巧合。**

**H-4 报告须据此写的三条**

1. **不得**把两轮 `regex` 的同一混淆矩阵写成「LLM 判定可复现」；应写成「**verdict 在失败集变动下保持不变**」，并给出 H-3 的四个样本为证。
2. **任一单轮的失败率是该轮机器时序窗口的性质，不是该臂的性质**——**不得跨对比较失败率**（§24 E 那张表只能逐对读）。
3. **§21 G 的 `+3/154` 是 run 1 专属的量**：它扣掉的是 run 1 的 2 条失败致 FP；run 2 只有 1 条（`sr-0012`），按其口径应为 **+2/154**。故「失败掩盖劣势」的**方向**成立且稳健（两种口径都大于实测的 +1/154），但**幅度不是点值**，报告须写成区间或注明所用轮次。



## 25. 首次 OOM 击杀：`oom_kill 1` 在产物里有唯一对应物 `HTTP Error 500`（2026-09-28）

本节登记 04:13:51Z 的 OOM 击杀，以及我在排查它时犯的**第三个诊断错误**。前两处仪器故障见 §19，共同点在下文 F 末点明。

### A. 事件与恢复

| 项 | 实测 |
| --- | --- |
| 监视器读到 `oom_kill` | `0 → 1`，**04:13:51Z** |
| 容器 `memory.peak` | `7168 MiB` **＝ `memory.max`**，headroom **为零** |
| 被杀对象 | `llama-server`（旧 pid 402） |
| 重生 | 04:13:59.411Z，日志行 `llama-server started in 7.06 seconds`（**该行自带时间戳**） |
| 停摆时长 | 击杀→重生 **约 8 秒**；新 pid 4112 |

**矩阵存活**，三项独立证据：驱动 pid 381 未变、`semgrep run 2` 无 `exit=` 行、eval（pid 1755）可从 `/proc/1755/cmdline` 直接读到命令行。重启后 3 分钟内该 server 处理 11 个不同任务、10 次 prompt processing 完成（约 17 s/次），**是真在生成，不是快速失败**——这一条是专门查的，因为「重启后任务号跳变」也可能是失败的假象。

### B. 落点：`dd-0055`，且这次有物证

当时在飞的样本是 `dd-0055`（语料序中第一个无报告的样本；04:16 时目录已建、报告未落）。其报告 04:17 落盘：

```
label=malicious  verdict=MALICIOUS  risk=CRITICAL  total_findings=18  statistics.uncertain=2
```

两条失败调用的 `llm_reason` **性质不同**，逐条可读：

| finding | reason | 性质 |
| --- | --- | --- |
| `NET_001@128` | `ollama 调用失败: HTTP Error 500: Internal Server Error` | **server 在请求中途被杀，由仍活着的 ollama 代答 500** ⇒ 本次 OOM 的签名 |
| `NET_001@95` | `ollama 调用失败: timed out` | 60 s 客户端上限，**与 OOM 无关** |

两条都落在**恶意**样本上，`dd-0055` 本就该阻断 ⇒ 该次击杀 **verdict 中性**，**没有制造误报**，与 §24 H-3 同类。

（顺带更正 §23 监视器注释里的一句措辞：被打断的调用在产物里落成 **`HTTP Error 500`**，不是「connection failure」——ollama 本体没死，它替死掉的 runner 回了 500。这比原措辞更有用，见 D。）

### C. 那个 6.5 分钟空档**不是** OOM 造成的

- 最后一份报告写在 **04:10:30**（`dd-0054`），距击杀 **3 分 21 秒** ⇒ 空档**早于**击杀。
- `dd-0055` 的 18 条 finding 去重后**仍是 18**（`dedupe_findings_for_llm` 的键是 `(file, rule_id, line)`，18 条互不相同），即该样本是 **18 + 1 = 19 次调用**（18 次逐发现 + 1 次逐文件）；在飞那次调用的提示为 **2050 token**、prefill 实测 **~51 tok/s**（≈40 秒只够 prefill）。
- 7 分钟 ÷ 19 次 ≈ **22 秒/次**，与真实生成长度一致。**空档是这个样本自身的成本**，把两件事分开是本节的要点——我先前正是从这段空档里读出过错误的结论。

### D. 三种失败模式在产物里可区分（报告须用这张表）

| `llm_reason` | 含义 | 四轮已知出现 |
| --- | --- | --- |
| `调用失败: timed out` | 60 s 客户端上限 | regex-r1 **7**、semgrep-r1 **2**、semgrep-r2 **1** |
| `调用失败: HTTP Error 500` | 运行进程被杀（OOM / 崩溃） | semgrep-r2 **1**（本次，四轮中**唯一一次**） |
| `无法解析模型输出` | 模型输出不可解析 | regex-r2 全部 **5** |

三者都计入 `statistics.uncertain`，故 §23 的标记口径**不变**（它标的是 `llm_state ∈ {llm_unavailable, parse_error}`）。但**只有 500 能回溯到一次具体的 OOM 击杀**：本矩阵至今 `oom_kill = 1`，而四轮产物里 500 **恰好 1 次**，一一对应。**报告须把 `oom_kill` 计数与 500 计数并列报出**，只报「未仲裁总数」会把这三件事混成一件。

（我在初次统计时用 `调用失败` 作过滤，只捞到 7/0/2/2，与 `statistics.uncertain` 的 11/5/7/6 对不上而一度怀疑 §23 错了。**§23 没错，错的是我的过滤器**——它漏掉了 `无法解析模型输出` 这一支。记在此处，因为「指标对不上时先怀疑自己的过滤器」与 F 是同一课。）

### E. 一处调用模型的更正（§24 B / §24 E）

§24 写「`total_findings` 全语料最大 **7** ⇒ `MaxFindings: 20` 截断从不生效」。**7 是 regex 那一臂的最大值**；semgrep 返回每一个匹配（这正是 `dedupe_findings_for_llm` 文档里写的两臂差异），`dd-0055` 一条就有 **18** 条。

更正为：**两臂在本语料中仍未触发 20 的上限，但依据必须分开写**——regex 实测最大 **7**，semgrep 实测最大 **≥18**（`semgrep-run2` 未跑完，终值待整轮结束回填）。这同时是 §24 E 调用数不对称（251 vs 192）的**机制**：semgrep 的仲裁预算更大，不只是「调用更多」。

### F. 我的第三个诊断错误：`grep -v grep`

我据 `ps -eo pid,args | grep -E "python3" | grep -v grep` **无输出**，判定「eval 进程已死」。**这是错的**：pid 1755 一直活着，正在发请求。

根因：**`grep -v grep` 会滤掉任何含子串 `grep` 的行，而 eval 的命令行里含 `--engine semgrep`** —— 我用它**精确地滤掉了我要找的那一行**。同一份 `ps` 输出：

| 取法 | 结果 |
| --- | --- |
| `… \| grep -v grep` | **0 行** |
| `… \| grep -E "[p]ython3"` | 2 行 |
| `pgrep -af audit_benchmark_eval` | **1755** |
| `/proc/1755/cmdline` | 直接可读 |

我先前对你说「是 `ps` 不可信」——**那句话同样是错的**。`ps` 的输出从头到尾都是对的，错的是我的过滤器。排查中我还误疑并排除了 `-E` 标志、`ps` 的 `comm` 参数、以及宿主 ugrep —— 都不是原因。

**规矩**：进程存在性以 `/proc/*/cmdline` 或 `pgrep -af` 为准，**禁用 `grep -v grep`**；空结果在排除掉过滤器自身之前**一律不算证据**。这与 §19 G 的 `pgrep -x dpkg` 是同一类错误：**把「我没看到」当成「不存在」**。三次仪器故障里两次是这个形状。

### G. 须写进报告的三条

1. 本矩阵**运行在内存上限处**（`peak == max`，headroom 为零），故 OOM 击杀是**可预期事件而非意外**；每次击杀须连同**它所打的那个样本及其 label** 一并记录。
2. 击杀污染**当时在飞的那次调用**。按 §24 H 的机制：落在恶意样本上 **verdict 中性**，落在良性样本上则**是一条 FP**（抬高该臂的 FPR）。本轮 `dd-0055` 属前者，**本轮无 OOM 所致误报**。
3. 击杀**未使矩阵停下**，也**未改变任何判定路径**。

## 26. 判据的判定顺序：pair 1 已经定死了结论，pair 2/3 是确认而非翻盘（2026-09-28）

读 `engine_compare_report.py:631-663` 的 `decide()`，判定顺序是**先失败、再 void、最后才是「对数不足」**：

```python
if failures:  return "未通过", failures + voids     # 657
if voids:     return "证据不足", voids               # 659
if len(outcomes) < EXPECTED_PAIRS: return "证据不足" # 661
```

判据本身是**逐对成立**（§2：`ΔFPR ≤ 0` **且** `Δrecall ≥ 0`，**每一对都要**）。两条合起来有四个后果：

1. **一对失败即终局**。pair 1 已实测 `ΔFPR = 18/154 − 17/154 = +0.0065 > 0`（§21 G）⇒ `failures` 非空 ⇒ 无论后面两对跑成什么样，预登记判据的结论都是 **「未通过」**。判据要求的是「每一对都非劣」，不是「多数对非劣」，故补测**不能翻盘**。
2. **因此 pair 2/3 是确认性证据，不是决策性证据**。它们回答的是「这个 FAIL 是稳定的还是某一轮的偶然」（§24 H-4 第 3 点要的幅度区间），而不是「到底通不通过」。
3. **更正我先前的一处说法**：我记过「少于 3 对则判据不给结论，故跑完 2 对不是合法出口」。**在 FAIL 的情形下这是错的**——第 657 行先于第 661 行，2 对（甚至 1 对）若有失败即返回「未通过」，那个「对数不足」的门只在**既不失败也无 void**时才咬合。故按工具本身，跑完 pair 2 就能得到预登记判据下的「未通过」。
4. **但协议写的是 3 对配对**。第 3 点只说明工具不会拒绝 2 对的输入，**不等于**可以从 2 对报出结论：那样做偏离了预登记协议，必须在报告里显式披露偏离。**是否提前收，是你的决定**（§22 你已裁定「矩阵跑完」，我不改）。

## 27. 监视器第四次缺陷：把「空闲卸载」报成了 OOM 击杀（2026-09-28，已修 `h2_matrix_watch.sh`）

### A. 事件

05:02:12Z 监视器报 `llama-server GONE (was 4112): OOM kill or crash; every LLM call in this window fails`。**这是一次误报**，而且它断言的那句话是**反的**。

| 时刻（实测） | 事件 |
| --- | --- |
| 04:56:51 | 最后一次 LLM 调用完成（`[GIN] … 200 | 5.909 s`）——此后是**不需要 LLM 调用的 `static_only` 样本** |
| ~05:01:51 | 空闲满 5 分钟（ollama `keep_alive` 默认）⇒ ollama **主动卸载** runner |
| 05:02:12 | 监视器轮询不到 runner ⇒ 报「OOM kill or crash」 |
| 05:02:22 | 下一个 LLM 调用到达 ⇒ 冷加载 |
| **05:02:28.434Z** | `llama-server started in 5.79 seconds`（新 pid 13291） |
| 05:02:43 | 该调用**成功**，`[GIN] … 200 | 21.086 s`（**含 5.79 s 冷加载**） |

判别量就是监视器**自己已经在读**的那个计数器：全程 `oom_kill = 1`、`oom = 1`（**自始至终只发生过一次 OOM，即 §25 那次**），`memory.peak` 仍是 7168 MiB（单调量，那次的残留）。矩阵同时在推进（报告数 283→285，18 秒内 +2），eval（pid 1755）的 socket 连的是 ollama 的 11434，不是 runner。

**故此事件不需要任何处置**：没有击杀、没有崩溃、没有调用失败。

### B. 缺陷

GONE 分支把「runner 不在」一律当成击杀，理由是「击杀到重生之间没有 pid 可比」。**前提错了**：runner 不在的成因有两个，只有一个是故障。本矩阵有大量 `static_only` 样本连续出现，**空闲卸载在这里是常态**。旧分支的后果有三层，一层比一层重：报出一个不存在的 OOM；断言「本窗口内每个 LLM 调用都会失败」；而它断言的那次调用**成功了**。

### C. 修复（`models/audit/tools/h2_matrix_watch.sh`，8/8 测试 + 两次变异）

用探针**已经在采集**的 `oom_kill` 计数器把两种情形分开，而不是猜：

- `oom_kill` 在本轮**有变化** ⇒ `ALERT … llama-server GONE (was …) after an OOM kill`（真正要盯的事件）
- `oom_kill` **无变化** ⇒ `INFO … llama-server unloaded while idle (…, oom_kill unchanged at N): not a fault; the next call reloads it and pays the model load`

实现上有一处必须留意：`prev_oom` 在存活分支**之前**就被推进了，所以比较必须在那之前完成（新增 `oom_moved`），否则判别式恒为假——这正是「两分支形同虚设」的写法，已避免。

测试 `RunnerDisappearanceTest` 钉住**两个方向**，加两次变异：把条件改成恒真（一律报击杀）→ `test_an_unload_with_no_kill_is_not_reported_as_one` 失败；改成恒假（一律报卸载）→ `test_a_kill_in_the_same_poll_is_reported_as_one` 失败。**后者尤其重要**：只往「少报」方向修会把真正要盯的 OOM 一起静音。

### D. 一处新测到的量：空闲卸载后的冷加载成本，以及一个**待验假设**

冷加载实测 **5.79 s**（`llama-server started in 5.79 seconds`），落在紧随其后的那次调用里（该调用总耗时 21.09 s）。这与驱动开头 `warm_model` 专门规避的是同一个代价，**但矩阵中途没有任何东西保证 runner 是热的**。

**假设（未验证，不得写进报告为结论）**：两臂的失败率差（§24 E：regex 12.1% vs semgrep 8.2%）可能部分来自这里——regex 的发现更少（有发现的样本 66 条），**不需要 LLM 调用的样本更长段连续** ⇒ 卸载更频繁 ⇒ 冷加载更多 ⇒ 更贴近 60 s 上限 ⇒ 超时更多。若成立，这是**测量条件在两臂间不对称**，而不是引擎性质。

**验证方法（矩阵跑完后做）**：对每轮，取每个样本首次 LLM 调用前的空闲间隔，比较「失败调用」与「非失败调用」所跟随的间隔分布，并按臂分开。若失败确实偏向长间隔之后，该假设成立；否则撤回。**在验证之前，报告中两臂失败率之差只能作为描述性统计报出，不得归因。**

### E. 顺带记下的容器状态

`memory.events` 实测：`max 2575959`、`oom 1`、`oom_kill 1`、`high 0`。`max` 计数两百五十余万次说明容器**长期贴着 `memory.max` 运行**（每次触碰上限计数一次），与 §25 的 `peak == max`、§17.13 的 OOM 是同一幅图。**后续再发生 OOM 是正常的，不是异常**；每次按 §25 B 的口径记录落点与 label。

## 28. pair 2 读数：两对以**同一幅度**失败在 ΔFPR；失败可以造出真阳性（2026-09-28）

### A. 两对的判据读数（点估计，读流水线自己的混淆矩阵）

| 对 | regex (tp/fp/tn/fn) | semgrep (tp/fp/tn/fn) | ΔFPR | Δrecall |
| --- | --- | --- | --- | --- |
| **pair 1** | 49 / 17 / 137 / 108 | 55 / 18 / 136 / 102 | **+0.0065 FAIL** | +0.0382 |
| **pair 2** | 49 / 17 / 137 / 108 | 54 / 18 / 136 / 102 | **+0.0065 FAIL** | +0.0341 |

（`n_benign = 154`、`n_mal = 157`，两对同。`FPR = fp/(fp+tn)`、`recall = tp/(tp+fn)`，与 §21 G 口径一致。）

三条：

1. **`regex-run2` 与 `regex-run1` 四项全同**——§24「两轮逐位复现」在判据的量上再次成立。
2. **两对的 ΔFPR 完全相同（`+0.0065`，都是 18 vs 17 一个样本）**。故 §21 G 的 FPR 侧失败**不是某一轮的偶然**，而是稳定量。按 §26「一对失败即终局」，结论**已被两对独立地判死**。
3. **FAIL 只在 FPR 侧**：recall 两对都为正，`Δrecall = +0.0382 / +0.0341`。

**本读数不跑 `engine_compare_report.py`**：它含 `BOOTSTRAP_N = 1000`，会从正在推理的 LLM 手里抢核，**制造我正要研究的超时**（§27 D 的机制）。故此处只报点估计；McNemar 与 bootstrap 区间留到矩阵跑完、按 §24 G 的收尾序列跑。**这是有意的偏离，须在报告里注明。**

### B. semgrep 两轮那一票之差，是失败造出来的

两轮 semgrep 只差 **1 个真阳性**（55→54，`fn` 都是 102）。逐样本比对预测标签，**差异恰好 1 条**：

| 样本 | 真标签 | run 1 | run 2 |
| --- | --- | --- | --- |
| `dd-0029` | **malicious** | **malicious**（`uncertain = 2`） | **benign**（`uncertain = 0`） |

机制：run 1 里它有 2 次仲裁失败 ⇒ `UNCERTAIN` 在高危发现上被抬升 ⇒ 阻断 ⇒ 判恶意，**恰好与真标签一致 ⇒ 一个真阳性**；run 2 没有失败、LLM 正常作答 ⇒ 判良性 ⇒ **假阴性**。⇒ **run 1 的 `Δrecall = +0.0382` 里含有 `+1/157` 是失败造出来的**；run 2 的 semgrep 侧失败（`dd-0007/dd-0018/dd-0020/dd-0021/dd-0055`）**全在恶意样本上且都 verdict 中性**，故 `Δrecall = +0.0341` **是不含失败通胀的值**。

### C. 由此更正 §25 B 的一句话，并新增一条报告要求

§25 B 我写「落在恶意样本上 **verdict 中性**」。**该说法对 `dd-0055` 成立，但不能推广**：`dd-0029` 就是反例——同一次失败机制，在它身上把一个**假阴性变成了真阳性**。

准确的陈述是：**一次失败的仲裁总是把样本推向「malicious」**（`UNCERTAIN` 在高危发现上被抬升 ⇒ 阻断），故其效果**取决于该样本的真标签**——

- 真标签为 **benign** ⇒ 制造 **FP**（抬高该臂 FPR，§21 G 实测 regex 侧 2 条）
- 真标签为 **malicious** ⇒ 制造 **TP**（抬高该臂 recall，本条实测 semgrep 侧 1 条）

故新增一条报告要求：**失败次数必须按臂报出，并按真标签拆开**（benign 侧失败数 / malicious 侧失败数）。只报「未仲裁总数」会把两个方向相反的效应混成一个数，而它们对 `ΔFPR` 与 `Δrecall` 的贡献符号相反。

### D. 与 §21 G / §24 H-4 的关系

§21 G 说「失败掩盖 semgrep 劣势」——那是**扣失败致 FP 后 `ΔFPR` 变大**（run 1 `+3/154`、run 2 `+2/154`，都大于实测的 `+1/154`）。本条补上的是**另一侧**：失败在恶意样本上会**抬高 semgrep 的 recall**，故它同时也**夸大**了 `Δrecall`。两个方向的结论一致且更强：**实测的 `ΔFPR` 与 `Δrecall` 都是失败机制下的保守读数**，扣掉失败后 semgrep 在 FPR 侧更差、在 recall 侧更好。判据是「`ΔFPR ≤ 0` 且 `Δrecall ≥ 0`」，故扣掉失败**只让 FPR 侧更不合格**，结论方向不变。

### E. 顺带修掉仪器自己那句不准确的断言（2026-09-28）

§28 C 的更正不只适用于计划文本——**监视器的告警句里写着同一个错误**，而那句话是运行期间我实际读到的输出：

> 旧：`… an LLM call did not arbitrate; on a HIGH/MEDIUM finding that blocks the sample (a false positive), it cannot hide one`

`(a false positive)` 无条件断言，按 §28 C 只在样本真标签为 benign 时成立。改为：

> 新：`… an LLM call did not arbitrate; that blocks the sample, so it is a false positive if the sample is benign and a true positive if it is malicious, and it can never hide a malicious one`

**「它藏不住恶意样本」这半句仍然成立**（失败只把样本推向 malicious），所以保留；被更正的只有「一定是假阳性」。头部注释第 2 条里同样的说法（「can only manufacture false positives」）一并改掉。

测试上有一处值得记：原先那条告警**无法被测试触发**——它会读的报告在测试里是**预先写好**的，于是计数从第一轮起就是 1、永不上升，而告警只在**上升**时触发。故给假 docker 加了一个始终递增的探针计数器，并支持「报告在第 N 轮之后才出现」，这样计数可以在运行中真的上升。「预先写好」这个写法会让告警文本永远处于未测状态，措辞漂移因此不会被发现——这正是它漂移了一次的原因。新测试 `test_the_alert_qualifies_a_blocked_sample_by_its_true_label` 钉住两个方向，变异检查：换回旧措辞 ⇒ 精确失败该项。共 **9/9 通过**。

## 29. 失败按真标签拆开后的读数、暴露量分母、以及 §24 E 调用数的一处更正（2026-09-28）

### A. 失败按真标签拆开（§28 C 的报告要求）

| 轮 | benign 侧失败 | malicious 侧失败 | 失败发现数 |
| --- | --- | --- | --- |
| `regex-run1` | **2** | 6 | 11 |
| `regex-run2` | **1** | 4 | 5 |
| `regex-run3`（20/311，进行中） | 0 | 2 | 2 |
| `semgrep-run1` | **0** | 6 | 7 |
| `semgrep-run2` | **0** | 5 | 6 |

即 §21 G 的「失败致 FP 只落在 regex 侧」在**真标签拆开**后依然成立（regex 2 条与 1 条，semgrep 两轮皆 0 条）。

### B. 分母：两臂的调用暴露量（**必须与 A 同时报**）

| 轮 | benign 侧调用数 | malicious 侧调用数 |
| --- | --- | --- |
| `regex-run1` / `run2` | **40** | 152 |
| `semgrep-run1` / `run2` | **43** | 206 / 198 |

- 两臂在 benign 侧的暴露量**几乎相同**（43 vs 40），故 A 表里「0 vs 1–2」**不是暴露量差异**造成的。
- 调用数的算法经交叉验证：**调用数 = 去重后发现数 + 文件数**，与 `sample-results.jsonl` 的 `llm_invoked` 样本数逐轮吻合（regex 66、semgrep 73），也与 §24 B 实测的「每发现一次 + 每文件一次」一致。

### C. 由 A、B **不能**下的结论（我先前差点写成结论，此处撤回）

「semgrep 的失败从不落在良性样本上」在**两整轮**成立（0/43），但它**不与基准率可分**：

- Fisher 精确检验（双侧）：`2/40` vs `0/43` ⇒ **p = 0.2292**。
- 按 regex 的良性侧失败率折算，semgrep 那 43 次调用里出现 0 次失败的概率是 **0.11**（按 run 1 的 2/40）到 **0.19**（按两轮合并的 3/80）。

（我口算时先说过「约 0.27」，**这个数是错的**，正确区间是 0.11–0.19；结论方向不变，但数字必须对。）

**故不得写**：「semgrep 的 FPR 不被失败抬高」、「semgrep 在语义上更稳」。**能写的只有**：在这两轮里，失败所致的假阳性**全部落在 regex 侧**（2 条与 1 条，semgrep 0 条），并把 C 的 p 值一并给出。

### D. §24 E 的调用数更正：`251` 是未去重数，真实为 `249`

| 轮 | 原始发现 | 去重后 | 文件 | `raw+files` | **`deduped+files`** |
| --- | --- | --- | --- | --- | --- |
| `regex-run1` | 126 | 126 | 66 | 192 | **192** |
| `semgrep-run1` | **178** | **176** | 73 | **251** | **249** |

eval 是**去重后**才逐条调用（`audit_benchmark_eval.py:1001`：`arbitrated = dedupe_findings_for_llm(findings)`，随后按 `max_findings` 截断），故**调用数是 `deduped+files`**：semgrep **249**、regex **192**。§24 E 的 `251` 是 `raw+files`。

- **方向不变**（semgrep 调用更多），幅度 **31% → 30%**。
- 顺带证实了 `dedupe_findings_for_llm` 文档里那句设计说明：去重**只在 semgrep 侧真的削掉了东西**（178→176），regex 侧 raw ≡ deduped（126）——因为 regex 每行只报第一条匹配。

### E. 强化 §28 C 的报告要求

失败数**必须与暴露量分母成对报出**（benign 侧失败 / benign 侧调用、malicious 侧失败 / malicious 侧调用）。孤立的 `0` 不可解释：它既可能是「更稳」，也可能是「没怎么被调用」——本语料里恰好是前者（43 > 40），但**只有把分母写出来才看得出**，而**即使写出分母也可能只是小样本**（C 的 p = 0.2292）。

## 30. `regex-run3` 完成：失败**完全不进**判定；§21 G 的反事实撤回（2026-09-28）

### A. 实测

`regex-run3` 结束（`exit=0`，2627 s ≈ 44 min）。三轮 regex 的读数：

| 轮 | 失败样本数 | benign 侧失败 | 判为恶意的样本集合 | 混淆矩阵 |
| --- | --- | --- | --- | --- |
| `regex-run1` | 8 | **2** | 66 条 | 49 / 17 / 137 / 108 |
| `regex-run2` | 5 | **1** | 与 run1 **逐位相同** | 49 / 17 / 137 / 108 |
| `regex-run3` | **3** | **0** | 与 run1 **逐位相同** | 49 / 17 / 137 / 108 |

**决定性的那一格是 run3 的 `benign 侧失败 = 0` 而 `fp` 仍为 17。**

### B. 由此撤回 §21 G 的推论

§21 G 说「失败只落在 regex 侧造成 FP（2 条：`pypi-0057`、`sr-0012`）… 扣掉失败机制的确定性部分后 **ΔFPR 变 +3/154，比实测更大** ⇒ 失败**掩盖**了 semgrep 劣势的约 2/3」。

**该推论不成立，撤回。** `pypi-0057` 与 `sr-0012` **确实是假阳性，但不是失败造成的**：run 2 里 `pypi-0057` 的 LLM 正常作答（`ok`）、run 3 里两者都没有失败，而两者在三轮里**始终被判恶意**，判恶意集合三轮逐位相同。⇒ **失败对 regex 的判定标签贡献为零，扣掉失败后 `ΔFPR` 一动不动（仍是 18 vs 17，`+0.0065`）。**

连带撤回 §24 H-4 第 3 点的 `+2/154`（同一口径），以及 §28 D 里「实测的 `ΔFPR` 与 `Δrecall` **都是**失败机制下的保守读数」中的 **`ΔFPR` 那一半**。§28 D 的 `Δrecall` 那一半**仍然成立**（`dd-0029` 的失败确把 run 1 的一个假阴性变成了真阳性，见 §28 B）。

**更正后的完整陈述**：

- **FPR 侧**：失败**不参与**。`ΔFPR = +0.0065`（18 vs 17）是**不含任何失败效应**的读数，既没有被掩盖也没有被夸大。判据在这一侧不合格，**没有任何反事实能救**。
- **recall 侧**：失败**参与**，方向是**夸大 semgrep**。run 1 的 `Δrecall = +0.0382` 含 `+1/157`（`dd-0029`）；run 2 的 `+0.0341` 不含（其 semgrep 侧失败全为 verdict 中性）。**不含失败效应的值是 `+0.0341`。**

### C. 一处过程教训（须记，因为这是同一份计划里的自相矛盾）

杀死 §21 G 的证据**早就写在本计划里**：§24 H-3 的表格明写 `pypi-0057` 与 `sr-0012` 在两轮里**都是 malicious/malicious**（即无论失败与否都被判恶意）。我登记了那张表，**却没有看出它与 §21 G 的反事实直接矛盾**，直到 run 3 用「benign 侧零失败而 `fp` 不变」把同一件事第三次测出来才发现。

**教训**：把「某样本失败了 **且** 它被判恶意」读成「它**因为**失败而被判恶意」是一个**因果推断**，必须先验证「不失败时它会被判良性」才能成立。§21 G 跳过了那一步。**「共现」不是「因果」，而在判据这种 0 容差的场合，跳过这一步会直接改掉结论的方向。** 同类错误在 §19 G（把「我没看到」当成「不存在」）出现过；本轮是第三次，形状不同但都是**把缺失的那一步补成自己期望的样子**。

### D. 报告须改的一句话

**删掉**「调用失败掩盖了 semgrep 在 FPR 侧的劣势」。**改写成**：本矩阵中，**失败不改变任何样本的预测标签在 FPR 侧的效果**（三轮 regex 的判恶意集合逐位相同，其中一轮 benign 侧失败为 0），故 `ΔFPR = +0.0065` 的 FAIL **与失败机制无关**；失败只在 recall 侧有效应（`dd-0029`），方向是**抬高** semgrep 的 `Δrecall`。

## 31. 第二次 OOM 击杀：落点 `dd-0003`，verdict 中性（经验证）；监视器修复在真实事件上生效（2026-09-28）

### A. 事件

| 项 | 实测 |
| --- | --- |
| `oom_kill` | `1 → 2`，监视器于 **06:01:06Z** 读到 |
| 击杀时刻 | 约 **06:00:36**（由重生行倒推） |
| 重生 | **06:00:43.936Z**，`llama-server started in 7.x seconds`；新 pid 15398 |
| 落点样本 | **`dd-0003`**（语料序中第一个无报告的样本），label **malicious** |
| 背景 | 05:35Z 时 `mem_current = 6892 MiB / 7168 MiB`（**96%**）、`anon = 4771 MiB` ⇒ 预期之内 |

### B. 修复后的监视器在真实击杀上生效

本次两条告警是从**新副本**发出的：`cgroup oom_kill 1 -> 2` 与 `llama-server pid 13291 -> 15398: killed and respawned between polls`。§27 的判别式（`oom_kill` 是否移动）**在这次真实击杀上给出了正确分支**——同一条分支在 05:02 的那次**卸载**上给出的是 `INFO … unloaded while idle`。**同一条代码路径、两次事件、两个相反的分支，都正确**，这是对 §27 修复的现场验证。

### C. verdict 中性：经验证，非假定

按 §28 C 的要求，不能因为「样本是恶意的」就假定中性，必须验证「不失败时它也会被判恶意」：

| 轮 | dd-0003 判定 | `uncertain` |
| --- | --- | --- |
| `regex-run1/2/3` | malicious / CRITICAL | 0 |
| `semgrep-run1/2` | malicious / CRITICAL | 0 |

**五轮、两臂、全部无失败，判定均为恶意** ⇒ 其判定与失败无关 ⇒ 本次击杀**不改变任何判定**。

### D. 一条可证伪的预测（待 `dd-0003` 报告落盘后验）

§25 D 记的是「`oom_kill` 计数与产物里的 `HTTP Error 500` 计数一一对应」。**该预测本次为：`dd-0003` 的报告里应出现一处 `ollama 调用失败: HTTP Error 500`**，且四轮至今的 500 总数应从 1 变为 2。报告落盘后核对；若不符，§25 D 的对应关系**必须撤回或收窄**（例如它可能只在「击杀恰好打断一次调用」时成立，而本次击杀若落在两次调用之间，就不会留下 500）。

### E. 累计与报告要求

- `oom_kill` 累计 **2**。两次落点（`dd-0055`、`dd-0003`）**都在恶意样本上**——样本量太小**不构成结论**（语料前段本就以体量大的恶意包为主，落点在那里是位置效应），但报告须把**每次击杀的落点、label 及其是否 verdict 中性**列表报出。
- 报告须把 **`oom_kill` 计数与 `HTTP Error 500` 计数并列**（§25 D），而不是只报「未仲裁总数」。

### F. 预测被证伪：`oom_kill` 与 `HTTP Error 500` **不是**一一对应（2026-09-28）

#### F-1. 读数

| 项 | 实测 |
| --- | --- |
| `dd-0003` 报告已落盘 | 是（`predicted_label=malicious`、`risk=CRITICAL`、`uncertain=0`） |
| 全库 `HTTP Error 500` 计数 | **仍为 1**（仅 `dd-0055` 那条） |
| `oom_kill` | **2** |

⇒ 第二次击杀**在产物里没有留下任何痕迹**。§31 D 预登记的处理（「不符则 §25 D 必须撤回或收窄」）**触发**。同时 `dd-0003` 的 `uncertain=0` 独立确认了 §31 C 的 verdict 中性。

#### F-2. 机制：ollama 的重载路径会吸收掉击杀（GIN 实测）

| 时刻（UTC） | 事件 |
| --- | --- |
| 06:00:04 / 06:00:16 / 06:00:22 | 击杀前最后三次请求，均 **200** |
| ≈**06:00:36** | 击杀（由重生行倒推） |
| **06:00:43.936** | 重生，`llama-server started in 7.x seconds` |
| **06:00:57** | 一次在 **≈06:00:36 到达**的请求以 **200** 返回，耗时 **20.91 s** |

20.91 s ≈ 7 s 模型装载 + 14 s 解码，**远低于 60 s 上限**。即：击杀瞬间到达的那次调用**没有失败**——ollama 把它排队、等 runner 重生并装载模型、然后正常作答。

#### F-3. 收窄后的规则（取代 §25 D 的一一对应）

- 击杀**只有当一次请求正处于解码中**（与 `llama-server` 已有在途流）才会留下产物痕迹：ollama 替死掉的 runner 回 **`HTTP Error 500`**。
- 尚未开始解码的请求（刚到达、或落在死窗口内）被**透明吸收**：等重生、付一次模型装载、返回 200。
- **推论**：`oom_kill` 计数是击杀致失败的**上界**，不是等值；**产物会低估 OOM 事件数**，只有 cgroup 计数器是权威。判别式不是「落在两次调用之间」，而是「**是否已在解码**」。

对号入座：击杀 #1（04:13:51，落点 `dd-0055`）**正在解码** ⇒ 1 条 500（`NET_001@128`）；击杀 #2（06:00:36，落点 `dd-0003`）**尚未解码** ⇒ 0 条。

#### F-4. 报告要求（修订 §31 E）

`oom_kill` 与 `HTTP Error 500` **仍须并列报出**，但理由反过来了：不是因为它们相等，而是因为它们**不等**——产物不能用来数击杀次数。报告须写明 **500 数是击杀致失败的计数下界**，并给出每次击杀的落点与「该次是否留下 500」。

## 32. `dd-0007`：同一输入在不同轮次解析结果不同 ⇒ 失败率含轮次间非确定性（2026-09-28）

### A. 读数

`dd-0007`（恶意）六轮中**只有一条发现**：`CMD_001@228`。

| 轮 | finding 判决 | 样本结论 | `predicted_label` |
| --- | --- | --- | --- |
| `regex-run1` | MALICIOUS | MALICIOUS / CRITICAL | malicious |
| `regex-run2` | MALICIOUS | MALICIOUS / CRITICAL | malicious |
| `regex-run3` | UNCERTAIN（无法解析） | UNCERTAIN / HIGH | **malicious** |
| `semgrep-run1` | UNCERTAIN（无法解析） | UNCERTAIN / HIGH | **malicious** |
| `semgrep-run2` | UNCERTAIN（无法解析） | UNCERTAIN / HIGH | **malicious** |
| `semgrep-run3` | UNCERTAIN（无法解析） | MALICIOUS / CRITICAL | **malicious** |

### B. 非确定性：同引擎、同输入、同种子，生成不同

`regex-run1` 与 `regex-run3` 的 finding 对象**除 `llm_reason` / `llm_risk` / `llm_verdict` 三个输出字段外逐字段相同**（`regex-run1 ≡ regex-run2` 则**全字段**相同）。同一引擎、同一样本、同一规则与行号、同一 prompt、同一 `--llm-seed 42`，第 3 轮生成的是**另一段文本**，且其中把代码原文 `os.system("python wz.py")` 连同**未转义的引号**写进了 JSON 字符串，并发生截断 ⇒ 解析失败。

**故 `无法解析模型输出` 这个记录串至少覆盖两种成因**：截断（§25 D 已记）与**内容触发**（本段：代码片段自带引号，模型照抄未转义而自我打断）。后者与负载、OOM、引擎都无关。

一处**须收窄**的说法：两臂对 `CMD_001@228` 的 finding 对象**并非逐字段相同**（`description`、`category`、`context_before/after`、`ast_enclosing_block`、`taint_trace` 都不同）⇒ **两臂的 prompt 文本本就不同**，故「同一输入」只对**同臂不同轮**成立。本段的非确定性主张只依赖后者，不依赖前者。

### C. `assist` 的判定由 `risk_level` 驱动，不由 verdict 驱动

`audit_benchmark_eval.py:860-866`：

```python
if has_malicious or any(r in ("CRITICAL", "HIGH") for r in risk_levels):
    blocked = True
    predicted_label = "malicious"
```

一条 `UNCERTAIN` / HIGH 的发现已足使 `risk_level = HIGH` ⇒ **阻断**。故上表里 `MALICIOUS` 与 `UNCERTAIN` 的差别**对判据是装饰性的**：六轮 `predicted_label` 全为 `malicious`，`dd-0007` 恒为 **TP**。

**这一条报告必须写**：产物的**头条结论**（`conclusion.verdict`）与它的 `predicted_label` **可以不一致**；按 `verdict` 统计会得到错误的混淆矩阵。

### D. 非确定性是否传播到样本级：**分臂而不同**

| 臂 | 判恶意集合 | 是否逐位相同 |
| --- | --- | --- |
| regex | 66 / 66 / 66（三轮） | **相同** |
| semgrep | 73 / 72（两轮） | **不同**，唯一差项 **`dd-0029`** |

- regex 臂：finding 级发生过翻转（`dd-0007`），但两种结果（MALICIOUS 与 UNCERTAIN/HIGH）在 `assist` 下**都阻断**，故**未传播**。
- semgrep 臂：`dd-0029` 在 run1 有 2 处解析失败 ⇒ 抬升 ⇒ 阻断 ⇒ **TP**；run2 解析成功 ⇒ **FN**。⇒ **解析失败的非确定性已实测传播到判据的 recall 侧**（`tp 55 → 54`，`Δrecall` 由此变动 `1/157 = 0.0064`）。

### E. 对 §29 的后果

§29 C 曾以「Fisher p = 0.2292，与基准率不可分」拒绝归因两臂失败率之差。本节原先写的是「**同一条输入在 regex 臂内就失败了 1/3 次**，故两臂失败数之差（11 vs 3）**至少部分**是轮次间非确定性恰好落在 semgrep 侧」——**该句的数字与方向都错，已撤回**：我把 `regex-run1` 的失败**发现数** `11` 与 `regex-run3` 的失败**样本数** `3` 混为一谈。逐轮对齐后的实测（§34）显示失败负载**在 regex 侧更重**（样本 8/5/3 vs 6/5/2；发现 11/5/2 vs 7/6/?），**不存在「semgrep 侧失败偏多」这一现象**。

仍成立的是：**非确定性真实存在**（本节 B、D），但它解释的是**边缘样本的漂移**（`dd-0007`、`dd-0029`），不是任何系统性偏向；而失败的**大部分是样本内禀且可复现的**（§34 B）。

## 33. pair 读数点名：判据的失败由**一个**良性样本 `sr-0155` 承担，两臂是**严格子集**关系（2026-09-28）

### A. 两臂判恶意集合的集合运算（两个完整配对）

| 配对 | benign 侧 | semgrep 独有 FP | malicious 侧 | semgrep 独有 TP | **regex 独有** |
| --- | --- | --- | --- | --- | --- |
| run1 | 17 vs 18 | **`sr-0155`** | 49 vs 55 | `sr-0034` `sr-0035` `sr-0036` `sr-0150` `sr-0156` + `dd-0029` | **∅ / ∅** |
| run2 | 17 vs 18 | **`sr-0155`** | 49 vs 54 | `sr-0034` `sr-0035` `sr-0036` `sr-0150` `sr-0156` | **∅ / ∅** |

⇒ 在已完成的四轮里，**regex 的判恶意集合是 semgrep 的严格子集**（良性侧与恶意侧**都是**，`regex-only = ∅` 四次）。

### B. 承担整个 ΔFPR 失败的样本

| 轮 | `sr-0155`（label benign） |
| --- | --- |
| `regex-run1/2` | `total_findings=0`、`llm_state=static_only`、`predicted=benign`、`fail_closed=False` |
| `semgrep-run1/2` | `total_findings=2`、`llm_state=ok`、`predicted=malicious`、`fail_closed=False` |

**regex 在该样本上一条发现都没有 ⇒ 根本没调用 LLM；semgrep 找到 2 条并经 LLM（成功）仲裁为恶意。**

⇒ `ΔFPR = +0.0065` 的 FAIL **不含失败效应、不含非确定性、不含 fail-closed**，是纯粹的**检测能力差**。这与 §30 的撤回一致，但比 §30 更强：§30 只证明了「失败不参与」，此处点名了唯一承担者并给出其机制。

### C. 判据解读（取代「+0.0065 的边缘失败」这一读法）

- 结构是 **semgrep = regex + 额外标记**：额外标记在恶意侧换来 +5/+6 条 TP（recall ↑），在良性侧付出 1 条 FP。
- 0 容差下，**一个严格超集的引擎在 FPR 侧不可能非劣**——除非把多出来的那一个标记去掉。
- 故 pair 1/2 的 `未通过` **不是边缘噪声判决**：重跑只能在 `dd-0029` 一票上晃动 recall；FPR 侧的 `sr-0155` 两轮都在，且 `regex-run3` 的混淆矩阵四项与 run1/run2 全同（§30）。
- **没有任何反事实能救 ΔFPR 侧**（承 §30）。

## 34. 失败逐轮对齐：**大部分失败是样本内禀且可复现的**，并更正 §32 E 的一处数字与方向错误（2026-09-28）

### A. 逐轮失败样本表（标签取自 `corpus-list.json`；`semgrep-run3` 未完成）

| 轮 | 失败样本 | benign 侧 | 失败发现数 | 明细 |
| --- | --- | --- | --- | --- |
| `regex-run1` | 8 | **2** | 11 | dd-0019 dd-0020 dd-0056 dd-0057 **pypi-0057** sr-0012 sr-0039 sr-0142 |
| `regex-run2` | 5 | **1** | 5 | dd-0019 dd-0020 dd-0063 **sr-0012** sr-0039 |
| `regex-run3` | 3 | 0 | 2 | dd-0007 dd-0019 dd-0020 |
| `semgrep-run1` | 6 | 0 | 7 | dd-0007 dd-0008 dd-0009 dd-0018 dd-0020 dd-0029 |
| `semgrep-run2` | 5 | 0 | 6 | dd-0007 dd-0018 dd-0020 dd-0021 dd-0055（含全库唯一 **500**） |
| `semgrep-run3`（未完成） | 2 | 0 | ? | dd-0007 dd-0018 |

（§29 A 的分模式表在此得到复核；**`HTTP Error 500` 全库仍仅 `dd-0055@semgrep-run2` 一处**，即击杀 #1 的物证，与 §31 F 一致。）

监视器读数 **29** 与本表合计 **29** 逐位吻合——这是对监视器计数的独立自校验（§23 的信号口径在六轮上均正确）。

### B. 大部分失败是**样本内禀、可复现**的，且按引擎具有特异性

| 样本 | regex r1/r2/r3 | semgrep r1/r2/r3 | 读法 |
| --- | --- | --- | --- |
| `dd-0020` | 失败 ×3 | 失败 ×3 | **6/6 全失败** ⇒ 内容内禀 |
| `dd-0019` | **失败 ×3** | 0 | **只在 regex 侧失败** |
| `dd-0018` | 0 | **失败 ×3** | **只在 semgrep 侧失败** |
| `dd-0007` | 成功 ×2 / 失败 | 失败 ×3 | 边缘样本，会翻（§32 B） |
| `dd-0029` | — / — / — | 失败 / 成功 / — | 边缘样本，会翻（§32 D） |

「`dd-0019` 只在 regex 侧失败、`dd-0018` 只在 semgrep 侧失败」**不是噪声，而是可解释的**：两臂对同一规则同一行的 finding 对象本就不同（§32 B 的字段差：`description`、`category`、`context_before/after`、`ast_enclosing_block`、`taint_trace`），故 **prompt 文本不同**，解析结果随之不同。⇒ 失败在很大程度上是 **(样本 × 引擎)** 对的确定性函数，而**非**轮次噪声。

### C. §32 E 的更正（数字与方向）

原句「两臂失败数之差（11 vs 3）至少部分是轮次间非确定性恰好落在 semgrep 侧」**撤回**：`11` 是 `regex-run1` 的失败**发现数**，`3` 是 `regex-run3` 的失败**样本数**，两者不可比，且方向相反。

按本节 A 表：

- 失败**样本**数：regex **8/5/3** vs semgrep **6/5/2**（`semgrep-run3` 未完成）；
- 失败**发现**数：regex **11/5/2** vs semgrep **7/6/?**；
- benign 侧失败：regex **2/1/0** vs semgrep **0/0/0**。

⇒ 失败负载**在 regex 侧更重**，**不存在「semgrep 侧失败偏多」**。§32 E 据以「把 §29 C 的拒绝加强为机制性」的那句话随之撤回。

**仍然成立的三条**（不得随更正一并丢掉）：

1. **FPR 侧失败完全不参与判定**（§30）——`ΔFPR = +0.0065` 由 `sr-0155` 承担，与失败无关（§33 B）。
2. **recall 侧失败抬高 semgrep**：机制是单样本的（`dd-0029`，§28 B、§32 D），**不是**某种总体偏向。
3. benign 侧失败**全部落在 regex 侧**，其**绝对** FPR 因此被抬高；但这些样本 semgrep 也标记（§17.12 D-2：`ΔFP` 完全由 `sr-0155` 承担），故 **`ΔFPR` 不受影响**。

### D. 非确定性的正确位置

§32 B/D 测得的轮次间非确定性**真实存在且已传播到判据**（`dd-0029`，recall 侧 1/157），但本节把它**定位**为**边缘样本的边界漂移**：`dd-0007`（输出贴住截断上限、且自带未转义引号）与 `dd-0029` 处在解析成败的边界上，而 `dd-0020`、`dd-0019`、`dd-0018` 远离边界、六轮或三轮稳定复现。⇒ 报告应把失败拆成**内禀（可复现）**与**边缘（可漂移）**两层，并说明只有后者给判据带来方差。

## 35. 跨对机器漂移落在**超时类失败**上，不落在标记集合上（2026-09-28）

### A. 事实：pair 1 与 pair 2/3 不在同一天测量

`regex-run1`（3562 s）与 `semgrep-run1`（5506 s）是 **2026-09-24** 的产物，在宿主重启前完成，故 09-28 续跑时被 `RESUME=1` 跳过（驱动日志报 `already complete, kept`，读数与重启前逐位相同，见 §19）。`regex-run2/3`、`semgrep-run2/3` 是 **09-28** 的产物。**即 pair 1 与 pair 2/3 跨日。**

### B. 超时类失败几乎全部集中在 pair 1

（下表按**样本**计；§25 报的 `regex-r1 7 / semgrep-r1 2 / semgrep-r2 1` 是**发现**数，两者口径不同，报告中不可混用。）

| 轮 | 日期 | `timed out` 样本 | 其他模式样本 |
| --- | --- | --- | --- |
| `regex-run1` | 09-24 | **4**（`dd-0056` `dd-0057` `pypi-0057` `sr-0142`） | parse 4 |
| `semgrep-run1` | 09-24 | **2**（`dd-0008` `dd-0009`） | parse 4 |
| `regex-run2` | 09-28 | 0 | parse 5 |
| `semgrep-run2` | 09-28 | 1（`dd-0055`，**OOM 击杀所致**，§25） | parse 4 |
| `regex-run3` | 09-28 | 0 | parse 3 |
| `semgrep-run3` | 09-28 | 0（至今） | parse 3 |

**7 次超时样本里 6 次在 09-24 的两轮**，09-28 的只有 `dd-0055` 一次且已归因于 OOM（§31 F）。⇒ 超时是**测量当时的机器状态**的函数（与 §21 F 实测「run 2 的模型吞吐更高：prefill 40.6→54.1、decode 9.2→10.5 tok/s」方向一致），**不是** (样本 × 引擎) 对的函数。

### C. 这与 `RUN_ORDER` 的设计意图一致，且**不威胁判据**

交替顺序（`h2_loaded_rounds.sh` 头部：regex1, semgrep1, regex2, semgrep2, regex3, semgrep3）就是为了让跨时段漂移表现为**轮次索引**之差而非**引擎**之差。实测正是如此：漂移落在 pair 1 的超时上。

而 pair 1 与 pair 2 的**判据量逐位相同**（§28：两对皆 `fp 18 vs 17`、`ΔFPR = +0.0065`；§30：三轮 regex 判恶意集合逐位相同）⇒ **漂移没有进入判据**。唯一触及判据的漂移项是 `dd-0029`（§32 D）：它在 pair 1 由失败抬成 TP、在 pair 2 为 FN，属 recall 侧 `1/157`。

### D. 报告须写

- pair 1 与 pair 2/3 **跨日**，超时类失败集中在 pair 1；给出 B 表。
- 由此**不得**把「两臂失败率差」当作引擎属性（承 §29 C、§34 C）。
- **也不得**把超时集中读成「semgrep 更稳」：09-24 两轮里 regex 4 次、semgrep 2 次，方向与 §34 C 一致（失败负载在 regex 侧更重）。

## 36. §27 D 的假设被其自身检验**证伪**：冷加载在 semgrep 侧更多，与预测反向（2026-09-28）

### A. 测量

`llama-server started in N seconds` 事件（同一事件会重复记两行，已按秒去重），按轮窗口切分：

| 轮 | 请求数 | 装载事件 |
| --- | --- | --- |
| `regex-run1` | 195 | **0** |
| `semgrep-run1` | 249 | 2（7.56 s、8.31 s） |
| `regex-run2` | 190 | 1（**25.67 s**） |
| `semgrep-run2` | 243 | 2（7.06 s、5.80 s） |
| `regex-run3` | 192 | **0** |
| `semgrep-run3`（未完成） | 45 | 1（7.06 s） |
| **regex 臂** | **577** | **1**（1.73‰） |
| **semgrep 臂** | **537** | **5**（9.31‰） |

### B. 结论：假设证伪，且方向相反

§27 D 的假设是「regex 发现少 ⇒ 调用序列短 ⇒ 空闲段长 ⇒ 卸载多 ⇒ 冷加载多 ⇒ 超时多」。**实测装载事件 semgrep 侧 5 次、regex 侧 1 次（约 5 倍）**，而超时样本是 regex 侧 4、semgrep 侧 2（pair 1）⇒ **冷加载不能解释 regex 侧的超时**。该假设**按其自身的验证方法即被否**；§27 D「验证前不得归因」的保留**就此结清：不得归因，且已排除**。

两点补强：

1. regex 臂唯一那次装载（**25.67 s**）与其余各次（5.80–8.31 s）**不同量级**，且落在 `regex-run2` 开头、紧随矩阵的 `warm_model`（3 次探测调用）⇒ 它是**冷启动装载**，**不是空闲卸载后的重载**。即 **regex 臂三轮实际上没有一次空闲重载**。
2. 全矩阵装载事件共 **6 次**，而超时**样本 7 个**（发现数更多）⇒ 即便把每次装载都记作一次超时成因，也**不足以**覆盖超时数量。

### C. 顺带：请求数在窗口口径下与 §24 E 的调用模型吻合

`semgrep-run1` 窗口内 **249** 次请求，与 §24 E 更正后的调用数 **249** **完全相等**；`regex-run1` 为 **195** vs **192**，高 3 次。窗口边界本身有几分钟的不确定度（`warm_model` 在矩阵 banner 之后、`regex-run1` 真正开始之前执行，且 `seconds=3562` 是从那次开始算的），故这 3 次**归属未验证**（可能是 warm-up 探测，也可能是边界把 `semgrep-run1` 的开头计入）。**能写的只有**：请求数与调用模型在**数条之内**吻合，其中 semgrep 一轮精确相等——这独立于产物地支持了 §24 E 的更正（`251 → 249`）。

### D. 报告须写

- §27 D 的假设**已检验且被否** ⇒ 「两臂失败率差源于空闲卸载/冷加载」**不得写入报告**。
- 残留的**未解释**描述量：装载事件两臂不等（5 vs 1）。**未进一步验证前不得归因**；报告可只列 A 表。

## 37. 预登记：pair 3 的混淆矩阵应**等于 pair 1**（趁 `semgrep-run3` 未结束时写下，2026-09-28）

### A. 依据（截至 `semgrep-run3` 33/311）

`semgrep-run3` 至今 4 处失败样本，**全部在恶意侧**：`dd-0007`(u=1)、`dd-0018`(u=1)、`dd-0020`(u=1)、**`dd-0029`(u=2)**。前三个是 §34 B 认定的**内禀**样本（semgrep 侧 3/3）；**`dd-0029` 是那个边缘样本**，其逐轮史为：

| 轮 | `dd-0029` | 抬升后判定（§28 B、§32 D） |
| --- | --- | --- |
| `semgrep-run1` | **失败 u=2** | 抬升至 HIGH ⇒ 阻断 ⇒ **TP** |
| `semgrep-run2` | 无失败 | 未阻断 ⇒ **FN** |
| `semgrep-run3` | **失败 u=2** | ⇒ 应同 run1 ⇒ **TP** |

### B. 预登记（可证伪）

若上述机制成立，则 `semgrep-run3` 的混淆矩阵应为

```
tp=55  fp=18  tn=136  fn=102
```

即**与 `semgrep-run1` 逐位相同**，于是 pair 3 的读数应为 `ΔFPR = (18-17)/154 = +0.0065`、`Δrecall = (55-49)/157 = +0.0382`（`regex-run3` 已实测为 `tp49/fp17/tn137/fn108`，与 run1/run2 全同）。

### C. 若不符，则证伪的是哪一条

- 若 `tp=54` ⇒ `dd-0029` 的失败**未**抬升为阻断 ⇒ §28 B 的「失败在恶意样本上致 TP」这一机制**不完整**，须查该样本失败发现的**severity**（`assist` 的抬升需要 ≥MEDIUM）。
- 若 `fp≠18` ⇒ `sr-0155` 的标记**不稳定** ⇒ §33 B「承担整个 ΔFPR 失败的唯一样本」须改为**两轮成立、第三轮不成立**，且 `ΔFPR` 的稳定性陈述须相应减弱。
- 若 `tp=55` 但 `fp=18` 之外还有第三处偏离 ⇒ `regex-run3` 的「三轮逐位相同」（§30）这一**对照臂的稳定性**须复核。

### D. 这一预测本身检验什么

它检验的是 §34 D 的定位：**只有边缘样本给判据带来方差**。若 pair 3 与 pair 1 逐位相同，则该定位得到最强的支持——三轮里唯一的矩阵差异恰好由唯一一个边缘样本解释。

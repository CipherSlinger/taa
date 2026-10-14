# 远程部署自洽化：Pod 内代码扫描引擎与 Pod→LLM 通路

日期：2026-10-14
状态：已实现

## 背景

`./deploy.sh remote taa`（TAA 部署进 178 上的 kata CSV2 Pod，LLM 换成本机 docker 容器
`taa-env-slim-v2`）失败，两个互不相干的原因：

1. **代码扫描引擎缺失**：`[TAA-FATAL] resolve code scan engine: semgrep rules
   /opt/taa/semgrep/rules: stat ... no such file or directory`。TAA 以 fail-closed 方式解析引擎
   （`internal/codeaudit/engine.go` 对规则路径 `os.Stat`，失败即退出），supervisor 每 10s 重启一次，
   120s 就绪门禁必然超时。
   - 配置侧：`configs/taa-production.json` 写死 `security.codeScanEngine=semgrep` +
     `security.semgrepRulesPath=/opt/taa/semgrep/rules`。
   - Pod 镜像 `taa-env:slim-v2` 里两样都没有（实测：Ubuntu 24.04 / python3.12 / GNU tar 1.35，
     无 `semgrep`，无 `/opt/taa/semgrep`）。
   - 只有 `deploy-docker.sh` 会装引擎，`deploy.sh` 从来没有处理过 → 远程路径必然撞 FATAL。

2. **Pod 到 LLM 容器不可达**：LLM 跑在 bridge 网络的容器里（172.17.0.2，只发布 6001），
   而宿主的 `DOCKER ! -i docker0 -o docker0 -j DROP` 会把 Pod（10.244.0.0/16）→ 172.17.0.2:8443
   的包静默丢掉（当时用规则计数器 332→342 证实）。Pod 能到宿主上任何监听端口，唯独到不了这个容器。

## 设计

### 一、部署前补齐扫描引擎（`deploy.sh remote`）

在「replacing remote taa, config, and certificates」之后、「pausing old taa」之前插一步
`provisioning code scan engine inside container`。放这个位置的原因：这一步可能失败，
失败时不该已经打断在跑的 taa。

流程：**探活 → 缺什么补什么 → 验证**。

1. **需求从配置读，不写死**：`taa_scan_engine_requirements` 解析模板的
   `security.codeScanEngine` / `security.semgrepRulesPath`。`codeScanEngine != semgrep` 时整步跳过
   （regex 引擎不依赖外部程序）。`semgrepRulesPath` 为空时快速失败：引擎会退化成相对仓库根的
   内置默认路径，在容器里必然还是 stat 失败，早点报比等 120s 好。

2. **引擎运行时来自宿主上的 payload 归档** `REMOTE_SEMGREP_BUNDLE`
   （默认 `$REMOTE_DIR/semgrep-bundle.tar.gz`，94MB）。可选 `SEMGREP_BUNDLE` 指向本地归档，
   设置时先 scp 到宿主再注入。

3. **规则从仓库上传**（`SEMGREP_RULES_SOURCE`，默认 `models/audit/semgrep/rules`），不跟着 payload
   一起变旧：规则是随提交演进的内容，Go 侧的规则表（severity/rule_family 映射）在同一个提交里，
   两者错位会 fail-closed。实测两端 5 个规则文件 sha256 完全一致，因此今天这步是无操作。

4. **注入统一走流式解包**：`kubectl exec -i ... tar -xzf - -C <dir>`，归档经 SSH 或本地管道喂进去。
   - 引擎：`remote_ssh "cat '$REMOTE_SEMGREP_BUNDLE' | $(container_exec_i) tar -xzf - -C /"`，
     数据不出宿主，避免本地→宿主再来一趟 94MB。
   - 规则：本地 `tar -czf - --transform ...` 经 `remote_ssh ... tar -xzf - -C <父目录>` 流入。
   - 用流式而不是 `kubectl cp`：目录语义（源目录名 vs 目标目录名）在 cp 里依赖两端命名，
     流式解包位置由我们显式给出，且不在宿主留临时文件。

5. **验证**：注入后跑 `semgrep --validate --config <rules>` 再 `semgrep --version`。
   前者证明 CLI、Python site-packages、规则三者串起来了（引擎在容器里由 PATH 解析 `semgrep`，
   与 `internal/codeaudit/semgrep_engine.go` 的 `defaultSemgrepBin` 一致），后者把版本号打进日志。

6. **payload 不在宿主上时快速失败**，给出构建/分发解法，不再干等 120s 重启循环。

### 二、Pod→LLM 容器的通路（`deploy-llm.sh remote-docker`）

容器是 `deploy-llm.sh remote-docker` 建的，只有它知道容器 IP 与端口，所以放行规则也由它落：

`iptables -I FORWARD 1 -s <POD_CIDR> -d <容器IP> -p tcp --dport <端口> -j ACCEPT`

- 只对「bridge 网络 + 有容器 IP」的情况动手；host 网络的容器本来就从宿主地址可达。
- 用 `iptables -C` 判重，幂等。
- `POD_CIDR` 默认 `10.244.0.0/16`（kube-flannel 的 Pod 网段），可覆盖。

## 已知边界（刻意不做）

- **不持久**：payload 注入进 Pod 的可写层，宿主上的 payload 归档与 iptables 规则都在内存里。
  Pod 重建（滚动/驱逐/容器重启）后注入丢失，镜像里依然没有引擎；宿主重启后规则消失。
  彻底解法是把 payload 烘进镜像、把规则随镜像发布，属于后续工作。
- **不校验规则内容**：部署只保证「路径存在 + 规则能被 semgrep 解析」，规则与 Go 侧规则表是否
  逐条对齐仍由测试（`models/audit/semgrep` 相关单测）保证。
- 不在 deploy.sh 里自动决定 LLM 端点的网络形态：`TAA_LLM_ENDPOINT` 仍然由调用方给出。

## 影响面

- `deploy.sh`：新增 2 个默认变量、2 个函数、1 个步骤，`usage()` 增 3 条环境变量说明。
- `deploy-llm.sh`：新增 1 个函数，在 remote-docker 建好容器后调用。
- 新增 `deploy/guest-build/build-semgrep-payload-container.sh`（容器形态 payload 的构建配方，
  产物 gitignore）与 `tests/deploy_scan_engine_test.sh`。

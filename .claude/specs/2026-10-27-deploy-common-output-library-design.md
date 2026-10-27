# 部署脚本公共输出层抽取

- **Date**: 2026-10-27
- **Specification Path**: `.claude/specs/2026-10-27-deploy-common-output-library-design.md`
- **Scope**: `deploy.sh`、`deploy-llm.sh` 中重复的终端输出组件
- **Lifecycle Status**: Target Architecture Specification
- **Affected Modules**: `deploy/lib/common.sh`（新建）、`deploy.sh`、`deploy-llm.sh`、`tests/deploy_llm_remote_pod_test.sh`

---

## 1. 背景与现状

仓库根有 5 个部署脚本，共约 7000 行。`deploy.sh`（2073 行）和 `deploy-llm.sh`（2269 行）各自维护了一整套终端输出组件，其中：

| 函数 | 形态 |
|---|---|
| `step`、`info`、`warn`、`err`、`detail`、`require_file`、`require_dir`、`require_command` | 逐字节相同 |
| `banner` | 差 4 行 |
| `spin_task`（86 行） | 只差 `mktemp` 前缀和 `/tmp/<name>-deploy-last-error.log` 文件名 |
| `cleanup_display`（37 行） | 只差临时文件清单、临时容器、横幅开关和错误日志名 |
| 颜色常量 + `IS_TTY` | 逐行相同 |

检查未发现死函数——所有定义都有调用点，所以简化空间只在结构，不在删除。

`deploy-fhe.sh` 是另一套风格（`log`/`warn` 前缀 `[deploy-fhe]`、无颜色、无 spinner），`deploy-taa-vm.sh` 是构建/部署调度器，`deploy-dataanaylsis.sh` 是 `deploy.sh` 的 120 行包装。四者不在本次范围内。

## 2. 目标与非目标

**目标**

1. 把上表所列的输出组件抽到 `deploy/lib/common.sh`，由 `deploy.sh` 和 `deploy-llm.sh` source。
2. 抽取后两个脚本的终端输出、错误横幅、`/tmp` 临时文件名**逐字节不变**。
3. 不改变任何部署语义、退出码、错误处理路径。

**非目标**

1. 不抽 `remote_ssh`、`container_exec`/`container_cp`、`container_exec_i`、`check_remote_connectivity`、`check_remote_pod`、`derive_cc_init_data`。这些函数共享了名字但语义不同：`deploy.sh` 的 `check_remote_pod` 有 `DEPLOY_DOCKER` 早退分支，`deploy-llm.sh` 的 `derive_cc_init_data` 读取 Pod 注解而 `deploy-taa-vm.sh` 的同名函数做的是另一件事。把它们塞进同一接口会让库承担调用方的模式差异，收益抵不上复杂度。
2. 不改 `deploy-fhe.sh`、`deploy-taa-vm.sh`、`deploy-dataanaylsis.sh` 的风格。
3. 不拆任何超长函数（`save_local_docker_image`、`handle_models_command` 等）。
4. 不新增测试文件。

## 3. 设计

### 3.1 库的位置与被 source 的方式

- 路径：`deploy/lib/common.sh`。
- 两个脚本以 `PROJECT_DIR` 为基准 source：`source "$PROJECT_DIR/deploy/lib/common.sh"`。`PROJECT_DIR` 在两个脚本中都已经由 `BASH_SOURCE` 解析为仓库根，抽库不引入新的路径推导。
- 库自身以 `# shellcheck shell=bash` 开头，不做 `set -euo pipefail`——选项由调用方持有，库只定义函数和常量。

### 3.2 调用方身份参数化

库需要知道"我是谁"，才能产出与改造前一致的文件名和横幅。用四个变量表达，由调用方在 source **之前**设置：

| 变量 | `deploy.sh` | `deploy-llm.sh` | 用途 |
|---|---|---|---|
| `DEPLOY_LOG_NAME` | `taa-deploy` | `teellm-deploy` | `/tmp/${DEPLOY_LOG_NAME}-last-error.log` |
| `DEPLOY_TASK_PREFIX` | `taa_task` | `teellm_task` | `spin_task` 的 `mktemp` 前缀 |
| `DEPLOY_TEMP_FILES`（数组） | `TEMP_EXPORT_FILE TEMP_FILELIST` | `TEMP_FILELIST TEMP_CONFIG_FILE TEMP_POD_MANIFEST` | `cleanup_display` 逐个删除 |
| `DEPLOY_TEMP_CONTAINERS`（数组） | `TEMP_BUILDER_CONTAINER` | 空 | `cleanup_display` 逐个 `docker rm -f` |
| `DEPLOY_ERROR_BANNER_SETTING` | 恒为 `true` | `TRAP_SUPPRESS_DEPLOYMENT_BANNER` | 控制失败横幅 |

数组里存的是**变量名**，库用 `printf -v` / 间接引用取值，因为那些变量在调用时才被赋值。

`DEPLOY_ERROR_BANNER_SETTING` 这一项是两脚本唯一的行为差异：`deploy-llm.sh models` 子命令要把失败横幅压掉，`deploy.sh` 没有这个需求。库按名字读取该变量，缺省视为 `true`。

### 3.3 库包含的内容

```
deploy/lib/common.sh
├── 颜色常量与 IS_TTY            （原 deploy.sh 4-29 行）
├── SPIN_FRAMES
├── cursor_hide / cursor_show
├── banner / step / info / warn / err / detail
├── require_file / require_dir / require_command
├── spin_task
└── cleanup_display
```

`handle_err` 与两处 `trap` 也一并进库：`trap 'handle_err $LINENO "$BASH_COMMAND"' ERR` 依赖库里的 `LAST_ERR_*` 变量，留在调用方会让变量跨文件散落。库被 source 时装 `ERR` trap，`cleanup_display` 的 `EXIT INT TERM` trap 也在库末尾装好——两脚本现在都是在文件顶部装这两个 trap，时机一致。

### 3.4 输出一致性的保证方式

1. 所有 `printf`/`echo -e` 的格式串、颜色码、前缀空格、框线字符从现文件逐字搬到库中，不做"顺手美化"。
2. `/tmp` 下产生的文件名由 §3.2 的变量拼出，取值与改造前相同。
3. 验证用改造前采集的基线：`--help` 输出、`/tmp/<name>-last-error.log` 文件名、失败横幅文字。

## 4. 迁移步骤

1. 新建 `deploy/lib/common.sh`，内容为两脚本输出组件的并集，全部参数化。
2. `deploy.sh`：删除颜色块、`cursor_*`、`handle_err`+trap、`cleanup_display`+trap、`banner/step/info/warn/err/detail`、`spin_task`、`require_*`；在 `PROJECT_DIR` 定义之后设置 §3.2 的变量并 source。
3. `deploy-llm.sh`：同样删除，设置自己的变量并 source。
4. 删除函数时保留每个脚本自己的状态变量初始化（`TEMP_EXPORT_FILE=""` 等），库不替它们初始化，因为哪些临时量存在是调用方的知识。
5. `tests/deploy_llm_remote_pod_test.sh`：在拷贝脚本之后补 `mkdir -p "$REPO/deploy/lib" && cp "$ROOT_DIR/deploy/lib/common.sh" "$REPO/deploy/lib/"`，否则临时仓库里的 `deploy-llm.sh" source 失败。

### 4.1 步骤 2 的落点

`deploy.sh` 中 `PROJECT_DIR` 定义在第 94 行，而颜色块在第 4-29 行。source 点必须在 `PROJECT_DIR` 之后，因此颜色常量从文件顶部移到 source 点生效。这带来的唯一约束是：第 4 行到 source 点之间不得使用任何库提供的符号。逐行核对后，该区间只有变量赋值，没有输出调用，约束成立。

`deploy-llm.sh` 的 `PROJECT_DIR` 定义在 222 行之后的 `Project & Environment Defaults` 段，同样处理。

## 5. 验证

1. **基线对比**：改造前已采集 `/tmp/taa-baseline/`（`deploy.sh --help`、`deploy-llm.sh --help`、三个测试的输出）。改造后重跑并 `diff`，要求 `--help` 输出逐字节一致。
2. **现有测试**：`tests/deploy_llm_remote_pod_test.sh`、`tests/deploy_ollama_preflight_test.sh`、`test-deploy-taa-vm.sh` 全部通过。
3. **语法检查**：`bash -n` 覆盖库和两个脚本。
4. **错误路径**：构造一次 `spin_task` 失败（例如让 `--help` 之外的某个命令失败），确认 `/tmp/taa-deploy-last-error.log` 与 `/tmp/teellm-deploy-last-error.log` 的生成、横幅文字、退出码与改造前一致。

## 6. 风险

| 风险 | 说明 | 缓解 |
|---|---|---|
| source 点晚于 top-of-file 使用 | 颜色常量在文件顶部生效改为在 source 点生效 | §4.1 已核对，该区间无输出调用；迁移时再逐行确认 |
| 测试临时仓库缺库文件 | pod 测试把脚本拷到临时根目录 | 迁移步骤 5 显式补拷 |
| 参数化变量未设置 | 调用方漏设 `DEPLOY_LOG_NAME` 时文件名退化为 `/tmp/-last-error.log` | 库内对每个参数给保底默认值，取值与 `deploy.sh` 原值相同 |
| 间接引用取未定义变量 | `DEPLOY_TEMP_FILES` 里的变量在 cleanup 时可能未赋值 | 用 `${!name:-}` 取值，与现有裸用的 `:-` 语义一致 |
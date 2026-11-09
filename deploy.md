# 部署命令

仓库里有 5 个部署脚本，按组件分工：

| 脚本 | 部署对象 | 使用的镜像 |
|---|---|---|
| `deploy.sh` | TEE 训练/推理 Pod 里的 TAA 本体 | 自建 `taa-train-infer:<YYYYMMDD>`，基座 `taa-env:slim-v2`，推到 `<REMOTE_HOST>:31313` |
| `deploy-fhe.sh` | FHE 服务 + TAA：默认建专用 FHE Pod，也可部署进已有 Pod 或 docker 容器 | 自建 `taa-fhe:<YYYYMMDD>`，基座 `latti/latti-server-node:latest`；`create` 建 Pod 时另把 FHE 模型树烤进镜像，推到 `<REMOTE_HOST>:31313` |
| `deploy-dataanaylsis.sh` | 数据分析角色（转发给 `deploy.sh`，换基座并注入 `CONTRACT_TYPE=3`） | 自建 `taa-dataanaylsis:<YYYYMMDD>`，基座 `jupyter-nologin-full:v2.2` |
| `deploy-llm.sh` | 独立的 TEE-LLM 推理网关 Pod | 自建 `teellm:<YYYYMMDD>`，基座 `teellm-base:<日期>`（由 `taa-env:slim-v2` 派生），内置 ollama 运行时与模型，推到 `<REMOTE_HOST>:31313` |
| `deploy-platform-mock.sh` | 平台 mock，需单独启动 | 不用镜像：静态二进制经 SSH 上传后在远端后台运行 |

平台（mock 或生产控制面）不由 `deploy.sh` / `deploy-fhe.sh` / `deploy-llm.sh` 启动；
这三个脚本只负责让部署对象找到平台地址。每个脚本的完整选项和环境变量以 `--help` 为准。

## 通用约定

- **动作**：`create`（默认）/ `update` / `start` / `stop` / `probe` / `delete`，互斥。
  `create` 是唯一创建 Pod 的动作；`start` 只启动 Pod 里的服务（`stop` 的另一端），不构建、
  不拷贝；`update` 把当前构建装进已有 Pod；`delete` 只删本脚本创建的 Pod。
- **目标 Pod**：`--pod <名字>` 表示接管已有 Pod。不给时作用于各自脚本的专用 Pod，见各脚本小节。
- **命名空间**：`--namespace <ns>`，默认 `osr`。
- **远端主机**：`REMOTE_HOST` / `REMOTE_USER` / `REMOTE_DIR` 环境变量。
- **SSH 密码**：`--remote-password <密码>`；不给时取脚本内置默认值，口令为空则改用密钥或
  agent 认证（`deploy.sh` 与 `deploy-llm.sh` 在缺省且为空时会交互式询问）。
- 能用命令行参数表达的配置一律用参数；只有参数没有对应开关时才用环境变量。

## TAA：`deploy.sh`

```bash
# 默认动作 create：用当前源码构建生产镜像、创建专用 Kata CSV2 Pod（默认名 taa-deploy）、
# 校验 Pod 里跑的正是这次构建，然后启动 taa
./deploy.sh

# 指定模型
./deploy.sh create --model qwen2.5-coder:7b

# 把当前构建更新进已有 Pod（不创建、不删除 Pod）
./deploy.sh update

# 只启停 Pod 里的 taa，Pod 本身留着
./deploy.sh stop
./deploy.sh start
./deploy.sh probe

# 删除本脚本创建的 Pod（guest 可写层里的数据、密钥、模型一并丢失）
./deploy.sh delete

# 接管一个不是本脚本创建的 Pod：只 update / start / stop / probe，绝不创建或删除它
./deploy.sh update --pod <pod 名> --namespace osr

# 只打包生产镜像，不部署
./deploy.sh save
./deploy.sh save --image taa-train-infer:$(date +%Y%m%d)
./deploy.sh save --archive /tmp/taa-env-production.tar.gz

# 覆盖默认平台端口（TAA 注册/上报使用的端口，默认 18080）
PLATFORM_PORT=18081 ./deploy.sh create
```

**动作**：`create`（默认）、`update`、`start`、`stop`、`probe`、`delete`、`save`，互斥。
`start` 只启动 Pod 里的 taa（等价于 `stop` 的另一端），不构建、不拷贝、不创建 Pod；`create`
才是唯一创建 Pod 的动作。`delete` 只删本脚本创建的 Pod，`--pod` 指定的 Pod 一律拒绝。

**实例角色**：`create` 把角色写进 Pod 的 `CONTRACT_TYPE` 环境变量（默认 `1`，即普通 tee 角色），
不再依赖配置里的 `server.type`。用 `TAA_POD_CONTRACT_TYPE` 改角色（`1`/`2` 都是 tee，`3` 数据分析）。
Pod 的环境变量不能原地修改，已有 Pod 的角色与本次请求不一致时 `create` 会拒绝复用，换角色需要
`delete` 后重建，或用另一个 `TAA_POD_NAME`。

**Pod 生命周期**：不给 `--pod` 时，首次 `create` 会先用当前源码构建生产镜像、上传并推送，
再创建 Pod 并校验；已有 Pod 会被原样保留并校验（guest 可写层里是 SM2 密钥、封存状态和导入的
数据，重建等于丢数据，而且是第二台常驻内存的机密虚拟机）。要换镜像先 `delete` 再 `create`。
`--pod` 指向的 Pod 永远不由本脚本创建或删除。

**镜像**：自动构建的镜像推到 `TAA_IMAGE_REGISTRY/TAA_POD_IMAGE_REPO:<YYYYMMDD>`
（默认 `172.16.10.178:31313/taa-train-infer:<日期>`），当天 tag 可变，因此 Pod 使用
`imagePullPolicy: Always`。用 `--image` 指定现成镜像则跳过构建，只校验文件存在，
保留 `IfNotPresent`。

**常用参数**

| 参数 | 说明 |
|---|---|
| `--pod <名字>` | 作用于已有 Pod（`update`/`start`/`stop`/`probe`）；`create`、`delete` 拒绝 |
| `--namespace <ns>` | 命名空间，默认 `osr` |
| `--model <名字>` | 写入配置的模型名 |
| `--port <端口>` | TAA 监听端口（默认 6001） |
| `--remote-password <密码>` | 远端 SSH 密码 |
| `--image <镜像>` | 部署指定的现成镜像，不构建 |
| `save --image` / `--archive` / `--base` / `--save-config` | 打包镜像名、归档路径、基座镜像/归档、配置模板 |

其余可调项（Pod 规格、节点、RuntimeClass、registry、就绪超时、semgrep payload 等）见
`./deploy.sh --help` 的 Environment overrides 段。

## FHE + TAA：`deploy-fhe.sh`

一个容器同时运行 FHE 服务（redis + api_server + worker，镜像
`latti/latti-server-node:latest`）与 TAA。TAA 在容器内经 `127.0.0.1:58996` 访问 FHE，
58996 不发布到宿主机；只发布 TAA 的 6001 供平台调用。

有两种部署目标，默认 `pod`：

- `pod`（默认）：Kata CSV2 机密虚拟机 Pod。guest 里没有宿主 bind，所以 `create` 把 FHE 基座
  镜像、TAA、supervisor、渲染好的配置和 FHE 模型树一起装配成一个镜像，推到本地 registry 后
  再建 Pod（guest 用自己的 CDH 拉镜像，宿主 `docker load` 不够用）。
- `container`：宿主上的普通 docker 容器，用 `--target container` 显式选择。

```bash
# 默认动作 create：装配并推送镜像、创建 Pod（默认名 taa-fhe）、校验 Pod 里跑的正是这次构建，
# 再等 FHE API 与 TAA 就绪
./deploy-fhe.sh
PLATFORM_IP=172.16.10.178:18081 PLATFORM_PUBLIC_KEY=<平台 SM2 公钥> ./deploy-fhe.sh create

# 接管一个已存在的 Pod：只更新文件，不创建、不删除 Pod
./deploy-fhe.sh update --pod <pod 名>
./deploy-fhe.sh update --pod <pod 名> --namespace osr

# 只启停 Pod 里的 taa，Pod 本身留着
./deploy-fhe.sh stop
./deploy-fhe.sh start
./deploy-fhe.sh probe

# 删除本脚本创建的 Pod（--pod 指定的 Pod 一律拒绝）
./deploy-fhe.sh delete

# 同一 Pod 里有多个容器时指定容器
POD_CONTAINER=<容器名> ./deploy-fhe.sh update --pod <pod 名>

# 部署到 docker 容器而不是 Pod
./deploy-fhe.sh --target container

# 用打包好的镜像部署（不装配、不推送，只校验文件存在）
TAA_IMAGE=taa-fhe:20261019 ./deploy-fhe.sh create

# 只打包镜像，不部署（模型不烤进镜像）
./deploy-fhe.sh save

# 只看会执行什么
./deploy-fhe.sh -n create
./deploy-fhe.sh --pod <pod 名> -n update
```

**动作**：`create`（默认）、`update`、`start`、`stop`、`probe`、`delete`、`save`，互斥。
`create` 是唯一创建 Pod 的动作，`update` 只改已有 Pod 里的文件（重渲染配置以匹配 Pod 内的
FHE 数据根、重启 supervisor 并等健康检查），`start`/`stop` 只通过 supervisor 的 `manual`
文件启停 taa，`probe` 只报告 TAA 是否应答，`delete` 只删本脚本创建的 Pod。给了 `--pod`
时脚本只接管这个 Pod：`create` 与 `delete` 会被拒绝（提示改用 `update --pod <名字>`）。

**创建 Pod 需要的身份**：`create` 要求 `PLATFORM_IP` 不是回环地址，并要求有平台 SM2 公钥
（`PLATFORM_PUBLIC_KEY`，或模板/配置里的 `platform.publicKey`）——TAA 没有公钥会在启动时退出。
`cc_init_data` 注解默认从宿主上任意一个运行中的 CoCo Pod 复制；没有可复制的就渲染
`FHE_POD_INITDATA_FILE` 指向的 initdata 文件，也可以用 `FHE_POD_CC_INIT_DATA` 直接给。

**校验而不修复**：`create` 建完 Pod 会逐字节核对 Pod 里的 taa、supervisor 与模型目录是不是
这次构建的产物，不一致就列出差异并失败，绝不就地“修好”。显式 `TAA_IMAGE` 是操作者自己的
构建，此时只校验文件存在。

**参数**

| 参数 | 说明 |
|---|---|
| `create` / `update` / `start` / `stop` / `probe` / `delete` | 动作，互斥，默认 `create` |
| `save` | 打包镜像并导出归档（`--image` 指定镜像名，默认 `taa-fhe:<YYYYMMDD>`） |
| `--target pod\|container` | 部署目标，默认 `pod` |
| `--pod <名字>` | 接管已有 Pod（`update`/`start`/`stop`/`probe`）；不能与 `create`、`save` 同用 |
| `--namespace <ns>` | Pod 命名空间，默认 `osr` |
| `--mode remote\|docker` | docker/kubectl 在哪执行：远端（默认）或本机 |
| `--image <名字>` | `save` 产出的镜像名 |
| `--remote-password <密码>` | 远端 SSH 密码 |
| `-n`, `--dry-run` | 只打印命令 |
| `--skip-build` | 复用 `TAA_BINARY_PATH` 指向的二进制 |

Pod 规格与来源用 `FHE_POD_NAME`、`FHE_POD_CPU`、`FHE_POD_MEMORY`、`FHE_POD_GPU`、
`FHE_POD_NODE`、`FHE_POD_RUNTIME_CLASS`、`FHE_POD_PULL_POLICY` 调整，镜像推送目标是
`FHE_IMAGE_REGISTRY`（默认 `<REMOTE_HOST>:31313`）；平台不在 docker 网桥网关时用 `PLATFORM_IP`。
其余挂载、端口、GPU、就绪超时等见 `./deploy-fhe.sh --help`。

## 数据分析角色：`deploy-dataanaylsis.sh`

转发给 `deploy.sh`，基座换成 `jupyter-nologin-full:v2.2`，并向 Pod 注入 `CONTRACT_TYPE=3`：
数据落盘目录（`/home/jovyan/systemAuthData`）和审计开关都由角色决定，配置文件原样使用。
动作与参数全部原样透传，因此 `create`（默认）/ `update` / `start` / `stop` / `probe` /
`delete` / `save` 都与 `deploy.sh` 一致：

```bash
./deploy-dataanaylsis.sh          # create
./deploy-dataanaylsis.sh update
./deploy-dataanaylsis.sh stop
./deploy-dataanaylsis.sh start
./deploy-dataanaylsis.sh probe
./deploy-dataanaylsis.sh delete
./deploy-dataanaylsis.sh save
```

角色拥有自己的镜像仓库（`TAA_POD_IMAGE_REPO=taa-dataanaylsis`）和 Pod 名
（`TAA_POD_NAME=taa-dataanaylsis`）。不能和 tee 角色共用：同一天两个角色都往
`<repo>:<YYYYMMDD>` 推镜像，基座不同却同名，后建的会覆盖先建的，任何按 tag 缓存的地方都可能
把另一个角色的镜像交给这次部署；Pod 名同理，环境变量不能原地改，两种角色抢同一个名字只会让
后一个 `create` 被角色校验拒绝。两个变量都可以由调用方覆盖。

`save` 的镜像名与归档名也由仓库名推出，与 `create` 落到同一处：
`taa-dataanaylsis:<YYYYMMDD>`、`deploy/out/taa-dataanaylsis-<YYYYMMDD>.tar.gz`。

本角色与其它角色一样只有一个自启文件 `/root/taa/taa-supervisor.sh`，但内容来自
`deploy/dataanaylsis/taa-supervisor.sh`：它同时启动 jupyter 和 TAA，jupyter 退出即容器退出。
细节见下文“3. 数据分析”。

## TEE-LLM 推理网关：`deploy-llm.sh`

```bash
# 模型管理
./deploy-llm.sh models list
./deploy-llm.sh models info qwen2.5-coder:7b
./deploy-llm.sh models switch qwen2.5-coder:7b

# 建专用 Pod 并部署（Pod 不存在时先构建镜像；数十分钟）
./deploy-llm.sh create

# 指定模型
./deploy-llm.sh create --model qwen2.5-coder:7b

# 更新已有 Pod（不创建、不删除 Pod）
./deploy-llm.sh update

# 重启/停止服务、探测端点
./deploy-llm.sh stop
./deploy-llm.sh probe       # 探 RFC 8998 TEE-TLS 就绪

# 删除专用 Pod，并核对宿主是否留下 kata 沙箱
./deploy-llm.sh delete
```

**动作**：`create`（默认，构建镜像并建专用 Pod）、`update`、`start`、`stop`、`probe`、
`delete`、`models`。`start` 只恢复 supervisor 并等服务就绪（`stop` 的另一端），不构建、
不拷贝；`update` 把当前构建增量部署进已有 Pod。`create`、`update`、`delete` 恒以专用 Pod
`TEELLM_POD_NAME`（默认 `taa-teellm`）为目标，用 `--pod` 指向别的 Pod 会被拒绝；
`start`/`stop`/`probe` 默认作用于 `TEELLM_POD_NAME`，也可以用 `--pod` 指向别的已有 Pod。

**常用参数**：`--model <名字>`、`--ollama-dir <路径>`、`--port <端口>`（默认 8443）、
`--config <路径>`、`--pod <名字>`、`--namespace <ns>`、`--remote-password <密码>`。

**镜像内建构建**：取 `taa-env:slim-v2` 派生一份剥掉 `/root/taa` 的 `teellm-base:<日期>`，
把当前工作树编出的 `teellm-service`、两份配置、`teellm-supervisor.sh`、ollama 运行库与模型
塞进一次性容器，补齐 6 个 soname 软链后 `docker commit` 成 `teellm:<YYYYMMDD>`。

**相同构建不上传**：提交镜像只是为了拿到 ID。提交之后先读 registry 上当天 tag 的 schema2
清单，把 `config.digest` 与本地 `docker image inspect --format '{{.Id}}'` 比对，相同就跳过
`docker save` / `scp` / `docker push`，直接用该 tag 建 Pod；不同才导出、上传、在远端
`docker load` → `tag` → 推送（推送前先删同 tag 的旧 manifest，当天重建不会冲突）。
无论有没有推送，这条路径都用 `imagePullPolicy: Always`，因为当天 tag 会被覆盖。

**Pod 已存在时不复用、直接报错**：`create` 只负责创建。`kubectl get pod` 查到时脚本打印
该 Pod 的 `-o wide`，说明"这里只创建、不复用也不替换"，然后以非 0 退出，并提示先执行
`./deploy-llm.sh delete` 再重跑。既不构建镜像也不 `apply`。理由：复用一个已有 Pod 会部署进
它当时碰巧在跑的镜像；而在同一路径里自动"删了重建"会悄悄丢掉 guest 可写层里的 ollama 运行时
与模型，并换掉 TAA `llm.endpoint` 指向的 Pod IP —— 这两件事都必须由操作者显式决定。
只是想更新一个已存在 Pod 时用 `update`。

**建之前先预检**：`create` 在**构建镜像之前**确认 API server 可达、Pod 名是合法
DNS label（≤63 字符）、命名空间与 RuntimeClass 存在、宿主端口空闲，任一不满足立即退出 ——
命名空间写错或端口被占不该先花几十分钟编译推送镜像。端口检查分两处：宿主 `ss` 看是否已有监听
（运行时是在宿主网络命名空间里开这个端口的），集群里看有没有别的 Pod 声明了同一个 `hostPort`
（只告警：不在运行的 Pod 不会阻塞调度）。镜像选定之后再 best-effort 查一次 registry 的
`tags/list`（这次运行自己构建并推送过就跳过）；查不到只告警。

**对外端口与时间**：Pod 声明两条宿主映射 —— `8443 → 18443`（`TEELLM_POD_HOST_PORT`）和
`6001 → 16001`（`TEELLM_POD_ATTESTATION_HOST_PORT`），各自的变量设 `0` 就不映射该条，两者都设时
必须不同号。所以不依赖随时会变的 Pod IP 也能访问：TEE-TLS 在 `https://<节点>:18443`，平台三个
明文接口在 `http://<节点>:16001/v1/llm/{heartbeat,log,getAttestation}`。`8443` 那条只对商密 TLS
客户端有意义（普通 `curl -k` / `openssl s_client` 完成不了 RFC 8998 握手，服务端直接断开），
`6001` 那条才是给人用 curl 查的。TAA 自己仍拨 Pod IP，这两条映射是给人的、给集群外调用方的，
也是重建 Pod 后唯一不变的地址。容器里另设 `TZ=Asia/Shanghai`，guest 日志与宿主、平台记录按同一
时区读。

**平台怎么连上实例**：方向已经反过来 —— 平台调用 teellm，teellm 不主动上报。teellm-service
在明文 `:6001` 上提供三个接口：`/v1/llm/getAttestation`（取远程证明报告）、
`/v1/llm/heartbeat`（心跳）和 `/v1/llm/log`（按 `sinceSeq` 增量拉日志）。本仓库的
`deploy-platform-mock.sh` 默认直接调**宿主地址** `http://<--host>:16001`（即上面那条 hostPort），
控制台 TEE-LLM 卡片显示的也是它——Pod IP 每次重建都会变，宿主端口不会，所以默认不再查 Pod IP；
传 `--llm-pod` / `--llm-ns` / `--llm-port` 才回到 kubectl 发现，`--llm-target` 可指定任意地址。
真实平台若仍按 K8s Pod 自动发现拿 Pod IP 也能用，两条路都存在。没有任何注册请求，也不再需要
`PLATFORM_IP`、`DOCKER_ID` 之类的环境变量。渲染进 Pod 的配置文件里不再有 `platform` 段，
`deploy-llm.sh` 的 `--platform` / `TEELLM_PLATFORM_ADDR` 已删除；重新部署会把旧配置里的
`platform` 段一并去掉。部署输出的 `Platform` 一行固定打印 `:6001` 上这三个被平台轮询的接口。

**删除后查残留**：`delete` 提交 `--grace-period=30 --wait=false`，轮询 180s 后必要时强制删除，
再比较三个数 —— 集群里的 kata Pod 数、`/run/vc/sbs` 目录数、`qemu-system` 进程数。不等就打印
每个 qemu 的 RSS 与 `-m`，并给出 `crictl pods` → `stopsandbox` → `rmp` 的顺序（不要直接 kill）。

**相关环境变量**：`TEELLM_IMAGE`（显式指定则不构建也不解析）、
`TEELLM_BUILD_POD_IMAGE=false`（回到"取 registry 最新日期 tag"的旧行为）、
`TEELLM_IMAGE_REPO` / `TEELLM_IMAGE_REGISTRY` / `TEELLM_POD_PULL_POLICY`、
构建用的 `TEELLM_IMAGE_BASE` / `TEELLM_IMAGE_BASE_ARCHIVE` / `TEELLM_IMAGE_KEEP_BUILDER`。
`TEELLM_IMAGE_KEEP_BUILDER=true` 会把构建容器留下，便于查 payload 为什么没打进去。

## 平台 mock：`deploy-platform-mock.sh`

构建、启动、停止和就绪检查统一由仓库根目录的 `deploy-platform-mock.sh` 负责。mock 在远端
主机上以后台进程运行，二进制经 SSH 上传；local 本地模式已移除。

```bash
./deploy-platform-mock.sh <start|stop|restart|status> [选项]
```

```bash
# 启动：静态构建后经 SSH 上传并后台启动
./deploy-platform-mock.sh start \
  --host 172.16.10.178 --user root --remote-password 'Osrd@2026' \
  --remote-dir /root/taa --taa-target http://127.0.0.1:6001

# 查看状态（未运行且端点无应答时退出码非 0）
./deploy-platform-mock.sh status --host 172.16.10.178

# 重启 / 停止
./deploy-platform-mock.sh restart --host 172.16.10.178
./deploy-platform-mock.sh stop --host 172.16.10.178

# 只查看会执行什么，不构建、不连接
./deploy-platform-mock.sh start --host 172.16.10.178 --dry-run
```

**常用选项**

| 选项 | 说明 |
|---|---|
| `--binary PATH` | 本地构建产物，默认 `bin/platform-mock` |
| `--binary-name NAME` | 进程名与远端安装名，默认 `platform-mock` |
| `--addr ADDR` / `--port N` | 监听地址，默认 `0.0.0.0:18081`（18080 留给宿主上的真实平台 ccs-node-agent） |
| `--state-dir DIR` / `--upload-dir DIR` | 为空时不传对应参数，沿用二进制自身默认目录 |
| `--log-file PATH` / `--pid-file PATH` | 默认在 `--remote-dir` 下（`platform-mock.log` / `platform-mock.pid`） |
| `--taa-target URL` | 固定到单个 TAA 地址；不传时按注册信息推导每个实例的地址 |
| `--pod` / `--namespace` / `--taa-port` | `--taa-target` 为空时的 Kubernetes 发现参数；`--taa-port` 同时用于多实例地址推导 |
| `--allow-empty-attestation` | 非 TEE 测试环境跳过证明校验 |
| `--reuse` | 端口已有实例应答时直接复用，不停止、不重启 |
| `--reset-register` | 就绪后 `POST /api/register/reset` |
| `--skip-build` | 复用 `--binary` 指向的现有二进制 |
| `--ready-timeout` / `--ready-interval` | 就绪等待，默认 60s / 2s |
| `--dry-run` | 只打印计划 |
| `--host` / `--user` / `--remote-password` / `--remote-dir` / `--remote-binary` | 远端目标、SSH 凭据与安装路径 |
| `--ssh-port` / `--ssh-opt` | 自定义 SSH 端口与额外选项 |

**生命周期语义**

- `start` 默认先构建，然后写 pidfile、后台启动并轮询 `GET /api/register/status`；
  超时会打印日志末尾并以非 0 退出。
- `stop` 先按 pidfile 终止，再按进程名兜底，未运行时也返回成功。
- `restart` 等于 `stop` + 构建 + `start`。
- `status` 打印 pid、日志与端点结果；进程存活或端点应答即返回 0。
- 远程启动使用 `nohup` 脱离 SSH，二进制上传到 `--remote-binary`（默认
  `--remote-dir/platform-mock`）。

**多实例模式（默认行为）**

- platform-mock 二进制默认多实例：不传 `--taa-target` 时，一个进程同时服务多个 TAA 实例，
  实例身份取注册请求里的 `dockerId`，每个实例在注册时按请求源 IP 推导自己的地址
  （`http://<源 IP>:<--taa-port>`，默认端口 6001）。
- 直接调用 `deploy-platform-mock.sh` 时省略 `--taa-target` 即可：
  ```bash
  ./deploy-platform-mock.sh start --host 172.16.10.178 --taa-port 6001
  ```
- 需要固定单实例地址时传 `--taa-target http://<ip>:6001`（未按注册推导出地址时作为后备）。
- 限制：反向代理或端口转发会丢失请求源 IP，此时无法按注册推导地址，应退回
  `--taa-target` 指定固定地址。


---

# 打包镜像依赖清单：基础镜像自带什么

四个部署脚本共五条打包链路；第 6 节是远端 DCU 测试 Pod 用的 vLLM 镜像，不由本仓库脚本打包。
每一节先列该镜像**从基础镜像继承到的依赖**，最后标注打包脚本
自己补进去的东西（"新增"），以便区分"镜像凭什么能跑"和"打包补了什么"。

体积取 `docker image inspect .Size`。`docker images` 的 SIZE 列对同一镜像会显示成 3.77 GB
这类更大的数字（实测与 inspect 不一致），本文一律用前者。

**镜像与归档命名规则**（四条打包链路统一）

| 打包路径 | 镜像 | 归档 |
|---|---|---|
| `deploy.sh save` | `taa-train-infer:<YYYYMMDD>` | `deploy/out/taa-train-infer-<YYYYMMDD>.tar.gz` |
| `deploy-fhe.sh save` | `taa-fhe:<YYYYMMDD>` | `deploy/out/taa-fhe-<YYYYMMDD>.tar.gz` |
| `deploy-dataanaylsis.sh save` | `taa-dataanaylsis:<YYYYMMDD>` | `deploy/out/taa-dataanaylsis-<YYYYMMDD>.tar.gz` |
| `deploy-llm.sh create`（内建构建） | `teellm:<YYYYMMDD>` | `deploy/out/teellm-<YYYYMMDD>.tar.gz` |

标签只有打包当天的本地日期，不带基础镜像的标签、不带 commit、不自动打 `latest`；
归档名与镜像名一一对应，只把 `:` 换成 `-`。推 registry 时加统一前缀
`172.16.10.178:31313/`，仓库名不变。基础镜像（`taa-env:slim-v2`、
`jupyter-nologin-full:v2.2`、`latti/latti-server-node:latest`、中间层 `teellm-base:<日期>`）
不适用本规则。每个名字都能用环境变量或 `--image`、`--archive` 覆盖。

**默认构建，不按日期猜**：`deploy-llm.sh create` 建 Pod 前用当前工作树构建镜像，tag 是
当天日期，所以不存在"今天的 tag 没人推过"的问题 —— 这次运行自己推。显式给了
`TEELLM_IMAGE` 就原样使用，不构建。只有 `TEELLM_BUILD_POD_IMAGE=false` 时才回到旧行为：
查 registry 的 `/v2/teellm/tags/list` 取最新的日期 tag，因为隔天部署时"今天"指向一个没人推过的
tag，Pod 会在 guest 启动之后停在 ImagePullBackOff；此时查询失败（401、不可达）则退回当天日期
并告警。

## 1. TEE 训练 / 推理 — `deploy.sh`

`tee` 训练与 `tee` 推理共用这一条链路和同一个镜像：平台在启动时注入 `CONTRACT_TYPE`
（`1` 训练 / `2` 推理），两者都落到普通 `tee` 角色，差别由平台下发的请求决定。
`data-anaylsis` 也复用 `configs/taa-production.json` 这个模板，但保留自己的 jupyter
基座镜像，见第 3 节。

基础镜像 `taa-env:slim-v2`：Ubuntu 24.04.4，glibc 2.39，dpkg 130 个包，解压 1.84 GB，`/opt` 为空。

**基础镜像自带**

- shell / 内核接口：`bash`、`dash`、`sh`、`mknod`
- Python：`/usr/bin/python3` = 3.12.3、`pip3`、`pip`
- Python 包（64 个，实测可 import）：`torch 2.13.0+cpu`、`torchvision 0.28.0+cpu`、
  `numpy 2.5.2`、`scipy 1.18.1`、`scikit-learn 1.9.0`、`scikit-image 0.26.0`、
  `opencv-python-headless`（cv2 5.0.0）、`pandas`、`matplotlib`、`ipython`、`sympy`、
  `tensorboardX`、`openpyxl`、`PyYAML`
- 命令：`curl`、`tar`、`gzip`、`unzip`、`openssl`、`sed`、`grep`、`find`、`mawk`、
  `ls/cat/cp/mv/rm/mkdir`、`ps`、`pgrep`/`pkill`、`flock`、`timeout`、`du`、`nproc`、
  `stat`、`md5sum`、`sha256sum`、`base64`、`hostname`、`passwd`、`useradd`
- 库：`libc.so.6`(2.39)、`libssl.so.3` / `libcrypto.so.3`、`libstdc++.so.6`、
  `libgcc_s.so.1`、`libgomp.so.1`、`libz.so.1`
- CA 证书：`/etc/ssl/certs/ca-certificates.crt`（TLS 校验依赖它）

**基础镜像没有（别在容器里调）**

`wget`、`git`、`xz`、`jq`、`rsync`、`ssh`、`sshpass`、`go`、`node`、`file`、`cpio`、`sudo`、`ip`

**打包新增**

`/root/taa/taa`（静态二进制，不吃 glibc）、两份证明证书、`taa-supervisor.sh`、
渲染后的 `taa-config.json`、`/opt/taa/semgrep/{pylib,MANIFEST,rules}`。
`semgrep` 的 wrapper 是 `exec /usr/bin/python3` —— 解释器就来自上表的基础镜像，
bundle 只带 `pylib`（66 个 wheel）。supervisor 的单例锁用 `flock`，也在基础镜像里。

**继承的历史残留**

基础镜像自己就带着 `/root/taa/{taa 10.8 MB, start.sh 858 B, taa.log}`，ENTRYPOINT 原本是
`bash /root/taa/start.sh`。打包时 `taa` 被 `docker cp` 覆盖，`start.sh`/`taa.log` 不删
（脚本没有对应 rm），`commit` 才把 ENTRYPOINT 指向 `taa-supervisor.sh`。

## 2. FHE 推理 — `deploy-fhe.sh`

基础镜像 `latti/latti-server-node:latest`：Ubuntu 24.04.4，glibc 2.39，dpkg 237 个包，解压 681 MB。

**基础镜像自带**

- 进程模型：`/opt/entrypoint.sh` 一个容器起三件套 —— `redis-server`（仅回环）、
  `python3 -u api_server.py`、`python3 -u worker.py`；源码在 `/app/server`（WORKDIR）
- Redis：`/usr/bin/redis-server`、`/usr/bin/redis-cli`
- Python：`/opt/venv/bin/python3` = 3.10.22（PATH 首位，26 个包：`fastapi 0.143.1`、
  `uvicorn 0.54.0`、`redis 8.1.0`、`pydantic 2.14.1`、`requests 2.34.2`、`python-multipart`、
  `sse-starlette`）；系统另有 `/usr/bin/python3` = 3.12.3 与 `/usr/bin/python3.10`，
  但系统解释器没装 redis 包
- FHE 运行时：`/opt/latti-runtime`，含 `build/inference/lattisense/` 下的
  `liblattisense.so`、`cxx_sdk_v2`、`fhe_ops_lib`、`mega_ag_runners`，以及 `SHA256SUMS`、licenses；
  `LATTI_AI_ROOT`、`LATTI_AI_BUILD` 与 9 段 `LD_LIBRARY_PATH`（首段 `/opt/cuda-libs`）
  已烘进 ENV，运行时不需要再设
- CUDA：`/opt/cuda-libs` 只放两个 —— `libcudart.so.12`、`libcurand.so.10`；
  `NVIDIA_VISIBLE_DEVICES=all`、`NVIDIA_DRIVER_CAPABILITIES=compute,utility` 已设
- 命令：`bash`、`dash`、`tar`、`gzip`、`openssl`、`sed`、`grep`、`find`、`mawk`、
  `flock`、`timeout`、`sha256sum`、`ps`、`mknod`、`passwd`、`useradd`
- 库：`libc`(2.39)、`libssl3`/`libcrypto3`、`libstdc++.so.6`、`libgcc_s.so.1`、`libgomp.so.1`
- 默认端口/路径：`API_PORT=58996`、`CONTAINER_DATA_DIR=/data`、
  `CONFIG_PATH=/data/config/config.toml`、`TZ=Asia/Shanghai`；`/data` 构建时为空

**基础镜像没有（TAA 侧也不该依赖）**

`curl`、`wget`、`git`、`xz`、`jq`、`rsync`、`unzip`、`ssh`、`sudo`

**打包新增**

`/root/taa/taa`、`/root/taa/taa-supervisor.sh`、`/root/taa/taa-config.json`（只改 5 个键）。
`taa-supervisor.sh` 是本角色唯一的入口：它拉起 `/opt/entrypoint.sh`（redis + api_server +
worker）并把 TAA 交给自己的 `--taa-loop` 子进程，更新时只杀子进程，入口与 FHE 服务不动。
`save` 与 docker 容器路径的镜像**不含**模型、密钥、redis 数据，运行时挂 `/data`、
`/data/redis`、`$HOST_TAA_STATE_DIR`；`create` 建 Pod 时另外把 FHE 模型树烤进 `/data/models`，
因为 Kata guest 里没有宿主 bind。GPU 由宿主 NVIDIA 驱动 + nvidia-container-toolkit 提供
（Pod 里是 `nvidia.com/gpu` 设备），镜像自带的只有上面那两个 CUDA 用户态库。

## 3. 数据分析 — `deploy-dataanaylsis.sh`

透传 `deploy.sh`，基座为 `jupyter-nologin-full:v2.2`：Ubuntu 22.04.3，glibc 2.35，
dpkg 437 个包，解压 7.55 GB，ENTRYPOINT `tini -g --`，USER `jovyan`(1000)，
HOME/WORKDIR = `/home/jovyan`，EXPOSE 8888。

配置不再有自己的模板，也不再渲染副本：`configs/taa-production.json` 原样使用。角色由 Pod 的
环境变量 `CONTRACT_TYPE=3` 指定，加载器据此在启动时关闭整个审计（开关、LLM、带规则的引擎），
并把数据落盘目录固定为 `/home/jovyan/systemAuthData`（jupyter 运行时读取的位置），与模板里的
`storage.data` 无关。打包路径仍需处理：`deploy.sh` 按模板文本决定是否注入 semgrep payload，
脚本因此导出 `TAA_SCAN_ENGINE_PROVISION=skip`，让 `save` 打包与远程部署两条路都不再装这个镜像
用不上的 payload。
密封密钥来源不需要渲染：TAA 启动时按 `/dev/csv-guest` 是否存在自动选择硬件密钥或 SM2 派生，
类型 1-3 会先等该节点出现（无上限）再决定来源，打包与远端两种路径行为一致。

打包时 ENTRYPOINT 被覆盖为统一的 `bash /root/taa/taa-supervisor.sh`（基座的 `tini -g --`
不再使用），这个角色装的是组合版（`deploy/dataanaylsis/taa-supervisor.sh`）：PID 1 先以 `HOME=/home/jovyan` 起
`start-notebook.py`（jupyter 只读 `$HOME/.jupyter`，`allow_root` 配置在那里），再拉起自己的
`--taa-loop` 子进程跑 TAA。jupyter 的 `ip=0.0.0.0`、`port=8888`、`root_dir=/home/jovyan`、
空 token 都来自基座镜像的 `/home/jovyan/.jupyter/jupyter_server_config.py`，脚本不重复配置。
**jupyter 是决定容器存活的服务**：它退出时脚本停掉 TAA 并以 jupyter 的退出码结束容器，由
kubelet 的 restartPolicy 处理重启；TAA 自己退出只在 10s 后重启循环，不影响 jupyter。
更新 TAA 时杀的是 `--taa-loop` 子进程，jupyter 和入口文件都不重启。

**基础镜像自带**

- Python（两套并存，默认 conda 那套）：
  - `/opt/conda/bin/python3` = 3.11.6（PATH 首位），conda 环境 226 个包：
    `numpy 1.24.4`、`pandas 2.2.3`、`scipy 1.11.3` 等；`pip3`/`pip` 同源
  - `/usr/bin/python3` = 3.10.12（系统解释器，不经 conda）
- 命令：`curl`、`wget`、`git`、`tar`、`gzip`、`xz`、`unzip`、`openssl`、`ssh`、`sudo`、
  `tini`、`sed`、`grep`、`find`、`mawk`、`flock`、`timeout`、`sha256sum`、`ps`、`pgrep`/`pkill`
- 其他运行时：`julia 1.9.3`（`/usr/local/bin`）、`node v20.19.6` + `npm`（conda 内）
- 库：`libc`(2.35)、`libssl3`/`libcrypto3`、`libstdc++.so.6`、`libgcc_s.so.1`、`libgomp.so.1`
- Jupyter 基础：`/home/jovyan`（`.jupyter`、`.cache`、`.conda`、`.config`、`work`）、
  `/usr/local/bin/start-notebook.py`（镜像 CMD）与它 exec 的 `start.sh`

**基础镜像没有**

`jq`、`rsync`、`java`、`torch`、`semgrep`；`/home/jovyan/systemAuthData` 不存在（TAA 启动时自建）；
`/root/taa`、`/opt/taa` 也不存在（打包时新建）。

**打包新增**

与审计镜像相同的 TAA 载荷（`taa` 静态二进制、两份证书、渲染后的 `taa-config.json`、空目录
`/root/taa/{models,data,results,keys}` 与 `/opt/taa/{input,output}`），但
`taa-supervisor.sh` 换成本角色的组合版（jupyter + TAA，同一容器路径）。
**不装 semgrep、不装 teellm**：配置里的 `codeAudit` 与生产模板
一致（含 `codeScan.engine=semgrep`），但运行时按角色关掉审计，打包时由
`TAA_SCAN_ENGINE_PROVISION=skip` 跳过 payload 注入。

## 4. TEE 推理网关 — 由 `deploy-llm.sh` 构建并部署

基础镜像 `teellm-base:<日期>` = `taa-env:slim-v2` 加一层 `RUN rm -rf /root/taa`，
**所以基础依赖与第 1 节完全相同**（Ubuntu 24.04.4、glibc 2.39、Python 3.12.3、`curl`、
`bash`、`flock`、CA 证书）。`/opt/teellm` 是打包新建的，基础镜像里没有。

**这份基础镜像真正承担的三件事**（缺一样就跑不起来）

- `bash` —— ENTRYPOINT 是 `bash /opt/teellm/teellm-supervisor.sh`，缺了容器直接起不来
- `curl` —— supervisor 轮询 `http://127.0.0.1:11434/api/tags` 判就绪，缺了就绪探测永远失败，
  120s 后放弃
- `libstdc++.so.6` / `libgcc_s.so.1` —— `llama-server`、`ollama` 的 `ldd` 直接解析到
  `/lib/x86_64-linux-gnu/`，缺了 `llama-server` 无法 exec

`libgomp.so.1` **不用基础镜像的**：bundle 自带 `lib/ollama/libgomp.so.1`，`RUNPATH=$ORIGIN`
先命中它。`teellm-service` 是 `CGO_ENABLED=0` 静态二进制，不吃 glibc。

**打包新增**

`teellm-service`、`teellm-supervisor.sh`、两份配置、两份证书、`ollama` + `start-ollama.sh` +
`lib/ollama` 顶层 30 项（排除 cuda/mlx/vulkan/include）、`qwen2.5-coder:7b` 的 5 个 blob、
`.teellm-model`，以及 6 个 soname 软链（缺则 exit 127）。

## 5. CSV2 机密 VM 启动镜像 — `deploy-taa-vm.sh`

基座 `kata-containers-initrd-confidential-csv.img`：57.3 MB，4682 条目，只追加不重写。
这一层的"依赖"是 guest 开机到 kata-agent 起来之前的全部家当。

产物是两个 gzip member 的拼接：种子镜像（基座；`taa-train` 另含 semgrep 载荷）+
只装 TAA 的成员。种子按基座 sha256 与载荷内容指纹缓存在 `deploy/guest-build/out/seeds/`，
输入不变就直接复用，因此重跑只重压几 MiB 的 TAA（秒级），而不是整份镜像（分钟级）。
内核逐个读取 gzip member，行为与单 member 等价。

**基座自带**

- kata-agent：`usr/sbin/init`（19 MB Rust 二进制，`/init -> /sbin/init` 即 `rdinit`/`init` 入口）；
  CoCo 侧 `usr/local/bin/attestation-agent`；`etc/kata-opa/{default-policy,allow-all}.rego`；
  `pause_bundle/`
- 通用工具面：4682 个条目里 `usr/bin/` 占 307 个，另有 `usr/sbin/` 的 `fsck.*`、`iptables-nft`、
  `ebtables-nft`、`ldconfig.real`、`installkernel` 等系统级命令
- shell / 通用命令：`bash`（1.4 MB）、`dash`（126 KB）、`perl`（`usr/bin/perl` →
  `perl5.34.0` 硬链接）、`mawk`；`ls/cat/cp/mv/rm/mkdir/ln/chmod/chown/touch/df/sync/env/
  stat/basename/dirname/readlink/printf`、`sed/grep/awk/find`、`ps/pgrep/pkill`、
  `tar/gzip/gunzip`、`flock/timeout`、`sha256sum/base64`、`head/tail/wc/tr/cut/sort/xargs/which`、
  `ip/mount/dmesg`、`mknod`、`nsenter/unshare`
- 库：`libc.so.6`（GLIBC 2.35）、`ld-linux-x86-64.so.2`、`libssl.so.3`/`libcrypto.so.3`、
  `libz.so.1`、`libgcc_s.so.1`；**没有 `libstdc++.so.6`**
- 没有内核模块工具：无 `modprobe`（`/dev/csv-guest` 得靠 `mknod` 建节点）

**基座没有**

`python3`、`semgrep`、`curl`、`wget`、`openssl`（命令行）、`xz`、`unzip`、`cpio`、`file`、`less`

**追加进 initrd**

`usr/local/bin/taa`（必须静态链接 —— 基座 glibc 2.35，动态链接会随打包机漂移）、
`usr/local/bin/taa-init`、`etc/taa/taa-config.json`、
`etc/default/taa.env`；选中 semgrep 时整棵 `semgrep-payload/rootfs`（4242 文件，
**自带 `python3.10`**，不依赖基座）。

## 6. DCU 机密测试 Pod — `/home/wj/dcu/dcu-tee-test-pod-create.sh`

基础镜像 `harbor.sourcefind.cn:5443/dcu/admin/base/vllm:0.9.2-ubuntu22.04-dtk26.04-0130-py3.10-20260202`：
Ubuntu 22.04.5，glibc 2.35，dpkg 984 个包，29 层，解压 25.6 GB（25611144188 B），
用户 root，WORKDIR `/workspace`（空），ENTRYPOINT `docker-entrypoint.sh`（figlet 横幅 +
检查 `/dev/kfd`、`/dev/dri`），CMD `/bin/bash`。

脚本本身**不构建镜像**：它只保证本地私有仓库有 `172.16.10.178:31313/vllm:ubuntu-dtk`
（没有就 `docker tag` + `docker push` 这份 25.6 GB 的上游镜像，`PULL_TIMEOUT=2400`），
把 initdata 与 root 口令渲染进 `dcu-tee-test-pod-template.yaml`，apply 后校验 vfio 绑定和
NodePort。所以这一节的"依赖"就是镜像里已经烘好的东西。

**基础镜像自带**

- 系统：`/usr/bin/python3` = 3.10.12（无 conda），237 个 pip 包，CA 证书齐全，`TZ=Asia/Shanghai`
- AI 栈（全是海光 das 分支）：`vllm 0.9.2+das.opt5.dtk2604.20260129.g56d6c689`、
  `torch 2.5.1+das.opt1.dtk2604.20260116.g78471bfd`、
  `triton 3.1.0+das.opt1.dtk2604.20260123.g0732375a`、`transformers 4.57.6`、`ray 2.48.0`、
  `numpy 1.25.0`、`fastapi 0.128.0`、`uvicorn 0.40.0`、`pydantic 2.12.5`、`accelerate 1.12.0`、
  `safetensors 0.7.0`、`tokenizers 0.22.2`、`sentencepiece 0.2.1`；`python3.10-dev` 也在
- DTK 26.04：`/opt/dtk -> /opt/dtk-26.04`，clang 17.0.0、dcc 25.10.0、`hipcc`、`rocminfo`、
  `rocm-smi`、`rocm_agent_enumerator`、`librccl.so.1`、hipblas/hipblaslt/opencl/dushmem/dcc-gcvm、
  `hipkernel.bin.gfx906/926/928/936/938`；另带 `/opt/ucx`、`/opt/mpi`、`/opt/hwloc`、
  `/opt/mellanox`（MOFED 23.10-4.0.9.1）
- 相关 ENV 已烘进镜像：`PATH`、`LD_LIBRARY_PATH`、`HYHAL_PATH=/opt/hyhal/`、
  `AMDGPU_TARGETS=gfx906;gfx926;gfx928;gfx936;gfx938`、`ROCM_PATH`、`HIP_PATH`、
  `MIOPEN_FIND_MODE=3`、`CMAKE_PREFIX_PATH`、`LIBRARY_PATH`、`*_INCLUDE_PATH`、
  `MOFED_VERSION`、`UCX_HOME`
- ssh：`openssh-server`/`client 1:8.9p1-3ubuntu0.13`，四把 host key 全部烘好
  （`ssh_host_{rsa,ecdsa,ed25519,dsa}_key`，重建 Pod 指纹不变），`chpasswd`/`useradd`/`passwd` 可用
- 命令：`bash`/`sh`/`dash`、`curl`、`wget`、`git`、`tar`、`gzip`、`xz`、`unzip`、`rsync`、
  `openssl`、`vim`、`sudo`、`figlet`、`gcc`/`g++ 11.4.0`、`make`、`cmake 3.29.0`、`ninja`、
  `ld`、`ifconfig`（net-tools）、`pgrep`/`pkill`、`flock`、`timeout`、`sha256sum`、`nproc`、`ldconfig`

**基础镜像没有（别调）**

`jq`、`ip`（iproute2，只有 `ifconfig`）、`less`、`nc`、`conda`、CUDA

**已知坑：`/opt/hyhal` 不存在**

镜像 ENV 里的 `HYHAL_PATH=/opt/hyhal/` 是宿主驱动路径，镜像和宿主上都没有这个目录。
`/opt/dtk-26.04/env.sh` 会连报两次找不到，然后回退到 `/opt/dtk-26.04/.hyhal`（把
`.hyhal/rocm_smi/lib` 追加进 `LD_LIBRARY_PATH`）。**不 source 就直接 `import torch` 会失败**：
`librocm_smi64.so.2: cannot open shared object file`；source 之后 torch / vllm 都能 import，
只留一条 `get hyhal driver version error!` 警告。`hy-smi` 在
`/opt/dtk-26.04/.hyhal/bin/hy-smi`，**不在烘好的 PATH 里**（`/opt/dtk/bin/hy-smi` 不存在）；
在没透传卡的普通容器里执行会报 `/dev/dri is empty or missing`。
`/etc/bash.bashrc` 第 72–73 行会 source `env.sh`，但只对交互式 shell 生效。

**不属于镜像的部分**（模板 command 运行时才造）

`/dev/kfd`、`/dev/mkfd`、`/dev/dri/*`（vfio 直通）、`/etc/profile.d/00-dtk-env.sh`、
root 口令、`sshd_config` 改动（放开 root 登录）。这些每次起 Pod 由
`dcu-tee-test-pod-template.yaml` 的 command 现场写入，镜像里没有。

## 基础镜像横向对照

taa-env（TEE 训练 / 推理、teellm）
- `bash` ✓，`python3` 3.12.3，`curl` ✓，`flock`/`timeout` ✓/✓
- `libstdc++` ✓，`jq`/`rsync` ✗/✗，`torch` ✓ 2.13.0+cpu

latti（FHE 推理）
- `bash` ✓，`python3` 3.10.22 (venv)，`curl` ✗，`flock`/`timeout` ✓/✓
- `libstdc++` ✓，`jq`/`rsync` ✗/✗，`torch` ✗

jupyter（数据分析）
- `bash` ✓，`python3` 3.11.6 (conda) / 3.10.12 (系统)，`curl` ✓，`flock`/`timeout` ✓/✓
- `libstdc++` ✓，`jq`/`rsync` ✗/✗，`torch` ✗

initrd 基座（CSV2 机密 VM）
- `bash` ✓，`python3` ✗（payload 自带 3.10），`curl` ✗，`flock`/`timeout` ✓/✓
- `libstdc++` ✗，`jq`/`rsync` ✗/✗，`torch` ✗

vllm:ubuntu-dtk（DCU 机密测试 Pod）
- `bash` ✓，`python3` 3.10.12，`curl` ✓，`flock`/`timeout` ✓/✓
- `libstdc++` ✓，`jq` ✗ / `rsync` ✓，`torch` ✓ 2.5.1+das（DTK 26.04，需先 source `env.sh`）

# image-bind

把一个已经 `load` 进节点本地仓库（`172.16.10.178:31313`）的镜像，插入到平台元数据库，
使 `172.16.10.113` 前端能查到、绑定并据此创建 Pod。

前端只展示数据库里有记录的镜像：`developmentModel` 列表按 `isEnabled`、`envType`、
`enableDcu` 过滤。因此“镜像已经存在仓库里”不等于“前端可见”，缺的就是这一行元数据。

## 前置条件

- 本机能访问 `https://172.16.10.178:31313`（自签证书，默认跳过校验）。
- 本机能访问平台 MySQL（默认 `172.16.10.113:3306`）。
- 数据库账号通过环境变量提供，**不要写进仓库、不要放在命令行**：

```bash
export CCS_DB_USER='...'
export CCS_DB_PASSWORD='...'
# 可选
export CCS_DB_HOST=172.16.10.113
export CCS_DB_PORT=3306
export CCS_DB_NAME=...          # 留空时自动在全库中探测候选表
export CCS_REGISTRY_PASSWORD='' # 仓库需要认证时才用
```

首次运行会创建本地 `.venv` 并安装 `pymysql`。

## 用法

```bash
cd tools/image-bind

# 0. 只读确认数据库类型/版本（握手包，不需要账号）
./bind-image.sh --db-version

# 1. 看仓库里有什么
./bind-image.sh --list-images

# 2. 只读探测：连库、找出候选镜像表、打印列结构，不写任何数据
./bind-image.sh --inspect

# 3. 试运行：读 manifest、挑模板行、打印将要执行的 SQL（默认不写库）
./bind-image.sh --image taa-env:my-tag --env-type TEE_INFER_DCU

# 4. 真正插入
./bind-image.sh --image taa-env:my-tag --env-type TEE_INFER_DCU --apply

# 可选：同时给某个节点建立“镜像可用”绑定
./bind-image.sh --image taa-env:my-tag --env-type TEE_INFER_DCU \
    --bind-node <NODE_ID> --apply

# 已存在同 model_name/version/env_type 时改为更新
./bind-image.sh --image taa-env:my-tag --apply --update-existing
```

`--image` 可以不带仓库前缀，默认 `172.16.10.178:31313`；`--model-name`/`--version`
不填时分别取仓库名和 tag。

## 插入策略

1. 从仓库读取 manifest（支持 OCI index，取 `linux/amd64`），用 config digest 作为镜像 ID，
   并累加 config+layers 得到大小。
2. 在 `information_schema` 中找同时含 `model_name`、`env_type`、`is_enabled`/`enable_dcu`
   的表；有多个时要求用 `--table schema.table` 指定。
3. 复制一条同 `env_type`、已启用的模板行（或 `--template-id` 指定的行），只覆盖镜像相关列。
   这样未知列、NOT NULL 列都沿用平台已经接受的值。
4. 新 id 为 32 位十六进制；自增列不写。`version` 列只有字符串类型时才写入 tag
   （避免把 MyBatis 的乐观锁数字列写成 tag）。
5. 默认 dry run，打印完整 SQL 和参数；加 `--apply` 才在事务中提交。

## 注意

- `--db-version` 只读握手包，能确认 MySQL 版本，但**不能**替代账号：MySQL 的握手本来就不需要认证，
  任何 `SELECT`/`INSERT` 仍要 `CCS_DB_USER`/`CCS_DB_PASSWORD`。
- `--inspect` 是只读的，应始终先跑一次，确认选中的表与列。
- 插入的只是**元数据**：镜像必须已经在该节点的仓库里，否则前端能显示，但创建 Pod 时
  guest 内拉取会失败。
- `envType` 与 `enableDcu` 要和前端一致：DCU 推理用 `TEE_INFER_DCU` + `--dcu`，
  CPU 推理用 `TEE_INFER_CPU` + `--no-dcu`。
- `--bind-node` 只在能识别出“节点-镜像绑定表”时生效；探测不到会直接报错，不会乱写。
- 脚本不保存任何凭据。

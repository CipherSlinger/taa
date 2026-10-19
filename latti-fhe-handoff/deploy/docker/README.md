# Docker 部署文档入口

本目录包含 Latti 服务端 Docker Compose 配置、环境变量示例和运维脚本。当前部署操作统一从 [docs/文档入口.md](docs/文档入口.md) 进入。

## 文档索引

| 场景 | 文档 |
| --- | --- |
| 查看完整文档目录 | [文档入口](docs/文档入口.md) |
| 了解当前部署架构和端口 | [00-部署总览](docs/00-部署总览.md) |
| 拉取代码并安装依赖 | [01-拉取代码与安装依赖](docs/01-拉取代码与安装依赖.md) |
| 配置环境变量 | [02-环境变量配置](docs/02-环境变量配置.md) |
| 准备 runtime 和模型目录 | [03-运行时与模型目录准备](docs/03-运行时与模型目录准备.md) |
| 构建镜像 | [04-构建镜像](docs/04-构建镜像.md) |
| 启动、重启、停止服务 | [05-启动与停止服务](docs/05-启动与停止服务.md) |
| 配置和启动 Host Nginx | [06-Nginx配置与启动](docs/06-Nginx配置与启动.md) |
| 健康检查和接口验证 | [07-健康检查与接口验证](docs/07-健康检查与接口验证.md) |
| 查看日志和容器状态 | [08-日志与状态查看](docs/08-日志与状态查看.md) |
| A130 构建镜像并离线分发到 8.62 | [09-镜像构建与离线分发](docs/09-镜像构建与离线分发.md) |
| 8.62 正式环境部署 | [10-8.62正式环境部署](docs/10-8.62正式环境部署.md) |
| 新增多服务器 Node | [12-多服务器节点接入](docs/12-多服务器节点接入.md) |
| 故障排查 | [13-故障排查](docs/13-故障排查.md) |

## 目录说明

```text
deploy/docker/
├── docker-compose.node.yml           # Node API / Worker / Local Redis
├── configs/                          # Node 配置模板
├── env/                              # 通用 env 和本机覆盖示例
├── scripts/                          # Docker Compose 操作脚本
└── docs/                             # 部署文档
```

入口 Nginx 配置在仓库根目录 `nginx.conf`，不由 Docker Compose 管理。

## 常用入口命令

```bash
cd /home/wuwm/prod-project/latti-client/deploy/docker

./scripts/run-stack.sh start
./scripts/run-stack.sh stop
./scripts/run-stack.sh status
./scripts/run-node.sh logs -f fhe-api
```

更多命令见 [05-启动与停止服务](docs/05-启动与停止服务.md) 和 [08-日志与状态查看](docs/08-日志与状态查看.md)。

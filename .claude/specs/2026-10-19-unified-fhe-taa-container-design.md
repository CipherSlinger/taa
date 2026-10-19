# FHE 与 TAA 合并为单容器部署

日期：2026-10-19
状态：已确认，已实施

## 背景

FHE 交付包已改为单个自包含镜像 `latti/latti-server-node:latest`：redis、`api_server`、
worker、FHE runtime 与 CUDA 运行库都在镜像内，由镜像自带的 `/opt/entrypoint.sh` 拉起。
原来的三服务 compose 栈、外挂 runtime 目录、`HOST_RUNTIME_DIR`/`HOST_REDIS_DIR` 与
`./deploy-fhe.sh fhe` 因此失去意义。

用户要求：TAA 访问容器内部的 58996 端口与服务，该端口不发布到宿主机，与宿主机上遗留的
服务/compose 栈互不干扰。

## 拓扑

一个容器，默认 `bridge` 网络：

```
latti/latti-server-node:latest（或 taa-fhe:<date>）
├── /opt/entrypoint.sh          redis 127.0.0.1:6379
│                               api_server 0.0.0.0:58996
│                               worker
├── /opt/taa-entrypoint.sh      新增的组合入口
├── /root/taa/taa               TAA 0.0.0.0:6001
├── /root/taa/start.sh          既有 supervisor（10s 重启）
└── /root/taa/taa-config.json   渲染后的配置
```

挂载：

- `$HOST_DATA_DIR:/data`：镜像 entrypoint 读取的契约数据树。
- `$HOST_DATA_DIR:$HOST_DATA_DIR`：TAA 渲染配置里写的绝对路径；两者相同时跳过。
- `$HOST_TAA_STATE_DIR:$HOST_TAA_STATE_DIR`：SM2 密钥对与 sealed state。单独一条 bind，
  FHE 侧读不到；与数据目录重叠时直接拒绝。
- `$HOST_FHE_REDIS_DIR:/data/redis`：默认 `$HOST_DATA_DIR/redis-unified`。镜像内的 redis 7.0
  读不了遗留 compose 栈（`redis:7-alpine`，RDB v12）写进 `$HOST_DATA_DIR/redis` 的持久化文件，
  共用目录会让统一容器启动即退出，因此单独隔离一条。

端口：

- 只发布 `-p ${TAA_PUBLISH_ADDR:-0.0.0.0}:$TAA_PORT:$TAA_PORT`（6001）。平台/平台 mock 在
  宿主机上，需要经此调用 TAA（注册是出站请求，不携带地址，所以反向可达性只能靠发布端口）。
- **绝不发布 58996**，**绝不使用 `-P`**（镜像声明了 58996）。
- `--gpus ${TAA_GPUS:-all}`、`--restart ${TAA_RESTART_POLICY:-unless-stopped}`。

地址：

- TAA → FHE：`http://127.0.0.1:58996`（同容器）。
- FHE → TAA 回调：`http://127.0.0.1:6001`（同容器，满足回调 handler 只接受环回来源的检查）。
- TAA → 平台：`PLATFORM_IP` 未显式设置时取 `TAA_DOCKER_NETWORK` 的网关加 `PLATFORM_PORT`
  （通常是 `172.17.0.1:18081`），因为 bridge 容器内的 `127.0.0.1` 是容器自己；显式值优先，
  但非 host 网络下拒绝环回值。

模式矩阵（保持既有语义，`taa` 不部署 mock）：

| 模式 | platform-mock | 统一容器 |
|---|---|---|
| 裸调用 | 是 | 是 |
| `taa` | 否 | 是 |
| `platform-mock` | 是 | 否 |
| `taa save` | 否 | 否（只打包） |

## 决策

1. **运行时注入，不要求预构建镜像**：`taa` 模式用 `docker create` + `docker cp` + `docker start`
   把 TAA 二进制、`start.sh`、组合入口与渲染配置放进容器。`TAA_IMAGE` 默认等于 `FHE_IMAGE`。
2. **组合入口负责存活判定**：`deploy/taa-fhe-entrypoint.sh` 后台启动
   `/opt/entrypoint.sh`，并用 `( cd /root/taa && exec ./start.sh ) &` 启动 supervisor（这样
   `$!` 就是 supervisor 本身，TERM 直达）。FHE 入口退出时停掉 TAA 并以该退出码退出，容器的
   重启策略据此生效；supervisor 自己退出时由组合入口按 10s 间隔重启。
3. **组合入口不 bind-mount**：Docker 对不存在的源路径会创建目录挂载点，所以在
   `docker start` 前 `docker cp` 到 `/opt/taa-entrypoint.sh`；`save` 直接烤进镜像。
4. **运行中容器的刷新**：先置 `manual` 标记并 `pkill` supervisor 与 taa，再把文件拷成
   `.new` 并在容器内 `mv` 覆盖（直接覆盖运行中的可执行文件会 `ETXTBSY`）；组合入口会在
   10s 延迟后重新拉起 supervisor。入口 sha 不一致时整容器重建。
5. **复用判定全字段匹配**：镜像 ID、binds、环境（`PLATFORM_IP`、`DOCKER_ID`、
   `TAA_ENTRYPOINT_SHA256`）、网络、entrypoint、`PortBindings`（6001 存在且 58996 不存在）、
   `PublishAllPorts=false`、GPU 请求、重启策略；任一字段读不到即视为不匹配并重建。
6. **模型 staging 不带 `--delete`**：交付包的 `models/<model_id>/server` 布局原样放进
   `HOST_DATA_DIR/models`，运维后加的模型不会被删。
7. **`taa save` 以 FHE 镜像为基底**：`docker commit` 设置
   `ENTRYPOINT ["/opt/taa-entrypoint.sh"]`、`CMD []`、`WORKDIR /root/taa`、
   `EXPOSE 58996 6001`，导出 `deploy/taa-fhe-<date>.tar.gz`，上传并 `docker load`。
   部署时若 `TAA_IMAGE != FHE_IMAGE`，只要求该镜像已存在，**绝不**把 FHE 交付归档 load 到
   自定义 tag 上。
8. **移除**：`fhe` 模式及 compose/runtime/redis/`NODE_*` 机制、`REMOTE_HANDOFF_DIR`、
   `TAA_BASE_IMAGE_ARCHIVE`、`run_node`、`run_in`、`upload_tree`、`require_input`、
   `read_env_path`、`path_contains`、`report_stack_binding`。

## 失败处理

- 失败或中断时保留容器运行，报告 `docker logs` / `taa.log` / `docker rm -f` 三条命令；
  脚本不自动删除容器，便于复用与取证。
- 未显式指定 `--skip-build` 时先构建二进制；`--skip-build` 下缺文件直接拒绝。
- 预检在 `--dry-run` 下也执行“路径重叠/网络/端口映射”这类配置错误检查。

## 验证

- `bash -n` 三个脚本；`--help`、`fhe` 移除报错、`save` 无 `taa` 报错、
  `platform-mock --no-platform-mock` 报错。
- 四种 dry-run：`taa`、裸调用、`taa --no-platform-mock`、`taa save`。
- 本地 `taa save --local` 冒烟：镜像 entrypoint/workdir/EXPOSE 正确；容器内
  `bash -n /opt/taa-entrypoint.sh`；镜像内 `/root/taa` 属主 root；归档可列出。
- 打包镜像直接启动：FHE entrypoint 起 redis + api_server + worker，TAA supervisor 起 taa，
  容器不发布任何端口；挂载交付模型后 `/api/v1/models/activate?model_id=resnet20` 返回
  `ready`。
- 远端 178 上：只发布 6001、`docker port` 无 58996、注册 `dockerId=taa-fhe` 且
  `accepted=true`、重跑复用容器并刷新 TAA。

## 不做

- 不修改 FHE 镜像与交付包内容。
- 不发布 58996，不把 TAA 改回 host 网络。
- 不在统一镜像里搭 TeeLLM/semgrep。

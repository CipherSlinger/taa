# taa-fhe 部署命令

来源：`deploy-fhe.sh` 的默认值（脚本在操作机上跑，默认部署到远端 GPU 主机）。

## 目标主机

| 参数 | 默认值 |
| --- | --- |
| `REMOTE_HOST` | `172.16.10.178` |
| `REMOTE_USER` | `root` |
| `TARGET_PASSWORD` | 见脚本第 72 行（口令可被同名环境变量覆盖） |
| `REMOTE_TARGET` | `$REMOTE_USER@$REMOTE_HOST` |
| `--local` | 置空目标，改成在操作机本地部署 |

## 目录

| 参数 | 默认值 |
| --- | --- |
| `REMOTE_DIR` | `/root/taa-fhe` |
| `REMOTE_HANDOFF_DIR` | `/root/taa-fhe/latti-fhe-handoff`（交付包上传位置） |
| `HOST_RUNTIME_DIR` | `/root/taa-fhe/latti-runtime` |
| `HOST_DATA_DIR` | `/opt/fhe-data` |
| `HOST_TAA_STATE_DIR` | `/opt/taa-state` |
| `HOST_REDIS_DIR` | `/opt/fhe-data/redis` |
| `PLATFORM_MOCK_STATE_DIR` | `/root/taa-fhe/platform-mock-state` |
| `PLATFORM_MOCK_UPLOAD_DIR` | `/root/taa-fhe/platform-mock-files` |

## 镜像

| 参数 | 默认值 |
| --- | --- |
| `FHE_IMAGE` | `latti/latti-server:latest` |
| `FHE_IMAGE_ARCHIVE` | `<HANDOFF_DIR>/image/latti-server-latest.tar.gz` |
| `TAA_IMAGE`（save 的基底） | `taa-env:slim-v2` |
| `TAA_BASE_IMAGE_ARCHIVE` | `deploy/taa-env-slim-v2.tar.gz` |
| `TAA_FHE_SAVE_IMAGE` | `taa-fhe:$(date +%Y%m%d)` |
| `TAA_FHE_SAVE_ARCHIVE` | `deploy/taa-fhe-$(date +%Y%m%d).tar.gz` |

## taa save 的归档位置

- 本地（打包机）：`deploy/taa-fhe-<YYYYMMDD>.tar.gz`
- 远端：`$REMOTE_DIR/taa-fhe-<YYYYMMDD>.tar.gz`，默认即 `/root/taa-fhe/taa-fhe-<YYYYMMDD>.tar.gz`
- 上传后执行 `docker load -i`；**加载完成后归档保留在远端**（不再删除），供后续重载/部署复用。

## 端口

| 参数 | 默认值 |
| --- | --- |
| `TAA_PORT` | `6001` |
| `PLATFORM_PORT` | `18081`（178 上 18080 被 ccs-node-agent 占用） |
| `API_HOST_PORT` | `58996` |

## 容器

| 参数 | 默认值 |
| --- | --- |
| `TAA_CONTAINER_NAME` | `taa-fhe` |
| `TAA_DOCKER_NETWORK` | `host` |
| `TAA_CONTAINER_WORKDIR` | `/root/taa` |
| `TAA_CONFIG_FILE` | `taa-config.json`（启动时渲染并拷入） |
| `TAA_LOG_FILE` | `/root/taa/taa.log` |

## 超时

| 参数 | 默认值 |
| --- | --- |
| `TAA_READY_TIMEOUT` | `120` 秒 |
| `TAA_READY_INTERVAL` | `2` 秒 |
| `FHE_READY_TIMEOUT` | `120` 秒 |
| `PLATFORM_READY_TIMEOUT` | `30` 秒 |

## 常用命令

```bash
# 打包（本地构建 taa-fhe 镜像、导出归档、上传并 load 到远端）
./deploy-fhe.sh taa save

# 只部署 TAA（FHE 栈与 platform-mock 假定已在运行）
TAA_IMAGE=taa-fhe:<YYYYMMDD> ./deploy-fhe.sh taa

# 只部署 FHE 三个服务
./deploy-fhe.sh fhe

# 只部署 platform-mock
./deploy-fhe.sh platform-mock

# 全量（FHE 栈 → platform-mock → TAA）
./deploy-fhe.sh

# 只看会执行什么
./deploy-fhe.sh taa save -n
```

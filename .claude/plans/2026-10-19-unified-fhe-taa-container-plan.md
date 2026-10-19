# 统一 FHE + TAA 单容器：实施计划

日期：2026-10-19
对应 spec：`.claude/specs/2026-10-19-unified-fhe-taa-container-design.md`

## 步骤

1. **组合入口**
   - 新增 `deploy/taa-fhe-entrypoint.sh`：启动 `/opt/entrypoint.sh` 与
     `( cd /root/taa && exec ./start.sh )`，`wait -n` 循环；FHE 退出则停 TAA 并透传退出码；
     supervisor 自行退出则 10s 后重启；TERM/INT 转发给两个子进程。
   - `chmod +x`，`bash -n` 通过。

2. **`deploy-fhe.sh` 常量与模式**
   - `FHE_IMAGE=latti/latti-server-node:latest`、`FHE_MODEL_ID=resnet20`、
     `TAA_IMAGE=$FHE_IMAGE`、`TAA_DOCKER_NETWORK=bridge`（拒绝 host）。
   - 新增 `TAA_PUBLISH_ADDR`、`TAA_GPUS`、`TAA_RESTART_POLICY`、`TAA_PROBE_HOST`、
     `TAA_ENTRYPOINT_SOURCE/CONTAINER`、`FHE_API_PORT`（保留 `API_HOST_PORT` 兼容别名）。
   - 删除 `HOST_RUNTIME_DIR`、`HOST_REDIS_DIR`、`NODE_*`、`NODE_DOCKER_DIR`、`NODE_ENV_FILE*`、
     `REMOTE_HANDOFF_DIR`、`TAA_BASE_IMAGE_ARCHIVE`、`DEPLOY_FHE_STACK`、`FHE_STACK_TOUCHED`
     及 `run_node`/`run_in`/`upload_tree`/`require_input`/`read_env_path`/`path_contains`/
     `report_stack_binding`。
   - 参数：`fhe` 直接报错说明已移除；`save` 仍只接受与 `taa` 组合。

3. **部署流程（`taa` / 裸调用）**
   - 预检：模板、`deploy/start.sh`、组合入口存在并 `bash -n`；路径重叠、host 网络、工作目录、
     `server.addr` 一致性检查；遗留 compose 容器与 6001 端口占用告警/拒绝。
   - 镜像：`TAA_IMAGE == FHE_IMAGE` 时按需校验并 upload/load 交付归档；否则要求镜像已存在。
   - staging：`rsync -a`（无 `--delete`）模型；上传 `start.sh`、`taa`、组合入口；
     `render_taa_config` 写入 endpoint、dataDir、keyCacheDir、result、keys 并做路径断言。
   - 平台地址：`PLATFORM_IP` 默认取 bridge 网关 + `PLATFORM_PORT`；拒绝环回。
   - 容器：`docker create`（无 `-d`）+ `docker cp` + `docker start`；运行中容器走
     `manual` + `pkill` + `.new`/`mv` 刷新；复用判定按全字段匹配。
   - 等待与校验：容器内 `python3` 探活 `/api/v1/health`；激活 `resnet20`；
     `docker port` 断言 6001 存在且 58996 不存在；宿主 curl 等 TAA 健康；注册闸门不变。
   - 报告：单容器的 `docker logs`、`docker exec tail`、`docker rm -f` 三条命令。

4. **打包流程（`taa save`）**
   - 本地构建 `bin/taa`；确保 FHE 基础镜像存在（缺则校验交付归档并 `docker load`）。
   - 渲染配置到临时目录；`docker run -d --entrypoint tail` 起 builder；拷贝
     `start.sh`、`taa`、`taa-config.json`、组合入口；`chown root:root` + `chmod`；
     删除 `manual`、`manual-teellm`、`taa.log`、`.start.lock`；断言 `/opt/entrypoint.sh` 存在。
   - `docker commit` 设置 entrypoint/workdir/EXPOSE；gzip 或 pigz 导出；
     上传并 `docker load`；打印 `TAA_IMAGE=taa-fhe:<date> ./deploy-fhe.sh taa` 与独立
     `docker run` 参数。

5. **文档与仓库记录**
   - `deploy.md`、`README.md`（FHE 部署章节与配置说明）、`CHANGELOG.md`、`TODO` 行数同步。
   - spec/plan 写入 `.claude/specs/`、`.claude/plans/` 并 `git add -f`。

## 验证

- `bash -n deploy-fhe.sh deploy/taa-fhe-entrypoint.sh deploy/start.sh`。
- CLI：`--help`、`fhe`、`save`（无 `taa`）、`platform-mock --no-platform-mock`。
- dry-run：`taa`、裸调用、`taa --no-platform-mock`、`taa save`；确认只出现一个
  `docker create`、`--network bridge`、`--gpus all`、`-p 0.0.0.0:6001:6001`，无 58996 发布。
- 本地 `taa save --local` 冒烟：`docker image inspect` 的 entrypoint/workdir/EXPOSE；
  容器内 `ls -l /root/taa`；`tar -tzf` 归档。
- 打包镜像启动冒烟：redis/api_server/worker 与 taa 同时运行；模型 activate 返回 `ready`。
- 远端 178：单容器、只发布 6001、注册通过、重跑复用。

## 回滚

改动集中在 `deploy-fhe.sh` 与新增的 `deploy/taa-fhe-entrypoint.sh`，文档同步修改；
回滚即还原这两个脚本并对交付包不做任何改动。

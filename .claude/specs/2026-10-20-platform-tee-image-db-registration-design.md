# 平台 TEE 镜像走数据库注册的方案

日期：2026-10-20

## 结论

前端“计算环境 → 环境镜像”和创建环境时的镜像下拉，**数据源都是平台数据库**，
不是宿主机镜像清单，也不是 containerd/registry 的自动发现：

- 列表接口：`developmentModel/findDevelopmentModelByPage`
- 表单提交：`createDevelopmentModel` / `editDevelopmentModel` / `rebuildDevelopmentModel`
- 对应表：`ccs_cipher_db_v1.tb_core_development_model`
- 宿主机镜像只同步到 `tb_core_node_image`（节点库存），该表不参与前端选择；
  前端 bundle 里的 `findNodeImageByPage` 无调用点，`node/synchronizationNode`
  只同步节点元数据。

因此，已经存在于 `172.16.10.178:31313` 的镜像，只要在
`tb_core_development_model` 插入一行并指向它，就会出现在前端的镜像列表/下拉里。
无需上传文件、无需重建、无需导入任务。

## 实测证据

表内已有手工插入的行，且确实被生产使用：

| model_name | image_ref | env_type | visibility |
|---|---|---|---|
| TAA-ENV-DCU-20261019 | `172.16.10.178:31313/taa-env:dcu-dtk26.04-20261019` | TEE_TRAIN | 2 |
| TAA-FHE-20261019 | `172.16.10.178:31313/taa-fhe:20261019` | FHE_INFER | 2 |
| TEE-ENV-SLIM-v2-20261017 | `172.16.10.178:31313/taa-env:slim-v2-20261017` | TEE_TRAIN / TEE_INFER | 2 |

`tb_core_development_model_service` 中有多条环境实例引用这些行
（例如 2026-10-20 09:31 创建的 `taa-env-dcu-dtk26-04-20261019-*`），说明
`image_ref` 就是运行时使用的镜像地址。

## 表结构关键点

`tb_core_development_model`：

- `id`：主键，varchar(128)
- `model_code`：唯一键（`UKe6lowkxa1lom9ye4uk3xc9xmx`），必须唯一
- 外键：`env_file_id`、`sdk_file_id` → `tb_sys_system_file.id`；
  `env_region_id` → `tb_core_env_region.id`；`tenant_id` → `tb_core_tenant.id`
- 非空：`create_time`、`modify_time`、`is_enabled`、`model_code`、`model_name`、
  `env_file_id`、`env_region_id`、`tenant_id`、`visibility`、`default_flag`
- `env_type`：`TEE_TRAIN` / `TEE_INFER` / `DATA_ANALYSIS` / `FHE_INFER`
- `visibility`：2 = 所有企业可见（1 为指定企业，前端详情页会额外显示“指定可用企业”）
- `image_ref`：完整镜像地址 `172.16.10.178:31313/<repo>:<tag>`，版本号体现在 tag 上
  （`model_version` 在现有行里均为 NULL）
- `is_enabled`：1 启用，-1 禁用（前端禁用后不可被新建环境引用）

可直接复用的既有行：

- TEE 区域：`env_region_id = 2c92808aa028a80101a02c78d4940000`
  （`GWOSR001`，registry `172.16.10.178:31313`，containerd，region_type=TEE）
- 企业：`tenant_id = 2c9280829eb44f54019efc7b29c30000`（虚无有限公司，
  现有 TEE 镜像均属该企业）
- 占位文件：`env_file_id = 2c928087a01f07ae01a01f2a01df0003`
  （`tb_sys_system_file` 中真实存在的 test.iso，用于满足外键）
- SDK：`sdk_file_id = 2c928082a041bfef01a046d5dcb5002a`
- `image_task_id`：`069c3ee4-4068-4fa3-9f5e-2145b5bf2348`（已完成的导入任务，可复用）

## 插入模板

```sql
START TRANSACTION;

INSERT INTO ccs_cipher_db_v1.tb_core_development_model
(id, create_time, modify_time, del_time, is_enabled,
 model_name, model_code, model_version, model_desc, env_type,
 image_ref, image_task_id,
 env_file_id, sdk_file_id, env_region_id, tenant_id,
 visibility, default_flag)
VALUES
('2c9280db9f0000019f00000000000001', NOW(6), NOW(6), NULL, 1,
 'TEE-ENV-SLIM-v2-20261016', 'DEV-17925600000000001', NULL,
 'host image: taa-env:slim-v2-20261016', 'TEE_TRAIN',
 '172.16.10.178:31313/taa-env:slim-v2-20261016',
 '069c3ee4-4068-4fa3-9f5e-2145b5bf2348',
 '2c928087a01f07ae01a01f2a01df0003',
 '2c928082a041bfef01a046d5dcb5002a',
 '2c92808aa028a80101a02c78d4940000',
 '2c9280829eb44f54019efc7b29c30000',
 2, 0);

COMMIT;
```

TEE 推理要同一个镜像可选时，用不同的 `id`/`model_code` 再插一行，
`env_type` 改为 `TEE_INFER`。

## 当前 registry 与数据库的差集

registry `172.16.10.178:31313` 中已有、但 `tb_core_development_model`
没有对应行的 TEE 相关 tag：

- `taa-env:slim-v2-20261016`
- `taa-fhe:20261017`
- `taa-fhe:20261017-v1`

另有 `taa-env:slim-v2-20260906` 已有行但 `env_type` 被写成 `TEETEE_TRAIN`
且已禁用；如需使用应改为 `TEE_TRAIN` 并启用。

Docker 里存在但未推送到 registry 的 tag（`taa-env:slim-v2-20260922-b`、
`taa-env:slim-v2-saved`、`taa-env:slim-v3`）不能直接注册，宿主机拉不到。

## 操作与回滚

1. 备份：
   `CREATE TABLE ccs_cipher_db_v1.tb_core_development_model_bak_20261020 AS SELECT * FROM ccs_cipher_db_v1.tb_core_development_model;`
2. 事务内插入，提交前核对行数。
3. 回滚：按新增 `id` 删除即可。
4. 预期无需重启服务，列表接口按请求查库；验证方式为刷新前端“环境镜像”页，
   或查询上表最新行。

## 风险

- 这是生产库写操作，必须先备份、只插入、不改既有行。
- 占位文件是 93KB 的 test.iso，列表里显示的“镜像大小”会失真；运行不受影响。
- `image_ref` 必须和 registry 中的 repo:tag 完全一致，否则创建环境后拉取失败。
- 若镜像要跨企业使用，`visibility` 必须是 2；为 1 时仅所属企业可见。

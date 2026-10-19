# taa-fhe 部署命令

一个容器同时运行 FHE 服务（redis + api_server + worker，镜像 `latti/latti-server-node:latest`）
与 TAA。TAA 在容器内经 `127.0.0.1:58996` 访问 FHE，58996 不发布到宿主机；只发布 TAA 的
6001，供 platform/platform-mock 调用。

```bash
# 打包（本地构建 taa-fhe 镜像、导出归档、上传并 load 到远端）
./deploy-fhe.sh taa save

# 只部署统一容器（FHE + TAA；platform-mock 假定已在运行，否则设置 PLATFORM_IP）
./deploy-fhe.sh taa

# 只部署 platform-mock
./deploy-fhe.sh platform-mock

# 全量（platform-mock → 统一容器）
./deploy-fhe.sh

# 用打包好的镜像部署
TAA_IMAGE=taa-fhe:20261019 ./deploy-fhe.sh taa

# 只看会执行什么
./deploy-fhe.sh taa save -n
```

# taa 部署命令

```bash
TARGET_POD=taa-env-slim-v2-20261016-7104e03003ae0072-f7fbbf8f5-kkdb2 ./deploy.sh taa 
./deploy.sh docker save
```

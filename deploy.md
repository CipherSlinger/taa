# taa-fhe 部署命令

```bash
# 打包（本地构建 taa-fhe 镜像、导出归档、上传并 load 到远端）
./deploy-fhe.sh taa save

# 只部署 TAA（FHE 栈与 platform-mock 假定已在运行）
./deploy-fhe.sh taa

# 只部署 FHE 三个服务
./deploy-fhe.sh fhe

# 只部署 platform-mock
./deploy-fhe.sh platform-mock

# 全量（FHE 栈 → platform-mock → TAA）
./deploy-fhe.sh

# 只看会执行什么
./deploy-fhe.sh taa save -n
```
# taa 部署命令

```bash
TARGET_POD=taa-env-slim-v2-20261016-7104e03003ae0072-f7fbbf8f5-kkdb2 ./deploy.sh taa 
./deploy.sh docker save
```
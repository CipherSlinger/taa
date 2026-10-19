# latti-ai 运行时（精简包）

给 **FHE worker 容器**用的原生运行时，只包含服务端推理真正加载的产物。
镜像本身不含原生库，容器启动时把本目录挂载为 `/runtime/latti-ai-runtime:ro`。

```
latti-ai-runtime/
├── build/inference/lattisense/
│   ├── liblattisense.so                 # 主运行时（worker 用 ctypes 直接加载）
│   ├── cxx_sdk_v2/libcxx_sdk_v2.so
│   ├── fhe_ops_lib/libfhe_ops_lib.so
│   ├── mega_ag_runners/{gpu,cpu}/*.so
│   └── lib/                             # 打包进来的第三方依赖（约 15 个）
├── inference/interface/python/build/
│   └── latti_inference.cpython-310-x86_64-linux-gnu.so   # Python 绑定（CPython 3.10）
├── build-info/{build-commands.sh,manifest.json,python-binding.patch}
├── licenses/{LattiSense.txt,Lattigo.txt,CUDA-EULA.txt}
├── LICENSE
└── SHA256SUMS
```

worker（`server/worker_runtime/inference_server.py`）只认两个锚点：

- `$LATTI_AI_BUILD/inference/lattisense/liblattisense.so`，环境变量
  `LATTI_AI_BUILD` 默认 `$LATTI_AI_ROOT/build`；
- `$LATTI_AI_ROOT/inference/interface/python/build/latti_inference...so`。

因此本包**保持目录层级不变**即可，不需要改任何服务端代码。

## 与旧包的差异

- 不再包含 `examples/`（各模型资源）、`validation/`、Node addon、Windows SDK。
  模型资源改由 `data/models/<model_id>/server/` 提供，服务端热加载（`POST /api/v1/models/activate`）。
- `liblattisense.so` 新增 `InferenceServer.release_device()`：把 GPU 显存真正归还驱动
  （回落到 CUDA context 常驻的 ~0.5 GiB），支持「进程常驻 + 任务间释放」。
- 池大小可用环境变量显式约束（一卡多容器）：
  `HEONGPU_DEVICE_POOL_MAX_BYTES` / `HEONGPU_DEVICE_POOL_INITIAL_BYTES` /
  `HEONGPU_HOST_POOL_MAX_BYTES` / `HEONGPU_HOST_POOL_INITIAL_BYTES`。
  不设置时沿用默认（首次上卡按当时空闲显存的 90% 预占）。

## 校验

```bash
sha256sum -c SHA256SUMS
```

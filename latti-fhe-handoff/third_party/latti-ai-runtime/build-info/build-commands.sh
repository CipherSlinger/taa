#!/usr/bin/env bash
# 在本机（A130 开发机）重建本运行时的命令，供复现/排障参考。
set -euo pipefail
REPO=/home/jiangsy/projects/latti-ai
export PATH=/home/jiangsy/.local/bin:$PATH
export LIBRARY_PATH=/home/jiangsy/.local/gmp/usr/lib64:/home/jiangsy/.local/ntl/lib
export CPATH=/home/jiangsy/.local/gmp/usr/include:/home/jiangsy/.local/ntl/include

cd "$REPO"
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DINFERENCE_SDK_ENABLE_GPU=ON -DLATTISENSE_CUDA_ARCH=89
cmake --build build --target lattisense inference_interface -j8

PYBIND11_DIR=/home/jiangsy/projects/latti-client/.venv/lib/python3.10/site-packages/pybind11/share/cmake/pybind11
cmake -S inference/interface/python -B inference/interface/python/build \
  -DCMAKE_BUILD_TYPE=Release \
  -DHDF5_ROOT=/home/jiangsy/.local/hdf5/usr \
  -DFHE_OPS_LIB="$REPO/build/inference/lattisense/fhe_ops_lib/libfhe_ops_lib.so" \
  -Dpybind11_DIR="$PYBIND11_DIR" \
  -DPYTHON_EXECUTABLE=/home/jiangsy/projects/latti-client/.venv/bin/python
cmake --build inference/interface/python/build --target latti_inference -j4

# 打包（依赖收集 + $ORIGIN 相对 RPATH + strip）
/home/jiangsy/projects/latti-client/.venv/bin/python /tmp/stage_runtime_slim.py

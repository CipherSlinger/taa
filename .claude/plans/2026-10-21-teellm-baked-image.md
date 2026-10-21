# Bake the TEE-LLM runtime and model into a dedicated image

## Context

`taa-teellm` is a bare Kata CSV2 Pod. With `shared_fs=none` its container rootfs upperdir is a
tmpfs inside the guest, so everything `deploy-llm.sh` copies in — `teellm-service`, the
supervisor, the ollama runtime and the 4.7 GB model — lives in guest RAM. Any event that
recreates the sandbox (host reboot, container restart, flannel misconfiguration) wipes it, and
the Pod's PID 1 (`mknod /dev/csv-guest; exec sleep infinity` on the pod created 2026-10-15) does
nothing to bring the service back. The Pod object itself survives a reboot, so the node comes up
with a confidential VM that listens on nothing.

The only structural fix is to stop keeping the runtime in the writable layer: put it in the
image, so a freshly booted guest already has it. A host-side bootstrap (systemd unit or similar)
would still work, but it re-copies 4.6 GB on every boot and leaves the service dependent on the
host being reachable at exactly the right moment.

What cannot be fixed the same way is the endpoint: TAA dials an IP that is baked into its own
image (`10.244.0.246` today, the Pod is at `.243`), and a recreated Pod may get a new IP. That
stays a separate, scripted step after a reboot (see *Out of scope*).

## Design

### 1. A dedicated image, not the TAA image

`deploy.sh docker save` calls `strip_teellm_from_image` (deploy.sh:484), which deliberately
deletes `teellm-service`, `ollama*`, `configs/teellm-*.json` and `configs/models.json` from every
TAA image. That is the right default — every TAA pod would otherwise carry 4.6 GB it does not
use — so this plan does not touch it.

Instead, build a second image **from the same base** that carries the TEE-LLM payload:

- Tag: `taa-env:teellm-<YYYYMMDD>`
- Registry tag: `172.16.10.178:31313/taa-env:teellm-<YYYYMMDD>`
- `TEELLM_POD_IMAGE` selects it (already an env override, deploy-llm.sh:274)

### 2. New build script `build-teellm-image.sh`

Same `docker run -d` + `docker cp` + `docker commit` + `docker save` shape as
`save_local_docker_image`, so there is one way images are produced in this repository.

Steps:

1. Resolve the base image `taa-env:slim-v2-20260916`; `docker load -i deploy/taa-env-slim-v2.tar.gz`
   when it is absent locally.
2. `docker run -d --name taa-teellm-builder --user root --entrypoint bash "$BASE" -c 'sleep infinity'`
3. Create `/root/taa/configs`, `/root/taa/certs`, `/root/taa/ollama`.
4. Copy the service payload:
   - `teellm/bin/teellm-service` -> `/root/taa/teellm-service`
   - `deploy/teellm-supervisor.sh` -> `/root/taa/teellm-supervisor.sh`
   - `teellm/configs/teellm-production.json`, `teellm/configs/models.json` -> `/root/taa/configs/`
   - `deploy/certs/hrk.cert`, `deploy/certs/hsk_cek.cert` -> `/root/taa/certs/`
5. Stream the pruned ollama bundle with the same file list the deployment uses today
   (37 entries, 4.5 GB):
   - `ollama`, `start-ollama.sh`
   - `lib/ollama/*` except `cuda_v12` (1.2 GB), `cuda_v13` (807 MB), `mlx_cuda_v13` (2.3 GB),
     `vulkan`, `include`
   - `models/models/{manifests,cache,id_ed25519*}` and the five blobs of `qwen2.5-coder:7b`
   - everything under `tar -C "$OLLAMA_LOCAL_DIR" -cf - -T "$list" | docker exec -i ... tar -xf -`
6. Inside the image:
   - recreate the six soname symlinks (`libllama-common.so.0`, `libggml*.so.0`, ...); the bundle
     ships versioned files only and `llama-server` exits 127 without them
   - `chmod +x` the service, the supervisor, `ollama`, `start-ollama.sh`, `lib/ollama/llama-*`
   - `printf %s qwen2.5-coder:7b > /root/taa/.teellm-model`
7. `docker commit -c 'WORKDIR /root/taa'` (the base image's ENTRYPOINT is left alone; the Pod
   overrides `command`/`args` anyway).
8. `docker save | pigz > deploy/taa-env-teellm-<date>.tar.gz`.
9. On 178: `docker load`, `docker tag`, `docker push 172.16.10.178:31313/taa-env:teellm-<date>`.

Acceptance check before tagging: in the builder container, `test -s` every payload path, run the
soname-link check, and `./ollama --version`. Image unpacked size should be ~7 GB (base ~2.5 GB +
4.6 GB model), well under the guest's 19 GB tmpfs.

### 3. Template: the supervisor exists at boot

`deploy/manifest/k8s/teellm-pod.yaml.tmpl` args currently wait for the deployment to install the
script:

```
while [ ! -x /root/taa/teellm-supervisor.sh ]; do
  echo "waiting for /root/taa/teellm-supervisor.sh" >&2
  sleep 2
done
```

With the script in the image this loop is dead weight (and the comment about "the deployment
installs the script after this container is Ready" becomes wrong). Remove the wait loop and keep:

```
while true; do
  /root/taa/teellm-supervisor.sh
  echo "supervisor exited; restarting in 2s" >&2
  sleep 2
done
```

The `mknod /dev/csv-guest` block stays: the guest registers the misc device but `/dev` in the
container is a fresh tmpfs.

`TEELLM_MODEL` stays as the first-boot fallback; `.teellm-model` is now baked in as well.

### 4. `deploy-llm.sh`: stop moving what the image already has

- `copy_ollama_to_remote_pod()` already probes the Pod for the runtime and the model and skips
  when both are present — no change needed.
- `sync_ollama_to_remote()` runs *before* that probe and copies the bundle local -> host. With a
  baked image it is pure overhead. Reorder `deploy_teellm()`: probe the Pod first, and call
  `sync_ollama_to_remote` only when the Pod is missing something.
- No change to Pod creation: `--create-pod` still renders the template and applies it; the image
  tag now comes from `TEELLM_POD_IMAGE`.

### 5. Sizing

Guest rootfs tmpfs: 19 GB, ~7 GB used after unpack, before the model loads. Model load adds
~5 GB of RSS inside the container cgroup, so keep the `16Gi` limit but verify with a real
inference after the first boot. If it is tight, `TEELLM_POD_MEMORY=20Gi` (guest RAM +4 GiB, a
permanent host cost because CSV2 memory is resident from boot).

### 6. Rollout

1. Build and push the image.
2. `TEELLM_POD_IMAGE=172.16.10.178:31313/taa-env:teellm-<date> ./deploy-llm.sh pod-down`
   (the Pod spec is immutable; the writable layer goes with it).
3. `TEELLM_POD_IMAGE=... ./deploy-llm.sh --create-pod --pod taa-teellm start`
4. Verify: `ps -ef` shows the supervisor, `ollama serve` and `teellm-service`; `-probe` returns
   `OK`; the log says `using Hygon hardware evidence provider`.
5. Reboot test: `systemctl reboot` the node (or `kubectl delete pod taa-teellm` — same effect on
   the guest) and confirm the service is up again without running the deployment.
6. Re-point TAA (see below).

## Out of scope

- **Endpoint binding**: after a reboot the Pod IP may change and TAA still dials the IP baked
  into its image. Fixing that needs either `hostNetwork: true` (node IP, needs a kata/CSV2
  feasibility test), a TAA-side env override (`TAA_LLM_ENDPOINT` is already honoured by
  `deploy.sh`), or a post-boot script that rewrites the config inside each TAA pod.
- **Model updates**: a baked model means a new image per model. `deploy-llm.sh --pod ... start`
  still works for an in-place update, but it only lasts until the next sandbox recreation.

## Risks

- Guest image pull grows by 4.6 GB, so every new sandbox spends that much longer in CDH unpack;
  `TEELLM_POD_READY_TIMEOUT=600` covers it today.
- The image is ~5 GB compressed; the local registry must hold it.
- Keeping `strip_teellm_from_image` in the TAA path is load-bearing: if a future TAA image is
  built from this teellm image by mistake, every TAA pod inherits 4.6 GB.

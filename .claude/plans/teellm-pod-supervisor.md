# TEE-LLM Pod supervisor

## Problem

`deploy-llm.sh --create-pod` started `teellm-service` and `ollama` with `nohup ... &` from the
deployment, and the Pod's container command ended in `sleep infinity`. Nothing owned either
daemon:

- `restartPolicy: Always` only reacts to PID 1 (`sleep infinity`) exiting, so a dead daemon did
  not restart the container.
- The Pod template has no liveness probe.
- `teellm/deploy/start.sh` already had the right shape but was never installed or started; it
  also hard-codes `configs/teellm-docker.json`, so it could not serve this Pod as-is.
- Restarting the whole container to recover one daemon would reload the model.

## Design

`deploy/teellm-supervisor.sh` becomes the container's PID 1. It owns both daemons and restarts
them. The deployment drives it through files in `/root/taa`, because a `kubectl exec` session
cannot own a process that outlives it:

| File | Meaning |
|---|---|
| `.teellm-supervisor-pause` | keep both daemons down; the deployment sets it before overwriting the binary or streaming a model over the live tree |
| `.teellm-supervisor-restart` | re-exec the supervisor, so an updated script applies without recreating the CSV2 guest |
| `.teellm-model` | model selected by the deployment; a reused Pod keeps its creation-time env |

The ollama health check runs inside the teellm-service supervision loop, not only between
service exits, so a dead ollama is recovered while the service keeps running.

### Pods that predate the supervisor

Their container command is still `sleep infinity`, and a Pod's command is immutable, so no
process inside the Pod will ever exec the installed script. After a short grace period the
deployment starts the supervisor detached. That copy is a flock singleton, so it cannot race
the container command of a Pod created with the new template. It is not PID 1, though: a
restart of the container on such a Pod loses it until the next deployment. Recreating the Pod
is what makes supervision container-durable.

## Deployment flow

1. Reuse or create the Pod (`pod_up`), recording `TEELLM_POD_REUSED`.
2. Pause the supervisor.
3. Stop the daemons.
4. Sync and stream the ollama bundle into the Pod.
5. Copy the binary, config and certificates; install the supervisor with `mv` (overwriting a
   running script fails with ETXTBSY).
6. Write `.teellm-model`, then make sure a supervisor is running (the container command starts
   it on a new Pod; the deployment starts it detached on one that predates it).
7. Resume: request a restart on a reused Pod, then remove the pause file.
8. Wait for ollama, then probe teellm-service through TEE-TLS.

`stop` pauses the supervisor before killing the daemons, so they stay stopped.

## Files

- `deploy/teellm-supervisor.sh` (new)
- `deploy/manifest/k8s/teellm-pod.yaml.tmpl` — env block, supervisor bootstrap as PID 1
- `deploy-llm.sh` — pause/resume helpers, install, model file, reordered start sequence
- `tests/teellm_supervisor_test.sh` (new)
- `tests/deploy_llm_remote_pod_test.sh` — manifest and ownership assertions, `stop` case

## Verification

- `bash tests/teellm_supervisor_test.sh`
- `bash tests/deploy_llm_remote_pod_test.sh`
- `bash tests/deploy_ollama_preflight_test.sh`
- `go test ./cmd/... ./internal/... ./pkg/... ./tools/...` (`go test ./...` is blocked by the
  audit corpus under `models/audit/holdout-sources`)

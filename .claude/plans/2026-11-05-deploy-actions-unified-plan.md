# Unify the deploy-script actions on deploy-llm.sh's vocabulary

## Decisions (confirmed)

- Actions: `create` (default) / `update` / `start` / `stop` / `probe` / `delete`, plus
  `save` where packaging exists (`deploy.sh`, `deploy-fhe.sh`).
- `start` and `stop` are the two ends of the same switch: start the TAA (or core) service
  already installed in the Pod, stop it. Neither copies files.
- `create` is the only action that creates a Pod. It builds the image from this tree, creates
  the Pod, then **verifies** that what the Pod carries is the freshly built artifact. It never
  repairs: a mismatch fails the run and prints the difference.
- Identity (`PLATFORM_IP`, `DOCKER_ID`, `PLATFORM_PUBLIC_KEY`, `CONTRACT_ID`) stays in the Pod
  manifest's environment, not in `taa-config.json` — the remote config renderer already drops
  the platform block (`write_taa_config ... false`), and the config loader falls back to the
  environment when the file's fields are empty. `create` does not verify identity.
- `delete` removes only a Pod this deployment owns. A Pod named by `--pod` is refused.
- `deploy-platform-mock.sh` keeps `start|stop|restart|status`: it manages a process, not a Pod.

## Target behaviour per script

### deploy.sh

| action | behaviour |
|---|---|
| `create` (default) | Refuse with `--pod` (it never creates a named Pod). Pod absent: build+push the production image, create the Pod, wait Ready, check `/dev/csv-guest`. Pod present: reuse it. In both cases verify `/root/taa/taa`, `taa-config.json`, `taa-supervisor.sh` and the semgrep payload when configured against the local build, then wait for the service. Any mismatch → "Pod creation failed", one line per item, no repair. |
| `update` | Pod must exist. Build the binary, render the config (model + `LLM_IP`, no identity), upload, pause, provision the scan engine, replace, resume, wait ready. Today's remote install path. |
| `start` | Pod must exist. `rm -f $TAA_WORKDIR/manual`, wait ready. No file changes. |
| `stop` | Pod must exist. `touch manual` + `pkill taa`. The Pod is left in place. |
| `probe` | Pod must exist. Wait for readiness, non-zero exit on timeout. |
| `delete` | Only without `--pod`. Pause the service, delete the Pod, report reclaimed memory. |
| `save` | Unchanged. |

Verification uses streamed hashes (`kubectl exec ... cat` piped to `sha256sum` on the remote
host) so it does not depend on tools inside the guest image.

### deploy-llm.sh

- Default action becomes `create`.
- `start` stops installing: resume the supervisor, wait for teellm-service, probe. No binary
  build, no model sync, no file copy.
- `update` keeps today's start/update install path (build binary, sync model/runtime, install
  supervisor and config, restart, verify).
- `create`, `stop`, `probe`, `delete`, `models *` unchanged.

### deploy-fhe.sh

- Add `deploy/manifest/k8s/fhe-pod.yaml.tmpl`: kata CSV2 Pod, `nvidia.com/gpu: 1`
  (overridable), `cc_init_data` annotation, csv-guest postStart hook, identity env, no hostPath.
- `create` (default): assemble the `save` image (FHE_IMAGE + TAA + supervisor + rendered config +
  **models baked in**), push it to the registry, create the Pod, wait Ready, verify the files
  inside against the build, wait for both health endpoints.
- `update` / `start` / `stop` / `probe` / `delete`: Pod mode uses the supervisor manual-file
  protocol (as the current `--pod` path does); docker mode maps to the container lifecycle
  (`create_or_reuse_container`, `docker start`, supervisor pause, `docker rm -f`).
- `save` unchanged (it still does not bake models; only `create` needs the Pod image to carry
  them).

Risk to verify on the host: `nvidia.com/gpu` through `kata-qemu-csv2` has not been exercised
here. `create` fails loudly (Pod Pending / no device) rather than silently degrading.

### deploy-dataanaylsis.sh

Forwards to `deploy.sh`; only its `save` defaults change (they already pass `--image` /
`--archive`). No action changes of its own.

## Documentation

- `deploy.md`: rewrite each script's action table; make `create` the default and state that it
  verifies instead of copying.
- `CHANGELOG.md`: one `### Changed` entry.

## Tests

- `tests/deploy_taa_remote_pod_test.sh`: `start` → `create` for the deploy cases, `stop` no
  longer deletes the Pod (add `delete`).
- New lightweight checks (dry-run / parser only, no SSH): unknown action, default action is
  `create`, `create --pod` refused, `delete --pod` refused.
- Run sequentially; never alongside another agent's tests.

## Out of scope

- Changing TAA's identity precedence or the config schema.
- GPU passthrough validation on the host (it needs a real Pod).

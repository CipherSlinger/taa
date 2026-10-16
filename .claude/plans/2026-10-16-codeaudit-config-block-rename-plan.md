# Rename the `security` config block to `codeAudit`, and move `llm` inside it

## Context

TAA's startup config has two blocks whose names no longer match what they hold:

- `security` holds the **code audit** settings (`codeScan`, `codeScanEngine`, `semgrepRulesPath`,
  `semgrepTimeoutSeconds`, `binaryAudit`) *plus* two things that are not a code audit at all:
  `resultCheck` (the plaintext-leakage check on training results) and `maxFileBytes`.
- `llm` sits at the **top level**, even though the inference service exists for exactly one
  purpose: adjudicating findings the static scanner raised. After TAA and TEE-LLM were split
  into separate deployments, a top-level `llm` block reads as though TAA owned a model.

The Go side already disagrees with the file: `controller.SecurityConfig`
(`internal/controller/route.go:42-57`) nests `LLM` and `Binary` inside one audit aggregate, and
`buildSecurityConfig` (`internal/app/taa/app.go:618-696`) builds them together. This change makes
the file say what the code already does.

Decided with the user:
1. `resultCheck` and `maxFileBytes` **stay inside** the renamed block (minimal diff, no
   reorganisation of unrelated settings).
2. The old keys `security` and top-level `llm` are **explicitly rejected** at load time rather
   than silently ignored.
3. The Go rename goes **all the way to `StartupConfig`'s flat fields**: `EnableSecurityScan` is
   renamed, and the nineteen `LLM*` fields are collapsed into one nested struct.

## Target shape

```json
{
  "codeAudit": {
    "codeScan": true,
    "codeScanEngine": "semgrep",
    "semgrepRulesPath": "/opt/taa/semgrep/rules",
    "resultCheck": { "enabled": true, "maxFileBytes": 3221225472 },
    "binaryAudit": { "enabled": true },
    "llm": {
      "enabled": true,
      "transport": "teetls",
      "endpoint": "https://127.0.0.1:8443",
      "model": "qwen2.5-coder:7b",
      "policy": "assist",
      "failClosed": true,
      "attestationMode": "permissive"
    }
  }
}
```

Key order inside the block follows the current templates (`resultCheck` before `binaryAudit`),
with `llm` appended last.

## 1. `internal/config/config.go` — the loader

**`startupConfigFile` (`:131-157`)**
- `Security startupSecurityConfigFile \`json:"security"\`` → `CodeAudit startupCodeAuditConfigFile \`json:"codeAudit"\``.
- Drop the top-level `LLM startupLLMConfigFile \`json:"llm"\`` field.

**Removed-key detection.** `encoding/json` drops unknown keys without a trace, so an old config
would keep loading and silently run every audit setting at its default — `codeScanEngine` back to
`regex`, `llm.endpoint` back to `127.0.0.1:8443` — with nothing in the log. Declare the two old
keys so their presence is observable:

```go
// Removed keys. Declared only so that their presence is detectable: encoding/json
// drops an unrecognised key silently, so a config that still says "security" would
// load with every audit setting at its default instead of failing.
RemovedSecurity json.RawMessage `json:"security"`
RemovedLLM      json.RawMessage `json:"llm"`
```

Add `rejectRemovedKeys(path string, fileCfg startupConfigFile) error`, called from
`LoadStartupConfig` (`:272-290`) between the unmarshal and `applyStartupConfigFile`. Treat nil and
the literal `null` as absent. Report both keys in one error when both are present, so an operator
fixes it in one pass:

```
startup config /etc/taa/taa-config.json uses removed keys: "security" (rename to "codeAudit"),
"llm" (move under "codeAudit.llm")
```

**`startupSecurityConfigFile` (`:181-193`)** → rename to `startupCodeAuditConfigFile`; keep every
field and its current order; add `LLM startupLLMConfigFile \`json:"llm"\``. Update the doc comment
at `:195`.

**Apply logic (`applyStartupConfigFile`, `:464-693`)**
- `fileCfg.Security.*` → `fileCfg.CodeAudit.*` throughout (`:495-533`, `:551`, `:561-566`).
- `fileCfg.LLM.*` (`:632-692`) → `fileCfg.CodeAudit.LLM.*`.

**Validation error strings** — every rejection should name the key path an operator must edit,
which is already the pattern for `binaryAudit`:
- `validateBinaryAudit` (`:339,342,345,348,351`): `security.binaryAudit.*` → `codeAudit.binaryAudit.*`.
- `validateCodeScanEngine` (`:399`): → `codeAudit.codeScanEngine`.
- `validateSemgrepTimeout` (`:387`): → `codeAudit.semgrepTimeoutSeconds`.
- `validateLLMTemperature` (`:375`): → `codeAudit.llm.temperature`.
- `validateLLMPolicy` (`:409`): → `codeAudit.llm.policy`.

**`StartupConfig` (`:17-129`)**
- `EnableSecurityScan bool` → `EnableCodeAudit bool`.
- The nineteen `LLM*` fields (`:104-128`) collapse into one field `LLM LLMConfig`, backed by a new
  `type LLMConfig struct` in this file. Field names drop the redundant prefix:
  `Enabled`, `Transport`, `Endpoint`, `AttestationMode`, `HRKCertPath`, `HSKCekCertPath`,
  `ExpectedMeasurements`, `RequireMutualAttest`, `InsecureSkipVerify`, `AuthToken`, `TimeoutMs`,
  `AllowedHosts`, `CircuitBreakerThreshold`, `CooldownSec`, `Model`, `Policy`, `Temperature`,
  `FailClosed`, `Dir`. Keep the existing `Temperature` doc comment (`:123-128`) attached to it.
  The name collides with `codeaudit.LLMConfig` in a different package only; call sites stay
  unambiguous because one is always qualified.
- **Unchanged and deliberately so:** `CodeScanEngine`, `SemgrepRulesPath`, `SemgrepTimeout`,
  `BinaryAudit*` (6), `EnableResultCheck`, `MaxFileBytes`, `MaxResultBytes` stay flat.

**`defaultStartupConfig()` (`:413-462`)** — `LLMModel:` etc. become `LLM: LLMConfig{...}`. Values
are unchanged (including the `hrkDefault` fallback logic at `:414-421`).

## 2. Go consumers

- `internal/app/taa/app.go`: `cfg.EnableSecurityScan` → `cfg.EnableCodeAudit` (`:650`);
  `cfg.LLM*` → `cfg.LLM.*` in `probeInferenceService` (`:222-291`, ~12 reads) and
  `buildSecurityConfig` (`:628-694`, ~19 reads). `logSecurityConfig` (`:723-735`) reads
  `sec.LLM.*` off `controller.SecurityConfig`, which is unchanged.
- `internal/controller/` needs **no source change**: it consumes `controller.SecurityConfig`,
  which keeps its name and field layout. (It is an aggregate that also carries `ModelDir`,
  `DataDir`, `ResultDir` and the staging dirs, so `codeAudit` would be the wrong name for it.)
- `cmd/taa/main.go` — no change.

## 3. Config templates

`configs/taa-docker.json`, `configs/taa-production.json`, `configs/taa-initrd.json`: rename the
`security` key to `codeAudit` and move the top-level `llm` object inside it, preserving each
file's current values (including `taa-initrd.json`'s `semgrepTimeoutSeconds: 900` and the
per-template `endpoint` / `failClosed` values).

## 4. Deploy scripts

These read and rewrite the two keys by name, so each must move in lockstep with the templates or
deployment breaks on a template that was not updated:

- `deploy.sh:969-984` `get_taa_config_llm_model()` — `(data.get("llm") or {}).get("model")` →
  `((data.get("codeAudit") or {}).get("llm") or {}).get("model")`.
- `deploy.sh:1001-1003` — `cfg.get("security")` → `cfg.get("codeAudit")`.
- `deploy.sh:1103,1105` — error text and hint naming `security.semgrepRulesPath` /
  `security.codeScanEngine`.
- `deploy.sh:1279-1284` `write_taa_config()` — `cfg.setdefault("llm", {})` →
  `cfg.setdefault("codeAudit", {}).setdefault("llm", {})` (keep the `llm.pop("dir", None)` line).
- `deploy.sh:137, 753` — comments/help naming the old paths.
- `deploy-docker.sh:379-382` — `cfg.setdefault("security", {})` → `cfg.setdefault("codeAudit", {})`;
  comments at `:193, 365-371, 389-391`.
- Leave the legacy **flat** strip list at `deploy.sh:1275` alone (`securityScan`, `resultCheck`,
  `maxFileBytes`, `maxResultBytes` are pre-existing root-level aliases, unrelated to this rename).
- `deploy/guest-build/build-initrd.sh:245` needs **no change**: it greps for the literal
  `"codeScanEngine": "semgrep"`, whose name is unchanged inside the block.

## 5. Documentation

- `README.md`: the sample config block (`:341-364` — the `security` block and the `llm` block
  become one `codeAudit` block), the field table rows (`:382-391`, `:394-402`), the config-domain
  list (`:313`), the remote-deploy note (`:467`), and the prose reference at `:269`.
- `docs/architecture-design.md:190` — the seven-section list.
- `docs/api-design.md:403, 1160` — `security.resultCheck.enabled` / `llm.failClosed` key paths.
  **This file is in the user's uncommitted WIP**; edit only these lines and stage per-hunk.
- `docs/architecture-design.md` and `deploy/2026-10-10-taa-in-csv2-initrd-design.md:240-241` are
  point-in-time records; the dated design doc keeps its old key names, as it already does for the
  removed `model.checkpoint`.
- `CHANGELOG.md`: one `### Changed` entry covering the rename, the moved `llm`, the new
  removed-key rejection, and the upgrade consequence below.

## 6. Tests

- `internal/config/config_test.go` — the `"security"` fixtures at `:204, 226, 520, 575, 929, 980,
  1033, 1060` and inline forms at `:954, 1001, 1019, 1134, 1150, 1163, 1199, 1209`; the `llm`
  fixtures at `:25-31, 275-278, 729-748, 863, 885-888, 903, 1121`. Then the flat-field assertions
  (`EnableSecurityScan` → `EnableCodeAudit`, `LLMModel` → `LLM.Model`, `LLMEndpoint` → `LLM.Endpoint`,
  and the rest of the `LLM*` set), and the prose in the test names/docstrings at `:221, 925`.
  `TestLoadStartupConfigMaxFileBytesPrecedence` (`:198-255`) keeps its precedence chain — only the
  fixture key names change.
- `internal/app/taa/app_test.go:82-406, 455-505` — `TestBuildSecurityConfig*` constructs
  `config.StartupConfig` literals; update the renamed/moved fields.
- **Two new tests**, both in `internal/config/config_test.go`:
  - `TestLoadStartupConfigRejectsRemovedSecurityKey` — a config with `"security": {...}` must fail
    with an error naming `codeAudit`.
  - `TestLoadStartupConfigRejectsRemovedTopLevelLLMKey` — a config with a top-level `"llm": {...}`
    must fail naming `codeAudit.llm`. Include the both-keys case so the combined message is pinned.

## 7. Upgrade consequence (must be stated in the CHANGELOG)

The new rejection is a **startup failure**, and on the CSV2 initrd path TAA is a boot gate
(`taa-init` sees TAA die and refuses to hand the VM to kata-agent). So:

- Binary and `configs/taa-initrd.json` must ship together — the initrd carries its config verbatim
  and a mismatched pair does not boot.
- Any previously baked production image or on-disk `.local/run/*-taa-config.json` has the old
  shape. `deploy.sh` regenerates the `.local/run` copies from the templates on the next deploy,
  so those recover with a redeploy; a pre-built image needs rebuilding.
- Moving `configs/taa-initrd.json` changes the bytes of a built initrd and therefore its boot
  MEASUREMENT (no in-repo constant pins it; `expectedMeasurements` is unset).

## Out of scope

- `config.StartupConfig.LLMDir` / `llm.dir` — no production consumer, and `deploy.sh` strips it on
  generation. Left as-is; noted here because it is dead config of the kind recently removed
  elsewhere.
- The root-level legacy aliases (`securityScan`, `resultCheck`, `maxFileBytes`, `maxResultBytes`)
  and the undocumented `codeAudit.scan` alias. All keep working with their current precedence.
- `controller.SecurityConfig`'s name and field layout.

## Drive-by fixes (small, in files this change already touches)

- `internal/config/config.go:23-24` claims `CodeScanEngine`'s "default stays `regex`";
  `defaultStartupConfig` sets `semgrep`. Correct the comment.
- `README.md:397` lists `llm.model`'s default as `qwen2.5-coder:3b`; the code default is
  `qwen2.5-coder:0.5b` and all three templates say `7b`. Correct it to the code default and note
  the templates override it.

## Verification

1. `CGO_ENABLED=0 GOOS=linux go build -o bin/taa ./cmd/taa` — the initrd build rejects a
   dynamically linked binary, so build it the way production does.
2. `go test ./internal/config/... ./internal/app/... ./internal/controller/... ./internal/runtime/...`
   Expected: the two new rejection tests pass, everything else green except the pre-existing
   `TestLoadStartupConfigTemplateFiles/taa-docker.json` failure (`platform.ip` is `28080` in the
   user's uncommitted WIP, assertion says `18080`) — unrelated to this change, already failing at
   baseline.
3. Load each template for real and diff the resolved config against the pre-change resolution, to
   prove the rename moved no *value*:
   `go run ./cmd/taa -config configs/taa-docker.json` is not usable (it starts the server), so pin
   this with a test instead: extend `TestLoadStartupConfigTemplateFiles` (already table-driven over
   `configs/taa-production.json` and `configs/taa-docker.json`) and confirm every `want*` field is
   byte-identical to before apart from the renamed identifiers.
4. `grep -rn '"security"\|"llm"' configs/ deploy*.sh README.md docs/` and confirm every remaining
   hit is either the `codeAudit` context, a legacy root alias, or a dated design record.
5. Negative test by hand: copy a template, rename the block back to `security`, and confirm TAA
   exits with the actionable message rather than starting.
6. Confirm `deploy.sh` still generates a config the loader accepts — run
   `bash -n deploy.sh deploy-docker.sh` plus the `write_taa_config` python body against a template
   copy, then load the result with `config.LoadStartupConfig` (a scratch `go test` is the cheap way;
   do not run it against the repo's tracked templates).

## Deliverable bookkeeping

Per `CLAUDE.md`, also drop this plan into `.claude/plans/` and `git add -f` it (`.claude/` is
gitignored, and recent specs/plans are committed with `-f`). Commit in English, Conventional
Commits, breaking marker — `feat(config)!: rename the security block to codeAudit and move llm into it`
— with no AI attribution lines.
